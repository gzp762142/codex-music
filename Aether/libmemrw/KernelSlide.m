//
//  KernelSlide.m
//  Aether
//
//  职责与依赖面见 KernelSlide.h。本文件做三件事，顺序即数据流：
//    ① 从「本进程的一条 vnode 描述符」反查出运行时 vn_kqfilter；
//    ② 用 XPF 给的链接期 vn_kqfilter 相减得到 kernel slide，并用 kernel_base
//       处的 Mach-O 头自检；
//    ③ 读回 ptov_table 与 gVirtBase/gPhysBase/gPhysSize，提供 PA → KVA 换算。
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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#pragma mark - 常量：值从哪来，为什么可以写死

/*
 * kernelcache 在文件里的链接地址（内核 image 的 __TEXT 段起点）。
 * 与 libkfd/info/static_info.h:12 的 ARM64_LINK_ADDR 同值。
 *
 * 它不随设备变：每个版本的 kernelcache 都按这个 vmaddr 链接，运行时被 ASLR
 * 整体搬到 ARM64_LINK_ADDR + slide —— slide 就是本文件要算的那个数。
 */
#define KM_SLIDE_LINK_ADDR 0xfffffff007004000ULL

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

/* 换算表。三项都读到位才置 g_convertReady，避免下游看到"读了一半"的表。 */
static bool g_convertReady = false;
static km_slide_ptov_entry g_ptov[KM_SLIDE_PTOV_COUNT];
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
 */
static uint64_t slide_read_kernel_ptr(uint64_t addr, const char *field,
                                      uint64_t t1sz, km_slide_text *t)
{
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
 * 步骤之间传递的数据。只活在一个栈帧里，所以它自己不需要任何并发保护；
 * 全局状态只在最后一次性提交（见 slide_run_locked 的收尾）。
 */
typedef struct {
    int      fd;              /* 探测用文件描述符，-1 表示未打开 */
    uint64_t proc;            /* 本进程 struct proc 的内核地址 */
    uint64_t fdOfilesOffset;  /* struct proc 内 p_fd->fd_ofiles 的偏移 */
    uint64_t t1sz;            /* T1SZ_BOOT，PAC 掩码的来源 */
    uint64_t foKqfilter;      /* 运行时 vn_kqfilter（已还原 PAC） */
    bool     slideVerified;   /* ⑤ 自检是否通过 —— 不能用 slide != 0 代替：
                               * 内核没开 ASLR 时 slide 合法地为 0，那时"0"是值不是标志 */
    uint64_t slide;
    uint64_t kernelBase;
    km_slide_ptov_entry ptov[KM_SLIDE_PTOV_COUNT];
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
 * 常数"和"该常数加在 ARM64_LINK_ADDR 上正对着 Mach-O 头"。
 */
static bool slide_resolve_fo_kqfilter(km_slide_run *run, km_slide_text *t)
{
    if (run->fd < 0 || run->fd >= KM_SLIDE_MAX_FD) {
        text_append(t, "  fd=%d 不在可用范围（0..%d）\n", run->fd, KM_SLIDE_MAX_FD - 1);
        return slide_refuse(run, t, "③ fd→fo_kqfilter", "fd 索引不合理");
    }

    const uint64_t fdOfiles = slide_read_kernel_ptr(run->proc + run->fdOfilesOffset,
                                                   "fd_ofiles", run->t1sz, t);
    if (!fdOfiles) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fd_ofiles 失败");

    const uint64_t fileprocAddr = fdOfiles + (uint64_t)run->fd * sizeof(uint64_t);
    const uint64_t fileproc = slide_read_kernel_ptr(fileprocAddr, "fileproc", run->t1sz, t);
    if (!fileproc) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fileproc 失败");

    const uint64_t fpGlob = slide_read_kernel_ptr(fileproc + KM_OFF_FILEPROC_FP_GLOB,
                                                 "fp_glob", run->t1sz, t);
    if (!fpGlob) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fp_glob 失败");

    const uint64_t fgOps = slide_read_kernel_ptr(fpGlob + KM_OFF_FILEGLOB_FG_OPS,
                                                "fg_ops", run->t1sz, t);
    if (!fgOps) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fg_ops 失败");

    const uint64_t foKqfilter = slide_read_kernel_ptr(fgOps + KM_OFF_FILEOPS_FO_KQFILTER,
                                                     "fo_kqfilter", run->t1sz, t);
    if (!foKqfilter) return slide_refuse(run, t, "③ fd→fo_kqfilter", "读 fo_kqfilter 失败");

    run->foKqfilter = foKqfilter;
    text_append(t, "③ 链：fd_ofiles=%#llx fileproc=%#llx fp_glob=%#llx fg_ops=%#llx fo_kqfilter=%#llx\n",
                (unsigned long long)fdOfiles, (unsigned long long)fileproc,
                (unsigned long long)fpGlob, (unsigned long long)fgOps,
                (unsigned long long)foKqfilter);
    return true;
}

/*
 * slide 自检 —— 与 perf.h:112-118 同一条判据：
 *     kernel_base = ARM64_LINK_ADDR + slide
 *     kernel_base 处的两个 32 位字必须是 MH_MAGIC_64 与 cputype(=arm64|ABI64)
 *
 * 为什么这条能证明 slide 对：slide 是「运行时 vn_kqfilter − 链接期 vn_kqfilter」，
 * 两边任一处错，得到的都是一个随机数；随机 slide 加在 ARM64_LINK_ADDR 上，恰好
 * 落在一段以这两个字开头（且相邻两个字都对）的内核数据上的概率是 2^-64 量级。
 *
 * 顺带把一处容易读错的细节写下来：0x0100000c 是 **cputype**（CPU_TYPE_ARM64 |
 * CPU_ARCH_ABI64），不是 arm64e 的标识 —— arm64e 体现在紧随其后的 cpusubtype
 * 里（CPU_SUBTYPE_ARM64E）。所以这条判据对 arm64 与 arm64e 是同一套。
 *
 * 失败时把**算出来的 slide、kernel_base、实际读到的两个字**都写进诊断 ——
 * 那是唯一能反推"是 slide 错还是读错"的证据。
 */
static bool slide_verify_kernel_base(km_slide_run *run, uint64_t candidate, km_slide_text *t)
{
    run->kernelBase = KM_SLIDE_LINK_ADDR + candidate;

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

    text_append(t, "⑤ 自检通过：slide=%#llx kernel_base=%#llx 头部=%#x/%#x\n",
                (unsigned long long)run->slide,
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

    if (!slide_verify_kernel_base(run, candidate, t)) return false;

    run->slide = candidate; /* 自检通过才采信 */
    run->slideVerified = true;
    return true;
}

#pragma mark - 步骤⑥⑦：换算表与抽样

/*
 * 读回 ptov_table（8 项定长表），逐行对照 perf.h:150-151。
 *
 * 每一项都要过形态检查：va 必须是内核地址（它描述的是内核虚拟映射）、pa 与 len
 * 必须落在物理地址空间（< 2^48）且 len 非 0。表按「len == 0 即结束」解释
 * （perf.h:240 的循环条件原样继承），至少要有 1 项有效。
 *
 * 任何一项不合法就整表拒绝 —— 半张表比没有表更危险：下游的 phystokv 会用它算出
 * 一个落点在别处的地址，而那正是"段外换算"的形态（KernelMemory.m 里记着的
 * bug_type 210 就是这一路）。
 */
static bool slide_read_ptov_table(uint64_t slide, km_slide_ptov_entry *out,
                                  km_slide_run *run, km_slide_text *t)
{
    const uint64_t symbol = km_xpf_resolve_symbol(@"kernelSymbol.ptov_table");
    if (symbol == 0) {
        text_append(t, "  XPF 取不到 kernelSymbol.ptov_table\n");
        return slide_refuse(run, t, "⑥ ptov_table", "XPF 没解析出 ptov_table");
    }

    const uint64_t tableAddr = symbol + slide;
    km_slide_ptov_entry table[KM_SLIDE_PTOV_COUNT] = {};
    const size_t tableSize = sizeof(table);

    if (!slide_read_bulk(tableAddr, table, tableSize)) {
        text_append(t, "  ptov_table=%#llx（符号 %#llx + slide）读失败\n",
                    (unsigned long long)tableAddr, (unsigned long long)symbol);
        return slide_refuse(run, t, "⑥ ptov_table", "表读不出来");
    }

    uint64_t valid = 0;
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        if (table[i].len == 0) break; /* 表结束（perf.h:240） */

        if (!km_slide_kernel_ptr(table[i].va) ||
            table[i].pa >= (1ULL << 48) ||
            table[i].len >= (1ULL << 48)) {
            text_append(t, "  ptov[%llu] 形态不合法：pa=%#llx va=%#llx len=%#llx\n",
                        (unsigned long long)i,
                        (unsigned long long)table[i].pa,
                        (unsigned long long)table[i].va,
                        (unsigned long long)table[i].len);
            return slide_refuse(run, t, "⑥ ptov_table", "表项形态不合法");
        }
        valid++;
    }

    if (valid == 0) {
        text_append(t, "  ptov_table 一项有效项都没有（首项 len 就是 0）\n");
        return slide_refuse(run, t, "⑥ ptov_table", "表是空的");
    }

    memcpy(out, table, tableSize);
    text_append(t, "⑥ ptov_table=%#llx（符号 %#llx + slide）有效项 %llu\n",
                (unsigned long long)tableAddr, (unsigned long long)symbol,
                (unsigned long long)valid);
    return true;
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

    for (size_t i = 0; i < 3; i++) {
        NSString *key = [NSString stringWithUTF8String:fields[i].key];
        const uint64_t symbol = km_xpf_resolve_symbol(key);
        if (symbol == 0) {
            text_append(t, "  XPF 取不到 %s\n", fields[i].name);
            return slide_refuse(run, t, "⑦ 全局基准", "XPF 没解析出 gVirtBase/gPhysBase/gPhysSize");
        }

        bool ok = false;
        *fields[i].slot = slide_read64(symbol + slide, &ok);
        if (!ok) {
            text_append(t, "  %s=%#llx（符号 %#llx + slide）读失败\n",
                        fields[i].name, (unsigned long long)(symbol + slide),
                        (unsigned long long)symbol);
            return slide_refuse(run, t, "⑦ 全局基准", "三个全局里有一个读不出来");
        }
    }

    if (!km_slide_kernel_ptr(run->virtBase) ||
        run->physBase == 0 || run->physBase >= (1ULL << 48) ||
        run->physSize == 0 || run->physSize >= (1ULL << 48)) {
        text_append(t, "  基准形态不合法：gVirtBase=%#llx gPhysBase=%#llx gPhysSize=%#llx\n",
                    (unsigned long long)run->virtBase,
                    (unsigned long long)run->physBase,
                    (unsigned long long)run->physSize);
        return slide_refuse(run, t, "⑦ 全局基准", "读到的值形态不合法");
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
    text_append(t, "== ptov_table（perf.h:232-248 的 8 段查表）==\n");
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT; i++) {
        if (run->ptov[i].len == 0) break;
        text_append(t, "  [%llu] pa=%#llx va=%#llx len=%#llx\n",
                    (unsigned long long)i,
                    (unsigned long long)run->ptov[i].pa,
                    (unsigned long long)run->ptov[i].va,
                    (unsigned long long)run->ptov[i].len);
    }
    text_append(t, "== 全局基准 ==\n");
    text_append(t, "  gVirtBase=%#llx gPhysBase=%#llx gPhysSize=%#llx\n",
                (unsigned long long)run->virtBase,
                (unsigned long long)run->physBase,
                (unsigned long long)run->physSize);

    /*
     * 交叉对照：xnu 在 arm_vm_init 里把启动期的物理内存段写进 ptov_table，所以
     * 某项的 (pa, va) 往往与 (gPhysBase, gVirtBase) 一致。
     * 这里只**报告**有没有匹配，不当判据 —— 我没有目标机型（iPad14,3 /
     * iPadOS 16.4.1）的第一手证据证明这条恒成立，拿它当判据会让正确的表在某些
     * 机型上被拒。
     */
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
        text_append(t, "（换算失败：既不在 8 段内，也不在 [gPhysBase, gPhysBase+gPhysSize) 内）\n");
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
    if (!slide_read_ptov_table(run->slide, run->ptov, run, t)) return false;
    if (!slide_read_bases(run->slide, run, t)) return false;

    /*
     * 全部到位才提交：避免下游读到"slide 有了、表只读了一半"的中间状态。
     * 提交点只有一个，也是这条流水线上唯一写全局的地方。
     */
    memcpy(g_ptov, run->ptov, sizeof(g_ptov));
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
        char summary[192];
        snprintf(summary, sizeof(summary),
                 "slide=%#llx kernel_base=%#llx 换算表=ready（8 段查表 + 兜底支可用）",
                 (unsigned long long)run.slide, (unsigned long long)run.kernelBase);
        slide_diag_finalize(summary);
        g_slideSettled = true;
        return true;
    }

    char summary[256];
    snprintf(summary, sizeof(summary), "未完成 @%s%s",
             run.failure[0] ? run.failure : "（未知步骤）",
             run.slideVerified ? "；slide 已通过自检，换算表未就绪" : "");
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
    pthread_mutex_lock(&g_slideLock);
    const bool ready = g_convertReady;
    pthread_mutex_unlock(&g_slideLock);
    return ready;
}

/*
 * 无锁版本，只在已持有 g_slideLock 的路径里用（resolve 自己的抽样验证）。
 * 公开的 km_phystokv 是它的加锁包装 —— 分开写是为了避免自己把自己锁死。
 */
static uint64_t slide_phystokv_locked(uint64_t pa)
{
    if (!g_convertReady) return 0;

    /* ① 逐段查表，条件与判据逐字对照 perf.h:240-244。 */
    for (uint64_t i = 0; i < KM_SLIDE_PTOV_COUNT && g_ptov[i].len != 0; i++) {
        if (pa >= g_ptov[i].pa && pa < (g_ptov[i].pa + g_ptov[i].len)) {
            return pa - g_ptov[i].pa + g_ptov[i].va;
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
     */
    if (pa < g_physBase || (pa - g_physBase) >= g_physSize) return 0;
    return pa - g_physBase + g_virtBase;
}

uint64_t km_phystokv(uint64_t pa)
{
    pthread_mutex_lock(&g_slideLock);
    const uint64_t kva = slide_phystokv_locked(pa);
    pthread_mutex_unlock(&g_slideLock);
    return kva;
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
