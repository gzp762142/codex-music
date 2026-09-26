//
//  KernelPhysWindow.m
//  实现见 KernelPhysWindow.h 的组织说明。这里只补「为什么这么写」与证据指针。
//

#import <Foundation/Foundation.h>
#include <sys/sysctl.h>

#include "KernelMemory.h"
#include "KernelSlide.h"
#include "KernelPhysWindow.h"

#pragma mark - 固定几何

/*
 * L1 块大小 / 块数的**来源不是这里，是页大小**。上游 libkfd 把 16K 那一套
 * 写成了常量是因为它只支持 16K 机型；本模块照样本的做法按页大小判定，
 * 所以这两个值只在下面 physwindow_geometry() 里成对出现，不散落到各处。
 *
 *   粒度    L1 块大小            块数   窗口地址 = SIZE × (COUNT − 1)   上界 = SIZE × COUNT
 *   16K     2^36 = 0x1000000000     8   7 × 2^36 = 0x7000000000       8 × 2^36 = 2^39 = 0x8000000000
 *   4K      2^30 = 0x40000000     256   255 × 2^30 = 0x3FC0000000     256 × 2^30 = 2^38 = 0x4000000000
 *
 * 窗口地址 = 上界 − 一个 L1 块 = **最末一个 L1 块的起点**，它本身不是上界
 * （早先这里写成"= 2^45 = MACH_VM_MAX_ADDRESS"，两处都错：既算错了量级，
 * 也把块首当成了上界）。16K 那一列的上界恰与 MACH_VM_MAX_ADDRESS 相等。
 *
 * 16K 那一列与样本反汇编逐位一致（docs/当前任务.md §0.4「地址推导」：
 * 0x101093820 出口读 [0x101cfff78] = _vm_kernel_page_size → 16K 返 0x1000000000，
 * 0x1010939d0 同源 → 16K 返 8；4K 返 0x40000000 与 0x100）。
 *
 * 「窗口地址落在用户地址空间最末一个 L1 块内」这条正是**必须建页表**的理由：
 * 它紧邻上界 MACH_VM_MAX_ADDRESS（0x8000000000），正常分配不会覆盖到它，
 * 所以它现在必然是未映射的（样本 §0.4 (II) 已把"它是不是别人建好的"排除掉了）。
 */
/*
 * 这两个常量是 **L1 表的表项数**，不是"最大索引"。
 *
 * 2026-09-26 纠正：它们原先是 7 / 255（= 表项数 − 1、即最大索引），于是
 * km_physwindow_address() 靠 `SIZE × COUNT` 凑出地址，而同一个文件里
 * physwindow_walk() 的几何自洽断言却按"掩码覆盖几项"来比 —— **7 ≠ 8，断言恒假**，
 * 探针在 `✗ 页表几何自相矛盾` 处终止、一次 kread 都不发（真机症状：
 * 「建窗 未完成：前置不成立」，诊断第 ⑥ 段那三行）。
 *
 * 名字叫 COUNT、注释写着 "= L1_BLOCK_COUNT(8) − 1"，这两件事本身就是矛盾的，
 * 而 KernelPhysMap.m:90 的同一对常量取的是 **8** —— 两个模块对同一套几何持相反语义。
 * 现在统一成"表项数"，最大索引一律在用到的地方写成 `COUNT − 1`。
 * 地址取值不变：2^36 × (8 − 1) = 0x7000000000。
 */
#define KM_PW_16K_BLOCK_SIZE 0x1000000000ULL /* 2^36，一个 L1 表项覆盖的字节数 */
#define KM_PW_16K_BLOCK_COUNT 8ULL           /* L1 表项数（= 最大索引 7 + 1） */
#define KM_PW_4K_BLOCK_SIZE 0x40000000ULL    /* 2^30 */
#define KM_PW_4K_BLOCK_COUNT 256ULL          /* L1 表项数（= 最大索引 255 + 1） */

/*
 * arm64 页表几何。
 *
 * 16K 粒度：L1 shift 36 / L2 shift 25 / L3 shift 14 —— 与
 * Aether/libmemrw/kfd/libkfd/info/static_info.h:62-75 的 ARM_16K_TT_L*_* 同值，
 * 也与 KernelMemory.m 里 KM_L*_SHIFT / KM_L*_MASK 同值。
 *
 * **L1 是 3 位（bits 38:36，掩码 0x7000000000=2^36×7），不是 11 位。** 两条独立出处：
 *   · ARM_16K_TT_L1_SIZE = 2^36 —— 一个 L1 表项覆盖 2^36；T1SZ_BOOT = 25 时用户
 *     地址空间上界 = 2^39（0x8000000000），2^39 / 2^36 = 8 个表项 → 3 位；
 *   · Dopamine `BaseBin/libjailbreak/src/info.c:355-365` 的 get_l1_block_count()
 *     在 16K 下返回 **8**（4K 返回 256），而 `translation.c:125` 里 16K 的 L1 索引
 *     掩码是运行期常量 ARM_TT_L1_INDEX_MASK = `libxpf/xpf/common.c:120` 在
 *     T1SZ_BOOT = 25 时给出的 `0x7000000000`。
 * 于是窗口地址 = 2^36 × (8 − 1) = 0x7000000000，即 **L1 索引 7、L2 索引 0、L3 索引 0**
 * —— Dopamine 的 MAGIC_PT_ADDRESS 与样本的取值完全相同（physrw_pte.c:13）。
 *
 * 本模块早先把这个掩码写成 11 位（0x7ff000000000），叠加 walk 里"用已被掩过的 base
 * 取各级索引"，L1 索引必然算成 0 —— 于是探的成了**地址 0 的祖先链**，而报告里写的
 * 是窗口地址。这正是本文件最该避免的那类错：结论看着有据，问题问的是另一个。
 *
 * 4K 粒度：**是四级表**（多一级 L0，shift 39）。上游 perf.h:252 把 ROOT_LEVEL 写死成
 * PMAP_TT_L1_LEVEL，只在 16K 上成立；本模块照样本按页大小分派，所以 4K 机型
 * 会明确报「几何未支持」而不是拿 16K 的掩码去走 4K 的表 —— 后者会在
 * L2/L3 那一级读到**别的表**里的表项，把一个未经确认的地址当成下一级表地址。
 * 本工程的目标机（iPad14,3 / iPadOS 16.4.1）是 16K，4K 那条路等真有设备再加。
 */
#define KM_PW_SHIFT_L1 36ULL
#define KM_PW_SHIFT_L2 25ULL
#define KM_PW_SHIFT_L3 14ULL
#define KM_PW_INDEX_L1 0x0000007000000000ULL /* 3 bits at 36（为什么是 3 位见上） */
#define KM_PW_INDEX_L2 0x0000000ffe000000ULL /* 11 bits at 25 */
#define KM_PW_INDEX_L3 0x0000000001ffc000ULL /* 11 bits at 14 */

/*
 * 页表项的类型判据（逐级不同，**不能三级共用一套**）。
 *
 * arm64 用 bit1 区分描述符形态，但同一形态在不同级别含义相反：
 *   L1 / L2：bit1 = 0 → 块描述符（大页），bit1 = 1 → 表描述符（下一级表）
 *   L3     ：bit1 = 0 → 不是叶（L3 之下无处可去），bit1 = 1 → 页描述符
 * 上游 perf.h:270-296 就是逐级换判据的（L1/L2 用 ARM_TTE_TYPE_BLOCK，
 * L3 用 ARM_TTE_TYPE_L3BLOCK），常量出处 static_info.h:30-32 / :50-53。
 *
 * valid 也随级变化：L3 要求 bit0、bit1 **都为 1**（0x3）。只查 bit0 会放过
 * (entry & 3) == 1 这种既不是页描述符也不是有效表项的形态，之后拿它当依据
 * 就是凭垃圾位下结论。
 */
#define KM_PW_TTE_VALID 0x0000000000000001ULL
#define KM_PW_TTE_TYPE_MASK 0x0000000000000002ULL
#define KM_PW_TTE_TYPE_BLOCK 0x0000000000000000ULL
#define KM_PW_PTE_TYPE_VALID 0x0000000000000003ULL
#define KM_PW_L3_TYPE_LEAF 0x0000000000000002ULL

/*
 * 表项里地址字段的掩码 = ARM_TTE_TABLE_MASK（static_info.h:54，与
 * ARM_TTE_PA_MASK :55 同值）。**这是 PA，不是 KVA** —— 下钻前必须经
 * km_phystokv 补回 KVA，理由见 KernelPhysWindow.h 的「依赖」一节。
 */
#define KM_PW_TTE_ADDR_MASK 0x0000fffffffff000ULL

/// 诊断文本缓冲。最坏情形（逐级都下钻成功、每行地址都满宽）大约 3.5KB，
/// 给到 8KB 是为了**留出富余而不是刚好装下**：刚好装下意味着将来加一行就悄悄
/// 截断，而截断掉的很可能正是结论那一段。真的溢出时下面会置 truncated 并在
/// 返回值里报 KM_PW_TRUNCATED（不是静默少几行）。
#define KM_PW_TEXT_SIZE 8192

#pragma mark - 状态

// 诊断文本与结论。都只在 km_physwindow_probe() 的末尾写、在
// km_physwindow_diagnostic() 里读，而调用方（面板）保证这两者都在同一条串行
// 路径上（AutoTracker.syncExternal）—— 与 KernelSlide.m 的 g_diagText 同一套口径。
// 刻意**不缓存"结论"给下一次点击**：建表之后"有没有页表"会变，
// 缓存会让"建完再探一次"永远拿到建之前的结果（这就是本按钮存在的意义）。
static NSString *g_pwText = nil;

/**
 * 最近一次探测算出的窗口地址。
 *
 * 为什么要单独存一份、而不是让面板自己调 km_physwindow_address()：
 * 面板在**主线程**上、探测刚跑完时读它，而 km_physwindow_address() 会走
 * sysctl 与 km_physwindow_probe() 用的那份进程级状态。面板再算一次就多出
 * 一条"绕过 AutoTracker 串行队列"的调用 —— 与 physWindowReport 里那条
 * "不复算任何判据"的口径冲突。结论由探测算出、面板只显示。
 */
static uint64_t g_pwAddress = 0;

#pragma mark - 工具

/*
 * 形态检查 —— 本模块每一条 kread 之前的唯一闸门。
 *
 * 两个判据缺一不可：
 *   ① 内核地址域：与 km_is_kernel_address 同口径（地址高 16 位全 1）。
 *      **刻意与它同口径而不是更严**：km_read64 自己也查这一条，本函数若更严，
 *      被拒的读在诊断里就会显示成"我拒了"，而实际上是 km_read64 会拒 ——
 *      两者口径一致，诊断文本才对应得上真实行为。
 *   ② 8 字节对齐：一条页表项永远是 8 字节，错位的地址即使落在有效页内，
 *      读到的也是相邻两个表项各一半拼起来的垃圾 —— 那种值"看着像合法表项"，
 *      会被下面的类型判据放行，然后被当成下一级表地址。这正是"错值比 0 危险"
 *      的同一个形态：0 会被拦下，错值不会。
 */
static bool physwindow_shape_ok(uint64_t addr)
{
    if ((addr >> 48) != 0xFFFF) {
        return false;
    }
    if ((addr & 0x7ULL) != 0) {
        return false;
    }
    return true;
}

/// 无溢出的加法。页表项里的 PA 加上换算出的基准理论上不会溢出，
/// 但"理论上"不是判据 —— 溢出让地址回绕到一个**形态合法**的小内核地址，
/// 正好是形态检查拦不住的那类值。
static bool physwindow_add(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return false;
    }
    *out = a + b;
    return true;
}

/// 无溢出的乘法（自表索引用）。
static bool physwindow_mul(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a != 0 && b > UINT64_MAX / a) {
        return false;
    }
    *out = a * b;
    return true;
}

/*
 * 文本追加 —— 记账按**实际写入**的字节数（snprintf + strlen），不用 snprintf 的返回值。
 *
 * 理由是 KernelMemory.m 里 km_self_test 那段踩过的坑：snprintf 返回的是
 * "空间够的话本来会写多少"，截断时它**大于**实际可用空间，`size - used` 在
 * size_t 上回绕成天文数字，下一句就写出缓冲区。本模块的缓冲区是静态的，
 * 越界就是踩相邻静态数据。
 */
typedef struct {
    char *buf;
    size_t size;
    size_t used;
    bool truncated;
} km_pw_text;

static void pw_append(km_pw_text *t, const char *fmt, ...)
{
    if (t->used >= t->size) {
        t->truncated = true;
        return;
    }
    const size_t room = t->size - t->used;
    va_list args;
    va_start(args, fmt);
    const int written = vsnprintf(t->buf + t->used, room, fmt, args);
    va_end(args);

    /*
     * 记账一律用 strlen，**不用 vsnprintf 的返回值**：
     * 它返回的是"空间够的话本来会写多少"，截断时**大于** room，
     * 拿它累加会让 used 越过 size，之后 `size - used` 在 size_t 上回绕成
     * 天文数字，下一句就往缓冲区外写（KernelMemory.m 的 km_self_test 里
     * 记的正是这个坑，它是真炸过的）。返回值在这里只用来判"有没有被截断"。
     */
    t->used += strlen(t->buf + t->used);
    if (written < 0 || (size_t)written >= room) {
        t->truncated = true;
    }
}

#pragma mark - 页大小与窗口地址

/*
 * 页大小 → (L1 块大小, L1 块数)。不认得的页大小返回 false ——
 * **不兜底成 16K**：兜底会在 4K 机型上算出一个不属于任何地址空间的窗口地址，
 * 然后拿 16K 的几何去遍历它。取不到就说取不到。
 */
static bool physwindow_geometry(uint64_t pageSize, uint64_t *blockSize, uint64_t *blockCount)
{
    switch (pageSize) {
    case 0x4000: /* 16K —— 目标机 */
        *blockSize = KM_PW_16K_BLOCK_SIZE;
        *blockCount = KM_PW_16K_BLOCK_COUNT;
        return true;
    case 0x1000: /* 4K —— 老机型；几何见下面 physwindow_walk 的说明 */
        *blockSize = KM_PW_4K_BLOCK_SIZE;
        *blockCount = KM_PW_4K_BLOCK_COUNT;
        return true;
    default:
        return false;
    }
}

uint64_t km_physwindow_address(void)
{
    const uint64_t pageSize = km_kernel_page_size();
    uint64_t blockSize = 0;
    uint64_t blockCount = 0;
    if (!physwindow_geometry(pageSize, &blockSize, &blockCount)) {
        return 0;
    }
    uint64_t window = 0;
    /*
     * 窗口 = **最后一个 L1 块的块首** = SIZE × (COUNT − 1)，不是 SIZE × COUNT。
     *
     * 为什么这里是 `− 1`：COUNT 是表项数（16K 下 8），而窗口落在**第 8 项、下标 7**
     * 那一块上（KernelPhysMap.m:1897 的同一条公式、同一个理由）。写成 × COUNT
     * 会得到 0x8000000000 —— 那是用户地址空间的上界本身，不是一个可用的窗口地址。
     */
    if (!physwindow_mul(blockSize, blockCount - 1ULL, &window)) {
        return 0;
    }
    return window;
}

#pragma mark - 只读探针

/// 一处表项的分类结果，只用于诊断文本。
typedef enum {
    KM_PW_ENTRY_INVALID = 0, /* bit0 = 0：无效表项（这里就是"没有页表"） */
    KM_PW_ENTRY_TABLE,       /* L1/L2：表描述符 → 有下一级表 */
    KM_PW_ENTRY_BLOCK,       /* L1/L2：块描述符（大页），遍历在此结束 */
    KM_PW_ENTRY_L3_LEAF,     /* L3：页描述符 */
    KM_PW_ENTRY_L3_ODD       /* L3：有效但不是叶 */
} km_pw_entry_kind;

static const char *physwindow_kind_name(km_pw_entry_kind kind)
{
    switch (kind) {
    case KM_PW_ENTRY_INVALID: return "invalid（bit0=0）";
    case KM_PW_ENTRY_TABLE: return "表描述符（有下一级表）";
    case KM_PW_ENTRY_BLOCK: return "块描述符（大页，遍历在此结束）";
    case KM_PW_ENTRY_L3_LEAF: return "页描述符（L3 叶）";
    case KM_PW_ENTRY_L3_ODD: return "有效但不是 L3 叶（bit1=0）";
    }
    return "?";
}

static km_pw_entry_kind physwindow_classify(int level, uint64_t entry)
{
    if (level < 2) {
        if ((entry & KM_PW_TTE_VALID) == 0) {
            return KM_PW_ENTRY_INVALID;
        }
        return ((entry & KM_PW_TTE_TYPE_MASK) == KM_PW_TTE_TYPE_BLOCK)
                   ? KM_PW_ENTRY_BLOCK
                   : KM_PW_ENTRY_TABLE;
    }
    if ((entry & KM_PW_PTE_TYPE_VALID) != KM_PW_PTE_TYPE_VALID) {
        return KM_PW_ENTRY_INVALID;
    }
    return ((entry & KM_PW_TTE_TYPE_MASK) == KM_PW_L3_TYPE_LEAF)
               ? KM_PW_ENTRY_L3_LEAF
               : KM_PW_ENTRY_L3_ODD;
}

/// 遍历的最终结论。
typedef enum {
    KM_PW_WALK_HIT = 0,   /* 窗口地址上已有 L3 叶（= 已有页表） */
    KM_PW_WALK_NO_TABLE,  /* 半路 invalid，或撞上块描述符 */
    KM_PW_WALK_NO_KVA,    /* 需要下钻但 PA → KVA 换算不出来 */
    KM_PW_WALK_L3_ODD,
    KM_PW_WALK_SHAPE_BAD, /* 自己算出的地址连形态检查都没过（防御性分支） */
    KM_PW_WALK_READ_FAIL,
    KM_PW_WALK_GEOMETRY   /* 页大小认不得 → 几何未知，一次读都不发 */
} km_pw_walk_result;

/*
 * 只读页表遍历。**祖先链是 L1表[7] → L2表[0] → L3表[0]**：窗口地址
 * 0x7000000000 = 2^36 × 7，落在 L1 表的第 7 项，而它在那个 2^36 块内的
 * 偏移为 0，所以 L2/L3 两级索引都是 0。
 *
 * base = window & ~L1 索引掩码 = 0，是"窗口所在 L1 块的基址"，只用来算 L2/L3
 * 两级的索引。**L1 那一级的索引必须取自 window** —— base 的 L1 索引位是按定义
 * 被掩掉的，用它取索引会得到「地址 0 的祖先链」，而报告里写的却是窗口地址。
 *
 * 从块基址走到 L2 时索引同样是 0（块基址的 L2 索引必为 0），所以
 * base → L2表 → 第0项 → L3表 → 第0项 这条链接在 L1表[7] 下面，就是窗口的完整祖先链。
 */
static km_pw_walk_result physwindow_walk(km_pw_text *t, uint64_t pmapTtep, uint64_t window,
                                         uint64_t *outEntry, uint64_t *outEntryKva)
{
    const uint64_t pageSize = km_kernel_page_size();

    /*
     * 几何判据。分派之前先说清 4K 那条路为什么在这里停住，而不是拿 16K 掩码硬走：
     * 4K 是四级表（多一级 L0，shift 39），本模块只实现了三级。拿 16K 的
     * INDEX_L1（bits 36-46）去索引 4K 的 L1 表，取到的是**另一张表**里的表项，
     * 然后把它当下一级表地址 —— 这正是"把一个未经确认的地址喂给 kread"。
     * 所以 4K 上明确返回 GEOMETRY，一次读都不发。
     */
    if (pageSize != 0x4000) {
        pw_append(t, "✗ 页大小 %#llx 的页表几何未实现（本模块只做 16K 的三级表）：\n",
                  (unsigned long long)pageSize);
        pw_append(t, "  4K 是四级表（多一级 L0，shift 39）。硬套 16K 掩码会在 L1 那一步\n");
        pw_append(t, "  索引到另一张表里，把它的表项当成下一级表地址 —— 那不是可以赌的事。\n");
        return KM_PW_WALK_GEOMETRY;
    }

    /*
     * 掩码 ↔ 表项数自洽检查：把"掩码位宽写错"变成可执行判据。
     *
     * 为什么不能靠"看一眼 L1 索引对不对"发现掩码写错：窗口地址 0x7000000000 的
     * bits 46:39 恰好全为 0，于是 **3 位掩码与 11 位掩码算出来的 L1 索引都是 7**，
     * 打印出来一模一样。唯一能分辨的是"掩码覆盖几个表项、对不对得上这一级的表项数"：
     *      (0x0000007000000000 >> 36) + 1 = 8     与 KM_PW_16K_BLOCK_COUNT 相等 ✓
     *      (0x00007ff000000000 >> 36) + 1 = 2048  ← 当年就是这一版，✗
     * 本文件踩过这个坑（L1 掩码曾写成 11 位），所以留成判据而不是留成注释。
     *
     * **但这条判据自己也曾因为常量语义不一致而恒假**：那个 ✓ 标注写在这里的时候，
     * KM_PW_16K_BLOCK_COUNT 的实际值是 7（最大索引），于是 8 != 7 永远成立、
     * 探针一直在 `✗ 页表几何自相矛盾` 处终止。断言"覆盖几项"就该和"表项数"比 ——
     * 这一点写在常量定义处（文件头），此处只是提醒：**改常量语义要先看这一行**。
     *
     * L2/L3 用"位移差"表达，同样把位数钉死：L1→L2 与 L2→L3 各跨 11 位索引，
     * 即两级各有 2^11 = 2048 个表项（与 Dopamine info.c:384-390 的 16K 取值一致）。
     */
    const uint64_t l1Entries = (KM_PW_INDEX_L1 >> KM_PW_SHIFT_L1) + 1;
    const uint64_t l2Entries = (KM_PW_INDEX_L2 >> KM_PW_SHIFT_L2) + 1;
    const uint64_t l3Entries = (KM_PW_INDEX_L3 >> KM_PW_SHIFT_L3) + 1;
    const uint64_t spanL1L2 = 1ULL << (KM_PW_SHIFT_L1 - KM_PW_SHIFT_L2);
    const uint64_t spanL2L3 = 1ULL << (KM_PW_SHIFT_L2 - KM_PW_SHIFT_L3);

    if (l1Entries != KM_PW_16K_BLOCK_COUNT || l2Entries != spanL1L2 || l3Entries != spanL2L3) {
        pw_append(t, "✗ 页表几何自相矛盾，终止（一次 kread 都不发）：\n");
        pw_append(t, "  L1 掩码 %#llx 覆盖 %llu 项，块数常量却是 %llu；\n",
                  (unsigned long long)KM_PW_INDEX_L1, (unsigned long long)l1Entries,
                  (unsigned long long)KM_PW_16K_BLOCK_COUNT);
        pw_append(t, "  L2 掩码 %#llx 覆盖 %llu 项，按位移差应为 %llu；\n",
                  (unsigned long long)KM_PW_INDEX_L2, (unsigned long long)l2Entries,
                  (unsigned long long)spanL1L2);
        pw_append(t, "  L3 掩码 %#llx 覆盖 %llu 项，按位移差应为 %llu。\n",
                  (unsigned long long)KM_PW_INDEX_L3, (unsigned long long)l3Entries,
                  (unsigned long long)spanL2L3);
        return KM_PW_WALK_GEOMETRY;
    }

    /* 窗口地址所属的 L1 块基址：掩掉 L1 索引位以下的全部位。 */
    const uint64_t base = window & ~KM_PW_INDEX_L1;

    /*
     * 两条自检，缺一不可。上面那条"第 0 项"推理只在窗口与块基址**同块**时成立 ——
     * 不成立就说明窗口地址或掩码算错了，此时**不能**继续走：走出来的结论是
     * 别的地址的结论，而报告里写的却是窗口地址的。这正是最坏的一类错
     * （结论有理有据，问的是另一个问题）。
     */
    if (base > window) {
        pw_append(t, "✗ 块基址 %#llx > 窗口地址 %#llx —— 掩码算错了，终止。\n",
                  (unsigned long long)base, (unsigned long long)window);
        return KM_PW_WALK_SHAPE_BAD;
    }
    /*
     * 窗口地址必须先落在**已经过 L3 掩码检查的地址**上：窗口的 L3 索引若非 0，
     * 那么"窗口的页表项 = L3 表第 0 项"就不成立，遍历会给出一条属于块基址的结论。
     * 样本的窗口地址 L3 索引恒为 0（0x7000000000 & 0x1ffc000 = 0），核对这一条
     * 比事后解释"为什么报告里那一行与窗口地址对不上"便宜得多。
     */
    if ((window & KM_PW_INDEX_L3) != 0) {
        pw_append(t, "✗ 窗口地址 %#llx 的 L3 索引非 0（%#llx）—— 本模块的判据只在索引 0 上成立，终止。\n",
                  (unsigned long long)window, (unsigned long long)(window & KM_PW_INDEX_L3));
        return KM_PW_WALK_SHAPE_BAD;
    }
    if ((base & KM_PW_INDEX_L2) != 0) {
        pw_append(t, "✗ 块基址 %#llx 的 L2 索引非 0（%#llx）—— 掩码与几何对不上，终止。\n",
                  (unsigned long long)base, (unsigned long long)(base & KM_PW_INDEX_L2));
        return KM_PW_WALK_SHAPE_BAD;
    }

    pw_append(t, "起点：块基址 base=%#llx（窗口 %#llx 的 L1 块，窗口相对它偏移 %#llx）\n",
              (unsigned long long)base, (unsigned long long)window,
              (unsigned long long)(window - base));
    pw_append(t, "  页大小=%#llx → 16K 三级几何：L1 shift=%llu mask=%#llx / "
                 "L2 shift=%llu mask=%#llx / L3 shift=%llu mask=%#llx\n",
              (unsigned long long)pageSize,
              (unsigned long long)KM_PW_SHIFT_L1, (unsigned long long)KM_PW_INDEX_L1,
              (unsigned long long)KM_PW_SHIFT_L2, (unsigned long long)KM_PW_INDEX_L2,
              (unsigned long long)KM_PW_SHIFT_L3, (unsigned long long)KM_PW_INDEX_L3);

    const uint64_t shifts[3] = { KM_PW_SHIFT_L1, KM_PW_SHIFT_L2, KM_PW_SHIFT_L3 };
    const uint64_t masks[3] = { KM_PW_INDEX_L1, KM_PW_INDEX_L2, KM_PW_INDEX_L3 };
    const char *levelNames[3] = { "L1", "L2", "L3" };

    /*
     * 顶层表用 **ttep**（PA），不是 tte（KVA）。
     *
     * 两种起点的差别只有一处：KVA 起点可以少一次 km_phystokv。这里选 PA 而
     * 不是 KVA，是为了让"起点"与"每一次下钻"用的是**同一条换算路径** ——
     * 顶层若用 tte（另一条路径来的 KVA），下面的表用 km_phystokv，
     * 一旦两者算出的基准不一致（pmap 不是真 pmap，或换算表本身有问题），
     * 遍历就会在层与层之间**悄悄换基准**，而报告里看不出这一点。
     */
    uint64_t tableKva = 0;
    /*
     * PA→KVA 换算表**按需建立**，不要求用户先去点「Slide」。
     *
     * 2026-09-26 改：这里原先是 `if (!km_phystokv_ready()) { 报「先点 Slide」; return; }`。
     * 那个写法与 KernelPhysMap.m:1584-1608 的同一处**刚好相反**——那边走的是
     * `km_phystokv_ensure()`，注释写明理由是「面板上只有一个按钮是"我这个动作"，
     * 用户不该知道实现里分成几步」。真机症状就是那次「只点建窗 → 遍历中断：
     * PA→KVA 换算不可用（先跑「Slide」）」，而用户按提示点了 Slide 之后一切正常，
     * 说明**能力本来就有，缺的只是这一句调用**。
     *
     * ensure 内部：已就绪则空操作；否则自己 km_xpf_init + 跑完那套自检
     * （KernelSlide.h 写了为什么换算表与 slide 分不开）。本模块是**只读**探针，
     * 但 ensure 会 kread —— 那是允许的：只读的定义是"不写内核内存"，不是"不发 kread"。
     * 面板侧已经把本探针放在串行队列上（与读取链不并发），前置条件满足。
     *
     * 耗时：首次要解压解析几十 MB 的 kernelcache，几十秒是预期耗时不是卡死 ——
     * 面板那侧按 `KernelPhysWindow.h` 的说明把按钮切成"计算中…"。
     */
    if (!km_phystokv_ready()) {
        pw_append(t, "PA→KVA 换算表未就绪 —— 调 km_phystokv_ensure() 按需建立\n");
        pw_append(t, "  （首次要解压解析几十 MB 的 kernelcache，几十秒是预期耗时，不是卡死）\n");
    }
    if (!km_phystokv_ensure()) {
        /*
         * 失败就只说「建立失败 + 去看谁建立的」。**此处刻意不调 km_xpf_ready() /
         * km_xpf_last_error()**：那两个声明在 XpfBridge.h，而本文件只包含
         * KernelMemory.h / KernelSlide.h / 自己的头 —— 为了两行提示给一个 900 行、
         * 一直只用两个头文件的模块引入新的 include 依赖，不划算（真编译代价由 CI 付，
         * 而这里给的信息量几乎没有增加）。换算表由 KernelSlide 建立，失败原因
         * 本来就在它的诊断里。
         */
        pw_append(t, "✗ 换算表建立失败：页表项里存的是**物理**地址，没有这条换算，\n");
        pw_append(t, "  本模块连顶层表都补不成 KVA。失败原因见 KernelSlide 的诊断。\n");
        return KM_PW_WALK_NO_KVA;
    }
    tableKva = km_phystokv(pmapTtep);
    if (tableKva == 0) {
        pw_append(t, "✗ ttep=%#llx 换算不出 KVA（km_phystokv 返回 0：既不在 ptov_table 的\n",
                  (unsigned long long)pmapTtep);
        pw_append(t, "  8 段里，也不在 [gPhysBase, gPhysBase+gPhysSize) 内）—— 遍历无法开始。\n");
        return KM_PW_WALK_NO_KVA;
    }
    pw_append(t, "顶层表：ttep(PA)=%#llx → KVA=%#llx（经 pmap->tte 交叉核对见上）\n",
              (unsigned long long)pmapTtep, (unsigned long long)tableKva);

    for (int level = 0; level < 3; level++) {
        /*
         * 级内索引。
         *
         * **L1 那一级必须取自 window，不能取自 base**：base 的定义就是"把 L1 索引位
         * 掩掉"，它的 L1 索引恒为 0，拿它取索引等于去走**地址 0 的祖先链**。
         * 窗口在 L1 表里的索引是 7（(0x7000000000 >> 36) & 0x7）。
         *
         * L2/L3 两级取自 base 是对的：窗口就是那个 L1 块的块首，这两级索引都是 0，
         * 而 base 的 L2/L3 索引位本来就不在 KM_PW_INDEX_L1 里，没有被掩掉。
         */
        const uint64_t index = (level == 0)
                                   ? ((window & masks[0]) >> shifts[0])
                                   : ((base & masks[level]) >> shifts[level]);

        uint64_t off = 0;
        if (!physwindow_mul(index, sizeof(uint64_t), &off)) {
            pw_append(t, "✗ %s 索引 %llu × 8 溢出\n", levelNames[level],
                      (unsigned long long)index);
            return KM_PW_WALK_SHAPE_BAD;
        }
        uint64_t entryAddr = 0;
        if (!physwindow_add(tableKva, off, &entryAddr) || !physwindow_shape_ok(entryAddr)) {
            /*
             * 防御性分支：正规情况下 tableKva 是内核 KVA、off < 0x4000，
             * 不可能不过。写在这里是因为**这条地址是由上一次读的结果算出来的** ——
             * 上一次读若拿到一个"形态合法但内容错"的表项，这里算出的就是未映射地址。
             */
            pw_append(t, "✗ %s 表项地址 %#llx 形态不过（表 KVA %#llx + %llu）—— 终止，不读\n",
                      levelNames[level], (unsigned long long)entryAddr,
                      (unsigned long long)tableKva, (unsigned long long)off);
            return KM_PW_WALK_SHAPE_BAD;
        }

        bool ok = false;
        /*
         * 这一条**刻意不还原 PAC**，理由是可执行的而不是手感：
         *   · 读出来的是一张 **PTE（页表项）**，不是指针字段。签名作用于内核结构里的
         *     指针字段（task->map / vm_map->pmap 那一类），不会签在页表项上；
         *   · 下面用的是 `entry & KM_PW_TTE_ADDR_MASK`（低位 PA）与类型位，而
         *     km_unsign_ptr 对高位做的是 `| PAC_MASK` —— 对 PTE 来说那等于把
         *     bits 47..63 全部置 1，紧接着 km_phystokv(nextPa) 就会打进一段
         *     不存在的物理范围。在这里加还原**不是保守，而是主动制造错值**。
         * 但 raw 值仍然值得打出来：这一跳是建窗链上第一次由"上一次读的结果"决定
         * 下一次读的地址，真机翻车时要能一眼分出是读错了还是解释错了。
         */
        const uint64_t entry = km_read64(entryAddr, &ok);
        if (!ok) {
            pw_append(t, "✗ %s 表项读失败（addr=%#llx，两次读到不同的值）—— 终止\n",
                      levelNames[level], (unsigned long long)entryAddr);
            return KM_PW_WALK_READ_FAIL;
        }

        const km_pw_entry_kind kind = physwindow_classify(level, entry);
        pw_append(t, "%s：表KVA=%#llx 索引=%llu 表项地址=%#llx 表项 raw=%#llx  → %s\n",
                  levelNames[level], (unsigned long long)tableKva,
                  (unsigned long long)index, (unsigned long long)entryAddr,
                  (unsigned long long)entry, physwindow_kind_name(kind));

        if (kind == KM_PW_ENTRY_INVALID) {
            pw_append(t, "  ⇒ 页表在 %s 就断了：**窗口地址上现在没有页表**。\n", levelNames[level]);
            return KM_PW_WALK_NO_TABLE;
        }
        if (kind == KM_PW_ENTRY_BLOCK) {
            /*
             * L1/L2 块描述符 = 大页。窗口地址被覆盖在一张 64GiB / 32MiB 的大页里，
             * 没有独立的 L3 表项 —— 所以既没有"窗口的页表项"可写，
             * 也不需要建表（那一段本来就有映射）。这与"没有页表"是两回事，
             * 但**同样意味着下一步不能按样本那条路写 PTE**。
             */
            pw_append(t, "  ⇒ %s 是块描述符：窗口地址落在已有的大页里，没有独立的 L3 表项。\n",
                      levelNames[level]);
            return KM_PW_WALK_NO_TABLE;
        }

        if (level == 2) {
            /*
             * 走到 L3 且表项有效 —— **这就是"窗口地址上已经有页表"的判据**。
             * 是不是叶（bit1=1）留给上面的 kind 分类去说：判据是"这条路
             * 一路走下来到了窗口自己的 L3 表项"，不是那一位的语义。
             *
             * 顺手把它自己的地址交出去：下一段的写自映射要写的正是**这个地址**
             * （不是窗口那个 VA）。这里报的是 KVA + 表内偏移 —— 表内偏移必须
             * 是 0，因为上面已经核对过窗口的 L3 索引为 0。
             */
            *outEntry = entry;
            *outEntryKva = entryAddr;
            return (kind == KM_PW_ENTRY_L3_LEAF) ? KM_PW_WALK_HIT : KM_PW_WALK_L3_ODD;
        }

        /* 还要下钻：把表项里的 PA 补回 KVA。 */
        const uint64_t nextPa = entry & KM_PW_TTE_ADDR_MASK;
        const uint64_t nextKva = km_phystokv(nextPa);
        if (nextKva == 0) {
            pw_append(t, "  ✗ %s 表项里的 PA=%#llx 换算不出 KVA —— 终止（不猜地址）\n",
                      levelNames[level], (unsigned long long)nextPa);
            return KM_PW_WALK_NO_KVA;
        }
        pw_append(t, "  ↓ 下钻：表项 PA=%#llx → KVA=%#llx\n",
                  (unsigned long long)nextPa, (unsigned long long)nextKva);
        tableKva = nextKva;
    }

    return KM_PW_WALK_NO_TABLE;
}

km_physwindow_status km_physwindow_probe(void)
{
    km_pw_text t = { NULL, 0, 0, false };
    static char buffer[KM_PW_TEXT_SIZE];
    memset(buffer, 0, sizeof(buffer));
    t.buf = buffer;
    t.size = sizeof(buffer);

    /* 面板上第一行就是摘要行，先占位，结论出来后再用 snprintf 覆盖首行。 */
    pw_append(&t, "[建窗] 探针未完成\n");

    NSString *summary = nil;
    km_physwindow_status status = KM_PW_NOT_READY;

    /* ── ① 前置：内核读写层 ── */
    pw_append(&t, "== ① 前置 ==\n");
    if (!km_ready()) {
        pw_append(&t, "✗ km_ready()=false：内核读写层未就绪（km_init 未成功），本次一次 kread 都不发。\n");
        status = KM_PW_NOT_READY;
        summary = @"[建窗] 前置不成立：内核层未就绪";
        goto done;
    }
    pw_append(&t, "✓ km_ready()=true\n");

    /*
     * 窗口地址在**函数作用域**算一次，②⑤ 都用它。
     *
     * 不能只在 ② 那个块里定义：⑤ 的遍历起点正是这个地址，而块作用域到 ②
     * 结束就没了 —— CI #153 那两条 "use of undeclared identifier 'window'"
     * 就是这么来的。也不在 ⑤ 里重算：km_physwindow_address() 会走 sysctl 与
     * 进程级状态，同一次探测里算两遍就多出一条并列路径，且两遍万一不一致
     * （页大小中途被改无从发生，但"一次探测一个结论"这条口径要守住）。
     *
     * 放在 ① 之后：① 不成立就直接 goto done，连页大小都不必问。
     * 本调用只读 hw.pagesize，不碰内核内存（见头文件）。
     */
    const uint64_t window = km_physwindow_address();

    /* ── ② 页大小与窗口地址 ── */
    {
        pw_append(&t, "== ② 窗口地址 ==\n");
        const uint64_t pageSize = km_kernel_page_size();
        g_pwAddress = window;
        pw_append(&t, "km_kernel_page_size()=%#llx，km_physwindow_address()=%#llx\n",
                  (unsigned long long)pageSize, (unsigned long long)window);
        if (window == 0) {
            pw_append(&t, "✗ 页大小取不到或不认得 —— 窗口地址算不出来（不兜底成 16K，见头文件）。\n");
            status = KM_PW_NOT_READY;
            summary = @"[建窗] 前置不成立：页大小取不到";
            goto done;
        }
        pw_append(&t, "  公式：L1_BLOCK_SIZE × (L1_BLOCK_COUNT − 1)；16K 下 L1 表共 8 项\n");
        pw_append(&t, "  （Dopamine info.c:355-365），取最后一块 = 2^36 × 7 = 0x7000000000 ——\n");
        pw_append(&t, "  样本 physrw_pte.c:13 用的是同一公式、同一取值。该块紧邻用户地址空间\n");
        pw_append(&t, "  上界 MACH_VM_MAX_ADDRESS(0x8000000000)，正常分配不会覆盖它：这正是\n");
        pw_append(&t, "  「必须先建出页表」的理由。\n");
    }

    /* ── ③ proc → task → vm_map → pmap ── */
    {
        pw_append(&t, "== ③ pmap 链路（四个偏移都不是魔数）==\n");

        const uint64_t proc = km_current_proc();
        const uint64_t taskOff = km_proc_object_size();
        const uint64_t mapOff = km_task_map_offset();
        const uint64_t pmapOff = km_vm_map_pmap_offset();

        pw_append(&t, "偏移：proc→task(proc__object_size)=%#llx [版本表] · "
                     "task→map(task__map)=%#llx [版本表] · map→pmap=%#llx [static_info.h 结构体]\n",
                  (unsigned long long)taskOff, (unsigned long long)mapOff,
                  (unsigned long long)pmapOff);
        pw_append(&t, "current_proc()=%#llx\n", (unsigned long long)proc);

        if (proc == 0) {
            pw_append(&t, "✗ km_current_proc()=0：info_run 没反查到本进程 proc。报「取不到」，不兜底。\n");
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：current_proc=0";
            goto done;
        }
        if (taskOff == 0 || mapOff == 0 || pmapOff == 0) {
            /* 偏移为 0 意味着"内核版本不在版本表里"或结构体定义被改坏 —— 两者都只能报错。 */
            pw_append(&t, "✗ 有一个偏移是 0 —— 版本表没命中，或结构体定义被改坏。终止。\n");
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：偏移为 0";
            goto done;
        }

        uint64_t task = 0;
        if (!physwindow_add(proc, taskOff, &task) || !physwindow_shape_ok(task)) {
            pw_append(&t, "✗ proc+%#llx=%#llx 形态不过 —— 终止\n",
                      (unsigned long long)taskOff, (unsigned long long)task);
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：task 地址形态不过";
            goto done;
        }
        bool ok = false;
        const uint64_t mapRaw = km_read64(task + mapOff, &ok);
        /*
         * task->map 是 **PAC 签名的内核指针** —— 直接当地址用会死在形态检查上
         * （真机现场：raw=0x52bc7e10023e93c0，高 16 位 0x52bc 而判据要 0xFFFF）。
         * 还原必须在形态检查**之前**：带签名时高 17 位是签名不是地址，先卡形态
         * 会把合法指针误判成垃圾（这条纪律原本只落在 KernelSlide.m:435，
         * 这里补上同一道）。对内核地址 km_unsign_ptr 是幂等的，所以不会改坏
         * "其实没被签名"的值；对用户态地址不是 —— 但这里读的是内核结构字段。
         */
        const uint64_t map = km_unsign_ptr(mapRaw);
        pw_append(&t, "task=%#llx → task+%#llx 读出 map raw=%#llx → %#llx%s\n",
                  (unsigned long long)task, (unsigned long long)mapOff,
                  (unsigned long long)mapRaw, (unsigned long long)map,
                  ok ? "" : "  ← 读失败（两次不一致）");
        if (!ok || map == 0) {
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：vm_map 读失败或为 0";
            goto done;
        }
        if (!physwindow_shape_ok(map)) {
            pw_append(&t, "✗ map=%#llx（raw=%#llx）还原 PAC 后形态仍不过 —— 终止\n",
                      (unsigned long long)map, (unsigned long long)mapRaw);
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：vm_map 还原后形态不过";
            goto done;
        }
        uint64_t mapPmap = 0;
        if (!physwindow_add(map, pmapOff, &mapPmap) || !physwindow_shape_ok(mapPmap)) {
            pw_append(&t, "✗ map+%#llx=%#llx 形态不过 —— 终止\n",
                      (unsigned long long)pmapOff, (unsigned long long)mapPmap);
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：pmap 字段地址形态不过";
            goto done;
        }
        const uint64_t pmapRaw = km_read64(mapPmap, &ok);
        /* vm_map->pmap 同样是签名指针字段，还原口径与上一处完全一致。 */
        const uint64_t pmap = km_unsign_ptr(pmapRaw);
        pw_append(&t, "     map+%#llx 读出 pmap raw=%#llx → %#llx%s\n",
                  (unsigned long long)pmapOff, (unsigned long long)pmapRaw,
                  (unsigned long long)pmap, ok ? "" : "  ← 读失败（两次不一致）");
        if (!ok || pmap == 0) {
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：pmap 读失败或为 0";
            goto done;
        }
        if (!physwindow_shape_ok(pmap)) {
            pw_append(&t, "✗ pmap=%#llx（raw=%#llx）还原 PAC 后形态仍不过 —— 终止\n",
                      (unsigned long long)pmap, (unsigned long long)pmapRaw);
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：pmap 还原后形态不过";
            goto done;
        }

        /* ── ④ pmap->tte / pmap->ttep ── */
        pw_append(&t, "== ④ pmap 头部（static_info.h:255-257，tte/ttep 是两个开头字段）==\n");
        pw_append(&t, "pmap=%#llx（上游 info.h:151 的 static_kget(struct _vm_map, pmap, ...) 同源）\n",
                  (unsigned long long)pmap);

        /*
         * tte / ttep **都不还原 PAC**（与上面 map / pmap 两处相反，这是判定不是遗漏）：
         *   · ttep 是顶层表的**物理地址** —— 这个模块紧接着就拿它去 km_phystokv()
         *     走页表（physwindow_walk 的起点），PA 上没有签名；还原会把高位污染成 0xFFFF；
         *   · tte 是同一张表的内核虚拟别名，只用来与 km_phystokv(ttep) 做交叉核对，
         *     两个值形态一致与否本身就是判据，动它反而毁掉判据。
         * 上游一致：Dopamine info.h:151 只对 `pmap` 那一次做 UNSIGN_PTR，读 pmap 的
         * mmu 结构字段（tte/ttep）一次都没还原。
         */
        const uint64_t tte = km_read64(pmap + 0x00, &ok);
        const bool tteOk = ok;
        const uint64_t ttep = km_read64(pmap + 0x08, &ok);
        const bool ttepOk = ok;
        pw_append(&t, "pmap->tte =%#llx%s\n", (unsigned long long)tte, tteOk ? "" : "  ← 读失败");
        pw_append(&t, "pmap->ttep=%#llx%s   ← 遍历起点（Dopamine physrw_pte.c:116-122 同构）\n",
                  (unsigned long long)ttep, ttepOk ? "" : "  ← 读失败");

        if (!tteOk || !ttepOk || ttep == 0) {
            pw_append(&t, "✗ tte/ttep 读失败或 ttep=0 —— 遍历无法开始（不猜起点）。\n");
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] pmap 取不到：ttep 读失败或为 0";
            goto done;
        }

        /*
         * 交叉核对，只用来**判断这两个值是不是同一张表**，不拿去当换算基准。
         *
         * 若 tte − ttep 恰好等于 km_phystokv(ttep) − ttep，说明换算表与 pmap
         * 说的是同一件事，这是一条独立的正向证据。**不相等不代表谁错** ——
         * 这两处来自完全不同的来源（pmap 字段 vs ptov_table），相等是佐证、
         * 不相等只是"没有额外证据"。刻意不把任何一个值写回全局：
         * KernelMemory.m 里 g_linear_delta 那次彩屏就是"把 tte − ttep 当基准"。
         */
        const uint64_t kvFromTable = km_phystokv(ttep);
        pw_append(&t, "  参考：tte − ttep = %#llx；km_phystokv(ttep) = %#llx%s\n",
                  (unsigned long long)(tte - ttep), (unsigned long long)kvFromTable,
                  (kvFromTable == tte) ? "  （两者一致 ⇒ 换算表与 pmap 说的是同一张表）"
                                       : "  （不一致 ⇒ 只说明来源不同，都不作为基准）");

        /* ── ⑤ 逐级下行 ── */
        pw_append(&t, "== ⑤ 对窗口地址逐级下行（每一步只读）==\n");
        uint64_t leafEntry = 0;
        uint64_t leafEntryKva = 0;
        const km_pw_walk_result walk = physwindow_walk(&t, ttep, window, &leafEntry, &leafEntryKva);

        switch (walk) {
        case KM_PW_WALK_HIT:
            pw_append(&t, "== ⑥ 判据 ==\n");
            pw_append(&t, "✓ **窗口地址上已经有页表**：L3 表项=%#llx（有效叶）。\n",
                      (unsigned long long)leafEntry);
            pw_append(&t, "  该表项**自身**的内核地址 = %#llx（相对该 L3 表页起点的偏移 = %#llu 字节）\n",
                      (unsigned long long)leafEntryKva,
                      (unsigned long long)(leafEntryKva & 0x3fffULL));
            pw_append(&t, "  ⇒ 第 ② 步的「建表」可以省，下一段直接进「写自映射」。\n");
            pw_append(&t, "  写自映射 = 把「页表页 PA | PTE 模板 0x0060000000000e43」写进上面那个地址。\n");
            status = KM_PW_HIT_EXISTING;
            summary = @"[建窗] ✓ 窗口地址上已有页表（L3 有效叶）";
            break;
        case KM_PW_WALK_NO_TABLE:
            pw_append(&t, "== ⑥ 判据 ==\n");
            pw_append(&t, "✗ **窗口地址上现在没有页表**（见上：第一处 invalid / 块描述符那一级）。\n");
            pw_append(&t, "  ⇒ 第 ② 步不能省：必须先解决「让内核在建这个地址时建出这张表」，\n");
            pw_append(&t, "  那是下一段的任务（Dopamine 用 pmap_expand_range；样本用 0x1010488e0）。\n");
            status = KM_PW_NO_TABLE;
            summary = @"[建窗] ✗ 窗口地址上没有页表（需先建表）";
            break;
        case KM_PW_WALK_NO_KVA:
            status = KM_PW_NOT_READY;
            summary = @"[建窗] 遍历中断：PA→KVA 换算表建立失败（见列表）";
            break;
        case KM_PW_WALK_L3_ODD:
            status = KM_PW_L3_NOT_LEAF;
            summary = @"[建窗] L3 表项有效但不是叶（异常形态，见列表）";
            break;
        case KM_PW_WALK_GEOMETRY:
            status = KM_PW_NOT_READY;
            summary = @"[建窗] 中断：该页大小的页表几何未实现";
            break;
        case KM_PW_WALK_SHAPE_BAD:
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] 中断：算出的地址形态不过（见列表）";
            break;
        case KM_PW_WALK_READ_FAIL:
            /*
             * 对外归到 PMAP_UNRESOLVED，**不新增枚举**。
             *
             * 头文件那组状态是面板与下一段共用的契约：某级表项读失败 = ttep 给
             * 出的那条链走不通，语义就是「pmap 链路取不到」，只是断点在下行
             * 途中而不是 ttep 本身。摘要与列表里会写明是"读失败"，区分度不丢。
             * 新增一个枚举值会牵动面板那侧的穷尽 switch，收益却不抵这次改动。
             */
            status = KM_PW_PMAP_UNRESOLVED;
            summary = @"[建窗] 中断：某级表项读失败（见列表）";
            break;
        }
    }

done:
    /*
     * 摘要行覆盖：首行先写了占位，这里把它整行换掉。
     *
     * 用 memcpy 而不是再 snprintf 一次 t.buf —— 摘要只占第一行，覆盖它不改变
     * 后面各行的位置，也不改变 t.used。摘要短于占位行时用空格把余下部分抹平，
     * 免得残留的占位字符留在行尾（"…未完成 == ① 前置 ==" 那种拼接）。
     * 长度上限 40 是占位行 "[建窗] 探针未完成\n" 的宽度；所有摘要都短于它。
     */
    if (summary != nil) {
        const char *s = summary.UTF8String;
        const size_t len = strlen(s);
        if (len + 1 <= sizeof(buffer)) {
            memcpy(buffer, s, len);
            buffer[len] = '\n';
            for (size_t i = len + 1; i < 40 && i < sizeof(buffer) - 1 && buffer[i] != '\n'; i++) {
                buffer[i] = ' ';
            }
        }
    }

    /*
     * 截断只降级**失败态**的结论，不覆盖已经算出来的判据。
     *
     * 为什么不是无条件返回 TRUNCATED：文本被截断时被切掉的往往是最后一两行，
     * 而 ⑥ 判据那两行正好在最后 —— 于是"结论不可信"与"结论正确"这两种情形
     * 会共用一个返回值。而判据本身（HIT / NO_TABLE）是在文本拼接过程中独立
     * 得出的，它不依赖文本有没有写完。所以：有判据就以判据为准，
     * 没有判据（走到了 NOT_READY / UNRESOLVED 这类"没得出判据"的路）才报 TRUNCATED。
     */
    if (t.truncated && (status == KM_PW_NOT_READY || status == KM_PW_PMAP_UNRESOLVED)) {
        status = KM_PW_TRUNCATED;
    }

    g_pwText = [NSString stringWithUTF8String:buffer];
    return status;
}

NSString *km_physwindow_diagnostic(void)
{
    if (g_pwText == nil) {
        return @"== 建窗诊断 ==\n还没跑过：点面板上的「建窗」按钮。\n"
                "本按钮**只读**：全程不写任何内核内存，写自映射是下一段。\n";
    }
    return g_pwText;
}

uint64_t km_physwindow_last_address(void)
{
    return g_pwAddress;
}
