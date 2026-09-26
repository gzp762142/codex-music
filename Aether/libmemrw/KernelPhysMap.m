//
//  KernelPhysMap.m
//  Aether
//
//  实现见 KernelPhysMap.h 的组织说明。这里只写「为什么这么写」与证据指针。
//
//  行号引用约定：`util.c:NNN` / `translation.c:NNN` / `kernel.c:NNN` / `physrw_pte.c:NNN`
//  一律指 D:\工作区\_Aether_rev\refs\Dopamine\BaseBin\libjailbreak\src\ 下的同名文件；
//  `pte.h:NNN` / `pvh.h:NNN` 同目录；`static_info.h:NNN` 指
//  Aether/libmemrw/kfd/libkfd/info/static_info.h；`common.c` / `non_ppl.c` / `xpf.c`
//  指 Aether/libxpf/xpf/ 下的同名文件（只读快照）。
//

#import <Foundation/Foundation.h>

#import "KernelMemory.h"
#import "KernelSlide.h"
#import "KernelPhysWindow.h"
#import "KernelPhysMap.h"
#import "XpfBridge.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma mark - 页表几何（16K 三级）

/*
 * L1 块大小 / 块数 / L2 块大小 / 块数。
 *
 * 出处是 Dopamine 的 info.c:338-394（四个 getter），16K 那一档：
 *     get_l1_block_size()  = 0x1000000000
 *     get_l1_block_count() = 8
 *     get_l2_block_size()  = 0x2000000
 *     get_l2_block_count() = 2048
 *
 * 窗口地址 = L1_BLOCK_SIZE × (L1_BLOCK_COUNT − 1) = 7 × 2^36 = 0x7000000000
 * （physrw_pte.c:13 的 MAGIC_PT_ADDRESS；本文件用 km_physwindow_address() 取，
 * 不另立一份）。
 *
 * ── L1 索引为什么是 3 位，而不是 11 位 ──
 *
 * 「L1 块数 = 8」这一条同时定死了 L1 索引的位宽：**用户**地址空间上界是
 * 2^39 = 0x8000000000（就是 MACH_VM_MAX_ADDRESS；KernelPhysWindow.m 的几何表
 * 16K 那一列把它与 2^36 × 8 写在了一行上，docs/当前任务.md §0.4「地址推导」
 * 用样本反汇编独立算出了同一个数），除以一个 L1 表项覆盖的 2^36，正好 8 项
 * → **L1 索引 3 位** → bits 38:36 → 掩码 0x0000007000000000。
 * 换成位数说就是**用户侧** TCR_EL1.T0SZ = 64 − 39 = **25**。
 *
 * **所以这个掩码不能从 XPF 取。** 上游 common.c:113-127 的
 * kernelConstant.ARM_TT_L1_INDEX_MASK 是按 kernelConstant.T1SZ_BOOT 选值的
 * （T1SZ_BOOT 本身由 common.c:100-111 数 pointer_mask 的置位数得出），而
 * T1SZ_BOOT 描述的是**内核侧**（TTBR1）的 VA 位宽：
 *     T1SZ_BOOT = 17 → common.c:118 给 0x00007ff000000000（11 位）
 *     T1SZ_BOOT = 25 → common.c:120 给 0x0000007000000000（3 位）
 *     T1SZ_BOOT = 26 → common.c:122 给 0x0000003fc0000000（9 位）
 * 老机型上 T0SZ 与 T1SZ 都是 25，两个语义重合，于是 case 25 恰好返回本模块要的
 * 那个值；本工程的目标机（iPad14,3 / M2 / iPadOS 16.4.1）是 ARM_LARGE_MEMORY
 * 内核（common.c:187 用 kernelBase == 0xfffffe0007004000 判它），T1SZ_BOOT 实读
 * 17，XPF 于是给出 11 位掩码 —— 而本模块建的是**用户 pmap** 的窗口，11 位掩码在
 * 这里推出 2048 个 L1 块，与真实的 8 块不符。真机就是这么翻的车：预检在 ③ 的
 * 自洽判据上停住，报「掩码推出 2048 块，常量是 8」。
 *
 * 结论：本文件把用户侧几何写成常量，**永不**从那个键取（XpfBridge 的那组键里
 * 也已经没有它了，见 XpfBridge.h 的「建页表窗口」一节）。同一套几何的另一半在
 * KernelPhysWindow.m 的 KM_PW_INDEX_L1 / KM_PW_SHIFT_L1 —— 两处必须逐位一致，
 * 那个模块在真机上从来没报过这个错，正因为它的 L1 一直是 3 位。
 */
#define KM_PM_16K_L1_BLOCK_SIZE 0x1000000000ULL /* 2^36 */
#define KM_PM_16K_L1_BLOCK_COUNT 8ULL
#define KM_PM_16K_L2_BLOCK_SIZE 0x2000000ULL /* 2^25 */
#define KM_PM_16K_L2_BLOCK_COUNT 2048ULL

#define KM_PM_L1_BLOCK_MASK (KM_PM_16K_L1_BLOCK_SIZE - 1ULL)
#define KM_PM_L2_BLOCK_MASK (KM_PM_16K_L2_BLOCK_SIZE - 1ULL)

/*
 * 窗口那句 L3 表一共多少项 —— 也就是「可用的槽位号上界」。
 *
 * 为什么不写 2048 这个数：它有两个独立来源，任一个抄错都要能被抓住。
 *   · Dopamine physrw_pte.c:39 的循环上界是 `L2_BLOCK_COUNT`
 *     （info.c:384-394 的 getter，16K 档 = 2048）；
 *   · 它的物理含义是：窗口落在一个 L2 块里，那句 L3 表覆盖整个 L2 块，
 *     于是项数 = L2 块大小 ÷ 页大小 = 0x2000000 ÷ 0x4000 = 2048。
 * 下面把**第二个来源**写成 _Static_assert：只要 L2 块大小或页大小这两条几何
 * 常量被改动（或抄成 4K 那一档），CI 立刻编译失败，而不是等真机上多写半张表。
 * 这也是本文件第一处编译期判据 —— 运行期判据再多也拦不住"常量本身就是错的"。
 *
 * 槽位 0 与 1 不参与分配（0 = 自映射项、1 = sw_asid 页映射），见 kpm_slot_choose。
 */
#define KM_PM_WINDOW_SLOT_COUNT (KM_PM_16K_L2_BLOCK_SIZE / 0x4000ULL)
_Static_assert(KM_PM_WINDOW_SLOT_COUNT == 2048ULL,
               "窗口槽位数必须等于 L2_BLOCK_COUNT（Dopamine physrw_pte.c:39 的循环上界）");
_Static_assert(KM_PM_WINDOW_SLOT_COUNT * 8ULL == 0x4000ULL,
               "窗口槽位数 × 8 必须是一页（本工程只有 16K 页的那一套几何）");
_Static_assert(KM_PM_WINDOW_SLOT_COUNT * 0x4000ULL == KM_PM_16K_L2_BLOCK_SIZE,
               "槽位数 × 页大小必须正好覆盖一个 L2 块（否则窗口外还有我们没算到的槽）");

/*
 * 三级的 shift 与索引掩码。
 *
 * L1：**用户侧几何**（为什么是 3 位、为什么不能从 XPF 取，见文件头部那段）。
 *     位移与掩码分开写是有意的：它们是两个独立的抄写点，kpm_load() 的 ③ 段
 *     会把"从掩码数出的位移"与 KM_PM_SHIFT_L1 对照，抄错任一个立刻停。
 *     与 KernelPhysWindow.m 的 KM_PW_SHIFT_L1 / KM_PW_INDEX_L1 必须逐位相同：
 *     两个模块算的是同一个窗口地址的同一套几何，分叉就会让一个说"已有页表"、
 *     另一个说"需要建表"（KernelPhysMap.h 的「面板调用顺序」第 3 条要求两者对得上）。
 *
 * L2 / L3：pte.h:77-78、pte.h:82-83 的 ARM_16K_TT_L2_SHIFT /
 *     ARM_16K_TT_L2_INDEX_MASK / ARM_16K_TT_L3_SHIFT / ARM_16K_TT_L3_INDEX_MASK
 *     （libkfd 快照 static_info.h:69/70 与 :74/75，同值）。这两级**不随**
 *     T0SZ / T1SZ 变（各自 11 位），所以一直是常量。
 *     三级合起来 3 + 11 + 11 + 14 = 39 —— 正好是用户地址空间上界 2^39 的位数，
 *     这一条是对整套几何的独立核验。
 */
#define KM_PM_SHIFT_L1 36ULL
#define KM_PM_INDEX_L1 0x0000007000000000ULL /* bits 38:36，3 位（见文件头部） */
#define KM_PM_SHIFT_L2 25ULL
#define KM_PM_INDEX_L2 0x0000000ffe000000ULL /* bits 35:25，11 位 */
#define KM_PM_SHIFT_L3 14ULL
#define KM_PM_INDEX_L3 0x0000000001ffc000ULL /* bits 24:14，11 位 */

/*
 * 三级的「页内偏移掩码」（pte.h:71 / :76 / :81 的 ARM_16K_TT_L*_OFFMASK）。
 * 只在 vtophys_lvl 撞到 block 描述符时用来把块基址 + va 低位置拼成最终物理地址
 * （translation.c:83）—— 那一步逐字照抄，所以这三个值也要跟着照抄。
 */
#define KM_PM_OFFMASK_L1 0x0000000fffffffffULL /* 2^36 − 1 */
#define KM_PM_OFFMASK_L2 0x0000000001ffffffULL /* 2^25 − 1 */
#define KM_PM_OFFMASK_L3 0x0000000000003fffULL /* 2^14 − 1 */

/*
 * 一条不许加回来的写法：**不要**再从这个键取 L1 掩码 ——
 * kernelConstant.ARM_TT_L1_INDEX_MASK（common.c:113-127）按 T1SZ_BOOT 选值，
 * 表达的是内核侧（TTBR1）几何；本模块建的是用户 pmap 的窗口，要用户侧（T0SZ）
 * 几何，两者在 T1SZ_BOOT = 17 的目标机上分家（全过程见文件头部）。
 *
 * 这**不违反**头文件「不许用兜底常量把失败包装成成功」那条硬约束：
 * 用户侧几何本身是常量（它由架构与页大小定死，不来自这台设备的任何一次读取），
 * 所以它不承担"取不到就回退"的风险。反过来，从那个键取才是真正的兜底 ——
 * 拿一台设备**内核侧**的几何去当**用户侧**地址空间的几何，正是这次翻车。
 * 同一套用户侧常量在 KernelPhysWindow.m 里一直是这么写的，那个模块在真机上
 * 从来没报过这条错 —— 两支的差别只有这一个。
 */

/// pmap 结构头部两个字段（static_info.h:255-257：struct pmap 以 tte / ttep 开头）。
#define KM_PM_PMAP_OFF_TTE 0x00ULL
#define KM_PM_PMAP_OFF_TTEP 0x08ULL

/// pt_desc 三处偏移，出处 Dopamine info.c:107-109。
#define KM_PM_PT_DESC_OFF_PMAP 0x10ULL
#define KM_PM_PT_DESC_OFF_VA 0x18ULL

/*
 * pmap 里三个字段的偏移，出处 Dopamine info.c:86-88 / :90-92。
 *
 * arm64e 支：sw_asid = 0xBE + pmapEl2Adjust、wx_allowed = 0xC2 + adj、
 *            type = 0xC8 + adj，其中 adj = (kernel_el == 2) ? 8 : 0（info.c:42）。
 * arm64 支（A8-A11）：sw_asid = 0x96、type = 0x9c + pmapA11Adjust。
 *
 * 本文件只实现 arm64e 支（A12+ 的机型都是 arm64e 内核），并用三条运行时佐证
 * 把关（见 kpm_verify_pmap_layout）；佐证不过就跳过这一步，而不是换一支继续猜。
 * 头文件「没能确证的部分」一节写了这条假设的来历与代价。
 */
#define KM_PM_PMAP_OFF_SW_ASID_ARM64E 0xBEULL
#define KM_PM_PMAP_OFF_WX_ALLOWED_ARM64E 0xC2ULL
#define KM_PM_PMAP_OFF_TYPE_ARM64E 0xC8ULL
#define KM_PM_PMAP_EL2_ADJUST 0x8ULL

/// pmap->type 的期望值：用户进程的 pmap 是 PMAP_TYPE_USER = 0。
/// 依据是 Dopamine util.c:283-289 —— 那一段把 type 设成 3（nested）再设回 0，
/// 说明 0 就是"普通用户 pmap"的取值。这条是下面的布局佐证之一。
#define KM_PM_PMAP_TYPE_USER 0x0ULL

#pragma mark - 页表项与 PVH 常量

/*
 * 描述符判据。pte.h:53-58（TTE）+ pte.h:35（ARM_TTE_TYPE_L3BLOCK）。
 *
 * 逐级不同这一点必须照抄：L3 的 typeBlock 是 ARM_TTE_TYPE_L3BLOCK = 0x2
 * （bit1 = 1 表示"是页描述符"），而 L1/L2 的 typeBlock 是 ARM_TTE_TYPE_BLOCK = 0
 * （bit1 = 0 表示"是大页"）。translation.c:138-145 就是这么设的。
 */
#define KM_PM_TTE_VALID 0x0000000000000001ULL
#define KM_PM_TTE_TYPE_MASK 0x0000000000000002ULL
#define KM_PM_TTE_TYPE_BLOCK 0x0000000000000000ULL
#define KM_PM_TTE_TYPE_TABLE 0x0000000000000002ULL
#define KM_PM_TTE_TYPE_L3BLOCK 0x0000000000000002ULL
#define KM_PM_TTE_TABLE_MASK 0x0000fffffffff000ULL
#define KM_PM_TTE_PA_MASK 0x0000fffffffff000ULL

/*
 * L3 叶项模板。**不是硬编码出来的，是从 pte.h 的四条定义推出来的**：
 *
 *   PERM_TO_PTE(PERM_KRW_URW)   = 0x60000000000040   (kernel.h:15 的 0x7 + pte.h:23-25)
 *   | PTE_NON_GLOBAL            = 0x000000000000800   (pte.h:4,  1 << 11)
 *   | PTE_OUTER_SHAREABLE       = 0x000000000000200   (pte.h:6,  2 << 8)
 *   | PTE_LEVEL3_ENTRY          = 0x000000000000403   (pte.h:5 + :11, (1 << 10) | 3)
 *   ────────────────────────────────────────────────────────────
 *                               = 0x6000000000000E43
 *
 * 这个值同时是样本那三处 `orr <pte>, <pa>, #0x6000000000000e43` 用的常量
 * （docs/当前任务.md §0.2）—— 两边**逐位相同**，是这条移植路线的独立交叉印证。
 *
 * 位域含义（pte.h:23-25 的逆运算）：bit54 UXN / bit53 PXN（都置 1 ⇒ 不可执行）、
 * bit6 AP[1]（置 1 ⇒ EL0 可读写）、bit10 AF、bit1 描述符类型。
 * AP[1] 与 UXN/PXN 这两组位是"用户态也能碰这张页"的关键 —— 与头文件里
 * 「PPL 不拦这条路径」那段结论指向同一件事。
 *
 * 注意 bits[47:12] 全 0：这是模板**不是成品**，必须 `pa | 它` 之后再写
 * （docs/当前任务.md §0.2 的加粗警告：裸写等于把 VA 指到物理页 0）。
 */
#define KM_PM_PERM_KRW_URW 0x7ULL
#define KM_PM_PERM_TO_PTE(perm) \
    (((((perm) & 0xCULL) << 4) | (((perm) & 0x2ULL) << 52) | (((perm) & 0x1ULL) << 54)))
#define KM_PM_PTE_NON_GLOBAL (1ULL << 11)
#define KM_PM_PTE_VALID (1ULL << 10)
#define KM_PM_PTE_OUTER_SHAREABLE (2ULL << 8)
#define KM_PM_PTE_LEVEL3_ENTRY (KM_PM_PTE_VALID | 0x3ULL)
#define KM_PM_PTE_LEAF                                                       \
    (KM_PM_PERM_TO_PTE(KM_PM_PERM_KRW_URW) | KM_PM_PTE_NON_GLOBAL |          \
     KM_PM_PTE_OUTER_SHAREABLE | KM_PM_PTE_LEVEL3_ENTRY)

/*
 * pv_head 表项的打包格式。pvh.h:4-5 / :16-17 / :19-22 三条。
 *
 * PVH_HIGH_FLAGS 那一位集合在高 16 位全 1 的内核地址上是**幂等**的（bits 63..48
 * 本来就全是 1），所以 `(entry & PVH_LIST_MASK) | PVH_HIGH_FLAGS` 得到的就是
 * ptd 的 KVA —— 这正是 Dopamine kernel.c:114 能直接 kread 它的原因。
 */
#define KM_PM_PVH_TYPE_MASK 0x3ULL
#define KM_PM_PVH_LIST_MASK (~KM_PM_PVH_TYPE_MASK)
#define KM_PM_PVH_TYPE_NULL 0x0ULL
#define KM_PM_PVH_TYPE_PVEP 0x1ULL
#define KM_PM_PVH_TYPE_PTEP 0x2ULL
#define KM_PM_PVH_TYPE_PTDP 0x3ULL
#define KM_PM_PVH_HIGH_FLAGS                                                              \
    ((1ULL << 62) | (1ULL << 61) | (1ULL << 60) | (1ULL << 59) | (1ULL << 58) |           \
     (1ULL << 57) | (1ULL << 56) | (1ULL << 54))

/// PMAP_TT_L*_LEVEL（pte.h:60-63）。
#define KM_PM_TT_L1_LEVEL 0x1ULL
#define KM_PM_TT_L2_LEVEL 0x2ULL
#define KM_PM_TT_L3_LEVEL 0x3ULL

/// 建表循环的防御上限。Dopamine util.c:308-333 的 do-while 每轮至少把 leafLevel
/// 抬一级，正常最多两轮；给 4 是"够用且能在几何被改坏时立刻停下"。
#define KM_PM_EXPAND_LOOP_GUARD 4

/// alloc_page_table_unassigned 的重试上限。Dopamine util.c:141 是 `while (true)` ——
/// 无限重试；本工程不许有不可终止的循环（面板在等它），所以给一个上界，
/// 超了就按"确定失败"返回。8 次 × 32 MB 的临时虚拟分配在目标机上是安全的
/// （每次失败都会 free 掉那一块）。
#define KM_PM_ALLOC_ATTEMPTS 8

/// 取一张"无主页表页"时临时占用的用户地址范围 = 一个 L2 块（util.c:143）。
#define KM_PM_ALLOC_SPAN KM_PM_16K_L2_BLOCK_SIZE

/// refcount 抬到 0x1337（util.c:194），回来时归 0（util.c:211）。
#define KM_PM_REFCOUNT_PINNED 0x1337U

/// 诊断文本缓冲。分成预检与执行两块会重复太多，共用一份。
#define KM_PM_TEXT_SIZE 16384

#pragma mark - 状态

// 诊断文本与两个结论值。都只在 km_physmap_precheck() / km_physmap_build() 的末尾写，
// 在访问器里读。调用方（面板）保证这些调用都在同一条串行路径上
// （AutoTracker.syncExternal）—— 与 KernelPhysWindow.m 的 g_pwText 同一套口径。
static NSString *g_physmapText = nil;
static uint64_t g_physmapWindow = 0;
static uint64_t g_physmapMagicPT = 0;

/// 是否已经跑过至少一次。用来区分「还没跑过」与「跑过了但诊断文本没能落地」——
/// 两者在面板上都表现为 g_physmapText 为 nil，但要求 YG 做的事完全不同。
static bool g_physmapRan = false;

/*
 * 把诊断缓冲收成 g_physmapText。
 *
 * **本文件没有钉 -fobjc-arc**（project.yml:28-30 只给 Aether/libmemrw/xpf 加了
 * -fobjc-arc），所以这里必须自己持有对象：`[NSString stringWithUTF8String:]`
 * 返回的是 autorelease 对象，直接赋给静态变量在 MRC 下等于"借一个随时会被
 * 回收池收走的东西"，面板随后读它就是 use-after-free。
 * 工程里另两处同样的赋值在 KernelPhysWindow.m（`g_pwText =` 那一句）与
 * KernelSlide.m 的 `text_append` 家族里。**这里刻意只引函数/变量名、不引行号**：
 * KernelPhysWindow.m 正在被并行修改（本轮就经历了 736 行 → 661 行的重构），
 * 行号引用会在作者毫不知情的时候指到别的地方去 —— 指错比不指更糟。
 * 是这个形态；本文件不复刻它。
 *
 * 两级编码是为了兑现头文件那句「永不返回 nil」：UTF-8 失败时用 ISO-Latin-1，
 * 它对任意字节序列都能成功（最坏情况是显示成乱码，而不是给不出文本）。
 * ARC 那一支走 stringWithUTF8String（ARC 下它会被正常持有）。
 */
static void kpm_store_text(const char *buffer)
{
#if __has_feature(objc_arc)
    g_physmapText = [NSString stringWithUTF8String:buffer];
#else
    NSString *text = [[NSString alloc] initWithBytes:buffer
                                              length:strlen(buffer)
                                            encoding:NSUTF8StringEncoding];
    if (text == nil) {
        text = [[NSString alloc] initWithBytes:buffer
                                        length:strlen(buffer)
                                      encoding:NSISOLatin1StringEncoding];
    }
    [g_physmapText release];
    g_physmapText = text;
#endif
    g_physmapRan = true;
}

#pragma mark - 文本工具

/*
 * 追加——记账按**实际写入**的字节数（strlen），不用 vsnprintf 的返回值。
 *
 * 理由是 KernelMemory.m 里 km_self_test 那段踩过的坑：截断时 snprintf 返回的是
 * "空间够的话本来会写多少"，它**大于**实际可用空间，`size - used` 在 size_t 上
 * 回绕成天文数字，下一句就写出缓冲区。本缓冲区是静态的，越界就是踩相邻静态数据。
 */
typedef struct {
    char *buf;
    size_t size;
    size_t used;
    bool truncated;
} km_pm_text;

/*
 * 前向声明带 format 属性 —— 本文件 100+ 处调用点的格式串由此获得编译期校验。
 *
 * 为什么非加不可：自定义变参函数没有这个属性时，Clang **不对任何调用点**做
 * `-Wformat` 检查（全工程此前 `__attribute__((format` 零命中）。本文件是工程里
 * 格式串最密集的地方，而"格式符与实参不匹配"是一类不报错、读垃圾、可能崩的错
 * （本轮就查出过一处 `%#llu`：`#` 标志与 `u` 搭配在 C 标准里是未定义行为）。
 * 加属性之后 CI 会替人盯着它；本地没有编译器，这一层只能交给它。
 */
static void kpm_append(km_pm_text *t, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void kpm_append(km_pm_text *t, const char *fmt, ...)
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

    t->used += strlen(t->buf + t->used);
    if (written < 0 || (size_t)written >= room) {
        t->truncated = true;
    }
}

#pragma mark - 地址工具

/*
 * 形态检查——本模块每一条 kread/kwrite 之前的唯一闸门。
 *
 * 与 KernelPhysWindow.m 的 `physwindow_shape_ok()` 同口径（那里写成 static，
 * 跨文件用不了；本文件自己留一份，是为了让"每一条进入内核读写原语的地址都经过
 * 同一个判据"这件事在本文件里可自查，而不是依赖另一个正在被修的模块）。
 *
 * 两个判据：
 *   ① 内核地址域：与 km_is_kernel_address 同口径（高 16 位全 1）。
 *      **刻意同口径而不是更严**：km_read64/km_write 自己也查这一条，本函数若更严，
 *      被拒的访问在诊断里会显示成"我拒了"，而实际上是底层会拒 —— 口径一致，
 *      诊断文本才对应得上真实行为。
 *   ② 8 字节对齐：一条页表项永远是 8 字节，错位地址读到的是相邻两项各一半拼起来的
 *      垃圾 —— 那种值"看着像合法表项"，会被类型判据放行，然后被当成下一级表地址。
 *      这正是"错值比 0 危险"的同一个形态：0 会被拦下，错值不会。
 */
static bool kpm_shape_ok(uint64_t addr)
{
    if ((addr >> 48) != 0xFFFF) {
        return false;
    }
    if ((addr & 0x7ULL) != 0) {
        return false;
    }
    return true;
}

/// 无溢出的加法。页表项里的 PA 加上换算出的基准理论上不会溢出，但"理论上"不是判据：
/// 溢出让地址回绕到一个**形态合法**的小内核地址，正是形态检查拦不住的那类值。
static bool kpm_add(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return false;
    }
    *out = a + b;
    return true;
}

/// 无溢出的乘法。
static bool kpm_mul(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a != 0 && b > UINT64_MAX / a) {
        return false;
    }
    *out = a * b;
    return true;
}

#pragma mark - 页表遍历

/// 一级的几何。与 Dopamine translation.c:8-15 的 struct tt_level 同构。
typedef struct {
    uint64_t offMask;
    uint64_t shift;
    uint64_t indexMask;
    uint64_t validMask;
    uint64_t typeMask;
    uint64_t typeBlock;
} km_pm_tt_level;

/*
 * 遍历失败原因。前三个与 Dopamine 的 errno 一一对应（translation.c:51 的 1041、
/// :77 的 1042、:72 的 1043），后三个是本工程的机制差异带出来的新分支
 * （Dopamine 的 physread64 不会"换算不出来"，也不会自查形态）。
 */
typedef enum {
    KM_PM_E_NONE = 0,
    /// curLevel 越过 L3（对应 errno 1041）：几何或 leaf_level 入参坏了。
    KM_PM_E_LEVEL,
    /// 某级表项 invalid（对应 errno 1042）。**这不是错误**：调用方靠它判断
    /// "页表在这里断了、该建下一级"，`*leaf_level` 与 `*leaf_addr` 保留在断点那一级。
    KM_PM_E_INVALID,
    /// 起点不是物理地址（高位非 0，对应 errno 1043 那一支）。本工程只走物理路径，
    /// 所以遇到就中止，而不是回退去用 kread。
    KM_PM_E_PATH,
    /// PA → KVA 换算不出来（km_phystokv 返回 0，或换算表未就绪）。
    KM_PM_E_PHYS2VIRT,
    /// 自己算出来的地址连形态检查都不过。
    KM_PM_E_SHAPE,
    /// 表项读失败（km_read64 两次读到不同的值）。
    KM_PM_E_READ
} km_pm_vt_err;

/// 遍历的整体输入。字段在 kpm_load() 里一次性填好，之后只读。
typedef struct {
    uint64_t pageSize;
    uint64_t pageShift;
    uint64_t window;

    km_pm_tt_level levels[4]; /* 下标即 PMAP_TT_L*_LEVEL，[0] 不用（16K 从 L1 起） */

    /* pmap 链路 */
    uint64_t proc;
    uint64_t task;
    uint64_t map;
    uint64_t pmap;
    uint64_t ttep; /* 顶层表的**物理地址** */

    /* XPF 取来的符号（已 + slide，可直接 kread） */
    uint64_t slide;
    uint64_t pvHeadTable; /* kernel.c:109 的 kread64(ksymbol(pv_head_table)) 的**符号地址** */
    uint64_t vmFirstPhysSymbol;
    uint64_t cpuTtepSymbol;
    uint64_t cpuTtep; /* 上面那个符号的**内容** = TTBR1 的值（PA） */

    /* 上面三个符号的**内容**（读一次，之后记账链与遍历都用它们，不再重复 kread） */
    uint64_t pvHeadTableValue; /* = pai_to_pvh 的基址（kernel.c:109） */
    uint64_t vmFirstPhysValue; /* = pa_index 的基准（kernel.c:104） */

    /* XPF 取来的常量（值，不是地址） */
    uint64_t ptIndexMax;

    /* pmap 布局（arm64e 支） */
    uint64_t ptDescOffPtdInfo;
    uint64_t swAsidOff;
    uint64_t typeOff;
    uint64_t wxAllowedOff;

    /* 窗口探测结果（kpm_probe_window 填） */
    uint64_t windowLeafLevel;
    uint64_t windowLeafAddr; /* 表项自身的**物理地址** */
    uint64_t windowLeafEntry;
    uint64_t windowWalkPa;
    km_pm_vt_err windowWalkErr;
    bool windowHasL3;
} km_pm_ctx;

/// 逐级下行。语义**逐条对齐** Dopamine translation.c:39-97，差异只在读表项那一步
/// （那边是 physread64(tte_pa)，这边是 km_phystokv(tte_pa) 之后 km_read64）；
/// 头文件「与 Dopamine 的有意差异」第 1 条。
///
/// 返回值的两种含义要一起看（这是调用方能工作的全部前提）：
///   · 撞到 block 描述符 → 返回映射出来的**物理地址**，`*leaf_level` 停在那一级；
///   · 一路走到 LEAF_LEVEL 全是表描述符 → 返回**最后一级表的物理地址**
///     （translation.c:94-96 的注释）；
///   · 某级 invalid → 返回 0，但 `*leaf_addr` / `*leaf_level` **保留在断点那一级**
///     （translation.c:60-62 先写地址与级号、再读表项的顺序就是为此）。
///
/// 所以返回值 0 **不等于**失败：`*err == KM_PM_E_INVALID` 时它是"这里还没有表"。
static uint64_t kpm_vtophys_lvl(const km_pm_ctx *ctx, uint64_t tte_ttep, uint64_t va,
                                uint64_t *leaf_level, uint64_t *leaf_addr,
                                km_pm_vt_err *err)
{
    if (err) {
        *err = KM_PM_E_NONE;
    }

    const uint64_t ROOT_LEVEL = KM_PM_TT_L1_LEVEL;
    /// 进入时取一次（translation.c:43 的 `const uint64_t LEAF_LEVEL = *leaf_level;`）。
    /// 循环条件用的就是这一份，所以函数中途改 `*leaf_level` 不会改自己的边界。
    const uint64_t LEAF_LEVEL = (leaf_level != NULL) ? *leaf_level : KM_PM_TT_L3_LEVEL;

    /*
     * translation.c:47 —— 高位为 0 走"物理"路径。
     *
     * 本工程的遍历起点**永远**是物理地址（pmap->ttep 与 cpu_ttep 都是），所以
     * physical 恒为真。保留这个判据而不是删掉它，是为了让"某天有人把一个 KVA
     * 当 tte 传进来"这件事在这里立刻变成 E_PATH，而不是被当成 PA 继续算下去 ——
     * 那种错的产物是一个形态合法的错地址。
     */
    const bool physical = ((tte_ttep & 0xf000000000000000ULL) == 0);
    if (!physical) {
        if (err) {
            *err = KM_PM_E_PATH;
        }
        return 0;
    }

    for (uint64_t curLevel = ROOT_LEVEL; curLevel <= LEAF_LEVEL; curLevel++) {
        if (curLevel > KM_PM_TT_L3_LEVEL) {
            if (err) {
                *err = KM_PM_E_LEVEL;
            }
            return 0;
        }

        const km_pm_tt_level *lvlp = &ctx->levels[curLevel];
        const uint64_t tteIndex = (va & lvlp->indexMask) >> lvlp->shift;

        uint64_t indexBytes = 0;
        uint64_t tte_pa = 0;
        if (!kpm_mul(tteIndex, sizeof(uint64_t), &indexBytes) ||
            !kpm_add(tte_ttep, indexBytes, &tte_pa)) {
            if (err) {
                *err = KM_PM_E_SHAPE;
            }
            return 0;
        }

        /*
         * 顺序要紧（translation.c:60-62）：**先**把这一级表项自身的地址与级号交出去，
         * **再**读表项。上面「返回值 0 时断点信息仍有效」这条契约完全建立在
         * 这个顺序上 —— 倒过来写，调用方拿到的就是上一级的信息，
         * 于是它会去写一个属于祖先表的表项。
         */
        if (leaf_addr) {
            *leaf_addr = tte_pa;
        }
        if (leaf_level) {
            *leaf_level = curLevel;
        }

        /// 读表项：PA → KVA。Dopamine 到这里直接 physread64(tte_pa)；
        /// 本工程必须换成 km_phystokv + km_read64（头文件差异第 1 条）。
        if (!km_phystokv_ready()) {
            if (err) {
                *err = KM_PM_E_PHYS2VIRT;
            }
            return 0;
        }
        const uint64_t tte_kva = km_phystokv(tte_pa);
        if (tte_kva == 0) {
            if (err) {
                *err = KM_PM_E_PHYS2VIRT;
            }
            return 0;
        }
        if (!kpm_shape_ok(tte_kva)) {
            if (err) {
                *err = KM_PM_E_SHAPE;
            }
            return 0;
        }

        bool ok = false;
        const uint64_t tteEntry = km_read64(tte_kva, &ok);
        if (!ok) {
            if (err) {
                *err = KM_PM_E_READ;
            }
            return 0;
        }
        /*
         * 这一条**刻意不还原 PAC**，理由是可执行的而不是手感：
         *   · 读出来的是一张 **PTE（页表项）**，不是指针字段。签名只作用于内核结构里
         *     的指针字段（task->map / vm_map->pmap 那一类），不会签在页表项上；
         *   · 下面用的是 `entry & mask`（低位 PA、类型位、下一级表 PA），而
         *     km_unsign_ptr 对高位做的是 `| PAC_MASK` —— 对页表项来说那等于把
         *     bits 47..63 **全部置 1**，会把 km_phystokv(pa) 打进一段不存在的物理
         *     范围。也就是说这里加还原**不是保守，而是主动制造错值**。
         * 同一条推理适用于 physwindow_walk 里的表项读（KernelPhysWindow.m）：
         * 上游 Dopamine 的 translation.c 全程 physread64(tte_pa) 后再 `& mask`，
         * 一次 UNSIGN_PTR 都没有。
         *
         * 这一跳的 raw 值本来值得打出来（它是读取链上第一次由"上一次读的结果"
         * 决定下一次读的地址），但**本函数没有诊断出口**：签名里没有 km_pm_text，
         * 这是刻意的 —— 它是个纯计算函数，断点信息通过 *err / *leaf_addr /
         * *leaf_level 回传给调用方。所以这里**一次 kpm_append 都不能有**，
         * 要打印就在调用方打。（CI 上真踩过：这里加了一句 kpm_append(t, ...)，
         * 而 `t` 在本函数里未声明，整个 build 直接挂。）
         */

        if ((tteEntry & lvlp->validMask) != lvlp->validMask) {
            if (err) {
                *err = KM_PM_E_INVALID;
            }
            return 0;
        }

        if ((tteEntry & lvlp->typeMask) == lvlp->typeBlock) {
            /// translation.c:81-84 —— 撞上块映射，无论在哪一级都是终点。
            return ((tteEntry & KM_PM_TTE_PA_MASK & ~lvlp->offMask) | (va & lvlp->offMask));
        }

        tte_ttep = tteEntry & KM_PM_TTE_TABLE_MASK;
    }

    return tte_ttep;
}

/// 内核 VA → PA，等价于 Dopamine translation.c:105-108 的
/// `kvtophys(va) { return vtophys(kconstant(cpuTTEP), va); }`。
///
/// Dopamine 的 `cpuTTEP` 是 info.c:289 读出来的**符号内容**（TTBR1 的值），
/// 本函数用同一个来源。返回值 0 或 err 非 NONE 表示换算不出来。
static uint64_t kpm_kvtophys(const km_pm_ctx *ctx, uint64_t va, km_pm_vt_err *err)
{
    uint64_t level = KM_PM_TT_L3_LEVEL;
    uint64_t leafAddr = 0;
    return kpm_vtophys_lvl(ctx, ctx->cpuTtep, va, &level, &leafAddr, err);
}

#pragma mark - 物理页记账链（kernel.c:102-115）

/// kernel.c:102-105 —— pa_index(pa) = atop(pa − kread64(ksymbol(vm_first_phys)))。
/// 本工程的 vm_first_phys **内容**在 kpm_load 里已经读到，不再每次 kread。
static uint64_t kpm_pa_index(const km_pm_ctx *ctx, uint64_t pa)
{
    return (pa - ctx->vmFirstPhysValue) >> ctx->pageShift;
}

/// kernel.c:107-110 —— pai_to_pvh(pai) = kread64(ksymbol(pv_head_table)) + pai × 8。
/// 同样：pv_head_table 的**内容**（表基址）在 kpm_load 里已读好。
static uint64_t kpm_pai_to_pvh(const km_pm_ctx *ctx, uint64_t pai)
{
    uint64_t offset = 0;
    if (!kpm_mul(pai, sizeof(uint64_t), &offset)) {
        return 0;
    }
    uint64_t pvh = 0;
    if (!kpm_add(ctx->pvHeadTableValue, offset, &pvh)) {
        return 0;
    }
    return pvh;
}

/// kernel.c:112-115 —— pvh_ptd(pvh) = (kread64(pvh) & PVH_LIST_MASK) | PVH_HIGH_FLAGS。
static uint64_t kpm_pvh_ptd(uint64_t pvhEntry)
{
    return (pvhEntry & KM_PM_PVH_LIST_MASK) | KM_PM_PVH_HIGH_FLAGS;
}

/// pvh 表项低 2 位的类型名（pvh.h:19-22 的四个值）。只给诊断文本用。
///
/// 为什么要把它翻成名字而不是只打数字：`type` 是这一步唯一的**形态判据**
/// （本工程只认 PTDP），而"读到 2 还是 3"这种事从屏幕上一眼分不出来 ——
/// 本项目已经因为"从屏幕抄字节抄错"烧掉过四轮设备实验（KernelSlide.m:1090-1098
/// 那段删掉原始 dump 的理由）。名字是给观察者的护栏。
///
/// 命名只照抄 pvh.h 的宏名，**不替上游解释语义** —— 页表页与页表描述符页
/// 在 PTEP/PTDP 之间到底怎么分，本工程没有独立证据（见头文件「没能确证的部分」）。
static const char *kpm_pvh_type_name(uint64_t type)
{
    switch (type) {
    case KM_PM_PVH_TYPE_NULL: return "NULL";
    case KM_PM_PVH_TYPE_PVEP: return "PVEP";
    case KM_PM_PVH_TYPE_PTEP: return "PTEP";
    case KM_PM_PVH_TYPE_PTDP: return "PTDP（可作 pt_desc 用）";
    }
    return "未定义";
}

#pragma mark - 受检写入

/*
 * ═══ 写入路径的纪律（硬约束 3）═══
 *
 * 每一次内核写都走这两条函数之一，它们做的是同一件事的三步：
 *     读旧值 → （旧值已是目标值则跳过写）→ 写 → 回读核对 → 不符即返回 false。
 * **没有**任何一条路径可以"先全部写完再统一验证"：每一步不符就立刻停，
 * 后面的步骤不会执行。理由写在头文件硬约束 3：写错一个地址的代价是整机内核
 * panic，而"先写完再验证"会让一个已经错了的中间状态继续被下一级当成输入。
 *
 * 旧值已是目标值时跳过写：这不是优化，是减少一次没有收益的内核写 ——
 * 重复调用 build 时自映射那一项已经是期望值，再写一遍只多一次风险窗口。
 */
static bool kpm_write_u64_kva(km_pm_text *t, uint64_t kva, uint64_t value, const char *what)
{
    if (!kpm_shape_ok(kva)) {
        kpm_append(t, "  [写入中止] %s：目标地址 %#llx 形态不过（未发出 kwrite）\n", what,
                   (unsigned long long)kva);
        return false;
    }

    bool ok = false;
    const uint64_t old = km_read64(kva, &ok);
    if (!ok) {
        kpm_append(t, "  [写入中止] %s：目标 %#llx 写前读失败（两次读不一致）\n", what,
                   (unsigned long long)kva);
        return false;
    }
    if (old == value) {
        kpm_append(t, "  [写入跳过] %s：%#llx 处旧值已是目标值 %#llx\n", what,
                   (unsigned long long)kva, (unsigned long long)value);
        return true;
    }

    if (!km_write(kva, &value, sizeof(value))) {
        kpm_append(t, "  [写入中止] %s：kwrite(%#llx) 被底层拒绝（地址形态或长度）\n", what,
                   (unsigned long long)kva);
        return false;
    }

    /*
     * 回读核对的这个值**不还原 PAC**，这是判定而不是遗漏：它核对的是"刚写进去的
     * 那个数有没有落地"，而写进去的是页表项 / 标量字段（`value` 本身），不是签名指针。
     * 对它做 km_unsign_ptr 会让回读值与被写入的期望值比较不上 —— 那正是"主动制造错值"。
     */
    const uint64_t back = km_read64(kva, &ok);
    if (!ok || back != value) {
        kpm_append(t, "  [写入中止] %s：%#llx 回读不符 —— 期望 %#llx，回读 raw=%#llx%s\n", what,
                   (unsigned long long)kva, (unsigned long long)value, (unsigned long long)back,
                   ok ? "" : "（且两次读不一致）");
        return false;
    }
    kpm_append(t, "  [写入核对] %s：%#llx 旧值 %#llx → 新值 %#llx，回读一致\n", what,
               (unsigned long long)kva, (unsigned long long)old, (unsigned long long)value);
    return true;
}

/// 物理地址入口：先 km_phystokv 换 KVA。**换算不出来就中止**，
/// 绝不自己拼 `pa + 某个 delta` 兜底（头文件硬约束 2）。
static bool kpm_write_u64_phys(km_pm_text *t, uint64_t pa, uint64_t value, const char *what)
{
    if (!km_phystokv_ready()) {
        kpm_append(t, "  [写入中止] %s：换算表未就绪（km_phystokv_ready()=false）\n", what);
        return false;
    }
    const uint64_t kva = km_phystokv(pa);
    if (kva == 0) {
        kpm_append(t, "  [写入中止] %s：PA %#llx 换算不出 KVA —— 中止，不猜地址\n", what,
                   (unsigned long long)pa);
        return false;
    }
    return kpm_write_u64_kva(t, kva, value, what);
}

/*
 * 16 位字段的受检写入（refcount 用）。
 *
 * Dopamine util.c:194 / :211 用的是 physwrite16；本工程只能 8 字节粒度写
 * （km_write 要求 len 是 8 的倍数），所以做读-改-写：读旧 8 字节 → 只替换低
 * 16 位 → 写回 → 回读核对低 16 位。比 Dopamine 的裸写多保住高 6 字节
 * （头文件差异第 3 条）。
 *
 * 这里明说一个**没能消除**的竞态：内核自己也会改 pinfo 指向那个结构的相邻字段，
 * 而"读"与"写"之间有窗口。缓解手段是让两步之间不做任何别的事（下面两句紧挨），
 * 以及写后回读核对。真正无竞态的做法是只写 2 字节，而本工程的写原语给不了。
 */
static bool kpm_write_u16_kva(km_pm_text *t, uint64_t kva, uint16_t value, const char *what)
{
    if (!kpm_shape_ok(kva)) {
        kpm_append(t, "  [写入中止] %s：目标地址 %#llx 形态不过（未发出 kwrite）\n", what,
                   (unsigned long long)kva);
        return false;
    }

    bool ok = false;
    const uint64_t old = km_read64(kva, &ok);
    /*
     * 本函数的两次 km_read64（写前读旧值、回读核对）**都不还原 PAC**：它们读的是
     * refcount 那个标量所在的 8 字节，做的是 `& 0xFFFF` 的读-改-写。
     * 对它做 km_unsign_ptr 会把 bits 47..63 全置 1，于是下面 `old & ~0xFFFFULL`
     * 保留的高 6 字节就被改了 —— 那是主动制造错值，不是保守。
     */
    if (!ok) {
        kpm_append(t, "  [写入中止] %s：目标 %#llx 写前读失败（两次读不一致）\n", what,
                   (unsigned long long)kva);
        return false;
    }
    if ((uint16_t)(old & 0xFFFFULL) == value) {
        kpm_append(t, "  [写入跳过] %s：%#llx 处低 16 位已是 %#x\n", what,
                   (unsigned long long)kva, (unsigned)value);
        return true;
    }

    const uint64_t next = (old & ~0xFFFFULL) | (uint64_t)value;
    if (!km_write(kva, &next, sizeof(next))) {
        kpm_append(t, "  [写入中止] %s：kwrite(%#llx) 被底层拒绝\n", what, (unsigned long long)kva);
        return false;
    }

    const uint64_t back = km_read64(kva, &ok);
    if (!ok || (uint16_t)(back & 0xFFFFULL) != value) {
        kpm_append(t, "  [写入中止] %s：%#llx 回读不符 —— 期望低 16 位 %#x，回读 %#llx\n", what,
                   (unsigned long long)kva, (unsigned)value, (unsigned long long)back);
        return false;
    }
    kpm_append(t, "  [写入核对] %s：%#llx 低 16 位 %#x → %#x，回读一致\n", what,
               (unsigned long long)kva, (unsigned)(old & 0xFFFFULL), (unsigned)value);
    return true;
}

#pragma mark - 窗口槽位（物理页 → 用户态窗口的数据通路）

/*
 * ═══ 这段是把「建好的自映射」用起来：把一张物理页挂进窗口的某个 L3 槽 ═══
 *
 * 机制照抄 Dopamine BaseBin/libjailbreak/src/physrw_pte.c:32-74 的 acquire_window：
 * 自映射生效之后，**页表页自己成了一块普通内存**，于是
 *     magicPT[i] = pa | 叶模板
 * 就是往第 i 个 L3 槽里写一条映射物理页 pa 的页表项；随后
 *     *(窗口 + i × 页大小 + 页内偏移)
 * 读到的就是 pa 上那一页的内容。
 *
 * Dopamine 用 `#define gMagicPT ((uint64_t *)MAGIC_PT_ADDRESS)`（physrw_pte.c:13-14）
 * 把窗口地址写死成编译期常量 —— 本文件**不这么做**，用 km_physmap_window_address()：
 * 窗口地址是运行时算出来的（4K/16K 两档几何不同），写死常量等于把页大小分支
 * 又抄了一遍。样本那侧同样没有固定常量（它的窗口基址也是运行时值）。
 *
 * ── 与 Dopamine 的**有意偏离**（两处，都是刻意的，不是遗漏）──
 *
 * 1. **写槽位这一句走内核写原语，不用用户态 `str`。**
 *    Dopamine 的 `gMagicPT[toUse] = ...` 编译出来是用户态 `str`
 *    （样本：`0x10104909c str x21, [x8, w22, uxtw #3]`）。理由是可执行的：
 *    本工程没有样本那套独立的原语分发层，而 km_write 有形态闸门、写前读旧值、
 *    写后回读核对的逐级可中止语义 —— 写错一格的代价是整机 panic，
 *    多花的这一次读换的是"写不进去就立刻知道"。
 *    ⚠ 但**页表项存在表页里**，它的物理地址 = magicPT + slot×8，换算出的 KVA
 *    永远是内核地址，所以这一句在本机是可行的（自映射那一次写走的是同一条路，
 *    真机已跑通）。
 *
 * 2. **槽位数据的读写用 `#if` 选一档，默认走用户态直访（与 Dopamine 同形态）。**
 *    这一条必须写成注释而不能含糊过去，因为它踩到了本工程的一道**硬边界**：
 *    `km_read` / `km_read64` / `km_write` 三者**都**先过
 *    `km_is_kernel_address()`（KernelMemory.m:241-244，判据 `addr >> 48 == 0xFFFF`，
 *    在 km_read:974 / km_read64:1027 / km_write:1053 三处调用），而窗口地址在
 *    用户地址空间（目标机 0x7000000000，高 16 位全 0），一定被拒。
 *    本文件自己的 kpm_shape_ok() 与它**同口径**（见上面那段注释），也一样拒。
 *    也就是说：「槽位数据的读写走 km_read/km_write」这条路在本工程的现有原语下
 *    **不可实现** —— 不是保守不保守的问题，是地址域过不去。
 *    于是给出两档，用 KM_PM_WINDOW_ACCESS 选：
 *      · 0（默认）= uaccess，用户态直访窗口。与 Dopamine physrw_pte.c:82/96 的
 *        `memcpy(curUA, ...)` 同形态，也是这套机制**原本**的样子；
 *      · 1 = kmprim，按任务要求走 km_read/km_write。它会**在形态闸门处确定地失败**
 *        （诊断里逐条写明「形态不过，未发出 kread/kwrite」），一次内核访问都不发。
 *    两档的**槽位选择、前置检查、失败路径完全共用**，差别只在这一处；所以切档
 *    不会改变"写错一格"的风险面，只决定数据通路这一句能不能通。
 *    详见附加诊断 `km_physmap_window_diag()` 的第一行（它会打出当前档位与原因）。
 *
 *    **这一档的失败形态也要说清**：uaccess 直访窗口，若那次访问真的失败，
 *    它是**本进程的用户态异常**（SIGSEGV / SIGBUS），不是内核 panic ——
 *    页表项本身是内核写、有回读核对；越界的是用户态那一步。这是两档在
 *    "出事代价"上的唯一区别，也是为什么默认取它。
 *
 * ── 并发 ──
 *
 * 一次 acquire 从选槽到用完为止都在同一把锁内：槽位是**共享资源**，
 * 别人在你用完之前复用同一个槽，你手上的窗口地址就指向了另一张物理页 ——
 * 那不是读到旧数据，是读到**别人的数据**（或内核刚改过的页表）。
 * 锁用 `pthread_mutex_t` + `PTHREAD_MUTEX_INITIALIZER` 静态初始化：
 * 不用 dispatch_once 造锁，是因为本函数可能被 C 侧调用、且工程里已经有
 * pthread 依赖（KernelSlide/KernelMemory 同）。所有出口都必须解锁 ——
 * 本段用 `goto unlock` 汇合，一个 return 都不许自己走。
 */

/// 数据通道档位。见上面「有意偏离」第 2 条。
#define KM_PM_WINDOW_ACCESS_UACCESS 0
#define KM_PM_WINDOW_ACCESS_KMPRIM 1

/*
 * 默认档。**这是本文件唯一一处"按任务要求实现、但本机不可通"的开关**，
 * 所以默认值取能用的那一档（uaccess），并把不可通的那一档完整保留、
 * 由诊断如实报出原因 —— 取 kmprim 当默认会让这个模块 100% 不可用。
 */
#define KM_PM_WINDOW_ACCESS KM_PM_WINDOW_ACCESS_UACCESS

/*
 * 保留槽位：0 / 1 / 2 / 3 —— **一个都不许被 acquire 复用**。
 *
 *   0 = 自映射项本身。把它改成别的页，窗口的第一页就不再是表页，
 *       而**它正是这段代码用来写后续槽位的那个东西** —— 一旦被覆盖，
 *       本模块在不重启进程的前提下永久失去写表能力（不是"下一次会修好"）。
 *   1 = 本次 build 写的 sw_asid 页映射（build 的第 ⑬ 段写的是 magicPT + 8）。
 *   2 = Dopamine physrw_pte.c:63 的 `toUse = 2` 起点；它可能被 sw_asid
 *       那一步占用（上游写的是 magicPT+8 即槽 1，但两个实现的槽位约定
 *       没有共享的常量，所以 2 与 3 一起保守留下）。
 *   3 = 预留给"槽位约定将来变一位"的余量。多留两个 16 KB 槽位的代价是
 *       可寻址窗口少了 32 KB，而代价的另一面是"绝不会把自映射或 sw_asid
 *       那一页换掉"。
 *
 * 为什么不是"只留 0 与 1"：本文件里**没有任何一处**把 sw_asid 用的槽位
 * 写成共享常量（build 里是字面量 `magicPT + 8`），所以"槽 1 就是它"这件事
 * 在代码里没有单一真相。多留两个槽位比在这里补一条会漂移的约定便宜。
 *
 * 它被三处引用：kpm_slot_hits_reserved_page()、km_physmap_acquire_window()
 * 的诊断文本、以及 kpm_report_window_slots() 的诊断文本。
 */
#define KM_PM_WINDOW_SLOT_RESERVED 4U

/// 单次物理读写的大小上界。有界循环是本工程的硬要求（面板在等它）；
/// 1 MiB 在 16K 页下是 64 页，正常调用远小于它。
#define KM_PM_RWBUF_MAX (1ULL << 20)

/// acquire 轨迹环形缓冲的条数。只服务于诊断（"这一轮用的是哪个槽、凭什么"）。
#define KM_PM_SLOT_TRACE_MAX 32

/*
 * 往 g_physmapWindowDiag 里追加一行。**与 kpm_append 分开写**，理由两条：
 *   · kpm_append 要一个 km_pm_text*（used/size/truncated 那套记账），
 *     而这里只有一个静态缓冲，没有"当次调用"这个作用域；
 *   · 这块文本是**滚动**的：它记的是最近若干次 acquire，不是某一次调用的完整记录。
 * 记账口径与 kpm_append 一致 —— 按**实际写入的字节数**（strlen）算，不用
 * vsnprintf 的返回值（截断时它返回"本来会写多少"，在 size_t 上能把下一句算出界）。
 */
static void kpm_append_window_diag(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void kpm_append_window_diag(const char *fmt, ...)
{
    char line[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    const size_t size = sizeof(g_physmapWindowDiag);
    size_t used = strlen(g_physmapWindowDiag);
    const size_t lineLen = strlen(line);
    if (used + lineLen + 2 > size) {
        /* 快满：丢掉全部历史重来 —— 诊断文本允许丢历史，不允许越界。 */
        g_physmapWindowDiag[0] = '\0';
        used = 0;
    }
    if (used + lineLen + 2 <= size) {
        memcpy(g_physmapWindowDiag + used, line, lineLen);
        used += lineLen;
        g_physmapWindowDiag[used] = '\n';
        used++;
        g_physmapWindowDiag[used] = '\0';
    }
    g_physmapWindowDiagRan = true;
}

/// 槽位决策的三种来源（照 physrw_pte.c:36-71 的三段）。
typedef enum {
    KM_PM_SLOT_NONE = 0,
    KM_PM_SLOT_REUSED = 1, /* 已经映射同一个 pa 的槽（physrw_pte.c:39-44） */
    KM_PM_SLOT_EMPTY = 2,  /* 值为 0 的空槽（physrw_pte.c:47-54） */
    KM_PM_SLOT_RESET = 3   /* 全清之后从 2 开始用（physrw_pte.c:57-64） */
} km_pm_slot_decision;

typedef struct {
    uint64_t pa;   /* 本次要映射的物理页（已页对齐） */
    uint64_t ua;   /* 交给调用方的窗口地址 */
    uint32_t slot; /* 用的槽位下标 */
    uint32_t how;  /* km_pm_slot_decision */
} km_pm_slot_trace;

/// 串行化「选槽 → 写项 → 用窗口 → 下次覆盖」这条链。见上面「并发」。
static pthread_mutex_t g_physmapSlotLock = PTHREAD_MUTEX_INITIALIZER;

/// 最近 KM_PM_SLOT_TRACE_MAX 次 acquire 的槽位决策（环形，最旧的被覆盖）。
static km_pm_slot_trace g_physmapSlotTrace[KM_PM_SLOT_TRACE_MAX];
static int g_physmapSlotTraceCount = 0;
static int g_physmapSlotTraceNext = 0;

/// acquire 自己的诊断文本 —— **不覆盖** g_physmapText。
///
/// 理由：预检/执行的结论文本是有契约的（面板拿第一行当状态行、且它是"那一次跑
/// 的完整记录"）。一次 acquire 是**下游动作**，它若把结论文本冲掉，面板上那张
/// 报告就再也不是"上次点按钮的结果"了。所以单开一块、单开一个访问器。
static char g_physmapWindowDiag[4096];
static bool g_physmapWindowDiagRan = false;

/// 选槽用的小工具：读一条槽。
///
/// **两道闸门，缺一不可**：
///   · 地址形态（kpm_shape_ok）：自映射生效时 magicPT 一定是**物理**地址，
///     而这里要的是内核虚拟地址。若 magicPT 被写成了 KVA（或高 16 位非 0），
///     `km_phystokv` 会返回 0 或一个别的值 —— 那正是"错值比 0 危险"的形态，
///     所以换算结果必须重过一次形态检查。
///   · 页内位置：这条读碰的是**页表页**，页表页跑出页界就是踩到相邻的物理页。
static bool kpm_slot_read(uint64_t slotIndex, uint64_t *value)
{
    *value = 0;
    if (g_physmapMagicPT == 0 || slotIndex >= KM_PM_WINDOW_SLOT_COUNT) {
        return false;
    }
    const uint64_t entryPa = g_physmapMagicPT + slotIndex * sizeof(uint64_t);
    const uint64_t entryKva = km_phystokv(entryPa);
    if (!kpm_shape_ok(entryKva)) {
        return false;
    }
    bool ok = false;
    *value = km_read64(entryKva, &ok);
    return ok;
}

/// 记一条槽位决策。**不解析地址**：它只是把决策记下来供诊断读，
/// 所以它不需要任何闸门，也永远不会失败。
static void kpm_slot_trace_push(uint64_t pa, uint64_t ua, uint32_t slot, uint32_t how)
{
    g_physmapSlotTrace[g_physmapSlotTraceNext].pa = pa;
    g_physmapSlotTrace[g_physmapSlotTraceNext].ua = ua;
    g_physmapSlotTrace[g_physmapSlotTraceNext].slot = slot;
    g_physmapSlotTrace[g_physmapSlotTraceNext].how = how;
    g_physmapSlotTraceNext = (g_physmapSlotTraceNext + 1) % KM_PM_SLOT_TRACE_MAX;
    if (g_physmapSlotTraceCount < KM_PM_SLOT_TRACE_MAX) {
        g_physmapSlotTraceCount++;
    }
}

/// 轨迹里的第 i 条（0 = 最旧）。i 越界返回 NULL。
static const km_pm_slot_trace *kpm_slot_trace_at(int i)
{
    if (i < 0 || i >= g_physmapSlotTraceCount) {
        return NULL;
    }
    const int oldest =
        (g_physmapSlotTraceNext - g_physmapSlotTraceCount + KM_PM_SLOT_TRACE_MAX) %
        KM_PM_SLOT_TRACE_MAX;
    return &g_physmapSlotTrace[(oldest + i) % KM_PM_SLOT_TRACE_MAX];
}

static const char *kpm_slot_decision_name(uint32_t how)
{
    switch (how) {
    case KM_PM_SLOT_REUSED: return "复用已有槽";
    case KM_PM_SLOT_EMPTY: return "空槽";
    case KM_PM_SLOT_RESET: return "全清后从 2 起";
    }
    return "未选";
}

/*
 * 槽位选择 —— 逐条对照 Dopamine physrw_pte.c:36-71 的**顺序**（顺序是语义的一部分）：
 *   ① 从下标 2 起找**已经映射同一个 pa** 的槽 → 命中就用（省一次写）；
 *   ② 没命中找**值为 0 的空槽** → 命中就用；
 *   ③ 都没有才把下标 2.. 全部清 0，然后用 2。
 *
 * 为什么 ① 必须在 ② 前面：先找空槽会让"同一个 pa 第二次进来"写到一个新槽上，
 * 于是**同一个物理页在窗口里有两处映射**，而旧的那处才是别人正在用的 —— 不崩，
 * 但会一点点吃光 2046 个槽，最后每次都走 ③（每 2047 次就把整张表清一遍）。
 * 顺序反了不会立刻出事，只会在跑了几千次之后变成另一套行为：这正是最难查的一类。
 *
 * 为什么 ③ 的"全清"必须逐条回读核对：那一段清的是**别人可能正在用的槽**，
 * 清不掉就说明这张表不由我们独占（或写通道坏了），此时继续往下走等于
 * 在半张别人的页表上写映射。**任意一条清不掉即中止**，不做部分继续。
 *
 * 返回 true 时 *slotOut 是选中的槽位；返回 false 时 *reasonOut 是原因（静态字符串）。
 */
static bool kpm_slot_choose(uint64_t pa, uint32_t *slotOut, km_pm_slot_decision *howOut,
                            const char **reasonOut)
{
    *slotOut = 0;
    *howOut = KM_PM_SLOT_NONE;
    *reasonOut = NULL;

    /* ① 已有同一个 pa 的槽 */
    for (uint32_t i = 2; i < KM_PM_WINDOW_SLOT_COUNT; i++) {
        uint64_t v = 0;
        if (!kpm_slot_read(i, &v)) {
            *reasonOut = "读槽位失败（换算不出 KVA 或两次读不一致）";
            return false;
        }
        if ((v & KM_PM_TTE_PA_MASK) == pa) {
            *slotOut = i;
            *howOut = KM_PM_SLOT_REUSED;
            return true;
        }
    }

    /* ② 空槽 */
    for (uint32_t i = 2; i < KM_PM_WINDOW_SLOT_COUNT; i++) {
        uint64_t v = 0;
        if (!kpm_slot_read(i, &v)) {
            *reasonOut = "读槽位失败（换算不出 KVA 或两次读不一致）";
            return false;
        }
        if (v == 0) {
            *slotOut = i;
            *howOut = KM_PM_SLOT_EMPTY;
            return true;
        }
    }

    /*
     * ③ 全清。physrw_pte.c:59-63 在这里调 flush_tlb()（它要靠 gSwAsid 那套机制）；
     *    Aether 没有 flush_tlb，所以这一处**刻意不做** —— 代价写在诊断里，
     *    不藏起来：清掉的项在本进程的 TLB 里可能还留着，而它们指向的物理页
     *    已经被别人（或内核）复用。这是本段唯一一处"照抄机制但少一步"的地方，
     *    真机上若复现「读到陈旧内容」，第一处要查的就是这里。
     */
    for (uint32_t i = 2; i < KM_PM_WINDOW_SLOT_COUNT; i++) {
        uint64_t entryPa = 0;
        uint64_t entryKva = 0;
        if (!kpm_mul(i, sizeof(uint64_t), &entryPa) ||
            !kpm_add(g_physmapMagicPT, entryPa, &entryPa)) {
            *reasonOut = "清槽位时下标×8 溢出";
            return false;
        }
        entryKva = km_phystokv(entryPa);
        if (!kpm_shape_ok(entryKva)) {
            *reasonOut = "清槽位时目标地址形态不过";
            return false;
        }
        bool ok = false;
        const uint64_t old = km_read64(entryKva, &ok);
        if (!ok) {
            *reasonOut = "清槽位前读旧值失败（两次读不一致）";
            return false;
        }
        if (old == 0) {
            continue; /* 已经是 0：不写。没有收益的内核写只多一次风险窗口 */
        }
        const uint64_t zero = 0;
        if (!km_write(entryKva, &zero, sizeof(zero))) {
            *reasonOut = "清槽位写入被底层拒绝";
            return false;
        }
        const uint64_t back = km_read64(entryKva, &ok);
        if (!ok || back != 0) {
            *reasonOut = "清槽位回读不为 0";
            return false;
        }
    }

    *slotOut = 2;
    *howOut = KM_PM_SLOT_RESET;
    return true;
}

/// 把一条 PTE 写进选中的槽。写入值 = pa | 叶模板（**不是**裸 pa，见 KM_PM_PTE_LEAF 段）。
///
/// 这一步与自映射那一次写是同一条路：先 km_phystokv 把表页物理地址换成 KVA，
/// 再走受检写入（形态检查 → 写前读旧值 → 写 → 回读核对）。
static bool kpm_slot_write(uint64_t slotIndex, uint64_t pa, uint64_t *oldOut)
{
    *oldOut = 0;
    uint64_t entryOff = 0;
    uint64_t entryPa = 0;
    if (!kpm_mul(slotIndex, sizeof(uint64_t), &entryOff) ||
        !kpm_add(g_physmapMagicPT, entryOff, &entryPa)) {
        return false;
    }
    const uint64_t entryKva = km_phystokv(entryPa);
    if (!kpm_shape_ok(entryKva)) {
        return false;
    }

    bool ok = false;
    const uint64_t old = km_read64(entryKva, &ok);
    if (!ok) {
        return false;
    }
    *oldOut = old;

    const uint64_t value = pa | KM_PM_PTE_LEAF;
    if (old == value) {
        return true; /* ① 命中已有槽时就是这一支：一个字节都不写 */
    }
    if (!km_write(entryKva, &value, sizeof(value))) {
        return false;
    }
    const uint64_t back = km_read64(entryKva, &ok);
    return ok && back == value;
}

/*
 * 数据通道：读 / 写窗口地址上的 size 字节。
 *
 * 两个档位（见上面「有意偏离」第 2 条）。两档都必须**自己**做形态检查 ——
 * 理由是本文件的硬约束 1（每一条送进内核读写原语的地址使用前过形态检查），
 * 而不是依赖底座再拒一次：诊断文本要能分清"我拒了"与"底座拒了"。
 */
static bool kpm_window_data_is_uaccess(void)
{
    /*
     * 写成 #if 而不是 `return KM_PM_WINDOW_ACCESS == KM_PM_WINDOW_ACCESS_UACCESS;`：
     * 两个宏都是 0 时那句是常量比较，clang 的 -Wtautological-compare 会报
     * "self-comparison always evaluates to true"，而本工程把警告当错误看
     * （CI 上白跑一次的成本已经算过）。预处理期解决掉，编译期什么都不剩。
     */
#if KM_PM_WINDOW_ACCESS == KM_PM_WINDOW_ACCESS_UACCESS
    return true;
#else
    return false;
#endif
}

#if KM_PM_WINDOW_ACCESS == KM_PM_WINDOW_ACCESS_UACCESS
static void kpm_window_data_sync(void)
{
    /*
     * 与 Dopamine physrw_pte.c:67-69 的三句（usleep(0) / dmb sy / usleep(0)）同义：
     * 让刚写进页表的这一项对本核（以及被抢占走的上下文）可见，再取数据。
     * __sync_synchronize 就是全屏障，等价于 dmb sy。
     */
    __sync_synchronize();
}

static bool kpm_window_data_read(uint64_t ua, void *out, uint64_t len)
{
    const volatile uint8_t *src = (const volatile uint8_t *)ua;
    uint8_t *dst = (uint8_t *)out;
    for (uint64_t i = 0; i < len; i++) {
        dst[i] = src[i];
    }
    __sync_synchronize();
    return true;
}

static bool kpm_window_data_write(uint64_t ua, const void *in, uint64_t len)
{
    volatile uint8_t *dst = (volatile uint8_t *)ua;
    const uint8_t *src = (const uint8_t *)in;
    for (uint64_t i = 0; i < len; i++) {
        dst[i] = src[i];
    }
    __sync_synchronize();
    return true;
}
#else
/*
 * kmprim 档：按任务文字走 km_read / km_write。
 *
 * **这一段在本工程的现有原语下一定失败**，而且失败得**安全**：形态闸门在
 * 发第一个内核访问之前就拒掉，一个字节都不会发出。这不是"没写完"，
 * 是把"为什么不可行"钉在代码里 —— 谁把它调成默认，谁就会在诊断第一行看到原因。
 */
static void kpm_window_data_sync(void)
{
    __sync_synchronize();
}

static bool kpm_window_data_read(uint64_t ua, void *out, uint64_t len)
{
    if (!kpm_shape_ok(ua)) {
        return false;
    }
    return km_read(ua, out, len);
}

static bool kpm_window_data_write(uint64_t ua, const void *in, uint64_t len)
{
    if (!kpm_shape_ok(ua)) {
        return false;
    }
    return km_write(ua, in, len);
}
#endif

#pragma mark - 前置装载

/*
 * 把「建表要用的每一个输入」读出来。返回 km_physmap_status：
 *   KM_PM_READY 之后的步骤只有在返回 KM_PM_READY 或 KM_PM_TABLE_ALREADY 时才走。
 *
 * 诊断分区 ①-④ 在这里写；⑤ 之后的窗口探测与记账链在 kpm_probe_window /
 * kpm_report_accounting 里。
 */
static km_physmap_status kpm_load(km_pm_ctx *ctx, km_pm_text *t)
{
    memset(ctx, 0, sizeof(*ctx));

    kpm_append(t, "== ① 前置 ==\n");
    if (!km_ready()) {
        kpm_append(t, "✗ km_ready()=false：内核读写层未就绪（km_init 未成功），本次一次内核访问都不发。\n");
        return KM_PM_NOT_READY;
    }
    kpm_append(t, "✓ km_ready()=true\n");

    /* ── XPF 与 PA→KVA 换算表：**按需建立**，不要求用户先去点另一个按钮 ── */
    /*
     * 这两样要走 km_phystokv_ensure() 而不是"检查就绪就报错、让用户去点 Slide"：
     * 面板上只有一个按钮是"我这个动作"，用户不该知道实现里分成几步
     * （KernelSlide.h 的 km_phystokv_ensure 说明写了为什么换算表与 slide 分不开）。
     * ensure 内部：已就绪则空操作；否则自己 km_xpf_init + 跑完那套自检。
     *
     * 耗时说明要留在诊断里：首次可能几十秒（解析 kernelcache），
     * 面板那侧必须先把按钮切到"计算中…"，否则会被读成卡死。
     */
    if (!km_phystokv_ready()) {
        kpm_append(t, "  PA→KVA 换算表未就绪 —— 调 km_phystokv_ensure() 按需建立\n");
        kpm_append(t, "  （首次要解压解析几十 MB 的 kernelcache，几十秒是预期耗时，不是卡死）\n");
    }
    if (!km_phystokv_ensure()) {
        if (!km_xpf_ready()) {
            kpm_append(t, "✗ XPF 未就绪且这次初始化没成功：建表要的六个符号/常量全部来自它。\n");
            NSString *const xpfError = km_xpf_last_error();
            kpm_append(t, "  原因：%s\n", xpfError != nil ? xpfError.UTF8String : "(没有错误文本)");
            return KM_PM_NOT_READY;
        }
        kpm_append(t, "✗ 换算表建立失败：页表项里存的是**物理**地址，没有这条换算，\n");
        kpm_append(t, "  本模块连一次下钻都完成不了。原因见 km_slide_diagnostic()。\n");
        return KM_PM_NOT_READY;
    }
    kpm_append(t, "✓ PA→KVA 换算表可用（km_phystokv_ready()=true）\n");

    ctx->slide = km_slide_value();
    if (ctx->slide == 0) {
        kpm_append(t, "✗ slide=0：符号的运行时地址算不出来。\n");
        kpm_append(t, "  （XPF 给的 kernelSymbol.* 是**链接期**地址 —— XpfBridge.h 写明，\n");
        kpm_append(t, "   必须自己加 slide 才能 kread；见 KernelSlide.m:1073 的同口径用法。\n");
        kpm_append(t, "   本模块与「建窗」探针的区别就在这里：它只用 pmap 链路（不碰符号），\n");
        kpm_append(t, "   而建表要读 pv_head_table / vm_first_phys / cpu_ttep 三个符号。）\n");
        return KM_PM_NOT_READY;
    }
    kpm_append(t, "✓ slide=%#llx（km_slide_value()）\n", (unsigned long long)ctx->slide);

    ctx->pageSize = km_kernel_page_size();
    if (ctx->pageSize != 0x4000) {
        /*
         * 只做 16K。4K 是四级表（多一级 L0，shift 39），而本文件的几何只有三级；
         * 拿 16K 的 L1 掩码去索引 4K 的 L1 表会取到**另一张表**里的表项，然后把它
         * 当下一级表地址 —— 那不是可以赌的事。（KernelPhysWindow.m 的
         * `physwindow_walk()` 里有同一条几何判据；那里只引函数名不引行号，
         * 因为那个文件正被并行修改。）
         */
        kpm_append(t, "✗ 页大小 %#llx：本模块只实现 16K 的三级几何（4K 是四级表，多一级 L0）。\n",
                   (unsigned long long)ctx->pageSize);
        return KM_PM_NOT_READY;
    }
    uint64_t shift = 0;
    while (((uint64_t)1 << shift) < ctx->pageSize && shift < 63) {
        shift++;
    }
    if (((uint64_t)1 << shift) != ctx->pageSize) {
        kpm_append(t, "✗ 页大小 %#llx 不是 2 的幂 —— 页内掩码算不出来。\n",
                   (unsigned long long)ctx->pageSize);
        return KM_PM_NOT_READY;
    }
    ctx->pageShift = shift;
    kpm_append(t, "✓ 页大小 %#llx → page_shift=%llu（16K 三级几何）\n",
               (unsigned long long)ctx->pageSize, (unsigned long long)ctx->pageShift);

    ctx->window = km_physwindow_address();
    if (ctx->window == 0) {
        kpm_append(t, "✗ 窗口地址算不出来（km_physwindow_address()=0）。\n");
        return KM_PM_NOT_READY;
    }
    g_physmapWindow = ctx->window;

    /* ── ② XPF 键 ── */
    kpm_append(t, "== ② XPF 键（必需项缺一就中止；t1sz_boot / vm_last_phys 只作诊断）==\n");
    km_xpf_physmap_keys keys = {};
    if (!km_xpf_physmap_keys_fetch(&keys)) {
        kpm_append(t, "✗ km_xpf_physmap_keys_fetch 失败：XPF 未就绪。\n");
        return KM_PM_NOT_READY;
    }
    /*
     * 数组顺序**必须**与 XpfBridge.h 的 km_xpf_physmap_keys 字段顺序逐个对齐：
     * km_xpf_physmap_key_name(i) 按下标取名字，错位会把 A 键的结果挂在 B 键的标题
     * 下，而那种错在屏幕上看起来完全正常。结构体那一侧由 XpfBridge.m 里那组
     * offsetof 静态断言钉住；这一侧靠本注释，以及下面用 sizeof 取循环上界
     * （数组增减时循环自动跟随，不会再出现"数组 7 项、循环写 8"这种分叉）。
     */
    const km_xpf_item_result *const all[] = {
        &keys.pv_head_table, &keys.vm_first_phys, &keys.vm_last_phys, &keys.cpu_ttep,
        &keys.pt_index_max,  &keys.kernel_el,     &keys.t1sz_boot,
    };
    const int keyCount = (int)(sizeof(all) / sizeof(all[0]));
    for (int i = 0; i < keyCount; i++) {
        const km_xpf_item_result *r = all[i];
        kpm_append(t, "  [%d] %s：registered=%s fetched=%s value=%#llx\n", i,
                   km_xpf_physmap_key_name(i), r->registered ? "yes" : "no",
                   r->fetched ? "yes" : "no", (unsigned long long)r->value);
    }

    /*
     * 必需的五个（另两个 vm_last_phys / t1sz_boot 只作参考与诊断：
     * vm_last_phys 本文件确实没用它 —— 下溢检查用 vm_first_phys，上界检查留到有实测
     * 需求时再加；t1sz_boot 只用来在诊断里说明这台设备**内核侧**几何的来源，
     * 它**不参与**任何几何计算，见 ③ 段）：
     *   pv_head_table   → 物理页记账表（kernel.c:109）
     *   vm_first_phys   → 物理页索引的基准（kernel.c:104）
     *   cpu_ttep        → 内核页表根，算 sw_asid 那一页的物理地址用（translation.c:107）
     *   PT_INDEX_MAX    → pt_desc 里 va[] 数组的长度（info.c:109）
     *   kernel_el       → pmapEl2Adjust（info.c:42）
     *
     * ARM_TT_L1_INDEX_MASK 不在这里：它已经从 XpfBridge 的键集合里移除，
     * 因为它是内核侧（T1SZ）几何、而本模块要用户侧（T0SZ）几何 —— 见文件头部。
     */
    if (!keys.pv_head_table.fetched || !keys.vm_first_phys.fetched || !keys.cpu_ttep.fetched ||
        !keys.pt_index_max.fetched || !keys.kernel_el.fetched) {
        kpm_append(t, "✗ 上面标 fetched=no 的键里有必需项缺失 —— 中止（不回退成兜底常量）。\n");
        return KM_PM_KEYS_MISSING;
    }

    /* ── ③ 页表几何 ── */
    /*
     * L1 用**本文件的用户侧常量**（KM_PM_INDEX_L1），不从 XPF 取 —— 理由见文件头部：
     * ARM_TT_L1_INDEX_MASK 按 T1SZ_BOOT（内核侧 TTBR1 几何）选值，本模块建的是
     * 用户 pmap 的窗口，要的是 T0SZ 那一套。老机型上两者重合（都是 25），
     * 目标机上 T1SZ_BOOT = 17 → 分家。
     *
     * `l1Shift` 仍然**从掩码里数出来**、而不是把 KM_PM_SHIFT_L1 直接赋进
     * levels[].shift：位移与掩码是两个独立的抄写点，只留一个来源时抄错哪个都会安静
     * 生效；两个来源互相对照，任一侧抄错立刻停。所以这里的推导从"取值手段"变成
     * "自检手段"，判据见下面那两段。
     */
    kpm_append(t, "== ③ 页表几何（三级都是 16K 用户侧常量；不从 XPF 取 L1 掩码）==\n");
    const uint64_t l1IndexMask = KM_PM_INDEX_L1;
    kpm_append(t, "  L1 掩码 = %#llx（bits 38:36 共 3 位 = 用户侧 T0SZ 25：上界 2^39 ÷ "
                  "L1 块 2^36 = 8 块）\n",
               (unsigned long long)l1IndexMask);
    /*
     * T1SZ_BOOT 只打不用。它是这台设备**内核侧**几何的来源，也正是本模块不再从
     * XPF 取掩码的原因；摆在这里是为了日后一眼辨认 —— 看到 T1SZ_BOOT = 17 就应当
     * 知道 XPF 那个键会给 11 位（common.c:118），与上面这行 3 位掩码不是同一套几何。
     * 值为 0 表示这个键没取到（它是可选项，不阻断预检）。
     */
    kpm_append(t, "  kernelConstant.T1SZ_BOOT 实读 = %llu（内核侧几何，仅诊断；"
                  "任一情况下都不参与本模块的几何计算）\n",
               (unsigned long long)keys.t1sz_boot.value);

    uint64_t l1Shift = 0;
    while (l1Shift < 63 && ((l1IndexMask >> l1Shift) & 0x1ULL) == 0) {
        l1Shift++;
    }
    if (l1IndexMask == 0 || ((l1IndexMask >> l1Shift) & 0x1ULL) == 0) {
        kpm_append(t, "✗ L1 索引掩码 %#llx 解不出位移 —— 中止。\n",
                   (unsigned long long)l1IndexMask);
        /*
         * 归到 NOT_READY，**不是** KEYS_MISSING。
         *
         * 这条判据看的是源文件里那两个几何常量的自洽，与 XPF 有没有取到键无关。
         * 而 KEYS_MISSING 的摘要会显示"有必需的 XPF 键取不到" —— 那是误导：
         * 上一轮 L1 掩码翻车时，真正的原因是取错了**来源**（内核侧 T1SZ 几何），
         * 报的却是键缺失，会把人往"XPF 解析失败"的方向带。
         */
        return KM_PM_NOT_READY;
    }
    if (l1Shift != KM_PM_SHIFT_L1) {
        kpm_append(t, "✗ L1 掩码 %#llx 解出的位移是 %llu，KM_PM_SHIFT_L1 是 %llu ——\n",
                   (unsigned long long)l1IndexMask, (unsigned long long)l1Shift,
                   (unsigned long long)KM_PM_SHIFT_L1);
        kpm_append(t, "  两个抄写点不一致（源文件里的掩码与位移不是同一套几何），"
                      "中止，不挑一个继续。\n");
        return KM_PM_NOT_READY; /* 同上：常量自洽问题，不是键缺失 */
    }
    kpm_append(t, "✓ L1 shift 自检：从掩码数出 %llu，与 KM_PM_SHIFT_L1（%llu）一致\n",
               (unsigned long long)l1Shift, (unsigned long long)KM_PM_SHIFT_L1);

    ctx->levels[KM_PM_TT_L1_LEVEL] = (km_pm_tt_level){
        .offMask = KM_PM_OFFMASK_L1,
        .shift = l1Shift,
        .indexMask = l1IndexMask,
        .validMask = KM_PM_TTE_VALID,
        .typeMask = KM_PM_TTE_TYPE_MASK,
        .typeBlock = KM_PM_TTE_TYPE_BLOCK,
    };
    ctx->levels[KM_PM_TT_L2_LEVEL] = (km_pm_tt_level){
        .offMask = KM_PM_OFFMASK_L2,
        .shift = KM_PM_SHIFT_L2,
        .indexMask = KM_PM_INDEX_L2,
        .validMask = KM_PM_TTE_VALID,
        .typeMask = KM_PM_TTE_TYPE_MASK,
        .typeBlock = KM_PM_TTE_TYPE_BLOCK,
    };
    ctx->levels[KM_PM_TT_L3_LEVEL] = (km_pm_tt_level){
        .offMask = KM_PM_OFFMASK_L3,
        .shift = KM_PM_SHIFT_L3,
        .indexMask = KM_PM_INDEX_L3,
        .validMask = KM_PM_TTE_VALID,
        .typeMask = KM_PM_TTE_TYPE_MASK,
        .typeBlock = KM_PM_TTE_TYPE_L3BLOCK,
    };

    const uint64_t windowL1Index = (ctx->window & l1IndexMask) >> l1Shift;
    const uint64_t windowL2Index = (ctx->window & KM_PM_INDEX_L2) >> KM_PM_SHIFT_L2;
    const uint64_t windowL3Index = (ctx->window & KM_PM_INDEX_L3) >> KM_PM_SHIFT_L3;
    kpm_append(t, "  窗口 %#llx 的三级索引：L1=%llu（shift %llu） L2=%llu（shift %llu） L3=%llu（shift %llu）\n",
               (unsigned long long)ctx->window, (unsigned long long)windowL1Index,
               (unsigned long long)l1Shift, (unsigned long long)windowL2Index,
               (unsigned long long)KM_PM_SHIFT_L2, (unsigned long long)windowL3Index,
               (unsigned long long)KM_PM_SHIFT_L3);
    /*
     * 合法性判据（两条都不是"应该成立"，是这条算法的前提）：
     *   · L1 索引 < L1_BLOCK_COUNT：窗口是"最后一个 L1 块"，索引必须是 7（16K）。
     *     越界就说明本文件那套几何常量与窗口地址说的不是同一个地址空间。
     *   · L3 索引必须是 0：自映射写的是窗口地址那条 L3 表的**第 0 项**。
     *     L3 索引非 0 时"窗口的页表项 = 表第 0 项"就不成立，写进去的是别的项的地址
     *     —— 那是一次写错地址的内核写。
     */
    if (windowL1Index >= KM_PM_16K_L1_BLOCK_COUNT) {
        kpm_append(t, "✗ 窗口的 L1 索引 %llu ≥ L1 块数 %llu —— 几何常量与窗口地址不自洽，中止。\n",
                   (unsigned long long)windowL1Index,
                   (unsigned long long)KM_PM_16K_L1_BLOCK_COUNT);
        return KM_PM_KEYS_MISSING;
    }
    if (windowL3Index != 0) {
        kpm_append(t, "✗ 窗口的 L3 索引 %llu ≠ 0 —— 自映射写的是表第 0 项这条前提不成立，中止。\n",
                   (unsigned long long)windowL3Index);
        return KM_PM_KEYS_MISSING;
    }
    kpm_append(t, "✓ L1 索引 %llu < %llu（= L1_BLOCK_COUNT）；L3 索引 0（自映射写第 0 项的前提）\n",
               (unsigned long long)windowL1Index, (unsigned long long)KM_PM_16K_L1_BLOCK_COUNT);

    /*
     * ── 几何自洽，两条 —— 这条判据是本轮真机翻车时**唯一抓住问题的地方**，
     *    不要删、不要放宽，只能加强 ──
     *
     * 这不是"再确认一遍"，而是把一个**已经踩过两次的坑**变成可执行判据：
     * L1 索引掩码有两种写法（11 位 0x7ff000000000 / 3 位 0x7000000000），
     * 而窗口地址 0x7000000000 在**两种写法下都给出索引 7** —— 于是"用错掩码"
     * 这件事在看索引那一行时**看不出来**。掩码与块数的关系才是能分辨它的东西：
     *     (l1IndexMask >> l1Shift) + 1 必须等于 L1 块数（16K 大内存机型 = 8）
     * 11 位掩码会算出 2048，立刻中止 —— 而它一旦漏过去，遍历会在 L1 那一步
     * 索引到别的表项，把一个不属于自己的表当成下一级表。
     *
     * **不要把这条判据当成形式主义**：在窗口地址 0x7000000000 这一个点上，
     * 11 位掩码算出的索引与 3 位的**恰好相同**（用户 VA 的 bits 39..46 恒为 0，
     * 11 位掩码多覆盖的那几位在用户空间里永远是 0 —— KernelMemory.m:1212-1218
     * 记着同一件事："对用户 VA 恰好蒙对"）。所以"用错掩码"在那一点上不产生
     * 错的索引值，只有在地址往下移（用户空间更低处）时才真错。
     * 换句话说：位宽自洽判据是**唯一**能在本机上分辨这两套几何的东西；
     * 拿"索引值看起来对"去论证掩码没问题，正是这次翻车的推理。
     *
     * 真机（iPad14,3 / M2 / iPadOS 16.4.1）上就是这么停住的，而当时这一条的
     * 失败文本只说了"XPF 给的掩码不是这台机器的几何（或常量抄错了）"——
     * 方向对，但没有指向根因。根因是**语义错配**，所以下面把两条路都铺在文本里：
     *     本模块的 L1 掩码必须是**用户侧 T0SZ** 几何（上界 2^39 ÷ L1 块 2^36 = 8 块）
     *     11 位掩码则来自**内核侧 T1SZ_BOOT**（common.c:113-127 按它选值）
     * 两者在 T0SZ == T1SZ == 25 的老机型上重合、在 T1SZ_BOOT = 17 的目标机上分家。
     * 失败时一并打印 T1SZ_BOOT 的实读值：那是"这台设备内核侧几何长什么样"的
     * 唯一线索，下次看一眼就知道该往哪个方向查。
     *
     * 第二条同理：一个 L2 块覆盖多少页，必须与 Dopamine util.c:384-394 的块数一致
     * （16K：0x2000000 / 0x4000 = 2048）。把"我抄的两个数是不是同一套几何的"
     * 变成可执行检查，而不是靠人比对两行常量。
     */
    const uint64_t l1BlockCountFromMask = ((l1IndexMask >> l1Shift) + 1);
    kpm_append(t, "  自洽：掩码 %#llx >> %llu 再 +1 = %llu 个 L1 块（常量 %llu）；"
                  "L2 块 %#llx / 页 %#llx = %llu 页（常量 %llu）\n",
               (unsigned long long)l1IndexMask, (unsigned long long)l1Shift,
               (unsigned long long)l1BlockCountFromMask,
               (unsigned long long)KM_PM_16K_L1_BLOCK_COUNT,
               (unsigned long long)KM_PM_16K_L2_BLOCK_SIZE, (unsigned long long)ctx->pageSize,
               (unsigned long long)(KM_PM_16K_L2_BLOCK_SIZE / ctx->pageSize),
               (unsigned long long)KM_PM_16K_L2_BLOCK_COUNT);
    if (l1BlockCountFromMask != KM_PM_16K_L1_BLOCK_COUNT) {
        kpm_append(t, "✗ L1 掩码与 L1 块数不自洽：掩码 %#llx 推出 %llu 块，常量是 %llu ——\n",
                   (unsigned long long)l1IndexMask, (unsigned long long)l1BlockCountFromMask,
                   (unsigned long long)KM_PM_16K_L1_BLOCK_COUNT);
        kpm_append(t, "  先查掩码的**来源方向**：本模块要的是**用户侧 T0SZ** 几何 ——\n");
        kpm_append(t, "    用户地址空间上界 2^39（MACH_VM_MAX_ADDRESS）÷ L1 块 2^36 = 8 块 → "
                      "3 位 → 0x0000007000000000。\n");
        kpm_append(t, "  若掩码是 11 位 0x00007ff000000000，那属于**内核侧 T1SZ_BOOT** 几何：\n");
        kpm_append(t, "    XPF 的 kernelConstant.ARM_TT_L1_INDEX_MASK 就是按 T1SZ_BOOT 选值的"
                      "（common.c:113-127，17 → 11 位 / 25 → 3 位）。\n");
        kpm_append(t, "  本机内核侧 T1SZ_BOOT 实读 = %llu；两个语义在 T0SZ == T1SZ == 25 的\n",
                   (unsigned long long)keys.t1sz_boot.value);
        kpm_append(t, "  老机型上重合，在 T1SZ_BOOT = 17 的 ARM_LARGE_MEMORY 机型上分家 ——\n");
        kpm_append(t, "  本模块要的**始终**是前者（常量 KM_PM_INDEX_L1，与 KernelPhysWindow 的\n");
        kpm_append(t, "  KM_PW_INDEX_L1 同一取值）。也可能是 KM_PM_INDEX_L1 / KM_PM_SHIFT_L1 / "
                      "KM_PM_16K_L1_BLOCK_COUNT 三个常量之间被改坏了。中止。\n");
        return KM_PM_KEYS_MISSING;
    }
    if ((KM_PM_16K_L2_BLOCK_SIZE / ctx->pageSize) != KM_PM_16K_L2_BLOCK_COUNT) {
        kpm_append(t, "✗ L2 块 / 页大小 = %llu ≠ 常量 %llu —— 几何常量之间不自洽，中止。\n",
                   (unsigned long long)(KM_PM_16K_L2_BLOCK_SIZE / ctx->pageSize),
                   (unsigned long long)KM_PM_16K_L2_BLOCK_COUNT);
        return KM_PM_KEYS_MISSING;
    }
    kpm_append(t, "✓ 几何自洽（L1 掩码↔块数、L2 块↔页大小都一致；"
                  "T1SZ_BOOT=%llu 只作辨认，未参与计算）\n",
               (unsigned long long)keys.t1sz_boot.value);

    /*
     * 第三条：与 KernelPhysWindow 的几何**对齐检查**。
     *
     * 两个模块算的是同一个窗口地址的同一套几何（KernelPhysWindow.m 的
     * KM_PW_16K_BLOCK_SIZE / KM_PW_16K_BLOCK_COUNT 与本文件的
     * KM_PM_16K_L1_BLOCK_SIZE / KM_PM_16K_L1_BLOCK_COUNT 是同一对常量），
     * 而窗口地址是**它**算出来的（km_physwindow_address()）。于是"两处有没有分叉"
     * 这件事在这里可以判：窗口必须恰好是最后一个 L1 块的块首，即
     *     window == L1_BLOCK_SIZE × (L1_BLOCK_COUNT − 1)
     * 分叉的失败形态很明确：KernelPhysWindow 那侧若改了页大小分支或块常量
     * （例如换到 4K 的 0x3FC0000000）而本文件还是 16K，这条立刻不过；反过来
     * 本文件这几个常量被改坏也一样。这是把任务书那句"两个模块必须表达同一套几何"
     * 从注释约定变成可执行判据 —— 只靠注释约定，本轮就已经分叉过一次。
     * 判据写成乘法而不是与 0x7000000000 比较：写死就多出第三个抄写点。
     */
    uint64_t expectedWindow = 0;
    if (!kpm_mul(KM_PM_16K_L1_BLOCK_SIZE, KM_PM_16K_L1_BLOCK_COUNT - 1ULL, &expectedWindow) ||
        ctx->window != expectedWindow) {
        kpm_append(t, "✗ 窗口地址 %#llx ≠ L1_BLOCK_SIZE %#llx × (L1_BLOCK_COUNT %llu − 1) = %#llx ——\n",
                   (unsigned long long)ctx->window, (unsigned long long)KM_PM_16K_L1_BLOCK_SIZE,
                   (unsigned long long)KM_PM_16K_L1_BLOCK_COUNT,
                   (unsigned long long)expectedWindow);
        kpm_append(t, "  说明 km_physwindow_address() 给出的几何与本文件的 L1 常量不是同一套\n");
        kpm_append(t, "  （KernelPhysWindow.m 那侧的页大小分支或块常量改了）。中止，不猜窗口。\n");
        return KM_PM_NOT_READY;
    }
    kpm_append(t, "✓ 与 KernelPhysWindow 的几何对齐：窗口 %#llx = L1 块大小 %#llx × %llu"
                  "（第 %llu 个 L1 块的块首）\n",
               (unsigned long long)ctx->window, (unsigned long long)KM_PM_16K_L1_BLOCK_SIZE,
               (unsigned long long)(KM_PM_16K_L1_BLOCK_COUNT - 1ULL),
               (unsigned long long)(KM_PM_16K_L1_BLOCK_COUNT - 1ULL));

    /* ── ④ pmap 链路 ── */
    kpm_append(t, "== ④ pmap 链路（proc → task → vm_map → pmap）==\n");
    const uint64_t taskOff = km_proc_object_size();
    const uint64_t mapOff = km_task_map_offset();
    const uint64_t pmapOff = km_vm_map_pmap_offset();
    kpm_append(t, "  偏移：proc→task=%#llx · task→map=%#llx · map→pmap=%#llx\n",
               (unsigned long long)taskOff, (unsigned long long)mapOff,
               (unsigned long long)pmapOff);
    if (taskOff == 0 || mapOff == 0 || pmapOff == 0) {
        kpm_append(t, "✗ 有一个偏移是 0 —— 版本表没命中，或结构体定义被改坏。\n");
        return KM_PM_PMAP_UNRESOLVED;
    }

    ctx->proc = km_current_proc();
    if (ctx->proc == 0) {
        kpm_append(t, "✗ km_current_proc()=0：info_run 没反查到本进程 proc。\n");
        return KM_PM_PMAP_UNRESOLVED;
    }
    kpm_append(t, "  current_proc=%#llx\n", (unsigned long long)ctx->proc);

    if (!kpm_add(ctx->proc, taskOff, &ctx->task) || !kpm_shape_ok(ctx->task)) {
        kpm_append(t, "✗ proc+%#llx=%#llx 形态不过。\n", (unsigned long long)taskOff,
                   (unsigned long long)ctx->task);
        return KM_PM_PMAP_UNRESOLVED;
    }
    bool ok = false;
    const uint64_t mapRaw = km_read64(ctx->task + mapOff, &ok);
    /*
     * task->map 是 **PAC 签名的内核指针**，读出来不能直接当地址用 ——
     * 真机现场：raw=0x52bc7e10023e93c0，高 16 位 0x52bc 而形态判据要 0xFFFF，
     * 于是链路断在这里。还原必须在形态检查**之前**做（KernelSlide.m:435 的那条
     * 纪律），还原后 0xfffffe10023e93c0 才落在内核域。
     *
     * 对内核地址 km_unsign_ptr 幂等（bit 55 已置位，`| PAC_MASK` 不改动它），
     * 所以对"其实没被签名"的内核指针过一遍是无害的 —— 正因如此这里可以无条件调用，
     * 而不需要先猜这个字段有没有签名。ctx->map 写回的是**还原值**。
     */
    ctx->map = km_unsign_ptr(mapRaw);
    kpm_append(t, "  task=%#llx +%#llx → vm_map raw=%#llx → %#llx%s\n",
               (unsigned long long)ctx->task, (unsigned long long)mapOff,
               (unsigned long long)mapRaw, (unsigned long long)ctx->map,
               ok ? "" : "  ← 读失败（两次不一致）");
    if (!ok || ctx->map == 0) {
        return KM_PM_PMAP_UNRESOLVED;
    }
    if (!kpm_shape_ok(ctx->map)) {
        kpm_append(t, "✗ vm_map=%#llx（raw=%#llx）还原 PAC 后形态仍不过 —— 中止。\n",
                   (unsigned long long)ctx->map, (unsigned long long)mapRaw);
        return KM_PM_PMAP_UNRESOLVED;
    }

    uint64_t mapPmapAddr = 0;
    if (!kpm_add(ctx->map, pmapOff, &mapPmapAddr) || !kpm_shape_ok(mapPmapAddr)) {
        kpm_append(t, "✗ vm_map+%#llx=%#llx 形态不过。\n", (unsigned long long)pmapOff,
                   (unsigned long long)mapPmapAddr);
        return KM_PM_PMAP_UNRESOLVED;
    }
    const uint64_t pmapRaw = km_read64(mapPmapAddr, &ok);
    /* vm_map->pmap 与 task->map 同类：内核结构里的签名指针字段，还原口径完全一致。 */
    ctx->pmap = km_unsign_ptr(pmapRaw);
    kpm_append(t, "  vm_map=%#llx +%#llx → pmap raw=%#llx → %#llx%s\n",
               (unsigned long long)ctx->map, (unsigned long long)pmapOff,
               (unsigned long long)pmapRaw, (unsigned long long)ctx->pmap,
               ok ? "" : "  ← 读失败（两次不一致）");
    if (!ok || ctx->pmap == 0 || !kpm_shape_ok(ctx->pmap)) {
        return KM_PM_PMAP_UNRESOLVED;
    }

    /*
     * pmap->tte 与 pmap->ttep **都不还原 PAC**，判定依据是这两个字段存的东西：
     *   · ttep 是顶层表的**物理地址**（下面那条 `& 0xf000000000000000` 判据就是在
     *     核这件事），PA 没有签名，还原只会把高 16 位污染成 0xFFFF；
     *   · tte 是同一张表的内核**虚拟别名**（下面用来与 km_phystokv(ttep) 交叉核对）。
     *     上游 Dopamine 的 info.h:151 只对 read `pmap` 字段那一次做 UNSIGN_PTR，
     *     拿到 pmap 之后读它的 mmu 结构字段（tte/ttep）一次都没还原 ——
     *     mmu 结构由内核自己初始化、存的是裸地址，不是签名指针字段。
     */
    const uint64_t tte = km_read64(ctx->pmap + KM_PM_PMAP_OFF_TTE, &ok);
    const bool tteOk = ok;
    ctx->ttep = km_read64(ctx->pmap + KM_PM_PMAP_OFF_TTEP, &ok);
    kpm_append(t, "  pmap->tte =%#llx%s\n", (unsigned long long)tte, tteOk ? "" : "  ← 读失败");
    kpm_append(t, "  pmap->ttep=%#llx%s   ← 遍历起点（PA，physrw_pte.c:122 同构）\n",
               (unsigned long long)ctx->ttep, ok ? "" : "  ← 读失败");
    if (!ok || ctx->ttep == 0) {
        return KM_PM_PMAP_UNRESOLVED;
    }
    if ((ctx->ttep & 0xf000000000000000ULL) != 0) {
        kpm_append(t, "✗ ttep 高位非 0 —— 它不是物理地址，物理路径的遍历不成立。\n");
        return KM_PM_PMAP_UNRESOLVED;
    }
    /*
     * 交叉核对：tte 是同一张表的内核虚拟别名。两者若一致（tte − ttep ==
     * km_phystokv(ttep) − ttep）说明换算表与 pmap 说的是同一件事。
     * **不相等不代表谁错** —— 来源完全不同，相等是佐证、不相等只是没有额外证据。
     * 刻意不把任何一个值写回全局或当基准：KernelMemory.m 的 g_linear_delta 那次
     * 彩屏就是"把 tte − ttep 当基准"（KernelMemory.m:176-205 的完整推导）。
     */
    const uint64_t kvFromTable = km_phystokv(ctx->ttep);
    kpm_append(t, "  参考：tte − ttep = %#llx；km_phystokv(ttep) = %#llx%s\n",
               (unsigned long long)(tte - ctx->ttep), (unsigned long long)kvFromTable,
               (kvFromTable == tte) ? "  （一致 ⇒ 换算表与 pmap 指着同一张表）"
                                    : "  （不一致 ⇒ 只说明来源不同，都不作基准）");

    /* ── 符号内容（+slide 之后 kread）── */
    kpm_append(t, "== ⑤ 符号内容（链接期地址 + slide 之后读出来）==\n");
    ctx->pvHeadTable = keys.pv_head_table.value + ctx->slide;
    ctx->vmFirstPhysSymbol = keys.vm_first_phys.value + ctx->slide;
    ctx->cpuTtepSymbol = keys.cpu_ttep.value + ctx->slide;
    ctx->ptIndexMax = keys.pt_index_max.value;

    if (!kpm_shape_ok(ctx->pvHeadTable) || !kpm_shape_ok(ctx->vmFirstPhysSymbol) ||
        !kpm_shape_ok(ctx->cpuTtepSymbol)) {
        kpm_append(t, "✗ 符号运行时地址形态不过（slide 可能不对）：pv_head_table=%#llx "
                      "vm_first_phys=%#llx cpu_ttep=%#llx\n",
                   (unsigned long long)ctx->pvHeadTable,
                   (unsigned long long)ctx->vmFirstPhysSymbol,
                   (unsigned long long)ctx->cpuTtepSymbol);
        return KM_PM_KEYS_MISSING;
    }
    kpm_append(t, "  pv_head_table  = %#llx（链接期 %#llx + slide）\n",
               (unsigned long long)ctx->pvHeadTable,
               (unsigned long long)keys.pv_head_table.value);
    kpm_append(t, "  vm_first_phys  = %#llx（链接期 %#llx + slide）\n",
               (unsigned long long)ctx->vmFirstPhysSymbol,
               (unsigned long long)keys.vm_first_phys.value);
    kpm_append(t, "  cpu_ttep       = %#llx（链接期 %#llx + slide）\n",
               (unsigned long long)ctx->cpuTtepSymbol,
               (unsigned long long)keys.cpu_ttep.value);

    /*
     * 三处 kread 逐字对照 Dopamine：
     *   kernel.c:109  pai_to_pvh 里 kread64(ksymbol(pv_head_table)) → 表的基址
     *   kernel.c:104  pa_index 里   kread64(ksymbol(vm_first_phys)) → 物理基址
     *   info.c:289    cpuTTEP =     kread64(ksymbol(cpu_ttep))       → TTBR1 的值
     *
     * 这三处**都不还原 PAC**，依据与那几个指针字段正相反：读的是**符号的内容**，
     * 也就是内核在数据段里放的一个裸值。其中两处还有可执行的旁证 ——
     * pv_head_table 的内容会被当内核地址用（下面 shape 判据要它落内核域），
     * vm_first_phys / cpu_ttep 的内容会被下面判据要求"高位为 0 的物理地址"。
     * 对这三者做 km_unsign_ptr 会把 bits 47..63 全置 1，后两条判据当场就会不过 ——
     * 也就是说"加了反而立刻失败"，不是"加了更保险"。
     * 上游依据：Dopamine 这三处全是裸 kread64(ksymbol(...))，一次 UNSIGN_PTR 都没有。
     */
    ctx->pvHeadTableValue = km_read64(ctx->pvHeadTable, &ok);
    kpm_append(t, "  · pv_head_table 内容 = %#llx%s\n", (unsigned long long)ctx->pvHeadTableValue,
               ok ? "" : "  ← 读失败");
    if (!ok || !kpm_shape_ok(ctx->pvHeadTableValue)) {
        kpm_append(t, "✗ pv_head_table 内容不是内核地址 —— 中止。\n");
        return KM_PM_KEYS_MISSING;
    }

    ctx->vmFirstPhysValue = km_read64(ctx->vmFirstPhysSymbol, &ok);
    kpm_append(t, "  · vm_first_phys 内容 = %#llx%s\n", (unsigned long long)ctx->vmFirstPhysValue,
               ok ? "" : "  ← 读失败");
    if (!ok || ctx->vmFirstPhysValue >= (1ULL << 48)) {
        kpm_append(t, "✗ vm_first_phys 内容不像物理地址（≥ 2^48）—— 中止。\n");
        return KM_PM_KEYS_MISSING;
    }

    ctx->cpuTtep = km_read64(ctx->cpuTtepSymbol, &ok);
    kpm_append(t, "  · cpu_ttep 内容（TTBR1 的值）= %#llx%s\n", (unsigned long long)ctx->cpuTtep,
               ok ? "" : "  ← 读失败");
    if (!ok || ctx->cpuTtep == 0) {
        kpm_append(t, "✗ cpu_ttep 读不出来 —— sw_asid 那一页的物理地址算不出来（可选步骤）。\n");
        ctx->cpuTtep = 0;
    } else if ((ctx->cpuTtep & 0xf000000000000000ULL) != 0) {
        kpm_append(t, "✗ cpu_ttep 内容高位非 0 —— 它不是页表根的物理地址，遍历不成立。\n");
        ctx->cpuTtep = 0;
    } else {
        kpm_append(t, "✓ cpu_ttep 是物理地址，可用作内核页表遍历的起点。\n");
    }

    /* ── pmap 布局（arm64e 支）+ 记账链偏移 ── */
    kpm_append(t, "== ⑥ pmap / pt_desc 布局（arm64e 支，见头文件「没能确证的部分」）==\n");
    const uint64_t elAdjust = (keys.kernel_el.value == 2) ? KM_PM_PMAP_EL2_ADJUST : 0;
    ctx->swAsidOff = KM_PM_PMAP_OFF_SW_ASID_ARM64E + elAdjust;
    ctx->wxAllowedOff = KM_PM_PMAP_OFF_WX_ALLOWED_ARM64E + elAdjust;
    ctx->typeOff = KM_PM_PMAP_OFF_TYPE_ARM64E + elAdjust;

    /*
     * PT_INDEX_MAX 的范围判据必须在**用它算偏移之前**（这是复查时改过来的顺序）：
     * 它来自 XPF 的一次计数（common.c:129-176 数 str 指令直到 RET），返回的是一个
     * 计数器而不是经过形态检查的地址。一个垃圾值乘 8 就是溢出，而溢出出来的偏移
     * 会指向 pmap 对象**外面**的内存 —— 后面每一次 kread/kwrite 都会打在别的东西上。
     * 判据放在前面，崩溃面就只在下游而不是在这里。
     */
    if (ctx->ptIndexMax == 0 || ctx->ptIndexMax > 64) {
        kpm_append(t, "✗ PT_INDEX_MAX=%llu 不在合理范围（1..64）—— ptd_info 偏移不可信，中止。\n",
                   (unsigned long long)ctx->ptIndexMax);
        return KM_PM_KEYS_MISSING;
    }
    ctx->ptDescOffPtdInfo = KM_PM_PT_DESC_OFF_VA + (ctx->ptIndexMax * sizeof(uint64_t));

    kpm_append(t, "  kernelConstant.kernel_el 实读 = %llu → pmapEl2Adjust = %#llx\n",
               (unsigned long long)keys.kernel_el.value, (unsigned long long)elAdjust);
    kpm_append(t, "  ⇒ sw_asid=%#llx  wx_allowed=%#llx  type=%#llx（info.c:86-88 的 arm64e 支）\n",
               (unsigned long long)ctx->swAsidOff, (unsigned long long)ctx->wxAllowedOff,
               (unsigned long long)ctx->typeOff);
    kpm_append(t, "  pt_desc.pmap=%#llx  pt_desc.va=%#llx  PT_INDEX_MAX=%llu → ptd_info=%#llx"
                  "（info.c:107-109）\n",
               (unsigned long long)KM_PM_PT_DESC_OFF_PMAP, (unsigned long long)KM_PM_PT_DESC_OFF_VA,
               (unsigned long long)ctx->ptIndexMax, (unsigned long long)ctx->ptDescOffPtdInfo);
    return KM_PM_READY;
}

#pragma mark - 窗口探测与记账链诊断

/// 对窗口地址逐级下行，把级号 / 断点表项地址 / 旧值 / 结论留下来。
static void kpm_probe_window(km_pm_ctx *ctx, km_pm_text *t)
{
    kpm_append(t, "== ⑦ 窗口地址上的页表（对 va 逐级算索引，不是从块基址走）==\n");
    kpm_append(t, "  窗口 = %#llx = L1_BLOCK_SIZE %#llx × (L1_BLOCK_COUNT %llu − 1)\n",
               (unsigned long long)ctx->window, (unsigned long long)KM_PM_16K_L1_BLOCK_SIZE,
               (unsigned long long)KM_PM_16K_L1_BLOCK_COUNT);

    uint64_t level = KM_PM_TT_L3_LEVEL;
    uint64_t leafAddr = 0;
    km_pm_vt_err err = KM_PM_E_NONE;
    ctx->windowWalkPa = kpm_vtophys_lvl(ctx, ctx->ttep, ctx->window, &level, &leafAddr, &err);
    ctx->windowLeafLevel = level;
    ctx->windowLeafAddr = leafAddr;
    ctx->windowWalkErr = err;

    const char *errName = "none";
    switch (err) {
    case KM_PM_E_NONE: errName = "none"; break;
    case KM_PM_E_LEVEL: errName = "level-overflow"; break;
    case KM_PM_E_INVALID: errName = "invalid（这一级还没有表）"; break;
    case KM_PM_E_PATH: errName = "path"; break;
    case KM_PM_E_PHYS2VIRT: errName = "phys2virt-failed"; break;
    case KM_PM_E_SHAPE: errName = "shape-bad"; break;
    case KM_PM_E_READ: errName = "read-failed"; break;
    }

    static const char *const levelNames[4] = { "L0", "L1", "L2", "L3" };
    kpm_append(t, "  下钻结果：停在 %s（%llu） · 断点表项自身 PA=%#llx · 返回=%#llx · 状态=%s\n",
               levelNames[level & 0x3], (unsigned long long)level,
               (unsigned long long)leafAddr, (unsigned long long)ctx->windowWalkPa, errName);

    /*
     * 读那个表项的旧值。这一步既是诊断（"现在是什么"），也是**写入路径的第一步**
     * （硬约束 3 的"写前读旧值"）—— 所以它在预检里也要发生。
     */
    ctx->windowLeafEntry = 0;
    if (err == KM_PM_E_NONE || err == KM_PM_E_INVALID) {
        const uint64_t kva = km_phystokv(leafAddr);
        if (kva == 0 || !kpm_shape_ok(kva)) {
            kpm_append(t, "  ✗ 表项自身 PA=%#llx 换算不出可用的 KVA（km_phystokv→%#llx）\n",
                       (unsigned long long)leafAddr, (unsigned long long)kva);
        } else {
            bool ok = false;
            const uint64_t rawLeafEntry = km_read64(kva, &ok);
            /* 同上：页表项不是指针字段，不做 PAC 还原；raw 与解释值一起打出来只为诊断。 */
            ctx->windowLeafEntry = rawLeafEntry;
            kpm_append(t, "  表项旧值：PA=%#llx → KVA=%#llx → raw=%#llx → %#llx%s\n",
                       (unsigned long long)leafAddr, (unsigned long long)kva,
                       (unsigned long long)rawLeafEntry,
                       (unsigned long long)ctx->windowLeafEntry,
                       ok ? "" : "  ← 读失败（两次不一致）");
        }
    }

    ctx->windowHasL3 = (err == KM_PM_E_NONE && level == KM_PM_TT_L3_LEVEL);

    /*
     * 结论分档。**"有 L3 表"与"没有"是两件事，而"撞上大页"是第三件** ——
     * 撞上大页时既不需要建表（那一段本来就有映射），也不能按样本那条路写 PTE
     * （没有独立的 L3 表项可写）。把三者混成 bool 会让面板只能给出一句含糊的话。
     */
    if (ctx->windowHasL3) {
        kpm_append(t, "  ⇒ 窗口地址上**已经有 L3 表项**（表项值 %#llx）—— 建表这一步已经完成过。\n",
                   (unsigned long long)ctx->windowLeafEntry);
    } else if (err == KM_PM_E_INVALID) {
        kpm_append(t, "  ⇒ 页表在 %s 就断了（表项 %#llx）—— **需要建表**，这正是本模块要做的。\n",
                   levelNames[level & 0x3], (unsigned long long)ctx->windowLeafEntry);
    } else if (err == KM_PM_E_NONE && level < KM_PM_TT_L3_LEVEL && ctx->windowWalkPa != 0) {
        kpm_append(t, "  ⇒ %s 上是块描述符（大页）：没有独立的 L3 表项可写，本模块的算法不适用。\n",
                   levelNames[level & 0x3]);
    }
}

/// 窗口地址上**是不是已经写好了自映射**。是则把表页 PA 写进 *outTablePa。
///
/// 判据：窗口的 L3 第 0 项必须等于「L2 表项指向的那张 L3 表页的 PA | 叶模板」——
/// 也就是它确实指向表页自己。左边来自 `kpm_probe_window` 读到的表项旧值，
/// 右边来自一次沿 L2 停下的遍历（`vtophys_lvl` 在 L2 停下时返回的就是那张表页的 PA）。
///
/// 为什么不能用"窗口上有 L3 表项"当判据：那一项完全可能是别的值（手工建表被
/// 打断、或别的实现留下的）。**只读**：一次遍历 + 一次比较，不写任何东西。
static bool kpm_window_is_selfmapped(const km_pm_ctx *ctx, uint64_t *outTablePa)
{
    if (outTablePa) {
        *outTablePa = 0;
    }
    if (!ctx->windowHasL3) {
        return false;
    }

    uint64_t level = KM_PM_TT_L2_LEVEL;
    uint64_t leafAddr = 0;
    km_pm_vt_err err = KM_PM_E_NONE;
    const uint64_t tablePa =
        kpm_vtophys_lvl(ctx, ctx->ttep, ctx->window, &level, &leafAddr, &err);
    if (tablePa == 0 || err != KM_PM_E_NONE) {
        return false;
    }
    if (outTablePa) {
        *outTablePa = tablePa;
    }
    return ctx->windowLeafEntry == (tablePa | KM_PM_PTE_LEAF);
}

/// 记账链诊断：把「新页表页 PA 是怎么来的、现在有没有」说清楚。
static void kpm_report_accounting(const km_pm_ctx *ctx, km_pm_text *t)
{
    kpm_append(t, "== ⑧ 物理页记账链（kernel.c:102-115）==\n");
    kpm_append(t, "  vm_first_phys 内容 = %#llx（物理基址）\n",
               (unsigned long long)ctx->vmFirstPhysValue);
    kpm_append(t, "  pv_head_table 基址 = %#llx（每项 8 字节，下标 = 物理页号）\n",
               (unsigned long long)ctx->pvHeadTableValue);
    kpm_append(t, "  pa_index(pa) = (pa − vm_first_phys) >> %llu\n",
               (unsigned long long)ctx->pageShift);
    kpm_append(t, "  pt_desc 布局：pmap@+%#llx va@+%#llx ptd_info@+%#llx\n",
               (unsigned long long)KM_PM_PT_DESC_OFF_PMAP,
               (unsigned long long)KM_PM_PT_DESC_OFF_VA,
               (unsigned long long)ctx->ptDescOffPtdInfo);
    kpm_append(t, "  分配公式：posix_memalign(%#llx 对齐, %#llx) → 触碰一页 → vtophys_lvl(只到 L2)\n",
               (unsigned long long)KM_PM_ALLOC_SPAN, (unsigned long long)KM_PM_ALLOC_SPAN);
    kpm_append(t, "  ⇒ **新页表页的 PA 此刻还不存在**：预检是只读的，不会去分配；\n");
    kpm_append(t, "    它由执行阶段现场取得（util.c:132-222）。这里能核对的只是它的全部输入。\n");
    if (g_physmapMagicPT != 0) {
        kpm_append(t, "  （上一次执行建出的 magicPT = %#llx）\n", (unsigned long long)g_physmapMagicPT);
    }
}

/// 窗口槽位那一节的诊断（自映射状态 / 数量上限 / 档位 / 最近的槽位决策）。
///
/// 它同时被两条路用：
///   · km_physmap_precheck() / km_physmap_build() 的结论文本（当次跑完就能看到）；
///   · km_physmap_window_diag() 的近期动作记录（acquire 只往这里写）。
///
/// **全是只读**：它读的是模块自己的状态（g_physmapMagicPT / 轨迹环），
/// 一次内核访问都不发 —— 所以它可以在任何一次预检/执行里无条件调用。
static void kpm_report_window_slots(km_pm_text *t)
{
    kpm_append(t, "== ⑩ 窗口槽位（物理页 → 用户态窗口的数据通路）==\n");
    if (g_physmapMagicPT == 0) {
        kpm_append(t, "✗ 自映射未就绪（magicPT = 0）：km_physmap_acquire_window() 会直接返回 false，\n");
        kpm_append(t, "  且**一次内核写都不发**（硬约束 1 的前置检查）。先跑 km_physmap_build()。\n");
    } else {
        kpm_append(t, "✓ 自映射已就绪：magicPT（表页**物理**地址）= %#llx\n",
                   (unsigned long long)g_physmapMagicPT);
    }

    const uint64_t window = km_physmap_window_address();
    kpm_append(t, "  窗口基址 = %#llx（km_physmap_window_address()）\n", (unsigned long long)window);
    kpm_append(t, "  槽位下标 2 .. %llu（共 %llu 项；0 = 自映射项、1 = sw_asid 页映射，\n",
               (unsigned long long)(KM_PM_WINDOW_SLOT_COUNT - 1ULL),
               (unsigned long long)KM_PM_WINDOW_SLOT_COUNT);
    kpm_append(t, "    2 与 3 是保守保留的余量 —— acquire 一律不碰下标 < %u 的槽）\n",
               KM_PM_WINDOW_SLOT_RESERVED);
    kpm_append(t, "  页大小 = %#llx；槽位数 × 页大小 = %#llx = 一个 L2 块（编译期 _Static_assert 已钉住）\n",
               (unsigned long long)0x4000ULL,
               (unsigned long long)(KM_PM_WINDOW_SLOT_COUNT * 0x4000ULL));

    /*
     * 数据通道那一档必须显式打出来，而且要打**为什么**。
     * 它的选择直接决定"这段代码在真机上通不通"，所以它不是一个实现细节，
     * 是一条要让人一眼看到的事实。完整说明在 .m 的「窗口槽位」段头。
     */
#if KM_PM_WINDOW_ACCESS == KM_PM_WINDOW_ACCESS_UACCESS
    kpm_append(t, "  数据通道档位 = uaccess（默认）：槽位**数据**的读写走用户态直访窗口。\n");
    kpm_append(t, "    理由：km_read / km_read64 / km_write 三者都先过 km_is_kernel_address()\n");
    kpm_append(t, "    （KernelMemory.m:241-244，判据 addr>>48 == 0xFFFF），而窗口地址在用户地址空间\n");
    kpm_append(t, "    （高 16 位全 0）—— 走内核原语一定被拒；本模块的 kpm_shape_ok() 与它同口径，\n");
    kpm_append(t, "    也一样拒。槽位**页表项本身**的写入仍走内核原语（它在页表页里，是内核地址）。\n");
#else
    kpm_append(t, "  ⚠ 数据通道档位 = kmprim：槽位数据的读写走 km_read / km_write。\n");
    kpm_append(t, "    **本工程现有原语下这条路一定失败**：窗口地址高 16 位为 0，形态闸门\n");
    kpm_append(t, "    在发出任何内核访问之前就拒掉（因此不会有任何内核副作用）。\n");
#endif

    kpm_append(t, "  最近 %d 次槽位决策（环形，最多 %d 条）：\n", g_physmapSlotTraceCount,
               KM_PM_SLOT_TRACE_MAX);
    if (g_physmapSlotTraceCount == 0) {
        kpm_append(t, "    （还没有 acquire 过）\n");
    }
    for (int i = 0; i < g_physmapSlotTraceCount; i++) {
        const km_pm_slot_trace *e = kpm_slot_trace_at(i);
        if (e == NULL) {
            continue;
        }
        kpm_append(t, "    [%d] pa=%#llx → slot=%u（%s）→ ua=%#llx\n", i,
                   (unsigned long long)e->pa, (unsigned)e->slot,
                   kpm_slot_decision_name(e->how), (unsigned long long)e->ua);
    }
}

/// pmap 布局的三条佐证。返回 true 表示"可以按 arm64e 支继续"。
///
/// 为什么需要它：sw_asid / type / wx_allowed 三个偏移是硬编码的（头文件写明未确证）。
/// 佐证用的是**语义上必须成立**的三件事，而不是"读出来不为 0"这类弱判据：
///   ① kernel_el 取到了（它是偏移公式的输入，取不到就无从谈起）；
///   ② pmap->type 读出来是 PMAP_TYPE_USER(0) —— Dopamine util.c:283-289 把 type
///      当"是不是 nested"的开关用（设 3 再设回 0），用户进程的 pmap 必须是 0；
///   ③ wx_allowed 是一个 bool（低字节只能是 0 或 1）—— 读出来别的值说明偏移落在了
///      一个非布尔字段中间。
/// 三条全过也**不等于**确证（0 与 1 都可能碰巧），所以诊断里把实读值原样打出来，
/// 让人自己看。任一条不过就跳过这一步 —— 它只服务于 Dopamine 的 flush_tlb()，
/// 而 Aether 没有 flush_tlb。
static bool kpm_verify_pmap_layout(const km_pm_ctx *ctx, km_pm_text *t)
{
    kpm_append(t, "== ⑨ sw_asid 那一步的前置佐证（三条全过才执行）==\n");

    if (ctx->cpuTtep == 0) {
        kpm_append(t, "✗ cpu_ttep 不可用：算不出 sw_asid 那一页的物理地址。\n");
        return false;
    }
    kpm_append(t, "✓ ① cpu_ttep 可用（TTBR1 的值 %#llx，可作内核页表遍历起点）\n",
               (unsigned long long)ctx->cpuTtep);

    bool ok = false;
    const uint64_t typeAddr = ctx->pmap + ctx->typeOff;
    if (!kpm_shape_ok(typeAddr)) {
        kpm_append(t, "✗ ② pmap->type 地址 %#llx 形态不过。\n", (unsigned long long)typeAddr);
        return false;
    }
    const uint64_t typeWord = km_read64(typeAddr, &ok);
    const uint8_t typeValue = (uint8_t)(typeWord & 0xFFULL);
    kpm_append(t, "  ② pmap+%#llx 读出的字节 = %#x（期望 PMAP_TYPE_USER=0）\n",
               (unsigned long long)ctx->typeOff, (unsigned)typeValue);
    if (!ok || typeValue != KM_PM_PMAP_TYPE_USER) {
        kpm_append(t, "✗ ② 不符：type 偏移在这一台上不是我们假设的那个位置 —— 跳过这一步。\n");
        return false;
    }

    const uint64_t wxAddr = ctx->pmap + ctx->wxAllowedOff;
    if (!kpm_shape_ok(wxAddr)) {
        kpm_append(t, "✗ ③ pmap->wx_allowed 地址 %#llx 形态不过。\n", (unsigned long long)wxAddr);
        return false;
    }
    /*
     * ②③ 两处读的是 pmap 里的**标量字段**（type / wx_allowed 的字节），不还原 PAC：
     * 判据只看低 8 位（`& 0xFF`），而这里关心的正是"偏移有没有落在那个字段上"。
     * 过一遍 km_unsign_ptr 只会改动 bits 47..63 —— 那几位与判据无关，加它除了
     * 掩盖问题没有任何作用。
     */
    const uint64_t wxWord = km_read64(wxAddr, &ok);
    const uint8_t wxValue = (uint8_t)(wxWord & 0xFFULL);
    kpm_append(t, "  ③ pmap+%#llx 读出的字节 = %#x（bool，期望 0 或 1）\n",
               (unsigned long long)ctx->wxAllowedOff, (unsigned)wxValue);
    if (!ok || wxValue > 1) {
        kpm_append(t, "✗ ③ 不符：wx_allowed 偏移不像一个 bool 字段 —— 跳过这一步。\n");
        return false;
    }

    kpm_append(t, "⇒ 三条佐证都过：按 arm64e 支的偏移继续（sw_asid=%#llx）。\n",
               (unsigned long long)ctx->swAsidOff);
    kpm_append(t, "  （说明：这一步只服务于 Dopamine 的 flush_tlb()；Aether 目前没有 flush_tlb，\n");
    kpm_append(t, "   跳过它的代价只是窗口里少一条 sw_asid 页的映射，不影响建表与自映射。）\n");
    return true;
}

#pragma mark - 建表

/// 页表页分配的结果。
typedef enum {
    KM_PM_ALLOC_OK = 0,
    KM_PM_ALLOC_MEMALIGN_FAILED,
    KM_PM_ALLOC_WALK_FAILED,
    KM_PM_ALLOC_ACCOUNTING_FAILED,
    KM_PM_ALLOC_REFCOUNT_BUSY,
    KM_PM_ALLOC_WRITE_FAILED
} km_pm_alloc_result;

/*
 * alloc_page_table_unassigned —— 逐行对照 Dopamine util.c:132-222。
 *
 * 它要解决的问题：**怎么从内核手里弄到一张"没有主人"的 L3 页表页**。
 * 内核只为它自己的映射建表，所以办法是"自己制造一个映射、把它下面那张表骗过来"：
 *   ① 分配一个 L2 块大小的用户地址范围（起始按 L2 块对齐）—— 这样那张 L3 表
 *      只服务我们这一段映射，可以假定归我们独占（util.c:142 的注释）；
 *   ② 触碰一页，逼内核为它建出页表；
 *   ③ 用页表遍历找到刚建的那张 L3 表（只走到 L2 就返回，见下面）；
 *   ④ 顺着物理页记账链找到这张表的 pt_desc，把它的引用计数抬到 0x1337；
 *   ⑤ free() 掉那段用户地址 —— 引用计数不为 0，内核不会释放那张表，它就此"泄漏"成无主表；
 *   ⑥ 把原来指向它的那个 L2 表项清 0，正式解除它与原地址的关联；
 *   ⑦ 引用计数归 0（我们的新表项不进 pmap 记账，所以这张表自身必须是 0）。
 *
 * 四处物理读写（Dopamine 的注释逐条说明了为什么）：⑤ 之后的行为全部依赖 ④ 的
 * 引用计数——顺序不能换。
 */
static km_pm_alloc_result kpm_alloc_page_table_unassigned(km_pm_ctx *ctx, km_pm_text *t,
                                                          uint64_t *outPa)
{
    for (int attempt = 0; attempt < KM_PM_ALLOC_ATTEMPTS; attempt++) {
        void *freeLvl2 = NULL;

        /* util.c:143 */
        if (posix_memalign(&freeLvl2, (size_t)KM_PM_ALLOC_SPAN, (size_t)KM_PM_ALLOC_SPAN) != 0) {
            kpm_append(t, "  ✗ posix_memalign(%#llx) 失败\n", (unsigned long long)KM_PM_ALLOC_SPAN);
            return KM_PM_ALLOC_MEMALIGN_FAILED;
        }

        /* util.c:148 —— 触碰一页。volatile 保证这次访问真的发生（编译器不许省掉它）。 */
        *(volatile uint64_t *)freeLvl2;

        /*
         * util.c:151-152 —— **只走到 L2**。
         *
         * 这一点是整套算法的关键：LEAF_LEVEL 传 PMAP_TT_L2_LEVEL，于是 vtophys_lvl
         * 在 L2 就停下并返回"最后一级表的地址"（translation.c:94-96），也就是
         * L2 表项指向的**那张 L3 表的 PA**；同时 `tte_lvl2` 拿到的是
         * **指向它的那个 L2 表项自身的 PA**（下面第 ⑥ 步要清的就是它）。
         */
        uint64_t lvl = KM_PM_TT_L2_LEVEL;
        uint64_t tteLvl2 = 0;
        km_pm_vt_err err = KM_PM_E_NONE;
        const uint64_t allocatedPt =
            kpm_vtophys_lvl(ctx, ctx->ttep, (uint64_t)freeLvl2, &lvl, &tteLvl2, &err);
        if (allocatedPt == 0 || err != KM_PM_E_NONE) {
            kpm_append(t, "  ✗ 找不到刚分配的页表（va=%#llx 设备=%#llx err=%d）\n",
                       (unsigned long long)(uint64_t)freeLvl2, (unsigned long long)allocatedPt,
                       (int)err);
            free(freeLvl2);
            return KM_PM_ALLOC_WALK_FAILED;
        }

        /* ── 记账链：allocatedPt → pai → pvh → ptdp → pinfo ── */
        if (allocatedPt < ctx->vmFirstPhysValue) {
            kpm_append(t, "  ✗ 新表 PA %#llx < vm_first_phys %#llx —— 减法会下溢（kernel.c:104）\n",
                       (unsigned long long)allocatedPt,
                       (unsigned long long)ctx->vmFirstPhysValue);
            free(freeLvl2);
            return KM_PM_ALLOC_ACCOUNTING_FAILED;
        }
        const uint64_t pai = kpm_pa_index(ctx, allocatedPt);
        const uint64_t pvh = kpm_pai_to_pvh(ctx, pai);
        if (pvh == 0 || !kpm_shape_ok(pvh)) {
            kpm_append(t, "  ✗ pvh 地址 %#llx 形态不过（pai=%llu）\n", (unsigned long long)pvh,
                       (unsigned long long)pai);
            free(freeLvl2);
            return KM_PM_ALLOC_ACCOUNTING_FAILED;
        }

        bool ok = false;
        /*
         * pvh 表项**不还原 PAC**。它不是一个指针字段，而是 `类型(低 2 位) | 描述符地址`
         * 的打包值（kpm_pvh_ptd 做 `entry & ~3 | HIGH_FLAGS`，见下面那条类型判据）。
         * 对它做 km_unsign_ptr 有两种坏法，都不是理论上的：
         *   · 取 `| PAC_MASK` 支 → 类型位虽在低 2 位不受影响，但地址字段的高位被污染；
         *   · 取 `& PTR_MASK` 支 → 直接清掉描述符地址的高位。
         * 上游 Dopamine kernel.c:109-115 的 pai_to_pvh / pvh_ptd 全程裸读 + 掩码，
         * 一次 UNSIGN_PTR 都没有。
         */
        const uint64_t pvhEntry = km_read64(pvh, &ok);
        if (!ok) {
            kpm_append(t, "  ✗ pvh 表项 %#llx 读失败\n", (unsigned long long)pvh);
            free(freeLvl2);
            return KM_PM_ALLOC_ACCOUNTING_FAILED;
        }

        /*
         * **类型判据（本工程加的，Dopamine 没有）**：pvh 表项低 2 位是类型，
         * 页表描述符必须是 PVH_TYPE_PTDP(3)（pvh.h:19-22）。
         *
         * 为什么非加不可：kpm_pvh_ptd() 做的是 `entry & ~3 | HIGH_FLAGS`。
         * 如果这一项其实是 PVH_TYPE_NULL(0)，那么 entry 往往就是 0，
         * 于是算出来的 ptdp 等于 PVH_HIGH_FLAGS —— 一个**形态合法**的内核地址，
         * 后面的 kread 会直接打在内核空洞上。这正是"0 会被拦下、错值不会"的
         * 同一个形态（KernelMemory.m:196-200）。
         */
        const uint64_t pvhType = pvhEntry & KM_PM_PVH_TYPE_MASK;
        kpm_append(t, "  pvh[%llu]=%#llx（type=%llu = %s）\n", (unsigned long long)pai,
                   (unsigned long long)pvhEntry, (unsigned long long)pvhType,
                   kpm_pvh_type_name(pvhType));
        if (pvhType != KM_PM_PVH_TYPE_PTDP) {
            free(freeLvl2);
            return KM_PM_ALLOC_ACCOUNTING_FAILED;
        }

        const uint64_t ptdp = kpm_pvh_ptd(pvhEntry);
        if (!kpm_shape_ok(ptdp)) {
            kpm_append(t, "  ✗ ptdp=%#llx 形态不过\n", (unsigned long long)ptdp);
            free(freeLvl2);
            return KM_PM_ALLOC_ACCOUNTING_FAILED;
        }

        uint64_t pinfoAddr = 0;
        if (!kpm_add(ptdp, ctx->ptDescOffPtdInfo, &pinfoAddr) || !kpm_shape_ok(pinfoAddr)) {
            kpm_append(t, "  ✗ ptdp+ptd_info=%#llx 形态不过\n", (unsigned long long)pinfoAddr);
            free(freeLvl2);
            return KM_PM_ALLOC_ACCOUNTING_FAILED;
        }
        /*
         * pt_desc->pinfo **不还原 PAC** —— 如实说明这一条是"判定 + 未确证的部分"，
         * 不是遗漏：
         *   · 它确实是块级 vm_page 记帐对象的指针字段，但**上游 Dopamine 对读出来的
         *     pinfo 不做还原**（util.c:159 之后直接用它定位 refcount 并 physwrite16），
         *     而上面所有做了还原的地方都有上游同源代码与真机现场两重依据；
         *   · 本文件目前没有任何证据说明这个字段被签名（真机现场只覆盖到 task->map
         *     与 vm_map->pmap 这两跳）。
         * 本轮的边界是"确证过的还原 + 其余处写清理由"，所以这里不凭手感加。
         * 若真机在 ptdp/pinfo 这一跳失败，判据是：pinfo 读出来高 16 位不是 0xFFFF
         * 而低 47 位像内核地址 —— 那时它就是被签名了，改成 km_unsign_ptr 即可。
         */
        const uint64_t pinfo = km_read64(pinfoAddr, &ok);
        kpm_append(t, "  ptdp=%#llx ptd_info@+%#llx → pinfo=%#llx%s\n", (unsigned long long)ptdp,
                   (unsigned long long)ctx->ptDescOffPtdInfo, (unsigned long long)pinfo,
                   ok ? "" : "  ← 读失败");
        if (!ok || !kpm_shape_ok(pinfo)) {
            free(freeLvl2);
            return KM_PM_ALLOC_ACCOUNTING_FAILED;
        }

        /*
         * util.c:159-164 —— 引用计数必须是 1。
         *
         * 为什么是 1：这张表此刻只被"我们为它造的那一个映射"引用。不等于 1 说明
         * 它还被别的映射共用，那我们就不能把它整张偷走（偷走会连带毁掉别人的映射）。
         *
         * 这里用单次 km_read（不是 km_read64 的双读一致检查）：refcount 是内核对
         * 象里会被并发改动的字段，双读一致检查会把"内核刚好在这两次读之间动了它"
         * 误报成读失败。判据本身带重试（下一轮），所以单次读足够 ——
         * Dopamine util.c:159 的 physread16 同样是单次读。
         */
        uint16_t refCount = 0;
        if (!km_read(pinfo, &refCount, sizeof(refCount))) {
            kpm_append(t, "  ✗ pinfo=%#llx 读不到引用计数\n", (unsigned long long)pinfo);
            free(freeLvl2);
            return KM_PM_ALLOC_ACCOUNTING_FAILED;
        }
        kpm_append(t, "  第 %d 次尝试：新表 PA=%#llx refcount=%u\n", attempt + 1,
                   (unsigned long long)allocatedPt, (unsigned)refCount);
        if (refCount != 1) {
            free(freeLvl2);
            continue; /* util.c:160-163 的重试 */
        }

        /* ── ④ 抬高引用计数（util.c:194）── */
        if (!kpm_write_u16_kva(t, pinfo, (uint16_t)KM_PM_REFCOUNT_PINNED,
                               "抬高页表页引用计数")) {
            free(freeLvl2);
            return KM_PM_ALLOC_WRITE_FAILED;
        }

        /* ── ⑤ 释放地址范围（util.c:197）：引用计数不为 0，那张表不会被回收 ── */
        free(freeLvl2);
        freeLvl2 = NULL;
        kpm_append(t, "  已 free() 掉那段 %#llx 的地址范围（表被引用计数保住）\n",
                   (unsigned long long)KM_PM_ALLOC_SPAN);

        /* ── ⑥ 解除它与原地址的关联（util.c:200）── */
        if (!kpm_write_u64_phys(t, tteLvl2, 0, "清掉原 L2 表项（解除关联）")) {
            /*
             * 停在这里的**残留状态**必须说清楚，因为它不是"什么都没发生"：
             * 那张 L3 表已经被引用计数保下来了（第 ④ 步）、并且已经从原地址
             * 泄漏出来 —— 但指向它的 L2 表项还挂着，所以它此刻**既是我们的孤儿、
             * 又被原来的映射引用着**。不做回退：回退要再写一次，而"再写一次"
             * 本身就是这次要避免的东西；泄漏一张 16 KB 表页是可控代价。
             */
            kpm_append(t, "  ⇒ 残留状态：那张表页已被引用计数保下（0x%x）且已从原地址泄漏出来，\n",
                       (unsigned)KM_PM_REFCOUNT_PINNED);
            kpm_append(t, "    但原 L2 表项仍指向它。不做回退（回退要再写一次内核内存）。\n");
            return KM_PM_ALLOC_WRITE_FAILED;
        }

        /*
         * ── ⑦ 引用计数归 0（util.c:211）──
         * 我们的新 PTE 不进 pmap 层，所以这张表的记账必须是 0；
         * 留成 0x1337 会让内核的页表记账与实际情况不符。
         */
        if (!kpm_write_u16_kva(t, pinfo, 0, "引用计数归 0")) {
            kpm_append(t, "  ⇒ 残留状态：表页已完全泄漏（原关联已断），引用计数停在 0x%x。\n",
                       (unsigned)KM_PM_REFCOUNT_PINNED);
            kpm_append(t, "    这张表是孤儿、不会被任何一条路径回收；停在 0x%x 只影响记账，不影响安全。\n",
                       (unsigned)KM_PM_REFCOUNT_PINNED);
            return KM_PM_ALLOC_WRITE_FAILED;
        }

        *outPa = allocatedPt;
        return KM_PM_ALLOC_OK;
    }

    kpm_append(t, "✗ 连续 %d 次拿到的页表页引用计数都不是 1 —— 放弃（不无限重试）。\n",
               KM_PM_ALLOC_ATTEMPTS);
    return KM_PM_ALLOC_REFCOUNT_BUSY;
}

/*
 * pmap_alloc_page_table —— 逐行对照 Dopamine util.c:224-250。
 *
 * 拿到一张无主 L3 表之后，把它的归属从"当前 pmap 的那个临时地址"换成
 * "要用它的那个地址"：写 pt_desc.pmap 与 pt_desc.va。
 *
 * **与 Dopamine 的差异（头文件第 2 条）**：Dopamine 在这两步之前做了
 * `ptdp_pa = kvtophys(ptdp)`，因为它的 physwrite64 吃物理地址；Aether 的
 * pvh_ptd 返回值本来就是内核虚拟地址，直接 km_write 更短，也少一次换算——
 * 少一次换算就少一处可能出错的地方。
 */
static uint64_t kpm_pmap_alloc_page_table(km_pm_ctx *ctx, km_pm_text *t, uint64_t va)
{
    uint64_t tt_p = 0;
    const km_pm_alloc_result r = kpm_alloc_page_table_unassigned(ctx, t, &tt_p);
    if (r != KM_PM_ALLOC_OK || tt_p == 0) {
        kpm_append(t, "  ✗ alloc_page_table_unassigned 失败（结果 %d）\n", (int)r);
        return 0;
    }

    if (tt_p < ctx->vmFirstPhysValue) {
        kpm_append(t, "  ✗ 新表 PA %#llx < vm_first_phys —— 记账链会下溢，中止\n",
                   (unsigned long long)tt_p);
        return 0;
    }
    const uint64_t pai = kpm_pa_index(ctx, tt_p);
    const uint64_t pvh = kpm_pai_to_pvh(ctx, pai);
    if (pvh == 0 || !kpm_shape_ok(pvh)) {
        kpm_append(t, "  ✗ 新表的 pvh 地址 %#llx 形态不过\n", (unsigned long long)pvh);
        return 0;
    }
    bool ok = false;
    /* 与 kpm_alloc_page_table_unassigned 里那条同源：pvh 表项是打包值，不是指针字段，不还原。 */
    const uint64_t pvhEntry = km_read64(pvh, &ok);
    if (!ok || (pvhEntry & KM_PM_PVH_TYPE_MASK) != KM_PM_PVH_TYPE_PTDP) {
        kpm_append(t, "  ✗ 新表的 pvh 表项 %#llx 不是 PTDP（或读失败）—— 不给它挂链\n",
                   (unsigned long long)pvhEntry);
        return 0;
    }
    const uint64_t ptdp = kpm_pvh_ptd(pvhEntry);
    if (!kpm_shape_ok(ptdp)) {
        kpm_append(t, "  ✗ 新表的 ptdp=%#llx 形态不过\n", (unsigned long long)ptdp);
        return 0;
    }

    /* util.c:241 */
    if (!kpm_write_u64_kva(t, ptdp + KM_PM_PT_DESC_OFF_PMAP, ctx->pmap, "关联 pt_desc.pmap")) {
        return 0;
    }

    /*
     * util.c:245-247 —— 按槽位写 va。
     *
     * Dopamine 的循环上界是 vm_page_size、步长是 vm_real_kernel_page_size，
     * 而 `physwrite64(ptdp_pa + va + (po / vm_page_size), va + po)` 里那个下标
     * **没有乘 8** —— 在 16K 机型上两个页大小相等，po 只能取 0，于是循环头一轮
     * 就把 (va+0) 写进 offset 0，之后 po 已经 ≥ 上界而退出。所以本机行为就是
     * 「只写第一个槽」；上游注释（util.c:244）也写着 "in practice, only the first
     * slot is used"。这里照抄循环形状，把语义留在注释里，而不是偷偷改成一句
     * 赋值 —— 日后若真有 po 走第二轮的机型，形状还在。
     */
    for (uint64_t po = 0; po < ctx->pageSize; po += ctx->pageSize) {
        const uint64_t vaSlot = ptdp + KM_PM_PT_DESC_OFF_VA + (po / ctx->pageSize);
        if (!kpm_write_u64_kva(t, vaSlot, va + po, "关联 pt_desc.va")) {
            return 0;
        }
    }
    return tt_p;
}

/// pmap_expand_range 的结果。
///
/// 枚举值刻意**避开**上面那个 `KM_PM_EXPAND_LOOP_GUARD` 宏名：预处理阶段宏会把
/// 同名标识符整个换掉，枚举那一行就会变成 `4`，编译直接报 "expected identifier"。
/// 这类错本地两个脚本都抓不到（它们只看词法与括号），只有 CI 会炸。
typedef enum {
    KM_PM_EXPAND_OK = 0,
    KM_PM_EXPAND_WALK_FAILED,
    KM_PM_EXPAND_ALLOC_FAILED,
    KM_PM_EXPAND_LINK_FAILED,
    KM_PM_EXPAND_LOOP_RUNAWAY
} km_pm_expand_result;

/*
 * pmap_expand_range —— 逐行对照 Dopamine util.c:303-335（**无 kcall 的那一支**）。
 *
 * 那一支为什么不需要 kcall：它自己就是"页表遍历 + 物理写"两步的循环 ——
 * 每次下钻看断在哪一级，就在该级缺表的地方手工挂一张新表上去，直到能走到 L3 为止。
 * 让内核建表（有 kcall 那一支）反而是绕路：先建好再撤掉，只为了让那张空表留下。
 *
 * 循环的语义（靠 vtophys_lvl 的两条契约才成立）：
 *   · leafLevel 每轮先置回 L3 作为 LEAF_LEVEL 入参；
 *   · 断在 L2 → 缺的是 L3 表 → 在**窗口地址所在 L2 块**的基址上关联新表；
 *   · 断在 L1 → 缺的是 L2 表 → 在**窗口地址所在 L1 块**的基址上关联新表；
 *   · 走到 L3 → 什么都不做（这一级已经有了），循环也到此为止。
 */
static km_pm_expand_result kpm_pmap_expand_range(km_pm_ctx *ctx, km_pm_text *t, uint64_t vaStart,
                                                 uint64_t size)
{
    /* util.c:304-305 */
    const uint64_t l2Start = vaStart & ~KM_PM_L2_BLOCK_MASK;
    const uint64_t l2End = (((vaStart + size) + KM_PM_L2_BLOCK_MASK) & ~KM_PM_L2_BLOCK_MASK);

    kpm_append(t, "  范围 L2 块：%#llx .. %#llx（步长 %#llx）\n", (unsigned long long)l2Start,
               (unsigned long long)l2End, (unsigned long long)KM_PM_16K_L2_BLOCK_SIZE);

    for (uint64_t va = l2Start; va < l2End; va += KM_PM_16K_L2_BLOCK_SIZE) {
        uint64_t leafLevel = KM_PM_TT_L3_LEVEL;
        int guard = 0;
        do {
            if (++guard > KM_PM_EXPAND_LOOP_GUARD) {
                kpm_append(t, "  ✗ 建表循环超过 %d 轮（几何被改坏的迹象）—— 中止\n",
                           KM_PM_EXPAND_LOOP_GUARD);
                return KM_PM_EXPAND_LOOP_RUNAWAY;
            }

            /* util.c:307-311 */
            leafLevel = KM_PM_TT_L3_LEVEL;
            uint64_t pte = 0;
            km_pm_vt_err err = KM_PM_E_NONE;
            kpm_vtophys_lvl(ctx, ctx->ttep, va, &leafLevel, &pte, &err);

            if (err != KM_PM_E_NONE && err != KM_PM_E_INVALID) {
                /*
                 * invalid 之外的失败（换算不出来 / 形态不过 / 读失败）**不是**
                 * "这里没有表"，而是"我们不知道这里有什么"。此时按 Dopamine 的
                 * 流程会拿一个无效的 pte 去写 —— 这里必须停下。
                 */
                kpm_append(t, "  ✗ 下钻 %#llx 失败（err=%d）—— 中止，不写\n",
                           (unsigned long long)va, (int)err);
                return KM_PM_EXPAND_WALK_FAILED;
            }

            kpm_append(t, "  va=%#llx 断在 %s：该级缺表，要挂新表的表项 PA=%#llx\n",
                       (unsigned long long)va,
                       (leafLevel == KM_PM_TT_L1_LEVEL
                            ? "L1"
                            : (leafLevel == KM_PM_TT_L2_LEVEL ? "L2" : "L3")),
                       (unsigned long long)pte);

            if (leafLevel != KM_PM_TT_L3_LEVEL) {
                /* util.c:313-324 —— 这一级缺表，缺的是它的**下一级** */
                uint64_t pt_va = 0;
                if (leafLevel == KM_PM_TT_L1_LEVEL) {
                    pt_va = va & ~KM_PM_L1_BLOCK_MASK;
                } else if (leafLevel == KM_PM_TT_L2_LEVEL) {
                    pt_va = va & ~KM_PM_L2_BLOCK_MASK;
                } else {
                    /* leafLevel 只可能是 1 或 2（3 已被上面排除）；真出现别的值说明
                       vtophys_lvl 的级号语义被改坏了，宁可停下。 */
                    kpm_append(t, "  ✗ 断点级号 %llu 不在 L1/L2 之内 —— 中止\n",
                               (unsigned long long)leafLevel);
                    return KM_PM_EXPAND_WALK_FAILED;
                }
                leafLevel++;

                if (guard > 1) {
                    kpm_append(t, "  （第 %d 轮：再补一级）\n", guard);
                }
                const uint64_t newTable = kpm_pmap_alloc_page_table(ctx, t, pt_va);
                if (newTable == 0) {
                    kpm_append(t, "  ✗ 分配页表页失败（pt_va=%#llx）—— 中止\n",
                               (unsigned long long)pt_va);
                    return KM_PM_EXPAND_ALLOC_FAILED;
                }
                kpm_append(t, "  新页表页 PA=%#llx（关联到 pt_va=%#llx）\n",
                           (unsigned long long)newTable, (unsigned long long)pt_va);

                /* util.c:327 —— ARM_TTE_VALID | ARM_TTE_TYPE_TABLE = 0x3 */
                if (!kpm_write_u64_phys(t, pte, newTable | KM_PM_TTE_VALID | KM_PM_TTE_TYPE_TABLE,
                                        "把它挂进上一级表项")) {
                    return KM_PM_EXPAND_LINK_FAILED;
                }
            }
        } while (leafLevel < KM_PM_TT_L3_LEVEL);
    }
    return KM_PM_EXPAND_OK;
}

#pragma mark - 对外：预检

km_physmap_status km_physmap_precheck(void)
{
    static char buffer[KM_PM_TEXT_SIZE];
    memset(buffer, 0, sizeof(buffer));
    km_pm_text t = { buffer, sizeof(buffer), 0, false };

    kpm_append(&t, "[建表] 预检未完成\n");

    km_physmap_status status = KM_PM_NOT_READY;
    NSString *summary = nil;

    km_pm_ctx ctx;
    const km_physmap_status load = kpm_load(&ctx, &t);
    if (load != KM_PM_READY) {
        status = load;
        switch (load) {
        case KM_PM_NOT_READY: summary = @"[建表] 前置不成立（见列表）"; break;
        case KM_PM_KEYS_MISSING: summary = @"[建表] 有必需的 XPF 键取不到"; break;
        case KM_PM_PMAP_UNRESOLVED: summary = @"[建表] pmap 链路取不到"; break;
        default: summary = @"[建表] 预检未通过（见列表）"; break;
        }
        goto done;
    }

    kpm_probe_window(&ctx, &t);
    kpm_report_accounting(&ctx, &t);
    kpm_report_window_slots(&t);       /* 窗口槽位那一段的状态（只读，含档位） */
    kpm_verify_pmap_layout(&ctx, &t); /* 只写诊断，不阻断预检结论 */

    if (ctx.windowHasL3) {
        /*
         * "有 L3 表项"与"已经写好自映射"是两件事，面板上要分开说：
         * 前者说明这一步已经动过，后者才说明**可以跳过建表**。
         * 预检多做一次只读遍历就能分辨，比让人去点一次写按钮便宜得多。
         */
        uint64_t tablePa = 0;
        status = KM_PM_TABLE_ALREADY;
        if (kpm_window_is_selfmapped(&ctx, &tablePa)) {
            summary = @"[建表] 窗口上已经是自映射（建表与自映射都已完成）";
        } else {
            summary = @"[建表] 窗口上已有 L3 表项，但还不是自映射项（见列表）";
        }
    } else if (ctx.windowWalkErr == KM_PM_E_NONE && ctx.windowLeafLevel < KM_PM_TT_L3_LEVEL &&
               ctx.windowWalkPa != 0) {
        status = KM_PM_BLOCK_MAPPING;
        summary = @"[建表] 窗口落在已有的大页里（没有独立 L3 表项）";
    } else if (ctx.windowWalkErr == KM_PM_E_INVALID) {
        status = KM_PM_READY;
        summary = @"[建表] ✓ 前置齐备且窗口上没有页表 —— 可以执行建表";
        kpm_append(&t, "== ⑪ 结论 ==\n");
        kpm_append(&t, "✓ 可以执行：km_physmap_build() 会在 %#llx 上建表 → 写自映射。\n",
                   (unsigned long long)ctx.window);
    } else {
        status = KM_PM_PMAP_UNRESOLVED;
        summary = @"[建表] 窗口下钻状态异常（见列表）";
    }

done:
    if (t.truncated && (status == KM_PM_NOT_READY || status == KM_PM_PMAP_UNRESOLVED ||
                        status == KM_PM_KEYS_MISSING)) {
        status = KM_PM_TRUNCATED;
    }
    if (summary != nil) {
        const char *s = summary.UTF8String;
        const size_t len = strlen(s);
        if (len + 1 <= sizeof(buffer)) {
            memcpy(buffer, s, len);
            buffer[len] = '\n';
            for (size_t i = len + 1; i < 44 && i < sizeof(buffer) - 1 && buffer[i] != '\n'; i++) {
                buffer[i] = ' ';
            }
        }
    }
    kpm_store_text(buffer);
    /*
     * 只在真的算出了窗口地址时才更新它。`kpm_load` 提前返回时 `ctx` 已被 memset
     * 成 0（窗口那一项还没算），无条件赋值会把"最近一次算出的窗口地址"抹成 0 ——
     * 于是 km_physmap_window_address() 会回落去重算，与它自己"优先回最近一次
     * 算出的那一个"的承诺相反。这是复查时发现的，不是设备上撞出来的。
     */
    if (ctx.window != 0) {
        g_physmapWindow = ctx.window;
    }
    return status;
}

#pragma mark - 对外：执行

km_physmap_build_status km_physmap_build(void)
{
    static char buffer[KM_PM_TEXT_SIZE];
    memset(buffer, 0, sizeof(buffer));
    km_pm_text t = { buffer, sizeof(buffer), 0, false };

    kpm_append(&t, "[建表] 执行未完成\n");

    km_physmap_build_status status = KM_PM_BUILD_NOT_READY;
    NSString *summary = nil;

    km_pm_ctx ctx;
    const km_physmap_status load = kpm_load(&ctx, &t);
    if (load != KM_PM_READY) {
        status = KM_PM_BUILD_NOT_READY;
        summary = (load == KM_PM_KEYS_MISSING)
                      ? @"[建表] 未执行：有必需的 XPF 键取不到"
                      : (load == KM_PM_PMAP_UNRESOLVED ? @"[建表] 未执行：pmap 链路取不到"
                                                       : @"[建表] 未执行：前置不成立");
        goto done;
    }

    kpm_probe_window(&ctx, &t);
    if (ctx.windowWalkErr == KM_PM_E_NONE && ctx.windowLeafLevel < KM_PM_TT_L3_LEVEL &&
        ctx.windowWalkPa != 0) {
        kpm_append(&t, "== 结论（未进入建表，本次未写任何内存）==\n");
        kpm_append(&t, "✗ 窗口地址落在已有的大页里：没有独立的 L3 表项可写，本模块的算法不适用。\n");
        status = KM_PM_BUILD_EXPAND_FAILED;
        summary = @"[建表] 未执行：窗口落在已有大页里";
        goto done;
    }

    if (ctx.windowHasL3) {
        uint64_t tablePa = 0;
        const bool selfmapped = kpm_window_is_selfmapped(&ctx, &tablePa);
        if (selfmapped) {
            g_physmapMagicPT = tablePa;
            kpm_append(&t, "== 结论（幂等命中，本次未写任何内存）==\n");
            kpm_append(&t, "✓ 窗口 %#llx 上**已经是自映射**：L3 第 0 项 = %#llx = 表页 PA %#llx | 叶模板。\n",
                       (unsigned long long)ctx.window, (unsigned long long)ctx.windowLeafEntry,
                       (unsigned long long)tablePa);
            kpm_append(&t, "  ⇒ 本次**没有写任何内核内存**（建表与自映射都已生效，重写没有收益只有风险）。\n");
            kpm_report_window_slots(&t); /* 幂等命中也是"自映射已就绪"的一种，槽位那一段可以用 */
            status = KM_PM_BUILD_ALREADY;
            summary = @"[建表] 已经建过且自映射已生效（本次未写任何内存）";
            goto done;
        }
        if (tablePa != 0) {
            kpm_append(&t, "  注：窗口上已有 L3 表项（%#llx）但它**不是**指向表页自己的自映射项"
                           "（表页 PA=%#llx）—— 按未建完处理，继续走下面的建表流程。\n",
                       (unsigned long long)ctx.windowLeafEntry, (unsigned long long)tablePa);
        }
    }

    /* ── 建表（util.c:303-335）── */
    kpm_append(&t, "== ⑪ 建表（pmap_expand_range 的无 kcall 支）==\n");
    const km_pm_expand_result expand =
        kpm_pmap_expand_range(&ctx, &t, ctx.window, KM_PM_16K_L2_BLOCK_SIZE);
    if (expand != KM_PM_EXPAND_OK) {
        kpm_append(&t, "✗ 建表失败（结果 %d）—— **停止**，自映射不执行。\n", (int)expand);
        status = KM_PM_BUILD_EXPAND_FAILED;
        summary = @"[建表] ✗ 建表失败（见列表）";
        goto done;
    }

    /*
     * 取 magicPT（physrw_pte.c:129-130）：LEAF_LEVEL 传 L2，
     * 于是返回的是 L2 表项指向的**那张 L3 表的 PA**（不是叶的值）。
     */
    uint64_t magicLevel = KM_PM_TT_L2_LEVEL;
    uint64_t magicLeafAddr = 0;
    km_pm_vt_err err = KM_PM_E_NONE;
    const uint64_t magicPT =
        kpm_vtophys_lvl(&ctx, ctx.ttep, ctx.window, &magicLevel, &magicLeafAddr, &err);
    kpm_append(&t, "  建表后取表：vtophys_lvl(ttep, 窗口, 只到 L2) = %#llx（状态 %d，L2 表项 PA=%#llx）\n",
               (unsigned long long)magicPT, (int)err, (unsigned long long)magicLeafAddr);
    if (magicPT == 0 || err != KM_PM_E_NONE) {
        kpm_append(&t, "✗ 建表之后仍然取不到那张 L3 表 —— **停止**，不写自映射。\n");
        status = KM_PM_BUILD_EXPAND_FAILED;
        summary = @"[建表] ✗ 建表后取表失败（见列表）";
        goto done;
    }

    /* ── 自映射（physrw_pte.c:132）── */
    kpm_append(&t, "== ⑫ 自映射（physrw_pte.c:132）==\n");
    kpm_append(&t, "  表页 PA=%#llx；窗口 %#llx 的 L3 表项 = 该表的第 0 项（L3 索引 0 已在 ③ 核对）\n",
               (unsigned long long)magicPT, (unsigned long long)ctx.window);
    kpm_append(&t, "  写入值 = 表页 PA | 叶模板 %#llx（PERM_TO_PTE(0x7)|NG|OSH|L3ENTRY）\n",
               (unsigned long long)KM_PM_PTE_LEAF);
    if (!kpm_write_u64_phys(&t, magicPT, magicPT | KM_PM_PTE_LEAF, "自映射")) {
        kpm_append(&t, "✗ 自映射写失败或回读不符 —— **停止**。\n");
        status = KM_PM_BUILD_SELFMAP_FAILED;
        summary = @"[建表] ✗ 自映射失败（见列表）";
        goto done;
    }
    g_physmapMagicPT = magicPT;

    /*
     * 自映射之后的独立复核：从**窗口那条路**再走一遍，看看窗口地址现在能不能翻出
     * 表页自己。这一步纯粹是证据 —— 如果 ⑪ 的回读已通过，这一步必然通过；
     * 不通过说明前面的判据之间有矛盾，那比写失败更值得看。
     */
    uint64_t verifyLevel = KM_PM_TT_L3_LEVEL;
    uint64_t verifyAddr = 0;
    err = KM_PM_E_NONE;
    const uint64_t verifyPa =
        kpm_vtophys_lvl(&ctx, ctx.ttep, ctx.window, &verifyLevel, &verifyAddr, &err);
    kpm_append(&t, "  [复核] 再走一遍窗口：级号 %llu · 表项 PA=%#llx · 翻出的 PA=%#llx · 状态 %d\n",
               (unsigned long long)verifyLevel, (unsigned long long)verifyAddr,
               (unsigned long long)verifyPa, (int)err);
    if (verifyPa == magicPT) {
        kpm_append(&t, "  ✓ 复核通过：窗口地址现在指向表页自己（自映射已生效）。\n");
    } else {
        kpm_append(&t, "  ✗ 复核不符：期望 %#llx，得到 %#llx —— 停下并如实报告。\n",
                   (unsigned long long)magicPT, (unsigned long long)verifyPa);
        status = KM_PM_BUILD_SELFMAP_FAILED;
        summary = @"[建表] ✗ 自映射复核不符（见列表）";
        goto done;
    }

    /* ── sw_asid 那一步（physrw_pte.c:134-140）── */
    kpm_append(&t, "== ⑬ sw_asid 页映射（physrw_pte.c:134-140）==\n");
    if (!kpm_verify_pmap_layout(&ctx, &t)) {
        status = KM_PM_BUILD_SWASID_SKIPPED;
        summary = @"[建表] ✓ 建表+自映射完成；sw_asid 一步前置佐证不过，已跳过";
        goto done;
    }

    const uint64_t swAsidKva = ctx.pmap + ctx.swAsidOff;
    const uint64_t swAsidPage = swAsidKva & ~(ctx.pageSize - 1);
    const uint64_t swAsidPageOff = swAsidKva & (ctx.pageSize - 1);
    kpm_append(&t, "  pmap->sw_asid 的内核地址 = %#llx（pmap %#llx + %#llx）\n",
               (unsigned long long)swAsidKva, (unsigned long long)ctx.pmap,
               (unsigned long long)ctx.swAsidOff);

    err = KM_PM_E_NONE;
    const uint64_t swAsidPagePa = kpm_kvtophys(&ctx, swAsidPage, &err);
    kpm_append(&t, "  所在页 %#llx → 内核页表遍历（cpu_ttep=%#llx）= %#llx（状态 %d）\n",
               (unsigned long long)swAsidPage, (unsigned long long)ctx.cpuTtep,
               (unsigned long long)swAsidPagePa, (int)err);
    if (swAsidPagePa == 0 || err != KM_PM_E_NONE) {
        kpm_append(&t, "✗ 那一页的物理地址算不出来 —— **跳过**（不猜一个 PA 写进去）。\n");
        status = KM_PM_BUILD_SWASID_SKIPPED;
        summary = @"[建表] ✓ 建表+自映射完成；sw_asid 页 PA 算不出，已跳过";
        goto done;
    }
    if (swAsidPagePa >= (1ULL << 48)) {
        kpm_append(&t, "✗ 算出的 PA %#llx ≥ 2^48 —— 不是物理地址，跳过。\n",
                   (unsigned long long)swAsidPagePa);
        status = KM_PM_BUILD_SWASID_SKIPPED;
        summary = @"[建表] ✓ 建表+自映射完成；sw_asid 页 PA 不在物理域，已跳过";
        goto done;
    }

    /*
     * 交叉核对（**只作证据，不作判据**）：那一页若落在内核线性映射段，
     * km_phystokv 会把它换回同一个内核地址。成立时这是很强的正向证据；
     * 不成立**不代表 PA 错** —— 内核堆对象未必在线性映射段，
     * 所以这一条不能拿来否决上面的结果。头文件「没能确证的部分」写明了这一点。
     */
    const uint64_t backKva = km_phystokv(swAsidPagePa);
    kpm_append(&t, "  [交叉核对] km_phystokv(%#llx) = %#llx%s\n",
               (unsigned long long)swAsidPagePa, (unsigned long long)backKva,
               (backKva == swAsidPage)
                   ? "  ⇒ 与遍历结果一致（强证据）"
                   : "  ⇒ 不一致：只说明该页不在线性映射段，不作判据");

    const uint64_t slotValue = swAsidPagePa | KM_PM_PTE_LEAF;
    kpm_append(&t, "  写入 magicPT+8 = %#llx（值 %#llx；窗口 +%#llx → %#llx 指向该页的 %#llx 偏移）\n",
               (unsigned long long)(magicPT + 8), (unsigned long long)slotValue,
               (unsigned long long)ctx.pageSize,
               (unsigned long long)(ctx.window + ctx.pageSize),
               (unsigned long long)swAsidPageOff);
    if (!kpm_write_u64_phys(&t, magicPT + 8, slotValue, "sw_asid 页映射")) {
        kpm_append(&t, "✗ sw_asid 页映射写失败或回读不符 —— **停止**。\n");
        status = KM_PM_BUILD_SWASID_FAILED;
        summary = @"[建表] ✗ sw_asid 页映射失败（见列表）";
        goto done;
    }

    status = KM_PM_BUILD_OK;
    summary = @"[建表] ✓✓ 建表 + 自映射 + sw_asid 映射全部完成";
    kpm_append(&t, "== ⑭ 结论 ==\n");
    kpm_append(&t, "✓ 全部完成：magicPT=%#llx，窗口 %#llx 现在指向表页自己。\n",
               (unsigned long long)magicPT, (unsigned long long)ctx.window);
    kpm_append(&t, "  复查办法：再点一次「建窗」（KernelPhysWindow 的只读探针），\n");
    kpm_append(&t, "  它应当在窗口地址上看到 L3 有效叶；两个模块的结论必须对得上。\n");
    kpm_report_window_slots(&t); /* 自映射已就绪 ⇒ 槽位那一段现在可用 */

done:
    /*
     * 截断只降级"没得出判据"的那一类结论（NOT_READY），不覆盖已经算出来的失败态。
     *
     * 与 precheck 那边**刻意不对称**：precheck 会把 NOT_READY / PMAP_UNRESOLVED /
     * KEYS_MISSING 三种都降级成 TRUNCATED，因为那三种都是"还没走到判据"；
     * 而 build 这边一旦走到 EXPAND_FAILED / SELFMAP_FAILED / SWASID_FAILED，
     * 说明**写路径已经动过内核内存**，那条结论比文本完整性重要得多 ——
     * 把它换成"诊断被截断"会让 YG 以为什么都没发生。失败态一律保留原值。
     */
    if (t.truncated && (status == KM_PM_BUILD_NOT_READY)) {
        status = KM_PM_BUILD_TRUNCATED;
    }
    if (summary != nil) {
        const char *s = summary.UTF8String;
        const size_t len = strlen(s);
        if (len + 1 <= sizeof(buffer)) {
            memcpy(buffer, s, len);
            buffer[len] = '\n';
            for (size_t i = len + 1; i < 46 && i < sizeof(buffer) - 1 && buffer[i] != '\n'; i++) {
                buffer[i] = ' ';
            }
        }
    }
    kpm_store_text(buffer);
    /*
     * 只在真的算出了窗口地址时才更新它。`kpm_load` 提前返回时 `ctx` 已被 memset
     * 成 0（窗口那一项还没算），无条件赋值会把"最近一次算出的窗口地址"抹成 0 ——
     * 于是 km_physmap_window_address() 会回落去重算，与它自己"优先回最近一次
     * 算出的那一个"的承诺相反。这是复查时发现的，不是设备上撞出来的。
     */
    if (ctx.window != 0) {
        g_physmapWindow = ctx.window;
    }
    return status;
}

#pragma mark - 对外：访问器

uint64_t km_physmap_window_address(void)
{
    /*
     * 优先回最近一次预检/执行算出的那一个：面板显示时那次调用刚跑完，
     * 再调 km_physwindow_address() 会走一遍 sysctl 与进程级状态，
     * 多出一条与本次结论**并列**的计算路径（KernelPhysWindow.h 里
     * `km_physwindow_last_address()` 的说明就是这条口径）。
     * 还没跑过时（0）才回落到重算 —— 那一次调用不会与任何结论并列。
     */
    if (g_physmapWindow != 0) {
        return g_physmapWindow;
    }
    return km_physwindow_address();
}

uint64_t km_physmap_magic_pt(void)
{
    return g_physmapMagicPT;
}

#pragma mark - 对外：窗口槽位

/// 目标物理页是否与某个保留槽位现在映射着的那一页重叠。
///
/// 需要它是因为**保留槽位里存的物理页地址是运行时才知道的**
/// （表页自身、sw_asid 页），不能靠常量枚举。判据用的是"槽位当前值里的
/// 物理地址" —— 这与 acquire 自己选槽时的判据完全同口径（`& KM_PM_TTE_PA_MASK`），
/// 不引入第二套解释。
static bool kpm_slot_hits_reserved_page(uint64_t pa)
{
    for (uint32_t i = 0; i < KM_PM_WINDOW_SLOT_RESERVED; i++) {
        uint64_t v = 0;
        if (!kpm_slot_read(i, &v)) {
            /*
             * 读不到就**当作命中**（拒绝这次 acquire）：这里读不到的三种原因
             * （换算不出 KVA / 两次读不一致 / magicPT 为 0）都说明"我们不知道
             * 那一项里是什么"，而"不知道"在写内核内存这条路上只能当"危险"。
             * 这正是本工程那条口径：0 会被拦下，错值不会 —— 所以宁可误拒。
             */
            return true;
        }
        if ((v & KM_PM_TTE_PA_MASK) == pa) {
            return true;
        }
    }
    return false;
}

bool km_physmap_acquire_window(uint64_t pa, void (^block)(uint64_t ua))
{
    /*
     * ── 前置（顺序即优先级）──
     *
     * ① block 为 NULL 直接拒：本函数存在的意义就是"给你一个地址去用"，
     *    没有回调就没有意义，而继续往下走会写一条没人用的映射（多一次内核写）。
     * ② **自映射未就绪就返回 false，一次内核写都不发**（硬约束 1）。
     * ③ pa 合理性：非 0、落在物理域（< 2^48）、按页对齐（硬约束 7）。
     *    对齐**不做静默纠正**：Dopamine 的调用方自己 `curPA & ~page_mask`
     *    （physrw_pte.c:80/94），本函数把这件事变成显式判据 —— 悄悄替你圆整
     *    会让"传进来的是页内地址，被圆到别的页"这种错安静生效。
     * ④ 与保留槽位重叠 → 拒（见 KM_PM_WINDOW_SLOT_RESERVED 那段）。
     */
    if (block == NULL) {
        return false;
    }
    if (g_physmapMagicPT == 0) {
        return false;
    }
    if (pa == 0 || pa >= (1ULL << 48)) {
        return false;
    }
    if ((pa & (0x4000ULL - 1ULL)) != 0) {
        return false;
    }

    const uint64_t window = km_physmap_window_address();
    if (window == 0) {
        return false;
    }
    /*
     * 窗口地址必须落在用户地址空间（高 16 位为 0）。这条不是形式主义：
     * 它是"窗口是**用户**地址空间里的映射"这句话的唯一判据，而下面算出的
     * ua 会被交给调用方当用户地址用。若某天它变成内核地址（比如有人把窗口
     * 常量改错），这条会立刻停住而不是交出一个语义已变的地址。
     */
    if ((window >> 48) != 0) {
        return false;
    }

    bool ok = false;
    pthread_mutex_lock(&g_physmapSlotLock);

    uint32_t slot = 0;
    km_pm_slot_decision how = KM_PM_SLOT_NONE;
    const char *reason = NULL;
    uint64_t oldEntry = 0;
    uint64_t ua = 0;
    uint64_t slotSpan = 0;

    if (!kpm_slot_choose(pa, &slot, &how, &reason)) {
        kpm_append_window_diag("acquire 失败：选槽中止（%s）", reason ? reason : "未说明");
        goto unlock;
    }
    /*
     * 选中槽位之后、写之前：**再确认这一页不是保留槽位映射着的那一页**。
     *
     * 为什么必须在这里（而不是在选槽之前）：① 命中已有槽时**本来就不会写**，
     * 所以那一支不需要这条判据 —— 而这条判据每次要读 4 个槽（4 次 km_read64
     * 是 8 次 kread），放在最前面等于给每一次复用都加上 8 次 kread 的税。
     * 放在这里只在"真要写"的时候收税。
     *
     * 代价说清楚：判据本身读的是**槽位当前值里的物理地址**
     * （与选槽同口径的 `& KM_PM_TTE_PA_MASK`），而槽位可能刚被改写 ——
     * 这个窗口里发生的事只有一种：别人（或本进程另一条路径）在 acquire 之间
     * 动了同一句表。那种情况下下面 kpm_slot_write 的"写前读旧值 + 写后回读"
     * 仍会拦住写在别处的值，所以这里不是唯一一道闸。
     */
    if (kpm_slot_hits_reserved_page(pa)) {
        kpm_append_window_diag("acquire 拒绝：pa=%#llx 与保留槽位（0..%u）映射着的那一页重叠"
                               " —— 写下去会毁掉自映射或 sw_asid 页，本次一个字节都没写",
                               (unsigned long long)pa, KM_PM_WINDOW_SLOT_RESERVED - 1U);
        goto unlock;
    }
    if (!kpm_slot_write(slot, pa, &oldEntry)) {
        kpm_append_window_diag("acquire 失败：写槽 %u 的页表项没通过受检写入（pa=%#llx）",
                               (unsigned)slot, (unsigned long long)pa);
        goto unlock;
    }
    /*
     * 数据通道档位在 kmprim 下必然失败（理由见本文件「窗口槽位」段头）：
     * 窗口地址过不了形态闸门。失败时**立刻中止**，不把地址交出去 ——
     * 交出去的那一刻调用方就会用一条没有生效的映射去读别人的物理页。
     */
    if (!kpm_window_data_is_uaccess()) {
        kpm_append_window_diag("acquire 中止：当前数据通道档位是 kmprim，"
                               "而窗口地址 %#llx 过不了内核地址形态闸门（未发出 kread/kwrite）",
                               (unsigned long long)window);
        goto unlock;
    }
    if (!kpm_mul((uint64_t)slot, 0x4000ULL, &slotSpan) || !kpm_add(window, slotSpan, &ua)) {
        kpm_append_window_diag("acquire 失败：窗口 + 槽 %u × 页大小 溢出", (unsigned)slot);
        goto unlock;
    }

    kpm_slot_trace_push(pa, ua, slot, (uint32_t)how);
    kpm_append_window_diag("acquire pa=%#llx → slot=%u（%s，旧项 %#llx）→ ua=%#llx",
                           (unsigned long long)pa, (unsigned)slot, kpm_slot_decision_name(how),
                           (unsigned long long)oldEntry, (unsigned long long)ua);
    kpm_window_data_sync();
    block(ua);
    kpm_window_data_sync();
    ok = true;

unlock:
    pthread_mutex_unlock(&g_physmapSlotLock);
    return ok;
}

/*
 * 物理读写。语义对齐 Dopamine physrw_pte.c:76-102（那两个函数底下的
 * enumerate_pages 逐页切分），差异只有一处：那边 memcpy 的是窗口地址，
 * 这边走 kpm_window_data_read / kpm_window_data_write（档位决定实现）。
 *
 * ── 三条必须成立的纪律 ──
 *
 * 1. **页内偏移保留**。传给 acquire 的必须是**页对齐**的 pa（那是 acquire 的硬判据），
 *    而真实目标 = 页首 + 页内偏移；偏移由下面的 pageOff 保留，页首交给 acquire。
 * 2. **不跨页**。每一段先按"页内剩余"截断（chunk），所以任何一次读写都不会
 *    伸到下一张物理页上 —— 那会是别人的内存。参数里那 8 字节对齐要求就是
 *    为了这件事：本工程的读写粒度是 8 字节，而页大小是 8 的倍数，于是
 *    "页对齐起点 + 8 字节对齐偏移"必然推出每一段长度都是 8 的倍数，
 *    于是"段内最后一个字节"永远还在这一页里。
 * 3. **写是读-改-写**。写不足 8 字节的尾段时先读出那一整字、只把属于本次写入的
 *    字节拼进去、再整字写回 —— 否则同一个字里不属于本次写入的字节会被抹掉，
 *    而那是目标物理页上原有的数据。
 *
 * 关于 **对齐要求**：`pa` 与 `size` 都必须是 8 的倍数。这不是"顺手加的约束"，
 * 而是"字节粒度做不到就必须说出来"：km_read/km_write 的粒度都是 8 字节，
 * 窗口地址又只能给出 8 字节对齐的偏移（槽位起点是页对齐的），所以一个 8 字节
 * 不对齐的请求**没有正确的实现方式**。拒绝它比"帮你圆整到附近"安全得多 ——
 * 圆整会安静地读写到不属于请求范围的字节。
 */
static bool kpm_physmem_range_ok(uint64_t pa, uint64_t size)
{
    if (size == 0 || size > KM_PM_RWBUF_MAX) {
        return false;
    }
    if ((size & 0x7ULL) != 0 || (pa & 0x7ULL) != 0) {
        return false; /* 8 字节粒度：见上面那段 */
    }
    if (pa == 0 || pa >= (1ULL << 48)) {
        return false;
    }
    /* 末字节必须仍在物理域内（pa + size − 1 < 2^48），用减法避免回绕。 */
    if (size - 1ULL > (1ULL << 48) - 1ULL - pa) {
        return false;
    }
    return true;
}

bool km_physmap_physreadbuf(uint64_t pa, void *out, uint64_t size)
{
    if (out == NULL || !kpm_physmem_range_ok(pa, size)) {
        return false;
    }
    uint8_t *cursor = (uint8_t *)out;
    uint64_t done = 0;
    while (done < size) {
        const uint64_t curPa = pa + done;
        const uint64_t pageOff = curPa & (0x4000ULL - 1ULL);
        uint64_t chunk = 0x4000ULL - pageOff;
        if (chunk > size - done) {
            chunk = size - done;
        }
        const uint64_t pagePa = curPa - pageOff;
        __block bool got = false;
        const bool acquired = km_physmap_acquire_window(pagePa, ^(uint64_t va) {
            got = kpm_window_data_read(va, cursor, chunk);
        });
        if (!acquired || !got) {
            kpm_append_window_diag("physreadbuf 中止：pa=%#llx size=%llu done=%llu"
                                   "（acquire=%s read=%s）",
                                   (unsigned long long)pa, (unsigned long long)size,
                                   (unsigned long long)done, acquired ? "ok" : "fail",
                                   got ? "ok" : "fail");
            return false;
        }
        cursor += chunk;
        done += chunk;
    }
    return true;
}

bool km_physmap_physwritebuf(uint64_t pa, const void *in, uint64_t size)
{
    if (in == NULL || !kpm_physmem_range_ok(pa, size)) {
        return false;
    }
    const uint8_t *cursor = (const uint8_t *)in;
    uint64_t done = 0;
    while (done < size) {
        const uint64_t curPa = pa + done;
        const uint64_t pageOff = curPa & (0x4000ULL - 1ULL);
        uint64_t chunk = 0x4000ULL - pageOff;
        if (chunk > size - done) {
            chunk = size - done;
        }
        const uint64_t pagePa = curPa - pageOff;
        __block bool wrote = false;
        __block bool readOld = true;
        const bool acquired = km_physmap_acquire_window(pagePa, ^(uint64_t va) {
            if ((chunk & 0x7ULL) == 0) {
                wrote = kpm_window_data_write(va, cursor, chunk);
                return;
            }
            /* 尾段不足 8 字节：读-改-写（见上面第 3 条）。 */
            uint64_t word = 0;
            if (!kpm_window_data_read(va, &word, sizeof(word))) {
                readOld = false;
                return;
            }
            uint8_t *w = (uint8_t *)&word;
            for (uint64_t i = 0; i < chunk; i++) {
                w[i] = cursor[i];
            }
            wrote = kpm_window_data_write(va, &word, sizeof(word));
        });
        if (!acquired || !wrote || !readOld) {
            kpm_append_window_diag("physwritebuf 中止：pa=%#llx size=%llu done=%llu"
                                   "（acquire=%s readold=%s write=%s）",
                                   (unsigned long long)pa, (unsigned long long)size,
                                   (unsigned long long)done, acquired ? "ok" : "fail",
                                   readOld ? "ok" : "fail", wrote ? "ok" : "fail");
            return false;
        }
        cursor += chunk;
        done += chunk;
    }
    return true;
}

NSString *km_physmap_window_diag(void)
{
    /*
     * 与 g_physmapText 同一套两级编码：**永不返回 nil**。
     * 本函数不调 kpm_store_text —— 那块文本属于预检/执行的结论，
     * acquire 只是下游动作，不许把它冲掉（理由见 g_physmapWindowDiag 的注释）。
     */
    if (!g_physmapWindowDiagRan) {
        return @"== 窗口槽位诊断 ==\n本进程还没有 acquire 过：先跑 km_physmap_build()，"
                "再用 km_physmap_physreadbuf() / km_physmap_physwritebuf()。\n";
    }
#if __has_feature(objc_arc)
    NSString *text = [NSString stringWithUTF8String:g_physmapWindowDiag];
#else
    NSString *text = [[NSString alloc] initWithBytes:g_physmapWindowDiag
                                              length:strlen(g_physmapWindowDiag)
                                            encoding:NSUTF8StringEncoding];
#endif
    if (text == nil) {
        text = [[NSString alloc] initWithBytes:g_physmapWindowDiag
                                        length:strlen(g_physmapWindowDiag)
                                      encoding:NSISOLatin1StringEncoding];
    }
#if !__has_feature(objc_arc)
    [text autorelease];
#endif
    return text;
}

NSString *km_physmap_diagnostic(void)
{
    if (g_physmapText != nil) {
        return g_physmapText;
    }
    /*
     * 跑过、但文本没转成字符串：这两句话必须分开。
     * 合成一句"还没跑过"是**误导** —— 用户会因为那句话去重点一次按钮，
     * 而那一次会重新跑一遍整条几十秒的链路；真实情况是上次已经跑过、
     * 结论值（status 与 km_physmap_magic_pt()）都在，只是文本没落地。
     */
    if (g_physmapRan) {
        return @"== 建表诊断 ==\n上一次跑过了，但诊断文本没能转成字符串（缓冲区不是合法 UTF-8）。\n"
                "结论值仍然有效，见 status 与 km_physmap_magic_pt()。\n";
    }
    return @"== 建表诊断 ==\n还没跑过：先点「建表预检」（只读），再点「建表」（写）。\n"
            "顺序见 KernelPhysMap.h 的「面板调用顺序」。\n";
}
