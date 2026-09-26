//
//  KernelPhysMap.h
//  Aether
//
//  「建页表窗口」这条路的**后半段** —— 在窗口地址上手工建出页表、写自映射。
//
//  与 KernelPhysWindow 的分工（两个文件是一件事的两半，不要混）：
//    · KernelPhysWindow —— **只读**探针：把 pmap 链路读出来，对窗口地址逐级下行，
//      回答「窗口地址上现在有没有页表？」。全程一次写都不发。
//    · 本文件        —— **写**路径：在没有页表时把它建出来，再让窗口地址指向
//      页表页自己（自映射）。执行完成之后，窗口地址才第一次成为"可被普通
//      PTE 写入操作的地方"。
//  为什么两半要分开：只读探针可以随便重跑、失败无害；写路径一旦写错一个地址
//  就是整机内核 panic 重启（不是 App 崩）—— 见 docs/physrw改造交接.md、
//  docs/Slide彩屏取证.md 的两次彩屏第一手取证。所以它们必须是两个函数、
//  两套状态枚举、面板上两个按钮。
//
//  ── 这条路照抄谁 ──
//
//  Dopamine 2.x 的两条 physrw 路里，**无 kcall 的那一条**（另一条要 kcall 调内核的
//  pmap_enter_options_addr，Aether 没有 gadget 链，不需要它）：
//
//    BaseBin/libjailbreak/src/physrw_pte.c:104-149   physrw_pte_handoff()
//    BaseBin/libjailbreak/src/util.c:252-337         pmap_expand_range() 的 else 支
//    BaseBin/libjailbreak/src/util.c:224-250         pmap_alloc_page_table()
//    BaseBin/libjailbreak/src/util.c:132-222         alloc_page_table_unassigned()
//    BaseBin/libjailbreak/src/kernel.c:102-115       pa_index / pai_to_pvh / pvh_ptd
//    BaseBin/libjailbreak/src/translation.c:39-97    vtophys_lvl()
//
//  本地克隆在 D:\工作区\_Aether_rev\refs\Dopamine\，上面每一处都在 .m 里逐行对照实现。
//
//  ── 与 Dopamine 的**有意差异**（只有三处，都在 .m 里写明理由）──
//
//  1. **物理读写全部换成 kwrite/kread**。Dopamine 的 physread64/physwrite64 入参是
//     物理地址；Aether 的写原语是 km_write，吃的是**内核虚拟地址**。所以每一次
//     物理访问都先 `km_phystokv(pa)` 换 KVA 再读写 —— 这正是 Dopamine 自己在
//     primitives.c:140-149 里写的那条路（`kwritebuf && phystokv` → `_physwritebuf_virt`），
//     样本也走它。`km_phystokv` 返回 0（或 `km_phystokv_ready()` 为假）时**立即中止**，
//     绝不用 `pa + 某个 delta` 兜底 —— 那是本项目两次彩屏的共同形态。
//  2. **page table descriptor 的地址不转回物理地址**。Dopamine 的
//     util.c:236 `ptdp_pa = kvtophys(ptdp)` 是因为它的 physwrite 吃 PA；
//     Aether 拿到的 `pvh_ptd()` 返回值本来就是 KVA，直接 km_write 更短也更少一次换算。
//  3. **refcount 用 8 字节读-改-写**。Dopamine 的 physwrite16 底下是 kwrite
//     （8 字节粒度），实际行为与读改写相邻字节接近，但读改写显式保留了高 6 字节，
//     并在写后回读核对（本工程硬约束：写入路径必须逐级可中止）。
//
//  ── 窗口槽位那一段（物理页 → 用户态窗口）的**有意差异**（两处）──
//
//  4. **槽位页表项的写入走内核写原语，不用用户态 `str`。** Dopamine
//     physrw_pte.c:66 的 `gMagicPT[toUse] = pa | ...` 编译出来是用户态 `str`
//     （样本 `0x10104909c str x21, [x8, w22, uxtw #3]`）。本工程走 km_write：
//     页表项在**页表页**里（物理地址 = magicPT + 槽位×8），换算出的 KVA 是内核
//     地址，所以这条走得通（自映射那一次写走的就是同一条路，真机已跑通）。
//     代价是多一次读（写前读旧值 + 写后回读），换来的是逐级可中止。
//  5. **槽位数据的读写默认走用户态直访窗口**（`KM_PM_WINDOW_ACCESS_UACCESS`），
//     与 Dopamine physrw_pte.c:82/96 的 `memcpy(curUA, ...)` 同形态。
//     **为什么不能按"全部走 km_read/km_write"实现**：`km_read` / `km_read64` /
//     `km_write` 三者都先过 `km_is_kernel_address()`
//     （KernelMemory.m:241-244，判据 `addr >> 48 == 0xFFFF`；调用点在
//     km_read:974 / km_read64:1027 / km_write:1053），而窗口地址在**用户**地址空间
//     （目标机 `0x7000000000`，高 16 位全 0）—— 一定被拒；本模块自己的
//     `kpm_shape_ok()` 与它同口径，也一样拒。所以那一档在本工程现有原语下
//     **不可实现**（不是保守不保守）。两档共用全部槽位选择与失败路径，
//     差别只在那一次数据读写；诊断第一行会打出当前档位与原因。
//     `KM_PM_WINDOW_ACCESS_KMPRIM` 这一档完整保留在代码里，供日后换了原语
//     （有用户态读写入口时）切换。
//
//  6. **不做 flush_tlb()**。Dopamine 在"清光整张表"之后调
//     physrw_pte.c:62 的 flush_tlb()（它靠 sw_asid 那套机制）。Aether 没有
//     flush_tlb，所以清表之后**刻意不做**这一步 —— 代价是清掉的项在本进程 TLB 里
//     可能还留着。诊断里如实写明；真机若复现"读到陈旧内容"，第一处查这里。
//
//  ── 每一步的地址从哪来（预检会把它们逐条打出来）──
//
//    ① 偏移          proc→task→vm_map→pmap 三段偏移
//                    km_proc_object_size() / km_task_map_offset() / km_vm_map_pmap_offset()
//                    （KernelMemory.h:84-101，来自 libkfd 版本表与 static_info.h）
//    ② 页表起点      pmap->ttep（pmap + 0x08，static_info.h:255-257 的 pmap 头两个字段）
//    ③ 窗口地址      km_physwindow_address()（= L1_BLOCK_SIZE × (L1_BLOCK_COUNT − 1)）
//    ④ 页表几何      三级**全部**是 16K 用户侧常量：L1 = bits 38:36 / 3 位
//                    （0x0000007000000000，共 8 块，即用户侧 T0SZ = 25），
//                    L2 / L3 各自 11 位（pte.h:78/83；libkfd 快照
//                    static_info.h:70/75 同值）
//                    **刻意不取** XPF 的 kernelConstant.ARM_TT_L1_INDEX_MASK：
//                    那个键按 kernelConstant.T1SZ_BOOT（**内核侧** TTBR1 几何）
//                    选值，与本模块要的**用户侧**（T0SZ）几何是两套东西 ——
//                    真机（M2）上第一次暴露就是这条，全过程记在 .m 文件头部。
//    ⑤ 物理页记账    vm_first_phys / pv_head_table / PT_INDEX_MAX（XPF，见 XpfBridge.h）
//    ⑥ 内核页表根    cpu_ttep（XPF 符号，读它的**内容** = TTBR1 的值），
//                    只在算 pmap->sw_asid 那一页的物理地址时用（见下面 ⑧）
//    ⑦ 新页表页 PA   执行时由 posix_memalign + 触碰 + vtophys_lvl 现场取得
//                    **预检阶段不存在这个值**（预检是只读的，不会去分配）
//    ⑧ sw_asid 页    pmap + pmap.sw_asid 偏移（Dopamine info.c:86，arm64e 分支）
//                    → 掩到页边界 → 经 cpu_ttep 遍历内核页表得到 PA
//
//  ── 硬约束（违反任一条的后果是整机内核 panic，不是 App 崩）──
//
//  1. 每一条送进 km_read*/km_write 的地址，**使用前**过形态检查：内核地址域
//     （与 km_is_kernel_address 同口径）、8 字节对齐、非 0。判据见 .m 的 shape_ok()。
//  2. 不许用兜底常量把失败包装成成功。任何输入取不到就报错并中止。
//  3. 写入路径**逐级可中止**：写前读旧值 → 写 → 回读核对 → 任一步不符立即返回
//     错误码并停止。禁止"先全部写完再统一验证"。
//  4. 本文件不改 KernelMemory.m 的止损逻辑、不改 KernelPhysWindow 的现有逻辑与
//     状态枚举语义、不改 Aether/libxpf/ 快照里的任何文件。
//
//  ── 面板调用顺序（FangUI 那侧照这个接）──
//
//    1. 点「建表预检」按钮（**只读**）→ km_physmap_precheck() → km_physmap_diagnostic()
//       状态行：KM_PM_READY 时才允许进第 2 步；KM_PM_TABLE_ALREADY 表示已经建过。
//    2. 点「建表并自映射」按钮（**写**）→ km_physmap_build() → km_physmap_diagnostic()
//    3. 想复查就再点一次「建窗」（KernelPhysWindow 的只读探针）——
//       建完之后窗口地址上应当出现 L3 有效叶，两个模块的结论要能对上。
//
//    **用户只点一个按钮**：XPF 初始化与 PA→KVA 换算表都由本模块在 func 内部经
//    `km_phystokv_ensure()` 按需触发（KernelSlide.h 有那个入口的说明）。
//    首次调用可能要几十秒（解压解析 kernelcache），面板必须在调用前把按钮切到
//    "计算中…"（与「Slide」按钮同一套写法）；那几十秒是预期耗时，不是卡死。
//
//    本模块会 kread/kwrite，而 libkfd 的后端**不是线程安全的**，所以调用必须与
//    读取链串行（面板侧靠 AutoTracker.shared.syncExternal 做到，与 KernelSlide 同）。
//
//  ── 没能确证的部分（写在这里，不藏在代码里）──
//
//  · `pmap.sw_asid` 的偏移（0xBE / 0xBE+8）来自 Dopamine info.c:86 的 arm64e 分支，
//    **不是**从本机内核里读出来的。libkfd 的 static_info.h:255-299 结构体定义独立
//    推出 sw_asid = 0xBE（与 Dopamine 的 EL1 取值一致），但仍不能替代真机确认。
//    所以这一步前面挂了三条佐证（kernel_el 实读、pmap->type 实读、wx_allowed 实读），
//    任一条不过就**跳过这一步**并如实报 KM_PM_BUILD_SWASID_SKIPPED ——
//    它只服务于 Dopamine 的 flush_tlb()，Aether 目前没有 flush_tlb，
//    所以跳过它不影响前 3 步的成果。
//  · `pt_desc` 的字段偏移（pmap 0x10 / va 0x18 / ptd_info 0x18 + PT_INDEX_MAX×8）
//    来自 Dopamine info.c:107-109，同样没有真机实测。
//  · `cpu_ttep` 的内容是不是 TTBR1 的值（PA）：依据是 Dopamine
//    info.c:289 `kernelConstant.cpuTTEP = kread64(ksymbol(cpu_ttep))` 与
//    translation.c:107 `kvtophys(va) = vtophys(kconstant(cpuTTEP), va)` 两处一起读出来的
//    语义。本机无法独立验证。
//  · `pvh` 表项的类型必须等于 `PVH_TYPE_PTDP(3)`：这一条**是本工程加的判据、
//    Dopamine 没有**（它直接把 `pvh_ptd()` 返回的指针当 pt_desc 用，等于隐含了这个
//    前提）。本模块把它变成显式硬判据，理由是错的类型会算出 `PVH_HIGH_FLAGS`
//    那个"形态合法但完全错误"的地址 —— 而它的**代价**是：真机若返回 PTEP(2) 之类，
//    本模块会在分配页表页那一步中止（安全，但功能不可用）。诊断里会打出实际类型名。
//  · 建表要为一张页表页临时 `posix_memalign` 一个 L2 块（16K 机型 32 MB）的地址范围，
//    成功路径上一次、失败重试最多 8 次（每次都 free）。Dopamine 的注释
//    （util.c:213-215）提到它为此"干脆在 launchd 里关掉了 jetsam" ——
//    本工程在一个普通 App 里跑，**32 MB 的虚拟预留会不会触发 jetsam 没有实测**。
//    实际只触碰一页（`util.c:148`），所以提交的内存是 16 KB，但预留量本身可能在
//    内存压力下失败 —— 失败路径是 `posix_memalign` 返回非 0 → 如实报错并中止，
//    不会带着半个状态往下走。
//
#ifndef KernelPhysMap_h
#define KernelPhysMap_h

#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * extern "C" 包裹。
 *
 * 同族的 KernelMemory.h / KernelSlide.h / KernelPhysWindow.h 都**没有**这一层，
 * 而工程里确实有 3 个 .mm（Aether/FangUISystemWindow.mm 等）—— 只是它们目前都不
 * include 这几个头，所以共 C 链接名还没出过问题。本文件是**新加的**，包一层是
 * 零风险的：将来任何一个 .mm（或 C++ 编译单元）包含它并调用其中函数时，没有这层
 * 就会出现 `ld: symbol(s) not found`（C++ 会把函数名改写成 `_Z…`，而实现在 .m
 * 里是 C 链接）。刻意**不**去动那三个既有头：那是别人的文件、且当前无害，
 * 顺手改过去只会把这次改动的范围扩大到需要重新验证的地方。
 */
#ifdef __cplusplus
extern "C" {
#endif

/// 预检结果。**刻意不合并成 bool**：调用方要区分
/// 「还不知道（前置没成立）」与「知道且不能做」与「已经建好了」。
typedef enum {
    /// 全部输入到位、且窗口地址上**还没有**页表 —— 可以执行建表。
    KM_PM_READY = 0,
    /// 前置不成立：内核层未就绪 / XPF 初始化失败 / 换算表建不起来 / 页表几何不支持。
    /// **不是**"不能建"，是"还没资格问这个问题"。
    KM_PM_NOT_READY,
    /// pmap 链路某一环取不到（值为 0、形态不过、或地址读失败）。
    KM_PM_PMAP_UNRESOLVED,
    /// 某个 XPF 键没注册或没取到值。诊断里逐个键列出 registered / fetched。
    /// **不许回退成硬编码常量**，所以这个状态直接封死执行。
    KM_PM_KEYS_MISSING,
    /// 窗口地址上已有**有效的 L3 表项**（叶），即 `vtophys_lvl` 在窗口地址上一路
    /// 走到 L3 且那一项有效。这一项只可能来自**自映射那一次写** ——
    /// 建表本身（pmap_expand_range）留下的 L3 第 0 项是 0（无效）：
    /// 它只分配页表页并写 pt_desc，不往表里填表项（Dopamine util.c:202-206 那段
    /// "Ensure there is at least one entry in page table" 是注释掉的，
    /// 理由写在它上面）。所以本状态 = "建表与自映射都已经发生过"。
    ///
    /// 想确认得更硬就去调 km_physmap_build()：它会逐项比对那一项是不是指向表页自己
    /// （是则返回 KM_PM_BUILD_ALREADY 且不写任何内存）。
    KM_PM_TABLE_ALREADY,
    /// 窗口地址上出现的是块描述符（大页）：没有独立的 L3 表项，本模块的算法不适用。
    KM_PM_BLOCK_MAPPING,
    /// 内部缓冲装不下诊断文本（只影响可读性，不影响结论）。
    KM_PM_TRUNCATED
} km_physmap_status;

/// 执行结果。
///
/// 「前置不成立」与「确定失败了」在这里是两组不同的值，**不要合并**：
/// 前者说明这条路还没到能问的地步（去补前置），后者说明走过了但某一步不符预期
/// （去看诊断里那一步的回读值）。把两者混成一个 FAILED 会让面板只能显示一句话，
/// 而这两句话要求 YG 做的事完全不同。
typedef enum {
    /// 建表 → 自映射 → sw_asid 映射（可跳过）全部完成，且每一级都回读核对通过。
    KM_PM_BUILD_OK = 0,
    /// 前置不成立（与 km_physmap_precheck 的 KM_PM_NOT_READY / KM_PM_KEYS_MISSING /
    /// KM_PM_PMAP_UNRESOLVED 同义）。**一次内核写都没发**。
    KM_PM_BUILD_NOT_READY,
    /// 已经建过且自映射已生效。判据是**逐项核对的**，不是"窗口上有表项"就算：
    /// 窗口地址的 L3 第 0 项的值必须等于「L2 表项指向的那张 L3 表页的 PA | 叶模板」
    /// —— 也就是它确实指向表页自己。
    /// 这是成功态的一种，而且是**最干净的一种：本次一个字节都没写**
    /// （没有写，就没有写错的可能）。重复调用会落到这里。
    KM_PM_BUILD_ALREADY,
    /// pmap_expand_range 在建表途中失败（分配页表页失败 / 下钻失败 / 写表项回读不符）。
    KM_PM_BUILD_EXPAND_FAILED,
    /// 建表成功，但自映射那一次写失败或回读不符。**停下**，不再往下走。
    KM_PM_BUILD_SELFMAP_FAILED,
    /// 建表 + 自映射都成功，但 sw_asid 那一步的前置佐证不过 → **跳过**这一步。
    /// 前 3 步的成果保留（诊断里说明跳过的原因）。
    KM_PM_BUILD_SWASID_SKIPPED,
    /// 建表 + 自映射成功，sw_asid 那一步执行了但写失败或回读不符。
    KM_PM_BUILD_SWASID_FAILED,
    /// 内部缓冲装不下诊断文本（不影响已经完成的写入）。
    KM_PM_BUILD_TRUNCATED
} km_physmap_build_status;

/// 本次用的窗口地址（`L1_BLOCK_SIZE × (L1_BLOCK_COUNT − 1)`，目标机 0x7000000000）。
///
/// 几何**不在这里另立常量**：它直接来自 `km_physwindow_address()` ——
/// 窗口几何是这件事的唯一真相，两个模块各持一份必然在某个时刻分叉。
/// 返回最近一次预检/执行算出的那一个（面板显示用，避免与当次结论并列）；
/// 还没跑过时回落到 `km_physwindow_address()`。返回 0 表示页大小取不到或不认得。
uint64_t km_physmap_window_address(void);

/// 最近一次 km_physmap_build() 建出来的页表页**物理地址**（= magicPT）。
/// 0 表示还没建过，或那次没走到那一步。面板上显示它，作为"这一步真的做了"的证据。
///
/// 它同时是窗口槽位那一段的**唯一前置**：见 `km_physmap_acquire_window()`。
uint64_t km_physmap_magic_pt(void);

#pragma mark - 窗口槽位：物理页 → 用户态窗口（建完表之后才有的能力）

/*
 * 机制照抄 Dopamine BaseBin/libjailbreak/src/physrw_pte.c:32-102 的 acquire_window
 * （本地克隆在 D:\工作区\_Aether_rev\refs\Dopamine\，逐行对照写在 .m 里）：
 *
 *   自映射生效之后，**页表页自己成了一块普通内存**，于是
 *       magicPT[槽位] = 物理页号 | 叶模板
 *   就是往那句 L3 表的第「槽位」项里写一条映射该物理页的页表项；
 *   随后 `*(窗口 + 槽位 × 页大小 + 页内偏移)` 读到的就是那张物理页。
 *
 * 槽位从下标 **2** 开始用；上界是这句表的项数 = `L2 块大小 ÷ 页大小` = 2048
 * （16K 档），在 .m 里有 `_Static_assert` 钉住。**实际保留的是 0..3** ——
 * 0 = 自映射项、1 = sw_asid 页映射（0 被覆盖就等于永久失去写这张表的能力），
 * 2 与 3 是保守余量（.m 里 `KM_PM_WINDOW_SLOT_RESERVED` 那一段写了为什么）。
 * 选择顺序（照 physrw_pte.c:36-71）：
 *   ① 已有映射同一个 pa 的槽 → 复用；② 值为 0 的空槽；③ 都没有才把 2.. 全清 0
 * 再用 2。
 *
 * **并发**：一次 acquire 从选槽到用完为止都在一把 `pthread_mutex_t` 锁内。
 * 槽位是共享资源：别人在你用完之前复用同一个槽，你手上的窗口地址就指向了
 * 另一张物理页。调用方（面板）仍应与读取链串行（libkfd 后端不是线程安全的）。
 */

/// 把物理页 `pa` 挂进窗口的一个槽，然后回调 `block(窗口地址)`。
///
/// **签名与 Dopamine 的 `void (^block)(void *ua)` 不同**：这里给的是 `uint64_t`。
/// 理由是想让"这个地址只能经本模块的读写函数碰"这件事在**类型上**就成立：
/// 给一个 `void *` 会诱导调用方直接 `memcpy` 或解引用，绕过形态闸门与
/// 数据通道档位那两条判据；给整数则每次访问都必须回到本模块的入口。
/// 回调收到的地址 = `窗口基址 + 槽位 × 页大小`（页首），页内偏移由调用方自己加。
///
/// 前置（**任一条不成立就返回 false，且一次内核写都不发**）：
///   ① `block` 非 NULL；
///   ② `g_physmapMagicPT != 0`（自映射已生效 —— 这是本函数的全部前提）；
///   ③ `pa` 非 0、落在物理域（< 2^48）、**16K 页对齐**（不做静默圆整：
///      Dopamine 的调用方自己 `curPA & ~page_mask`，本模块把它变成显式判据）；
///   ④ `km_physmap_window_address() != 0` 且落在用户地址空间；
///   ⑤ 在**真要写槽位**之前，`pa` 必须不与**保留槽位**（0/1/2/3）现在映射着的
///      那一页重叠 —— 尤其不许是表页自己：把槽 0 改成别的页就等于让本模块
///      **永久失去写这张表的能力**（不重启进程就修不回来）。
///      ① 命中已有槽（本来就不写）时不做这条检查，那是刻意的：判据要读 4 个槽，
///      给每一次复用都加税没有收益。
///
/// 返回 true 表示：槽位页表项已写并回读核对通过，`block` 已被调用；
/// 返回 false 表示**什么都没写**（含 block 为 NULL、前置不过、选槽/写入失败）。
/// 失败原因分两类：闸门拒（不产生诊断文本）与选槽/写入中止（进
/// `km_physmap_window_diag()`）。两类都不发内核写。
bool km_physmap_acquire_window(uint64_t pa, void (^block)(uint64_t ua));

/// 从物理地址 `pa` 读 `size` 字节到 `out`。成功返回 true。
///
/// 语义对齐 Dopamine `physrw_pte_physreadbuf`（physrw_pte.c:76-88）：按页切分
/// （enumerate_pages 的等价物），每页 acquire 一次，**页内偏移保留**。
///
/// 约束：`pa` 与 `size` 都必须是 **8 的倍数**（本工程的读写粒度是 8 字节，
/// 8 字节不对齐的请求没有正确的实现方式 —— 拒绝它比圆整到附近安全）；
/// `size` ∈ (0, 1 MiB]；`pa + size − 1` 仍在物理域内。
/// 任何一页 acquire 失败即**停止并返回 false**（已读出的部分留在 `out` 里，
/// 不做回滚 —— 回滚要再写一次窗口）。
bool km_physmap_physreadbuf(uint64_t pa, void *out, uint64_t size);

/// 往物理地址 `pa` 写 `in` 里的 `size` 字节。成功返回 true。
///
/// 语义对齐 Dopamine `physrw_pte_physwritebuf`（physrw_pte.c:90-102）。
/// 约束与 `km_physmap_physreadbuf` 完全相同。写不足 8 字节的尾段时做
/// **读-改-写**：目标页上那 8 字节里不属于本次写入的字节原样留住。
bool km_physmap_physwritebuf(uint64_t pa, const void *in, uint64_t size);

/// 窗口槽位那一段的近期动作记录 + 当前档位，**永不返回 nil**。
///
/// 与 `km_physmap_diagnostic()` 分开的理由：那块文本是**预检/执行那一次**的结论
/// （面板拿第一行当状态行），而 acquire 是下游动作 —— 它若把结论冲掉，报告就再也
/// 不是"上次点按钮的结果"。所以单开一块、单开一个入口。
///
/// 第一行是档位与原因（数据通道走用户态直访还是内核原语、以及为什么），
/// 之后是最近若干次 acquire 的槽位决策（用了哪个下标、是复用/空槽/全清）。
/// 再看槽位那一段在预检报告里的样子（含窗口基址与槽位上限），见
/// `km_physmap_precheck()` 报告里的第 ⑩ 段。
/// 全是只读，一次内核访问都不发。
NSString *km_physmap_window_diag(void);

#pragma mark - 对外：读一页物理内存（诊断入口）

/*
 * 这一段是「窗口槽位」那套机制的最下游**演示入口**：一次读一整页，并把这次读的
 * 结果写成一行给人看的摘要。它不改槽位选择、不改数据通道档位、不新增任何状态 ——
 * 槽位与「复用还是新写」直接取自 km_physmap_window_diag() 背后的同一条轨迹。
 */

/// 读一页（16K）物理内存到调用方缓冲，并返回一份**给面板显示用**的单行摘要。
///
/// 这是一个**诊断入口**，不是量产接口：它存在的意义是让面板上一个按钮就能验证
/// 「窗口 + PTE 写入 + EL0 直访」这条链第一次真正通了。
///
/// - `pa` 必须是页对齐的（内部核对；**不做静默圆整** —— 圆整会让"传进来的是页内
///   地址"这种错安静生效）。
/// - `out` 至少 16384 字节；`outSize` 是它的实际大小，小于一页时直接返回失败摘要，
///   一个字节都不读。
/// - 成功时摘要里写：页地址、用的槽位、读回的前 16 字节的十六进制、以及
///   「这次是复用已有映射还是新写了一条」。
/// - 失败时摘要写清**失败在哪一环**：参数拒 / 自映射未就绪（acquire 环）/
///   acquire 环失败 / 数据读取环失败。失败的详细记录在
///   `km_physmap_window_diag()` 里（本入口不覆盖它）。
///
/// 实际读取走 `km_physmap_physreadbuf(pa, out, 0x4000)`，一次恰好一页。
/// **永不返回 nil**（本工程硬约束 4：诊断路径），没跑过/读失败也返回一句话。
///
/// 调用纪律与其它入口相同：必须与读取链串行（libkfd 后端不是线程安全的），
/// 且只有在 `km_physmap_build()` 之后（自映射就绪）才有意义。
NSString *km_physmap_read_page_summary(uint64_t pa, void *out, size_t outSize);

/// 上面那次调用的多行诊断，**永不返回 nil**。
///
/// 第一行是那次调用的摘要（没调过就如实说没调过），之后**整块复用**
/// `km_physmap_window_diag()` 的内容 —— 不另开缓冲，也不覆盖
/// `km_physmap_diagnostic()` 里那份预检/执行的结论文本（那块有面板状态行的契约）。
NSString *km_physmap_read_page_diag(void);

/// 预检（**只读**）：把建表要用的每一个输入读出来并核对，一次内核写都不发。
///
/// 核对项（诊断里逐条成段）：
///   ① 前置：km_ready / XPF（按需初始化）/ PA→KVA 换算表（按需建立）/ slide / 几何
///   ② pmap 链路：proc → task → vm_map → pmap，以及 pmap->tte / pmap->ttep
///   ③ 窗口地址与它在本机页表几何下的索引（L1/L2/L3 三级都要不是 0 的判据）
///   ④ XPF 键逐个列出 registered / fetched / value
///   ⑤ vtophys_lvl 在窗口地址上的结果：**级号 + 断点表项自身的地址 + 读到的旧值**
///   ⑧ 物理页记账链：vm_first_phys / pv_head_table / PT_INDEX_MAX 算出的偏移，
///      以及"新页表页 PA"为什么在这一步还不存在（由执行阶段现场分配）
///   ⑨ pmap->sw_asid 的偏移与它的三条佐证（kernel_el / type / wx_allowed）
///   ⑩ **窗口槽位**：自映射是否就绪（magicPT）、窗口基址、槽位下标上界与页大小、
///      数据通道档位与原因、最近若干次 acquire 的槽位决策
///      （同一段内容也有单独入口：`km_physmap_window_diag()`，那一条只记下游动作）
///
/// 编号按**报告里的出现顺序**：①–⑥ 在前置装载里，⑦–⑩ 在预检主体，
/// 执行阶段紧接着 ⑪–⑭。
///
/// 可以重复调用；每次都重跑，**不缓存结论**（建表之后"有没有页表"会变）。
km_physmap_status km_physmap_precheck(void);

/// 执行（**写内核内存**）：建表 → 自映射 → sw_asid 那一步。
///
/// 前置检查在本函数内部重做一遍（不依赖调用方先跑 precheck），所以单独调它也安全。
///
/// 幂等：第二次调用时窗口地址上已经是自映射项，本函数会**直接返回
/// KM_PM_BUILD_ALREADY 且一个字节都不写**（判据见那个枚举值）。所以重复调用是安全的，
/// 而且不是"再写一遍一样的值"—— 无谓的内核写没有收益，只有风险。
///
/// 失败语义：任一步不符即**返回并停止**，不会继续下一级。已经完成的写入不回滚 ——
/// 回滚要再写一次，而写错的可能性比留下的状态更危险；诊断会写明停在哪一步、
/// 期望值是什么、回读值是什么。
km_physmap_build_status km_physmap_build(void);

/// 多行诊断文本，**永不返回 nil**。
/// 分区用「== xxx ==」标题行，不要依赖空行：面板会丢掉空行（见 showReport）。
/// 第一行是摘要（面板拿它当状态行），之后逐条列出每一步的判据与读到的值。
NSString *km_physmap_diagnostic(void);

#ifdef __cplusplus
}
#endif

#endif /* KernelPhysMap_h */
