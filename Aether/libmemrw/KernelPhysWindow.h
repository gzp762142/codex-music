//
//  KernelPhysWindow.h
//  Aether
//
//  「建页表窗口」这条路的第一段 —— **只读验证**。
//
//  ── 这条路要干什么（与样本逐字对齐，证据见 docs/当前任务.md §0.4）──
//
//  样本的 physrw 分四步：
//    ① PUAF（landa）拿可写窗口                       ← 本工程已有（libkfd）
//    ② 在固定地址上让内核建出页表页 + 写自映射         ← 本模块只做它的**前半段**
//    ③ 用普通 str 把目标物理页的 PTE 挂进窗口
//    ④ 本地 memcpy 读
//
//  第 ② 步的现场（样本 `[0x101049a7c, 0x10104cf00)` 内，VA 0x10104cdc0 起）：
//      0x10104cdc8  bl   #0x101093820   ; ret = L1_BLOCK_SIZE
//      0x10104cdd0  bl   #0x1010939d0   ; ret = L1_BLOCK_COUNT
//      0x10104cdd4  sub  x8, x0, #1
//      0x10104cdd8  mul  x1, x8, x26    ; x1 = (COUNT-1)*SIZE = 0x7000000000
//      0x10104cddc  mov  x0, x25        ; x0 = pmap
//      0x10104cde8  bl   #0x1010488e0   ; ★ 在 0x7000000000 上取/建页表 → 页表页地址
//      0x10104ce34  bl   #0x10104f800   ; ★ physwrite64(magicPT, magicPT|PTE) 自映射
//  与 Dopamine `BaseBin/libjailbreak/src/physrw_pte.c:13` 同源：
//      #define MAGIC_PT_ADDRESS (L1_BLOCK_SIZE * (L1_BLOCK_COUNT - 1))
//  而且**两边的取值也相同**：16K 下 get_l1_block_count() 返回 8
//  （Dopamine `info.c:355-365`），8 − 1 = 7 → 2^36 × 7 = 0x7000000000。
//  此前这里写过"Dopamine 取 511"，那是笔误（511 对应 4K 那套几何的另一支），
//  实际两边算出的窗口地址一模一样 —— 这是「样本走的就是这条路」的一条数值证据。
//
//  ── 本模块要回答的**唯一问题** ──
//
//      「窗口地址上现在有没有已存在的页表？」
//
//    有 → 第 ② 步的建表部分可以省，直接进入「写自映射」（下一段的任务）；
//    没有 → 必须先解决「怎么让内核建出这张表」，那是下一段的任务。
//
//  所以本模块**只读**：从 current_proc 自己走一遍 proc → task → vm_map → pmap，
//  读出 pmap 的 tte / ttep，再以 ttep 为起点对窗口地址逐级下行，把每一级读到
//  什么、是表描述符还是块/叶，逐条打出来。
//
//  ── 硬约束（写在头文件里，因为它比实现更容易被日后改动破坏）──
//
//  1. **一次写操作都不做**。本模块、以及它调用的每一条路径（km_read /
//     km_read64 / km_phystokv）内部都只有读。写自映射属于下一段。
//  2. 每个 kread 的地址在用于下一次读之前必须过形态检查（内核地址域 + 8 字节
//     对齐），判据见 .m 里的 physwindow_shape_ok()。本工程的血债：kread 一个
//     未映射地址 = 内核态 data abort = 整机彩屏重启，不是 app 崩。
//  3. 取不到就如实报「取不到」，不许用兜底常量把失败包装成成功
//     —— 那正是 g_linear_delta 那次彩屏的形态（见 KernelMemory.m 里
//     "0 会被形态检查拦下、错值不会"那段）。
//
//  ── 依赖 ──
//
//  · KernelMemory.h —— kread 的 C 接口、km_current_proc、以及四个只读访问器
//    （km_task_map_offset / km_proc_object_size / km_vm_map_pmap_offset / km_kernel_page_size）；
//  · KernelSlide.h  —— km_phystokv / km_phystokv_ready：页表项里的地址是**物理**地址，
//    而下钻要的是 KVA，这一步换算必须有可信来源。刻意**不**用 pmap 的
//    `tte − ttep` 那种"一次相减"兜底 —— 它只对顶层表所在那一段成立，
//    拿它换段外的物理页就是 bug_type 210 那份 panic（KernelMemory.m 里有完整推导）。
//
//  ── 线程 ──
//
//  与 KernelSlide 同：本模块会 kread，而 libkfd 的 kread 后端不是线程安全的
//  （kread_sem_open 每次读都要改写自己 psemnode 的 pinfo）。调用方必须与
//  读取链串行 —— 面板侧靠 AutoTracker.shared.syncExternal 做到。
//
#ifndef KernelPhysWindow_h
#define KernelPhysWindow_h

#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stdint.h>

/// 探针结果。**刻意不合并成 bool**：调用方（面板与下一段）要区分
/// 「还不知道」与「知道且没有」—— 前者该去补前置条件，后者是建表的依据。
typedef enum {
    /// 走通了：窗口地址上**已有**到 L3 的有效页表项（判据在 .m 里逐级写明）。
    KM_PW_HIT_EXISTING = 0,
    /// 前置不成立：内核层未就绪 / KernelSlide 换算表未就绪 / 页大小取不到。
    /// **不是**"没有页表"，是"还没资格问这个问题"。
    KM_PW_NOT_READY,
    /// pmap 链路某一环取不到（值为 0、形态不过、或地址读失败）。
    /// 诊断里会指明断在哪一环、读到的是什么值。
    KM_PW_PMAP_UNRESOLVED,
    /// 页表在窗口地址之前就断了：某一级表项 invalid，或本该是表描述符却是块描述符。
    /// **这就是「窗口地址上现在没有页表」** —— 下一段要先解决让内核建表。
    KM_PW_NO_TABLE,
    /// 走到了 L3 且表项有效，但不是叶（L3 之下无处可去）。属于异常形态，照实报。
    KM_PW_L3_NOT_LEAF,
    /// 内部缓冲装不下诊断文本（只影响可读性，不影响结论前的判据）。
    KM_PW_TRUNCATED
} km_physwindow_status;

/// 窗口地址 —— 样本公式 `L1_BLOCK_SIZE × (L1_BLOCK_COUNT − 1)`（取 COUNT = 7）。
/// 目标机（16K 粒度）为 0x7000000000；4K 粒度下是 0x3FC0000000。
/// 取不到页大小、或页大小不是 16K/4K 时返回 0。
///
/// 说明：本函数**不碰内核、不改任何状态**（只读 hw.pagesize），所以任何线程
/// 任何时候都可以调。但面板请用 km_physwindow_last_address() 而不是这个 ——
/// 理由见那个函数。
uint64_t km_physwindow_address(void);

/// 最近一次 km_physwindow_probe() 算出的窗口地址（0 表示那次没算出来，或还没跑过）。
///
/// 为什么面板要读这个而不是自己调 km_physwindow_address()：显示窗口地址时
/// 探测正跑在后台线程上，两条路径都去碰同一份进程级状态（sysctl 与静态缓冲），
/// 面板再算一次就多出一条"绕过串行队列"的调用。结论值一律由那次探测算好后传入，
/// 面板只负责显示，两边不复算 —— 与 physWindowReport 那条口径一致。
uint64_t km_physwindow_last_address(void);

/// 跑一次只读探针。返回值为上面的状态枚举（**不返回 bool**，理由见枚举注释）。
///
/// 需要 km_ready() 成立（要 kread）。**全程不写任何内核内存**：写自映射是下一段。
/// 可以重复调用；每次都会重跑（不缓存结论 —— 页表状态会在建表之后改变，
/// 缓存会让"建完再探一次"永远拿到建之前的结果）。
km_physwindow_status km_physwindow_probe(void);

/// 多行诊断文本，**永不返回 nil**。
/// 分区用「== xxx ==」标题行，不要依赖空行：面板会丢掉空行（见 showReport）。
/// 第一行是摘要（面板拿它当状态行），之后逐条列出每一步的判据与读到的值。
NSString *km_physwindow_diagnostic(void);

#endif /* KernelPhysWindow_h */
