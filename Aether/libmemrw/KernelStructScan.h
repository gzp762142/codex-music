//
//  KernelStructScan.h
//  Aether
//
//  「task->map 的偏移到底是几」—— **只读**探针。
//
//  ── 为什么需要它（真机证据）──
//
//  目标机（iPad14,3 / M2 / iPadOS 16.4.1）上「建窗」探针卡在 pmap 链路：
//
//      current_proc = 0xfffffe14cd4a8a40          ← 合法内核 VA
//      task         = 0xfffffe14cd4a9170          ← = proc + 0x730（proc__object_size）
//      task + 0x28  → 0x52bc7e10023e93c0          ← 高位 0x52bc，不在内核地址域
//
//  而 proc → task 这一步用的是同一条口径，两条独立证据（public chain 用
//  `task − object_size` 反推 proc 并用 p_pid 校验、真机上 task − proc 恰等于
//  版本表常量）都成立 —— 所以错的不是那一步，是 `task->map` 的字段偏移。
//
//  版本表里 task__map = 0x28（dynamic_info.h，注释标明取自
//  "Lrdsnow/kfd_offsets 的 M1/iOS_16.4.1 表"）。该字段偏移在 iOS 16.x 各构建间
//  会在 0x28–0x40 区间浮动：**不因 SoC 而变、会因构建而变**。所以硬编码值不可靠，
//  必须**测**出来。
//
//  ── 判据（本模块的全部方法就这一段）──
//
//  ① 在 task 结构里扫 0x00 … 0x100（步长 8）的每个槽。
//  ② 槽值是内核地址域（km_is_kernel_address）才有资格当候选 vm_map。
//  ③ 在候选对象里扫 0x00 … 0x100，把每个内核地址形态的槽值当候选 pmap；
//     读它的头两个字段，要求**同时**满足：
//          pmap+0x00 是内核地址域      ← tte 是 KVA
//          pmap+0x08 是物理地址域      ← ttep 是 PA（非 0、< 2^48、16K 对齐）
//     字段布局见 Aether/libmemrw/kfd/libkfd/info/static_info.h:255-257
//     （struct pmap 以 tte / ttep 开头）；KernelPhysWindow.m:663-665 读的是同一对。
//
//  为什么这条判据"硬"：KVA 与 PA 的物理意义互斥 —— 物理地址高 16 位恒为 0
//  （static_info.h:55 的 ARM_TTE_PA_MASK 就是 0x0000fffffffff000），而内核 VA
//  高 16 位恒为 0xffff。所以**一个结构里相邻 8 字节一个是 KVA 形态、一个是 PA 形态**
//  这个组合，与具体结构体的字段顺序无关，不是"某个偏移恰好如此"。
//
//  ④ **唯一性**：task 层只允许一个槽位通过上述全部判据。
//     vm_map 里只有 `pmap` 那一个字段指向 pmap 对象（其余是锁、vm_map_links、
//     rbh_root 这些**值**或指向别的对象的指针），所以真 vm_map 必然只出一条。
//     并列两个以上 → 返回 0 并把并列项全列出来，**绝不挑一个**。
//
//  ── 硬约束（违反任一条 = 整机内核 panic，不是 App 崩）──
//
//  1. **全程只读**：本模块一次 km_write / kwrite 都不发。这是它能在设备上安全
//     跑的前提，也是它与 KernelPhysMap 的分界线（后者是写路径，见
//     KernelPhysMap.h:8-16 的分工说明）。
//  2. 每一条送进 km_read* 的地址，**使用前**过形态检查：内核地址域 + 8 字节对齐
//     + 非 0。**由上一步读到的值算出来的地址必须再查一次** —— 那正是"读到一个
//     形态合法但内容错的值、再拿它去解引用"的形态（KernelMemory.m:1580、
//     KernelMemory.m:1695 记的两次彩屏就是这个）。
//  3. 不用兜底常量把失败包装成成功。扫完没命中就报未命中，并列就报并列。
//     连"命中偏移与版本表 0x28 不一致"这件事也照实打印，不悄悄采信任何一侧。
//  4. 不碰 KernelMemory.m 的止损逻辑、不碰 libxpf 快照、不改 KernelPhysWindow /
//     KernelPhysMap 的对外接口 —— 本模块是**旁路探针**，那两个模块日后可以调它。
//
//  ── 依赖 ──
//
//  · KernelMemory.h —— km_read64 / km_is_kernel_address / km_current_proc /
//    km_proc_object_size / km_task_map_offset / km_vm_map_pmap_offset / km_kernel_page_size；
//  · KernelSlide.h  —— km_phystokv_ready / km_phystokv，**只用于佐证打印**，
//    不参与取舍（换算表未就绪时 km_phystokv 恒返回 0，拿它当硬判据会误杀正确解）。
//
//  ── 线程 ──
//
//  与 KernelSlide / KernelPhysWindow 同：本模块会 kread，而 libkfd 的 kread 后端
//  不是线程安全的（kread_sem_open 每次读都要改写自己 psemnode 的 pinfo）。
//  调用方必须与读取链串行 —— 面板侧靠 AutoTracker.shared.syncExternal 做到。
//
#ifndef KernelStructScan_h
#define KernelStructScan_h

#import <Foundation/Foundation.h>
#include <stdint.h>

/// 只读：在 task 结构里测出 vm_map 字段的偏移。
///
/// 返回命中偏移（字节）；**0 表示没有唯一命中**。为什么用 0 而不是 bool：
/// 调用方要的是偏移本身，而"哪种没命中"在诊断文本里（第一行的
/// `[structscan] STATE=...`），三者语义完全不同、必须能分开看：
///   · STATE=not_ready   —— 前置不成立（内核层未就绪 / current_proc 或
///                          proc__object_size 取不到），**一次 kread 都没发**；
///   · STATE=miss        —— 扫完了，没有任何槽位通过判定（诊断里逐槽列出读到什么）；
///   · STATE=ambiguous   —— 有多个槽位通过判定，**不能确定是哪一个**（并列项已列出）；
///   · STATE=hit_unique  —— 唯一命中，返回值就是它。
///
/// **返回 0 时调用方不许退回版本表常量硬扛** —— 那正是本模块存在的理由
/// （KernelPhysWindow 现在读 task+0x28 拿到 0x52bc7e10023e93c0 就是这个后果）。
///
/// 需要 km_ready() 成立（要 kread）。可以重复调用，每次重扫（偏移不会变，但
/// task 地址会变，缓存结论会让"换一次现场再测"拿到旧答案）。
uint64_t km_scan_task_map_offset(void);

/// 多行诊断文本，**永不返回 nil**。
/// 分区用「== xxx ==」标题行，不要依赖空行：面板会丢掉空行（见 KernelPhysWindow.m:119）。
/// 第一行是摘要，形如 `[structscan] STATE=hit_unique offset=0x28`，之后逐条列出
/// 每一步的判据与**实测值** —— 失败路径也要能读出"它为什么不像"。
NSString *km_scan_diagnostic(void);

#endif /* KernelStructScan_h */
