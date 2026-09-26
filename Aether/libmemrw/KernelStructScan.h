//
//  KernelStructScan.h
//  Aether
//
//  「task 到底是不是 task」—— **只做一级读**的探针。
//
//  ── 这个模块的重心为什么变了（真机 panic 证据）──
//
//  上一版在 task 的每个「形如内核地址」的槽上再做一次读（把槽值当地址、读它指向的
//  对象），用来验证候选 vm_map / pmap。真机上点了对应按钮之后整机 panic（不是 App 崩）：
//
//      Kernel data abort
//      esr = 0x96000007   (EC = 0b100101 同 EL 级；DFSC = 0b000111 = level-3 translation fault)
//      far = 0xfffffe1009577ffc
//      x8  = 0xfffffe1009577ff4     (far == x8 + 8)
//      Zone map: 0xfffffe10f10e4000 - 0xfffffe16f10e4000
//      Kernel text base: 0xfffffe0022084000
//      Panicked task: 3603 pages, 10 threads: pid 370: Music
//
//  根因：那个候选地址「形如内核地址」（高 16 位 0xffff）却落在 **physmap 的空洞**里 ——
//  physmap 只映射真实 DRAM，设备 MMIO、DRAM bank 间隙、固件保留区都没有物理页 backing，
//  于是 L2 表覆盖了那段 VA 却没有 L3 表项（DFSC 报 level-3 正是这个）。而本模块的 kread
//  是**让内核替我们解引用**（改 psemnode->pinfo 指向目标地址，再调
//  proc_info(PROC_INFO_CALL_PIDFDINFO) 把内容读回来），内核 EL1 的 data abort 默认致命：
//  只有 copyin/copyout 那类显式注册了故障恢复 handler 的代码才会把 fault 变成错误返回，
//  我们的路径不在其列。
//
//  **结论：在现有 kread 路径下，「读一个未经确认的地址」没有安全形式。** 所以本次改动把
//  二级读**整类删除**，只保留一级读。
//
//  ── 一级读允许的范围（唯一）──
//
//  `task + 0x00` … `task + 0xF8`，步长 8（32 个槽），外加一次 `task + 0x00` 的前置
//  可读性读。这些地址都落在 **task 结构自身内部**，而 task 那个地址已被证明可读
//  （上一版读过它的 +0x28，没有崩）。**除此以外任何地址都不许读。**
//
//  ── 新判据：bsd_info，以及一个必须写在它前面的前提 ──
//
//  逐槽读出的值**只分类、不解引用**：是否等于 km_current_proc()；是否落在内核地址域；
//  是否为小整数（< 0x10000）；其余按十六进制原样打印。分类之前先做 PAC 还原（下一条）。
//
//  ── 分类之前先 `km_unsign_ptr` ──
//
//  内核结构里的**指针字段**是 PAC 签名的，高 17 位是签名而不是地址，所以原始读数
//  会落在内核地址域之外。真机上实测到的形态：`task+0x28`（vm_map）读回
//  `0x52bc7e10023e93c0` —— 高 16 位 `0x52bc` ≠ `0xffff`，于是被旧分类器归进 `[other]`。
//  还原之后它落在哪一类**由还原结果决定，不由本文件预设**：本模块把还原后的值拿去
//  分类，并且两个值都打印，读到诊断的人看到的就是实际结果。上游同样每次都还原：
//  libkfd/info.h:144-145 取 `task__map` 之后紧接着 `UNSIGN_PTR`，本工程的
//  KernelSlide / KernelPhysWindow / KernelPhysMap 也各自在做。
//
//  所以：**每读到一个值，先 `km_unsign_ptr` 还原，再拿还原后的值分类**，并且把
//  「原始读数 → 还原后」两个值都打进诊断（`raw <value> -> <value>`）。否则这份诊断
//  会说出假话：把一个内核指针标成 `[other]`。还原后的值**只用于分类与打印，永远
//  不参与任何地址运算** —— 那正是零二级读那条铁律。
//
//  用 `km_unsign_ptr` 的边界（照抄 KernelSlide.h:162-177 的结论，这里只记与本模块
//  有关的两条）：**对内核地址幂等**（内核 VA 的 bit 55 恒为 1，走 `p | pacMask`
//  那一支，已置位的位不会被改动），所以「从内核读出来、后面当地址用」的值可以
//  无脑过一遍；**对用户态地址会清掉 bit 47 以上**，绝对不要拿它处理用户态地址 ——
//  本模块只处理从内核读出来的槽值，正好落在允许的那一侧。
//
//  它**纯还原、不读取、不解引用**（KernelSlide.m:2126-2129 一行 `return`），加它
//  不引入任何内核访问 —— 零二级读那条铁律不被折损，一个字节都没折损。
//
//  ── 判据与它的边界 ──
//
//  本探针把每个槽分四类（等于 current_proc / 内核地址域 / 小整数 / other），
//  就这些。它**只回答一个问题**：`task + 0x00 … 0xF8` 这 32 个槽里，有没有哪一个
//  **等于** `km_current_proc()`。命中 ⟺ 这个对象里存在一个回指本进程 proc 的槽
//  （`bsd_info` 就是这样一个反向指针），那个槽的偏移就是实测偏移。
//
//  没有命中 ⇒ **只说明这个窗口里没有回指 current_proc 的槽**。它**不是**一条关于
//  上游 `proc + km_proc_object_size()` 的结论，本探针不再对这个推导下任何判断：
//  那条等式在上游是成立的，同一个库**两个方向都在用**它 ——
//    · 正方向 libkfd/info.h:137
//      `current_task = current_proc + dynamic_info(proc__object_size)`；
//    · 反方向 libkfd/krkw/kread/kread_sem_open.h:100-101
//      `task_kaddr = static_kget(struct semaphore, owner, …)` 之后
//      `proc_kaddr = task_kaddr − dynamic_info(proc__object_size)`。
//  库自身不矛盾，所以等式没有嫌疑可挂；没命中就是没命中，本模块到这里为止。
//
//  为什么 `task->map` 的偏移 0x28 与这件事无关（省得下一个人再来问）：那个偏移由三个
//  来源交叉确认，与本探针的判据互不相干 ——
//    · _Aether_rev/refs/Dopamine/BaseBin/libjailbreak/src/info.c:67
//      硬编码 `gSystemInfo.kernelStruct.task.map = 0x28;`
//    · .../Application/Dopamine/Exploits/kfd/kfd.m:175 把它喂进 kfd 表
//      （`.task__map = koffsetof(task, map)`）
//    · 本项目 Aether/libmemrw/kfd/libkfd/info/dynamic_info.h 七个条目全是
//      `.task__map = 0x0028`
//  本探针读不出 `task->map` 的值，因为那要求读候选 vm_map 内部（二级读，已整类删除）；
//  它只读 task 自己的槽。
//
//  ── 状态机（五个 STATE，互不冒充）──
//
//  第一行是摘要 `[structscan] STATE=...`：
//    · STATE=not_ready       —— 前置不成立（内核层未就绪 / current_proc 或
//                               proc__object_size 为 0 / proc + object_size 溢出 /
//                               task 不过形态门），**一次 kread 都没发**；
//    · STATE=task_unreadable —— task 自身读失败（task+0x00 两次读不一致）：另一种
//                               前置失败，必须与「扫完了但没命中」分开看；
//    · STATE=no_bsd_info     —— 窗口读完（或读到读失败），**没有任何槽等于
//                               current_proc** ⇒ 这个窗口里没有回指本进程 proc 的槽。
//                               它**只是关于这个窗口的观测**，不是关于上游 proc → task
//                               推导的结论（见上文「判据与它的边界」）；
//    · STATE=hit_bsd_info    —— 找到，返回值就是那个偏移（不止一个时取最低的那个，
//                               并在正文里把全部命中列出来）；
//    · STATE=partial         —— 窗口没走完（读预算耗尽 / 地址溢出守卫触发），
//                               **不返回偏移**，也不冒充 no_bsd_info。
//
//  ── 硬约束（违反任一条 = 整机内核 panic，不是 App 崩）──
//
//  1. **零二级读**：模块里不存在任何「把读出来的值当地址再读」的代码路径。旧版的
//     km_ss_pmap_like / km_ss_inspect_candidate（连同它们用到的 PA 域判据）整块删除，
//     不是注释掉、也不是加开关。改完后的验证方式：把本文件所有 km_read64 的实参
//     列出来，只允许出现 `task + <编译期常量>` 这一种形态。
//  2. 每一条送进 km_read* 的地址，**使用前**过形态检查：内核地址域 + 8 字节对齐
//     + 非 0。检查保留，即使当前唯一的地址来源（task + N）已经天然满足它 ——
//     它同时把「task 本身没对齐」变成一行诊断，而不是一次形态可疑的读。
//  3. 不用兜底常量把失败包装成成功。没有命中就报 no_bsd_info，并**只**说明「这个窗口
//     里没有槽等于 current_proc」；连"命中偏移与版本表 0x28 不一致"这件事也不悄悄
//     采信任何一侧。
//  4. 不碰 KernelMemory.m 的止损逻辑、不碰 libxpf 快照、不改 KernelPhysWindow /
//     KernelPhysMap 的对外接口 —— 本模块是**旁路探针**，那两个模块日后可以调它。
//
//  ── 依赖 ──
//
//  · KernelMemory.h —— km_ready / km_read64 / km_current_proc / km_proc_object_size /
//    km_task_map_offset（最后一个**只用于佐证打印**，从不参与取舍）；
//  · KernelSlide.h —— **只用 `km_unsign_ptr` 这一个纯还原入口**（KernelSlide.h:186），
//    本文件里它的调用点只有一处（槽扫描循环内、分类之前），不用它任何会 kread 的东西 ——
//    km_slide_resolve / km_slide_diagnostic / km_phystokv 都不在本模块的调用面上。
//    `km_unsign_ptr` 自己不读、不解引用（KernelSlide.m:2126-2129 一行 `return`），
//    所以它回到依赖里**不放宽零二级读**：它只把读到的值摆正，摆正后的值照样不参与
//    任何地址运算。
//    旧版确实不依赖这个头（那时它拿 km_phystokv 给 pmap 判据做旁证，判据随二级读
//    一起删了）；本次把依赖加回来，理由就是分类前那次 PAC 还原。
//
//  ── 线程 ──
//
//  与 KernelSlide / KernelPhysWindow 同：本模块会 kread，而 libkfd 的 kread 后端不是
//  线程安全的（kread_sem_open 每次读都要改写自己 psemnode 的 pinfo）。调用方必须与
//  读取链串行 —— 面板侧靠 AutoTracker.shared.syncExternal 做到。
//
#ifndef KernelStructScan_h
#define KernelStructScan_h

#import <Foundation/Foundation.h>
#include <stdint.h>

/// 只读：判定 `proc + km_proc_object_size()` 给出的那个对象里，**有没有一个槽等于
/// `km_current_proc()`**（`bsd_info` 就是一个这样的反向指针），有的话给出实测偏移。
/// 它**不**判定这个对象是不是 struct task —— 那要读二级指针，已整类删除。
///
/// 返回命中偏移（字节，等于 current_proc 的那个槽）；**0 表示没有可用的偏移**。
/// 为什么用 0 而不是 bool：调用方要的是偏移本身，而"哪一种没拿到"在诊断文本里
/// （第一行的 `[structscan] STATE=...`），几种语义完全不同、必须能分开看 ——
/// 见上面的状态机一节。
///
/// **函数名是历史遗留**：它不再是「task->map 偏移」的测量入口。测那个偏移必须读候选
/// vm_map 内部，而二级读已经整类删除（理由见上文的 panic 证据）。返回值是 bsd_info
/// 偏移，与版本表 task__map 相等与否**不构成任何结论** —— 两个不同的字段。
///
/// **它回答的只有一件事**：`task + 0x00 … 0xF8` 这 32 个槽里有没有哪一个等于
/// `km_current_proc()`，有的话给出那个槽的偏移。返回 0 **不代表**上游
/// `task = proc + km_proc_object_size()` 推导有问题 —— 那条等式成立（库自身两个方向
/// 都在用它，证据见上文），返回 0 只是说这个窗口里没有那个槽，见状态机里的
/// STATE=no_bsd_info。
///
/// **返回 0 时调用方不许退回版本表常量硬扛** —— 那正是本模块存在的理由
/// （KernelPhysWindow 现在读 task+0x28 拿到 `0x52bc7e10023e93c0` 就是这个后果：
/// 那是一个 PAC 签名后的内核指针，不是版本表常量的替代品）。
///
/// 需要 km_ready() 成立（要 kread）。可以重复调用，每次重扫（结论不会变，但 task
/// 地址会变，缓存结论会让"换一次现场再测"拿到旧答案）。
uint64_t km_scan_task_map_offset(void);

/// 多行诊断文本，**永不返回 nil**。
/// 分区用「== xxx ==」标题行，不要依赖空行：面板会丢掉空行（见 KernelPhysWindow.m:119）。
/// 第一行是摘要，形如 `[structscan] STATE=hit_bsd_info offset=0x10`，之后逐条列出实测值 ——
/// 窗口只有 32 个槽，所以每一个槽都单独一行（值 + 分类），失败路径也要能读出"它为什么
/// 不像"。**每个槽打印的是「原始读数 → PAC 还原后」两个值**，分类按还原后的值做；
/// 第 6 节专门列出所有「落在内核地址域」的槽并写明它们**没有被读取**及其理由。
NSString *km_scan_diagnostic(void);

#endif /* KernelStructScan_h */
