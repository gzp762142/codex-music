//
//  KernelSlide.h
//  Aether
//
//  职责：只回答两个问题 ——
//    ① 这一台设备上内核被搬到哪去了（kernel slide / kernel base）；
//    ② 一个物理地址对应哪个内核虚拟地址（PA → KVA，即上游的 phystokv()）。
//
//  不负责：内核读写原语（KernelMemory.m 的 kopen/kread/kwrite）、
//          XPF 的初始化与 kernelcache 定位（libmemrw/xpf）、
//          页表遍历（KernelMemory.m 的 km_page_table_walk —— 方向相反：
//          那条路要用本模块算出的换算基准下钻，本模块不依赖它）。
//
//  依赖面只有三样，少一样都不成立：
//    · KernelMemory.h —— kread 的 C 接口（km_read / km_read64 / km_read_u32 /
//                        km_is_kernel_address）
//                        与两个只读访问器（km_current_proc / km_proc_fd_ofiles_offset）；
//    · XpfBridge.h    —— 从设备上的 kernelcache 解出内核符号的链接期 vmaddr，
//                        以及这份 kernelcache 自己的链接基址（km_xpf_kernel_base）；
//    · libkfd/perf.h  —— **算法参照**（不是依赖）：求 slide 的链与 phystokv 的
//                        8 段查表都逐行对照它实现，见 .m 里的行号引用。
//
//  安全前提（血债，写在最前面）：kread 会让内核按内核语义解引用目标地址，
//  读一个未映射的地址就是内核态 data abort（彩灯重启，不是 app 崩）。
//  所以本模块每一步读到的指针，在用于下一次 kread 之前都要过形态检查 ——
//  任何一步不过就立刻失败退出，并把「是哪一步、读到的值是多少」写进诊断。
//
//  本模块**只读**：全程不写任何内核内存，也不改任何内核状态。因此
//  "失败即终止本次会话" 那条纪律（KernelMemory.m 的 kopen 层）在这里不适用，
//  失败之后可以重来一次。
//
//  线程：内部状态由一把互斥锁保护；但**kread 本身不是线程安全的**
//  （libkfd 的 kread_sem_open 每次读都要改写自己 psemnode 的 pinfo），
//  所以调用方要保证本模块的调用与 MemoryProbe 的读取链不并发 ——
//  面板侧是靠 AutoTracker 那条串行队列做到的。
//
#ifndef KernelSlide_h
#define KernelSlide_h

#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stdint.h>

/// 算 slide、自检 kernel base、读回 ptov_table 与 gVirtBase/gPhysBase/gPhysSize。
///
/// 返回值是**整套**是否成立：true 表示 slide 已通过自检、且换算表三项都到位。
/// 返回 false 时不要一概当成"什么都没算出来"：
///   · km_slide_value() ≠ 0  ── slide 本身已通过自检（可信），只是换算表没读完；
///   · km_slide_value() == 0 ── slide 都没算出来，诊断里有失败在哪一步。
/// 这个区分是刻意的：slide 对上层（例如按链接期 vmaddr 反推运行时地址）单独有用，
/// 不该因为 ptov_table 读失败就把它一起丢掉。
///
/// 需要 km_ready() 成立（要 kread）。XPF 没就绪时本函数会自己调 km_xpf_init()
/// —— 那一步要解压解析几十 MB 的 kernelcache，可能几十秒，面板要给出等待提示。
///
/// 成功之后重复调用是空操作（直接返回 true）；失败之后可以重来。
bool km_slide_resolve(void);

/// 已算出的 kernel slide。未算出自检未通过时返回 0。
uint64_t km_slide_value(void);

/// kernel base = 链接基址 + slide（即 kernelcache 的 MH_MAGIC_64 所在地址）。
///
/// 链接基址**不是**跨机型常量：优先取 XPF 现读的 gXPF.kernelBase
/// （XpfBridge.h 的 km_xpf_kernel_base），取不到才退回 .m 里那个兜底常量 ——
/// 两者在 ARM_LARGE_MEMORY 机型上相差整 2 TB，所以承诺里不能写死任何一侧的值。
/// 来源会在诊断里标明（link_const / link_xpf 两行）。
///
/// 未算出时返回 0。
uint64_t km_slide_kernel_base(void);

/// 换算表（ptov_table + gVirtBase/gPhysBase/gPhysSize）是否已就绪。
bool km_phystokv_ready(void);

/// **按需**建立 PA → KVA 换算表，并返回它此刻是否可用。
///
/// 为什么要有这个入口：面板上只有「Slide」按钮会触发 `km_slide_resolve()`，于是
/// 任何需要换算的下游（建窗探针、KernelPhysMap 的建表）都被迫要求用户"先点 Slide"。
/// 那是**实现耦合暴露给了用户**，不是真实依赖顺序。本函数把"我需要用换算"这件事
/// 收成一个入口：已就绪就立即返回 true；否则自己按需初始化 XPF、把那套自检跑完。
/// 调用方（KernelPhysMap、以及面板侧改过的「建窗」按钮）一律走它，
/// `km_phystokv_ready()` 保留下来只用于**显示状态**。
///
/// ── 为什么"换算表"和"slide"只能一起建立（如实写明，不含糊）──
///
/// 我不是没试过分开，是**分不开**，理由是数据依赖而不是代码摆放：
///   1. 读换算表要用符号的**运行时地址**，而符号地址 = 链接期 vmaddr + slide：
///      `slide_read_bases` 里是 `const uint64_t addr = symbol + slide;`
///      （KernelSlide.m:1852），`slide_read_ptov_table` 里是
///      `const uint64_t tableAddr = symbol + slide;`（KernelSlide.m:1524）。
///      **没有 slide 就不知道去 kread 哪个地址。**
///   2. slide 唯一可信的来源就是 `slide_run_find_slide` 的自检，发布点在
///      KernelSlide.m:2118-2121（`run.slideVerified` 只在自检通过后置位），
///      只有那个值才会被写出来。**自检的实际判据是两条**（复查时对着代码改准过，
///      早先这里写成"五个链接期符号各自反推一致"，那与代码不符）：
///        · `slide_verify_kernel_base`（KernelSlide.m:1109-1283）比对 kernel_base
///          **页首**那两个 32 位字：MH_MAGIC_64 与 cputype（上游 perf.h:112-118
///          的判据）。页首只能走**32 位读路径**（KernelMemory 的 km_read_u32，
///          delta = 0x04）；64 位路径的源访问从 addr − 0x08 起，会踩前一页 ——
///          前一页未映射就是整机 panic。两条路径的机制见那段注释，别简化。
///        · `slide_candidate_fits_image`（KernelSlide.m:750-819）做纯算术的映像窗口
///          检查，外加**最多两个**符号（ptov_table / gVirtBase）的偏移自洽 ——
///          取不到就跳过那一条（:797），所以缺符号时自检会降级成"只查头 + 算术"。
///      "五个符号各自反推一致"只是 `slide_read_bases`（KernelSlide.m:1807 起）里
///      的一句**注释**与诊断文本，代码里没有那条判据，
///      而且它发生在 slide 已经发布之后 —— 不能把它读成"自检更强"。
///      绕过上述两条去读表 = 在一个**未经验证**的地址上发 kread ——
///      那正是本工程两次彩屏的形态（KernelSlide.h:22-25 的血债那一段）。
///   3. `slide_run_load_tables` 的**这张表**只有一个提交点，且"全部到位才提交"
///      （KernelSlide.m:2072-2082：memcpy g_ptov 与三个基准、置 g_convertReady），
///      与 slide 的发布（:2118-2139）处在**同一个临界区**里 —— 中间状态对下游不可见。
///      要单独建表就得再开一个提交点，而脱离这个临界区的第二个提交点意味着
///      "slide 有了、表只读了一半"这种中间状态有机会被下游看见。
///      （不说"唯一一处写全局"：本模块还写 g_slide / g_kernelBase / 诊断缓冲，
///       安全边界是"同一临界区"而不是"只有一处写"。）
///
/// 所以在本轮实现下，`km_phystokv_ensure()` 与 `km_slide_resolve()` 的**可观测行为
/// 相同**（`slide_run_locked` 里 `g_convertReady` 与 `g_slideSettled` 同真同假）。
/// 本函数的价值不在行为差异，而在于：
///   · 把判据从"slide 那半也成立"改成"**换算表可用**"—— 判据落在真正被使用的东西上；
///   · 给下游一个**不需要知道按钮顺序**的入口（主控本轮要的就是这个）；
///   · 日后若 slide 的自检判据放松、或表的读取不再阻断整体成功，这个入口自动跟上，
///     调用方一行都不用改。
///
/// 返回 true 表示 `km_phystokv_ready()` 成立。失败原因见 `km_slide_diagnostic()`
/// 与 `km_xpf_last_error()`（两者都永不返回 nil）。
///
/// **只读**：本函数与它调用的整条链都只读内核内存（读符号、读那三个变量、读
/// ptov_table），一个字节都不写，也不改任何内核状态 —— 所以失败不留残留，
/// 重试是安全的。**但"可以重来"有一条边界，别说成无条件的**：
///   · kread 这一侧（读符号内容、读 ptov_table、读三个基准）—— 真的可以重来，
///     `g_slideSettled` 只在整体成功时置位（KernelSlide.m:2139）。
///   · **XPF finder 这一侧 —— 重来无效**：上游把 finder 的返回值（**包括 0**）
///     连同 cached 标志一起写在节点上（libxpf/xpf/xpf.c:702-705），只有
///     `xpf_stop()`（即 km_xpf_deinit()）才清链表，而 km_xpf_init() 在 ready 时
///     直接返回 true（XpfBridge.m:108-111）。所以某个键的 finder 一旦返回 0，
///     本进程内每次重试都会拿到同一个 0，`km_phystokv_ensure()` 会稳定地失败。
///     真要重试，得先 `km_xpf_deinit()` —— 代价是几十秒重新解析 kernelcache，
///     本函数**不**替你隐式做这件事（那会把一个几十秒的副作用藏在"再点一次"里）。
///     诊断文本会指出是哪一个键 fetched=no，据此可以判断该不该走那条路。
///
/// **耗时**：首次调用可能要解压解析几十 MB 的 kernelcache（几十秒，与「Slide」按钮
/// 同一条路径）。面板必须在调用前把按钮切到"计算中…"；这是预期耗时，不是卡死。
/// 需要 `km_ready()` 成立（要 kread）；内核层没就绪时直接返回 false，不尝试初始化 XPF。
bool km_phystokv_ensure(void);

/// PA → KVA，上游 perf.h 的 phystokv() 等价物：
///   ① 先查 ptov_table 的 8 段，命中返回 `pa - entry.pa + entry.va`；
///   ② 全落空则退回 `pa - gPhysBase + gVirtBase`（且要求 pa 落在
///      [gPhysBase, gPhysBase + gPhysSize) 内 —— 上游把这条写成 assert，
///      本工程不能用 assert，改成显式判据，不满足即视为换算不出来）。
///
/// **返回 0 表示换算不出来**（内核 VA 不会是 0，所以 0 是安全哨兵）。
/// 换算表未就绪时也返回 0。
uint64_t km_phystokv(uint64_t pa);

/// 指针的 PAC 还原：把内核结构里读出来的**签名指针**还原成可用的内核地址。
/// 等价于 libkfd/info/static_info.h:96-100 的
///     PTR_MASK = ONES(64 - T1SZ_BOOT) · PAC_MASK = ~PTR_MASK
///     UNSIGN_PTR(p) = SIGN(p) ? (p | PAC_MASK) : (p & ~PAC_MASK)
/// 其中 SIGN(p) = p & BIT(55)。T1SZ_BOOT 优先取 XPF 的
/// kernelConstant.T1SZ_BOOT，取不到按目标机（iPad14,3 / iPadOS 16.4.1）实测值 17
/// 兜底，**不写死** —— 写死了在 T1SZ = 25 的机型上会把内核地址的高位切错。
/// 解析结果在首次调用后缓存，后续调用不再进 XPF。
///
/// ── 用与不用的边界（这条比函数本身重要）──
///
/// **对内核地址幂等**：内核 VA 的 bit 55 恒为 1，还原走 `p | PAC_MASK` 那一支，
/// 而 PAC_MASK 每一位本来就是 1 —— 已经置位的位不会被改动，结果等于入参。
/// 所以「从内核结构里读出来、后面要当地址用」的值**可以无条件过一遍**，
/// 不会因为"它其实没被签名"而把值改坏。
///
/// **不要拿它处理用户态地址**：bit 55 = 0 时它走 `p & PTR_MASK` 那一支，
/// 会把 bit 47 以上**全部清掉**。那不是幂等，那是把地址改坏。
/// （因此它也不做任何形态回退：还原不动就原样返回，由调用方自己的形态检查去拒。）
///
/// **什么该过、什么不该过**：
///   · 该过 —— 内核结构里的**指针字段**（task->map、vm_map->pmap 等）；
///   · 不该过 —— 算出来的地址（链接期符号 + slide）、PTE 低位取出的**物理地址**、
///     页表项本身、以及符号的内容（例如 pv_head_table 的基址，上游 Dopamine
///     就是直接 kread64(ksymbol(...))，不做还原）。
///
/// **不加锁**：调用点（读取链）已持有别的锁，而本函数若取 g_slideLock 会与
/// km_slide_resolve / km_phystokv 在同一把锁上自锁死。所以它只做无锁的缓存读，
/// 可以安全地在持锁路径上调用。
///
/// 诊断口径：调用方应当把**原始读数与还原后的值一起打印**（`raw=0x… → 0x…`），
/// 否则真机失败时分不清是读错了还是还原错了 —— 与 KernelSlide.m 里 rawOut
/// 存在的理由同一条。
uint64_t km_unsign_ptr(uint64_t p);

/// 多行诊断文本，**永不返回 nil**。第一行是摘要（面板拿它当状态行），
/// 之后逐行列出每一步的判据与读到的值 —— 成功与失败都能看。
/// 分区用「== xxx ==」标题行，不要依赖空行：面板会丢掉空行。
NSString *km_slide_diagnostic(void);

#endif /* KernelSlide_h */
