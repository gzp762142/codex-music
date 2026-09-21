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
//    · KernelMemory.h —— kread 的 C 接口（km_read / km_read64 / km_is_kernel_address）
//                        与两个只读访问器（km_current_proc / km_proc_fd_ofiles_offset）；
//    · XpfBridge.h    —— 从设备上的 kernelcache 解出内核符号的链接期 vmaddr；
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

/// kernel base = ARM64_LINK_ADDR + slide（即 kernelcache 的 MH_MAGIC_64 所在地址）。
/// 未算出时返回 0。
uint64_t km_slide_kernel_base(void);

/// 换算表（ptov_table + gVirtBase/gPhysBase/gPhysSize）是否已就绪。
bool km_phystokv_ready(void);

/// PA → KVA，上游 perf.h 的 phystokv() 等价物：
///   ① 先查 ptov_table 的 8 段，命中返回 `pa - entry.pa + entry.va`；
///   ② 全落空则退回 `pa - gPhysBase + gVirtBase`（且要求 pa 落在
///      [gPhysBase, gPhysBase + gPhysSize) 内 —— 上游把这条写成 assert，
///      本工程不能用 assert，改成显式判据，不满足即视为换算不出来）。
///
/// **返回 0 表示换算不出来**（内核 VA 不会是 0，所以 0 是安全哨兵）。
/// 换算表未就绪时也返回 0。
uint64_t km_phystokv(uint64_t pa);

/// 多行诊断文本，**永不返回 nil**。第一行是摘要（面板拿它当状态行），
/// 之后逐行列出每一步的判据与读到的值 —— 成功与失败都能看。
/// 分区用「== xxx ==」标题行，不要依赖空行：面板会丢掉空行。
NSString *km_slide_diagnostic(void);

#endif /* KernelSlide_h */
