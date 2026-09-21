#import "FangUISystemWindow.h"
#import "FangUISBSHosting.h"
#import "FangUIOrientationBridge.h"
// XPF 符号解析层（libmemrw/xpf）：读设备上的 kernelcache、按内核源码字符串定符号。
// 与 KernelMemory.h 那条内核读写通路无关 —— 它只碰文件与 mmap，不需要 kopen 成功，
// 所以内核层挂掉时它照样能给出判据。
// 头文件目录已由 HEADER_SEARCH_PATHS 的 $(SRCROOT)/Aether/libmemrw/xpf 覆盖。
#import "XpfBridge.h"
// 内核内存读写层（libmemrw）：C 接口，实现在 KernelMemory.m ——
// 那是全工程唯一 include libkfd.h 的地方，其余文件只能走这个头。
#include "KernelMemory.h"
// 内核 slide 与 PA→KVA 换算（libmemrw，实现在 KernelSlide.m）：
// 用 XPF 的符号 + 一条 vnode fd 的 fileops 算出 slide，再读回 ptov_table。
// 它要 kread，所以面板侧必须与读取链串行（见 DebugProcView.runSlideProbe）。
#include "KernelSlide.h"
// 「建页表窗口」第一段的只读探针（libmemrw，实现在 KernelPhysWindow.m）：
// 从 current_proc 走 proc→task→vm_map→pmap，读出 tte/ttep，再对窗口地址
// 0x7000000000 逐级下行 —— 只回答「那里现在有没有已存在的页表」。
// **全程只读**：一次内核写都不发，写自映射是下一段。
// 依赖 KernelSlide 的 km_phystokv（页表项里是 PA，下钻要 KVA），
// 所以面板侧同样要与读取链串行（见 DebugProcView.runPhysWindowProbe）。
#include "KernelPhysWindow.h"
// 进程枚举需要 sysctl 与 kinfo_proc。iOS SDK 里有 <sys/sysctl.h>，
// 但**没有 <libproc.h>**（那是 macOS 的手册），所以 proc_listpids / proc_pidpath
// 无法在编译期声明，改在 Swift 里用 dlsym 运行时取。
#include <sys/sysctl.h>
