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
// 「建页表窗口」第二段的**写入**路径（libmemrw，实现在 KernelPhysMap.m）：
// 在窗口地址 0x7000000000 上手工建出页表、写自映射 —— 与上面那个只读探针是
// 同一件事的两半，但**会写内核内存**，所以是两个按钮、两套状态枚举。
// XPF 初始化与 PA→KVA 换算表由它自己在入口经 km_phystokv_ensure() 按需建立，
// 所以面板上不必先点「Slide」（首次会花几十秒解析 kernelcache，按钮要先切到
// "计算中…"）。调用同样要与读取链串行（AutoTracker.syncExternal）。
#include "KernelPhysMap.h"
// 「task 结构自身那 32 个槽里有什么」的**只读**探针（libmemrw，实现在
// KernelStructScan.m）：上一版会对 task 里每个「形如内核地址」的槽再做一次读
// （二级读），真机上让整机内核 panic —— 机制是 kread 把 psemnode->pinfo 改成
// `kaddr − 0x0C`，目标地址的页内偏移不足时内核先踩到前一页（完整推导见
// KernelMemory.m 的页下溢闸门那一段与 KernelStructScan.h 开头），
// 所以二级读整类删除。现在它只读 task 自身窗口内的 32 个槽
// （task+0x00 … task+0xF8），每个槽先过 km_unsign_ptr 做 PAC 还原、再分类，
// 判据是「有没有哪个槽等于 current_proc」。它**只回答这个窗口里的问题**，
// 不对 `task = proc + proc__object_size` 这条上游推导下任何判断 ——
// 那条等式在上游同一个库里两个方向都被使用（info.h:137 与 kread_sem_open.h:100-101）。
// **全程一次内核写都不发**，所以它失败了可以直接重跑。
#include "KernelStructScan.h"
// 进程枚举需要 sysctl 与 kinfo_proc。iOS SDK 里有 <sys/sysctl.h>，
// 但**没有 <libproc.h>**（那是 macOS 的手册），所以 proc_listpids / proc_pidpath
// 无法在编译期声明，改在 Swift 里用 dlsym 运行时取。
#include <sys/sysctl.h>
