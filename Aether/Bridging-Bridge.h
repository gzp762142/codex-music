#import "FangUISystemWindow.h"
#import "FangUISBSHosting.h"
#import "FangUIOrientationBridge.h"
// 内核内存读写层（libmemrw）：C 接口，实现在 KernelMemory.m ——
// 那是全工程唯一 include libkfd.h 的地方，其余文件只能走这个头。
#include "KernelMemory.h"
// 进程枚举需要 sysctl 与 kinfo_proc。iOS SDK 里有 <sys/sysctl.h>，
// 但**没有 <libproc.h>**（那是 macOS 的手册），所以 proc_listpids / proc_pidpath
// 无法在编译期声明，改在 Swift 里用 dlsym 运行时取。
#include <sys/sysctl.h>
