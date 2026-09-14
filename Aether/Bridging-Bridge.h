#import "FangUISystemWindow.h"
#import "FangUISBSHosting.h"
#import "FangUIOrientationBridge.h"

// 进程枚举需要 libproc 与 sysctl 的声明：
//   proc_listpids / proc_pidpath / PROC_ALL_PIDS / PROC_PIDPATHINFO_MAXSIZE
//   kinfo_proc / sysctl / KERN_PROC_ALL
// 头文件放在这里，Swift 侧才能直接看到这些符号（Foundation 不导出 libproc）。
#include <sys/sysctl.h>
#include <libproc.h>
