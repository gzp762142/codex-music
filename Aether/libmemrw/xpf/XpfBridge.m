//
//  XpfBridge.m
//  Aether
//
//  职责：Aether 与 XPF 之间唯一的接缝 —— 初始化、按键取符号、回报错误。
//
//  不负责：找 kernelcache（XpfKernelcacheLocator）、判断文件可用性（XpfKernelcacheProbe）、
//          内核读写（KernelMemory.m 的事），以及调用方的接线。
//
//  线程：XPF 的全局状态（gXPF、键值链、错误缓冲）自己没有锁，所以这里用一把互斥锁把
//        init / deinit / resolve 串行化。锁覆盖 finder 的耗时是故意的：两个线程同时跑
//        finder 会让 XPF 的节缓存和键缓存互相踩。
//

#import "XpfBridge.h"

#import "XpfKernelcacheLocator.h"
#import "XpfKernelcacheProbe.h"

#import "../../libxpf/xpf/xpf.h"

#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma mark - 状态（进程内单例；只在 g_xpfLock 内读写）

/// 刻意用 C 类型而不是 ObjC 对象持有：这几个字段的生命周期不该取决于本文件编译时
/// 有没有开 ARC —— 若哪天编译选项变了，静态持有的 ObjC 字符串会退化成悬空指针，
/// 而 C 字符串不会。
typedef struct {
    bool   ready;                     // km_xpf_init 成功，且此后没有 km_xpf_deinit
    char   kernelcachePath[PATH_MAX]; // 成功加载的那一份，空串表示尚未加载
    char  *lastFailure;               // malloc 的说明文本（可多行），NULL 表示无失败
    double initSeconds;               // 最近一次成功初始化的耗时
} XpfBridgeState;

static pthread_mutex_t g_xpfLock = PTHREAD_MUTEX_INITIALIZER;
static XpfBridgeState  g_xpfState;

/// 换掉失败说明。ownedMessage 必须是 malloc 的或 NULL；锁内调用。
static void state_set_failure(char *ownedMessage)
{
    free(g_xpfState.lastFailure);
    g_xpfState.lastFailure = ownedMessage;
}

#pragma mark - 小工具

static double seconds_since(struct timespec start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - start.tv_sec) + (double)(now.tv_nsec - start.tv_nsec) / 1e9;
}

/// XPF 的错误缓冲既不会自动清空，也没有「读取后清除」，所以判断「本次调用是否设了新
/// 错误」只能拿调用前的内容比 —— 只看它非 NULL，会把上一次的旧错误说成本次原因。
static bool xpf_error_is_new_since(const char *errorBeforeCopy)
{
    const char *errorNow = xpf_get_error();
    if (!errorNow) return false;
    if (errorBeforeCopy && strcmp(errorBeforeCopy, errorNow) == 0) return false;
    return true;
}

/// 取不到值时把三种原因分开说：未初始化 / 键没注册 / finder 自己报了错（带 [文件:行]）。
static NSString *describe_resolve_failure(NSString *name, const char *errorBeforeCopy)
{
    if (xpf_error_is_new_since(errorBeforeCopy)) {
        return [NSString stringWithFormat:@"%@: finder failed — %s", name, xpf_get_error()];
    }
    return [NSString stringWithFormat:
            @"%@: resolved to 0 — key is not registered in XPF, or its finder failed without an error",
            name];
}

#pragma mark - 单个候选的加载

/// 把一个候选路径交给 XPF。失败时把「路径: 原因」记进 failures，并复位 XPF 全局状态 ——
/// 这是继续试下一个候选的前提（失败路径上 XPF 可能已经 open 了 fd、mmap 了文件）。
static bool xpf_try_load_candidate(NSString *path, NSMutableArray<NSString *> *failures)
{
    NSString *probeFailure = nil;
    if (!km_xpf_kernelcache_is_loadable(path, &probeFailure)) {
        [failures addObject:[NSString stringWithFormat:@"%@: %@", path, probeFailure]];
        return false;
    }

    if (xpf_start_with_kernel_path(path.fileSystemRepresentation, NULL, NULL) == 0) return true;

    const char *xpfError = xpf_get_error();
    [failures addObject:[NSString stringWithFormat:@"%@: xpf_start_with_kernel_path failed: %@",
                         path, xpfError ? @(xpfError) : @"(no error reported)"]];
    xpf_stop();
    return false;
}

#pragma mark - 对外接口

bool km_xpf_init(void)
{
    pthread_mutex_lock(&g_xpfLock);

    if (g_xpfState.ready) {
        pthread_mutex_unlock(&g_xpfLock);
        return true;
    }

    struct timespec startedAt;
    clock_gettime(CLOCK_MONOTONIC, &startedAt);

    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    NSString *loadedPath = nil;
    for (NSString *candidatePath in km_xpf_kernelcache_candidate_paths()) {
        if (xpf_try_load_candidate(candidatePath, failures)) {
            loadedPath = candidatePath;
            break;
        }
    }

    if (!loadedPath) {
        NSString *joinedFailures = [failures componentsJoinedByString:@"\n"];
        state_set_failure(strdup(joinedFailures.UTF8String));
        pthread_mutex_unlock(&g_xpfLock);
        return false;
    }

    g_xpfState.ready = true;
    g_xpfState.initSeconds = seconds_since(startedAt);
    snprintf(g_xpfState.kernelcachePath, sizeof(g_xpfState.kernelcachePath), "%s",
             loadedPath.fileSystemRepresentation);
    state_set_failure(NULL);
    pthread_mutex_unlock(&g_xpfLock);
    return true;
}

void km_xpf_deinit(void)
{
    pthread_mutex_lock(&g_xpfLock);

    // 只有 init 成功过才有东西要还：失败路径已经在 xpf_try_load_candidate 里复位过了。
    if (g_xpfState.ready) xpf_stop();
    g_xpfState.ready = false;
    g_xpfState.kernelcachePath[0] = '\0';
    g_xpfState.initSeconds = 0;
    // lastFailure 刻意保留：deinit 之后最可能被追问的就是「上次为什么没跑起来」。

    pthread_mutex_unlock(&g_xpfLock);
}

bool km_xpf_ready(void)
{
    pthread_mutex_lock(&g_xpfLock);
    bool ready = g_xpfState.ready;
    pthread_mutex_unlock(&g_xpfLock);
    return ready;
}

uint64_t km_xpf_resolve_symbol(NSString *name)
{
    pthread_mutex_lock(&g_xpfLock);

    if (name.length == 0) {
        state_set_failure(strdup("km_xpf_resolve_symbol: empty key name"));
        pthread_mutex_unlock(&g_xpfLock);
        return 0;
    }
    if (!g_xpfState.ready) {
        NSString *message = [NSString stringWithFormat:@"%@: XPF is not initialised — call km_xpf_init() first",
                             name];
        state_set_failure(strdup(message.UTF8String));
        pthread_mutex_unlock(&g_xpfLock);
        return 0;
    }

    const char *errorBefore = xpf_get_error();
    char *errorBeforeCopy = errorBefore ? strdup(errorBefore) : NULL;

    uint64_t value = xpf_item_resolve(name.UTF8String);
    if (value == 0) {
        NSString *message = describe_resolve_failure(name, errorBeforeCopy);
        state_set_failure(strdup(message.UTF8String));
    }

    free(errorBeforeCopy);
    pthread_mutex_unlock(&g_xpfLock);
    return value;
}

uint64_t km_xpf_kernel_base(void)
{
    pthread_mutex_lock(&g_xpfLock);

    /*
     * 两个"不可用"哨兵都要挡：0 是没填过，UINT64_MAX 是 xpf.c:587 判定的失败值
     * （那里的检查在 xpf_start 内部，但字段本身在失败路径上会留成这个值）。
     * 调用方拿它去拼 kernel_base 再 kread —— 让哨兵漏出去就是一次彩屏。
     */
    uint64_t base = 0;
    if (g_xpfState.ready) {
        const uint64_t value = gXPF.kernelBase;
        if (value != 0 && value != UINT64_MAX) base = value;
    }

    pthread_mutex_unlock(&g_xpfLock);
    return base;
}

#pragma mark - 「建页表窗口」那条路的键（KernelPhysMap 用）

/*
 * 键名表。**顺序必须与 XpfBridge.h 的 km_xpf_physmap_keys 字段顺序逐个对齐** ——
 * km_xpf_physmap_key_name 按下标取名字，取错名字会让诊断把 A 键的结果挂在 B 键
 * 的标题下，而那种错在屏幕上看起来完全正常（这正是最该防的一类）。
 */
static const char *const kPhysmapKeyNames[] = {
    "kernelSymbol.pv_head_table",
    "kernelSymbol.vm_first_phys",
    "kernelSymbol.vm_last_phys",
    "kernelSymbol.cpu_ttep",
    "kernelConstant.PT_INDEX_MAX",
    "kernelConstant.kernel_el",
    "kernelConstant.T1SZ_BOOT",
};
#define KM_XPF_PHYSMAP_KEY_COUNT 7

_Static_assert(sizeof(kPhysmapKeyNames) / sizeof(kPhysmapKeyNames[0]) == KM_XPF_PHYSMAP_KEY_COUNT,
               "key name table size must match km_xpf_physmap_keys");

/*
 * 「名字表下标 ↔ 结构体字段」的**机器检查**。
 *
 * 上面那句 _Static_assert 只钉了名字表自己的条数，**钉不住结构体**：
 * km_xpf_physmap_keys 的 7 个字段类型完全相同（都是 km_xpf_item_result），
 * 所以 `out->cpu_ttep = results[3]` 这种赋值在字段被改名或换序之后**照样编译**，
 * 只是把 A 键的结果静默地放进 B 字段 —— 而那种错在屏幕上看起来完全正常，
 * 正是本项目最忌的一类（KernelSlide.m:1090-1098 记着"观测格式害人抄错"的账）。
 *
 * offsetof 是唯一能钉住顺序的东西：字段换序 → 偏移变 → 这两句立刻编译失败。
 * 钉三个不均匀分布的下标（0 与末位由 sizeof 那句间接覆盖）。
 *
 * 注意末位断言跟着字段总数走：本轮移除了 arm_tt_l1_index_mask（理由见
 * XpfBridge.h 的「为什么这里没有 ARM_TT_L1_INDEX_MASK」），t1sz_boot 从 7 挪到 6。
 */
_Static_assert(offsetof(km_xpf_physmap_keys, cpu_ttep) == 3 * sizeof(km_xpf_item_result),
               "field order drift: cpu_ttep must stay at slot 3");
_Static_assert(offsetof(km_xpf_physmap_keys, pt_index_max) == 4 * sizeof(km_xpf_item_result),
               "field order drift: pt_index_max must stay at slot 4");
_Static_assert(offsetof(km_xpf_physmap_keys, t1sz_boot) == 6 * sizeof(km_xpf_item_result),
               "field order drift: t1sz_boot must stay at slot 6");
_Static_assert(sizeof(km_xpf_physmap_keys) == 7 * sizeof(km_xpf_item_result),
               "field count drift: km_xpf_physmap_keys must hold exactly 7 results");

const char *km_xpf_physmap_key_name(int index)
{
    if (index < 0 || index >= KM_XPF_PHYSMAP_KEY_COUNT) return "";
    return kPhysmapKeyNames[index];
}

/// 锁内实现。调用者必须已持有 g_xpfLock。
static km_xpf_item_result item_get_locked(const char *name)
{
    km_xpf_item_result r = { false, false, 0 };

    /*
     * 「有没有注册」只能靠遍历链表回答：xpf_item_resolve 对未注册的键与
     * finder 返回 0 的键**都**返回 0（xpf.c:697-711 的循环走完就 return 0），
     * 两者在下游的处置完全不同：前者说明这份 XPF 快照不含这个键，后者说明含、
     * 但 finder 没解析出来。
     *
     * 注意 fetched=false 的**时效**：xpf.c:702-705 会把 finder 的返回值（**包括 0**）
     * 连同 `cached = true` 一起写在节点上，只有 xpf_stop()（即 km_xpf_deinit()）
     * 才清链表。所以它不是"这一次没找到"，而是"**本进程内该键的 finder 至今
     * 返回 0**"—— 重试同一个进程不会改变这个结果（见 KernelSlide.h 里
     * km_phystokv_ensure 对"可重来"那条承诺的限定）。
     *
     * 链表布局来自 xpf.h:10-17 的 XPFItem（nextItem / name / finder / ctx /
     * cached / cache），头在 gXPF.firstItem（xpf.h:101）。
     */
    for (const XPFItem *item = gXPF.firstItem; item != NULL; item = item->nextItem) {
        if (item->name == NULL) continue;
        if (strcmp(item->name, name) == 0) {
            r.registered = true;
            break;
        }
    }
    if (!r.registered) return r;

    const uint64_t value = xpf_item_resolve(name);
    r.value = value;
    r.fetched = (value != 0);
    return r;
}

bool km_xpf_physmap_keys_fetch(km_xpf_physmap_keys *out)
{
    if (out == NULL) return false;
    /* 入口先清零：失败路径不写 *out，调用方若忘了初始化就会读到自己的栈垃圾 ——
       那会被误读成"取到了某个键，值是垃圾"。 */
    memset(out, 0, sizeof(*out));

    km_xpf_item_result results[KM_XPF_PHYSMAP_KEY_COUNT] = {};
    bool anyTaken = false;

    pthread_mutex_lock(&g_xpfLock);
    if (g_xpfState.ready) {
        anyTaken = true;
        for (int i = 0; i < KM_XPF_PHYSMAP_KEY_COUNT; i++) {
            results[i] = item_get_locked(kPhysmapKeyNames[i]);
        }
    }
    pthread_mutex_unlock(&g_xpfLock);

    /*
     * false 只有两种含义：out 为 NULL，或 XPF 未初始化。**不含**"某个键取不到" ——
     * 那要看逐键的 registered / fetched（两者要分开报告，理由见 km_xpf_item_result）。
     */
    if (!anyTaken) return false;

    /*
     * 按位置逐个搬运而不是 memcpy：memcpy 会在字段换序/改名时静静地跟着错。
     * 逐个赋值同样挡不住（七个字段类型相同），所以顺序由上面那组 offsetof
     * 静态断言来钉。
     */
    out->pv_head_table = results[0];
    out->vm_first_phys = results[1];
    out->vm_last_phys = results[2];
    out->cpu_ttep = results[3];
    out->pt_index_max = results[4];
    out->kernel_el = results[5];
    out->t1sz_boot = results[6];
    return true;
}

NSString *km_xpf_last_error(void)
{
    pthread_mutex_lock(&g_xpfLock);

    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    const char *xpfError = xpf_get_error(); // 上游缓冲不会自动清空，可能是更早的一次失败
    if (xpfError) [lines addObject:[NSString stringWithFormat:@"xpf: %s", xpfError]];
    if (g_xpfState.lastFailure) [lines addObject:@(g_xpfState.lastFailure)];

    NSString *text = lines.count ? [lines componentsJoinedByString:@"\n"] : nil;
    pthread_mutex_unlock(&g_xpfLock);
    return text;
}

NSString *km_xpf_kernelcache_path(void)
{
    pthread_mutex_lock(&g_xpfLock);
    NSString *path = g_xpfState.kernelcachePath[0] ? @(g_xpfState.kernelcachePath) : nil;
    pthread_mutex_unlock(&g_xpfLock);
    return path;
}

NSString *km_xpf_diagnostic(void)
{
    pthread_mutex_lock(&g_xpfLock);

    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    [lines addObject:[NSString stringWithFormat:@"xpf: %@", g_xpfState.ready ? @"ready" : @"not initialised"]];

    if (g_xpfState.ready) {
        [lines addObject:[NSString stringWithFormat:@"kernelcache: %@", @(g_xpfState.kernelcachePath)]];
        /*
         * kernelBase 是这份镜像的**链接基址**（xpf.c:563 现读）。它单独打出来，
         * 是因为拼运行时 kernel_base 的另一个输入（KernelSlide.m 的兜底常量）
         * 曾经错到本机头上：两行数摆在一起，一眼就能看出常量该不该改。
         * 上游自己也把这个值当成机型判别依据（common.c:187 拿它判 ARM_LARGE_MEMORY）。
         */
        [lines addObject:[NSString stringWithFormat:@"kernelBase: 0x%llx",
                          (unsigned long long)gXPF.kernelBase]];
        [lines addObject:[NSString stringWithFormat:@"init took %.2f s", g_xpfState.initSeconds]];
        [lines addObject:[NSString stringWithFormat:@"darwin: %@  xnu: %@",
                          gXPF.darwinVersion ? @(gXPF.darwinVersion) : @"?",
                          gXPF.xnuBuild ? @(gXPF.xnuBuild) : @"?"]];
    }

    NSString *text = [lines componentsJoinedByString:@"\n"];
    pthread_mutex_unlock(&g_xpfLock);
    return text;
}
