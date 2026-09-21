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
        [lines addObject:[NSString stringWithFormat:@"init took %.2f s", g_xpfState.initSeconds]];
        [lines addObject:[NSString stringWithFormat:@"darwin: %@  xnu: %@",
                          gXPF.darwinVersion ? @(gXPF.darwinVersion) : @"?",
                          gXPF.xnuBuild ? @(gXPF.xnuBuild) : @"?"]];
    }

    NSString *text = [lines componentsJoinedByString:@"\n"];
    pthread_mutex_unlock(&g_xpfLock);
    return text;
}
