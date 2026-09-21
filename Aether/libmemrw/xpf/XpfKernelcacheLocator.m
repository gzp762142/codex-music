//
//  XpfKernelcacheLocator.m
//  Aether
//
//  职责：把「kernelcache 可能在哪些路径」这件事讲清楚，别的一概不做。
//
//  背景（为什么值得单独一个文件）：
//    Aether 取内核符号走的路线是：读设备上的 kernelcache → mmap 内核 Mach-O →
//    按内核源码字符串的 xref 定位符号。这条路的第一跳就是「找到 kernelcache 文件」，
//    而它在设备上有三种落点：
//      1. /System/Library/Caches/com.apple.kernelcaches/kernelcache
//      2. /private/preboot/active/System/Library/Caches/com.apple.kernelcaches/kernelcache
//      3. /private/preboot/<boot-uuid>/System/Library/Caches/com.apple.kernelcaches/kernelcache
//    1 和 2 在多数系统上是软链，最终都指向 3。三条都列出来是有意的：
//    系统升级 / 回滚中途软链会断，此时只剩枚举 <boot-uuid> 这一条路能走。
//
//  内存管理：本目录（Aether/libmemrw/xpf）在 project.yml 里单独带 -fobjc-arc。
//

#import "XpfKernelcacheLocator.h"

#include <limits.h>
#include <stdlib.h>

static NSString *const kKernelcachePathFromRoot = @"System/Library/Caches/com.apple.kernelcaches/kernelcache";
static NSString *const kPrebootDirectory        = @"/private/preboot";
static NSString *const kPrebootActiveDirectory  = @"/private/preboot/active";

/// /private/preboot 下除 active 之外、可能藏着 kernelcache 的 boot-uuid 目录。
/// 读不了这个目录（没有 no-sandbox 时会这样）就返回空表 —— 属于预期情况，不是错误。
static NSArray<NSString *> *preboot_uuid_directories(void)
{
    NSError *error = nil;
    NSArray<NSString *> *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:kPrebootDirectory
                                                                                     error:&error];
    if (!entries) return @[];

    NSMutableArray<NSString *> *directories = [NSMutableArray array];
    for (NSString *entry in entries) {
        // active 由固定路径覆盖；隐藏项是系统垃圾；cryptex1 是 Cryptex 卷，结构里没有 kernelcache。
        if ([entry hasPrefix:@"."]) continue;
        if ([entry isEqualToString:@"active"]) continue;
        if ([entry isEqualToString:@"cryptex1"]) continue;
        [directories addObject:[kPrebootDirectory stringByAppendingPathComponent:entry]];
    }
    return directories;
}

/// 按真实路径去重：上面 1/2/3 常常指向同一个文件，重复尝试的代价是每一遍几十 MB 的解压。
static NSArray<NSString *> *deduplicated_paths(NSArray<NSString *> *paths)
{
    NSMutableArray<NSString *> *uniquePaths = [NSMutableArray array];
    NSMutableSet<NSString *> *seenRealPaths = [NSMutableSet set];

    for (NSString *path in paths) {
        char resolved[PATH_MAX];
        // 路径不存在时 realpath 返回 NULL，此时用原路径当 key 即可（它后面会在 open 处失败）。
        NSString *key = realpath(path.fileSystemRepresentation, resolved) ? @(resolved) : path;
        if ([seenRealPaths containsObject:key]) continue;
        [seenRealPaths addObject:key];
        [uniquePaths addObject:path];
    }
    return uniquePaths;
}

NSArray<NSString *> *km_xpf_kernelcache_candidate_paths(void)
{
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    [paths addObject:[@"/" stringByAppendingPathComponent:kKernelcachePathFromRoot]];
    [paths addObject:[kPrebootActiveDirectory stringByAppendingPathComponent:kKernelcachePathFromRoot]];

    for (NSString *uuidDirectory in preboot_uuid_directories()) {
        [paths addObject:[uuidDirectory stringByAppendingPathComponent:kKernelcachePathFromRoot]];
    }
    return deduplicated_paths(paths);
}
