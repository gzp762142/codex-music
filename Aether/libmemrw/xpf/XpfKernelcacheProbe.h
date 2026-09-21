//
//  XpfKernelcacheProbe.h
//  Aether
//
//  职责：判断一个文件能不能安全地交给 xpf_start_with_kernel_path()。
//
//  不负责：找路径（XpfKernelcacheLocator）、调用 XPF、解析符号（XpfBridge）。
//
#ifndef XPF_KERNELCACHE_PROBE_H
#define XPF_KERNELCACHE_PROBE_H

#import <Foundation/Foundation.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// 判定结果：
///   true  —— 上游 xpf_start_with_kernel_path() 对这个文件会走已知的安全分支。
///   false —— 不放手，*outReason 写入可读原因（含 errno），*outReason 不为 NULL。
/// outReason 必须是有效指针；失败原因不需要调用方释放。
bool km_xpf_kernelcache_is_loadable(NSString *path, NSString **outReason);

#ifdef __cplusplus
}
#endif

#endif /* XPF_KERNELCACHE_PROBE_H */
