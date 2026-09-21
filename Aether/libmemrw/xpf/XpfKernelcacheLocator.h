//
//  XpfKernelcacheLocator.h
//  Aether
//
//  职责：回答「设备上的 kernelcache 可能在哪」，按尝试优先级给出一串绝对路径。
//
//  不负责：打开文件、判断文件能不能解析（那是 XpfKernelcacheProbe），
//          也不负责调用 XPF（那是 XpfBridge）。
//
#ifndef XPF_KERNELCACHE_LOCATOR_H
#define XPF_KERNELCACHE_LOCATOR_H

#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// 返回所有值得尝试的 kernelcache 绝对路径，顺序即尝试优先级，已按真实路径去重。
/// 任何一步失败（例如没有 /private/preboot 的读权限）都只是少给几条候选，不会返回 nil。
NSArray<NSString *> *km_xpf_kernelcache_candidate_paths(void);

#ifdef __cplusplus
}
#endif

#endif /* XPF_KERNELCACHE_LOCATOR_H */
