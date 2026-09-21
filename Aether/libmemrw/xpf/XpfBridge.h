//
//  XpfBridge.h
//  Aether
//
//  职责：Aether 调用 XPF（XNU Patch Finder）的唯一入口 —— 初始化、按键取符号、回报错误。
//
//  不负责：找 kernelcache（见 XpfKernelcacheLocator）、判断文件可用性（见 XpfKernelcacheProbe）、
//          以及任何内核读写（那是 KernelMemory.m 的事）。
//
//  命名对应：km_xpf_resolve_symbol() 即本轮任务书里写的 km_xpf_symbol()。
//
#ifndef XPF_BRIDGE_H
#define XPF_BRIDGE_H

#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stdint.h>

// 这些是 C 接口，Aether 里既有 .m 也有 .mm，用 extern "C" 兜住 C++ 编译单元。
#ifdef __cplusplus
extern "C" {
#endif

/// 初始化 XPF：按优先级逐个尝试设备上的 kernelcache，第一个能安全解析的交给
/// xpf_start_with_kernel_path()（SPTM / TXM 参数传 NULL）。成功返回 true。
///
/// 失败返回 false 且不崩溃、不留半成品状态；原因见 km_xpf_last_error()，
/// 其中逐条列出每个候选路径各自的失败原因。
/// 可以重复调用：已经就绪时直接返回 true。
bool km_xpf_init(void);

/// 释放 XPF 的内核映像映射、节缓存与键值链并复位全局状态。未就绪时是空操作。
void km_xpf_deinit(void);

/// 是否已就绪（km_xpf_init 成功且此后未 km_xpf_deinit）。
bool km_xpf_ready(void);

/// 解析一个 XPF 键，例如 "kernelSymbol.ptov_table"、"kernelStruct.vm_map.pmap"。
///
/// 返回 0 表示没有取到值，三种可能由 km_xpf_last_error() 区分：
///   · XPF 未初始化；
///   · 键名没在 XPF 里注册过；
///   · finder 跑了但没找到（此时 XPF 会带上 [文件:行] 的断言位置）。
///
/// 首次解析某个键要在内核 Mach-O 上做模式搜索，可能耗时几十到几百毫秒；
/// 之后的调用命中 XPF 自己的缓存。必须在 km_xpf_init 成功之后调用。
uint64_t km_xpf_resolve_symbol(NSString *name);

/// 最近一次失败/异常的可读说明（可能多行）；没有失败时返回 nil。
/// 初始化失败时，内容形如：
///     /System/Library/.../kernelcache: open failed (errno 2 (No such file or directory))
///     /private/preboot/<uuid>/.../kernelcache: xpf_start_with_kernel_path failed: ...
NSString *km_xpf_last_error(void);

/// 当前已加载的 kernelcache 路径；未就绪时返回 nil。
NSString *km_xpf_kernelcache_path(void);

/// 诊断快照（状态 / kernelcache 路径 / 初始化耗时 / 内核版本），供日志与面板显示。
NSString *km_xpf_diagnostic(void);

#ifdef __cplusplus
}
#endif

#endif /* XPF_BRIDGE_H */
