//
//  KernelMemory.h
//  Aether 内核内存读写层 —— 对外只暴露这几个 C 函数。
//
//  设计对齐样本（_kfd_port/施工总纲.md）：
//    · 不发任何 mach trap 特权调用，不用 task_for_pid，不用 mach_vm_read；
//    · 内核读写原语由 PUAFF → KRKW 建立（libkfd），kernel base 靠扫描而非查表；
//    · 本文件是 libkfd 的唯一 include 点，其余文件走这几个 C 接口。
//
#ifndef KernelMemory_h
#define KernelMemory_h

#include <stdbool.h>
#include <stdint.h>

/// 建立内核读写能力。成功返回 true；失败时 *err 写入可读原因（失败不崩）。
bool km_init(const char **err);

/// 释放内核读写能力与所有内核侧状态。
void km_deinit(void);

/// 当前是否已就绪。
bool km_ready(void);

/// 扫描到的 kernel base（kernelcache 的 MH_MAGIC_64 所在地址）。未就绪返回 0。
uint64_t km_kernel_base(void);

/// 读目标进程的一个地址（bytes 可为任意长度）。
/// 成功返回 true，并写入 out；失败返回 false。
bool km_read(uint64_t addr, void *out, uint64_t len);

/// 读一个 64 位字。失败返回 0（并置 *ok 为 false，ok 可为 NULL）。
uint64_t km_read64(uint64_t addr, bool *ok);

/// 往目标进程的一个地址写（len 必须是 8 的倍数）。
bool km_write(uint64_t addr, const void *in, uint64_t len);

/// 把内核地址合法性做一次快速检查（用于日志与断言，不参与功能）。
bool km_is_kernel_address(uint64_t addr);

#pragma mark - 地址翻译层
/*
 * 从「内核读写原语」走到「读目标进程用户态地址」。
 *
 *   procForPid   在 p_list 环上按 pid 找 struct proc
 *   translate    走该进程 pmap 的页表，把 VA 翻成 PA
 *   readProcess  对外：读目标进程 VA
 *
 * PA -> 内核 VA 的补回依赖线性映射的基准（内核 VA − PA 差值）。
 * 它在目标内核上是逐版本变动的，所以不写死：km_locate_linear_map() 在
 * kernel_pmap 上走一遍内核 VA（kernel_proc / current_proc），从「真实观测到的
 * (VA, PA) 对」反解出这个差值 —— 与上游 perf.h 的 phystokv() 兜底支同源。
 *
 * 这里没有独立的自校验步骤（先前注释写"再用内核自身的 pmap 自映射验证"，
 * 与代码不符）：采信条件就是那次 walk 成立、基线非 0、且差值形态合理。
 * 反面同样要写明：pmap 的 tte − ttep 那条路**刻意不采信** —— 它只是顶层表
 * 所在那一段的偏移，不是全地址恒定的差值（见 KernelMemory.m 里
 * km_bootstrap_linear_delta 的注释与 bug_type 210 的 panic 证据）。
 *
 * 基准没验通时 km_linear_map_ready() 返回 false，三处读路径入口
 * （km_translate / km_read_process / km_write_process）一律直接失败，不下探到
 * kread / kwrite —— 读不出数据是预期状态，把无效地址送进内核解引用会彩屏。
 */

/// 按 pid 找 struct proc 的内核地址。找不到返回 0。
uint64_t km_proc_for_pid(int32_t pid);

/// 读目标进程一个用户态虚拟地址。成功返回 true。
/// out 直接传缓冲指针 —— Swift 侧用 withUnsafeMutableBytes 传入 [UInt8] 即可。
bool km_read_process(int32_t pid, uint64_t uaddr, void *out, uint64_t len);

/// 写目标进程一个用户态虚拟地址。len 必须是 8 的倍数（写原语逐 64 位落笔）。
bool km_write_process(int32_t pid, uint64_t uaddr, const void *in, uint64_t len);

/// 把目标进程的 VA 翻译成 PA。失败返回 false（该页未映射）。
bool km_translate(int32_t pid, uint64_t uaddr, uint64_t *pa_out);

/// 线性映射基准是否已定位并通过自校验。
bool km_linear_map_ready(void);

/// 定位并校验线性映射基准。需要在 km_init 成功之后调用。
bool km_locate_linear_map(void);

/// 自检：读 kernel base 处的 Mach-O 头，确认内核读原语真的可用。
/// 返回一条可直接打进日志的多行描述；任何一步失败也返回描述而不是崩溃。
void km_self_test(char *out, size_t outSize);

#endif /* KernelMemory_h */
