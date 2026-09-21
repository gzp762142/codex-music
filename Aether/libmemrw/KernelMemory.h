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
 *   procForPid   按 pid 找 struct proc（现在只有 self pid 走短路命中，
 *                其余 pid 的 p_list 遍历已按 KM_ENABLE_PLIST_WALK = 0 停用）
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
 *
 * 止损补上的四件事（1-3 条是第二轮，第 4 条是紧接着的第三轮；只补闸门是不够的，
 * 闸门挡被检查的那一处、挡不住数据流；细节与两次 panic 的第一手证据见 KernelMemory.m）：
 *   1. 污染源封死：km_bootstrap_linear_delta 算出的 tte − ttep **不再写进**
 *      g_linear_delta，只留在诊断字符串里。它曾经把"安全的 0"换成
 *      "看似合法的错值"，反而让 km_is_kernel_address 从"必拒"变成"放行"。
 *   2. 闸门下沉到**使用点**：km_page_table_walk / km_pte_for 在下钻
 *      （拼 `PA + g_linear_delta`）之前自己检查 g_linear_map_valid。
 *      由此全局不变式成立：!g_linear_map_valid ⟹ g_linear_delta == 0。
 *   3. 内核 base 反向扫描停用（KM_ENABLE_KBASE_SCAN = 0）：它是唯一一处
 *      "在未验证地址上**连续盲扫**"的内核访问，且不使用 delta —— delta 闸门拦不住它。
 *      代价是 g_kernel_base 恒为 0（只有诊断消费者）。
 *   4. p_list 链表遍历停用（KM_ENABLE_PLIST_WALK = 0）：它同样**不使用 delta**
 *      （首跳 kernel_proc，之后每跳 `link + 偏移`），所以 delta 闸门也拦不住它。
 *      它拦不住的是"落在内核空洞里的 link"—— 形态检查只回答"像不像内核地址"，
 *      不回答"已映射吗"，而 kread 对未映射页就是内核态 data abort。
 *      短路命中（self pid → current_proc，零 kread）**保留**，km_init 自证仍走它。
 *
 * 由此带来的**预期**状态：四条 km_compute_linear_delta 路径互为前提，
 * 会稳定落到 linear=unresolved，读路径整体不可用；且按 pid 定位 proc
 * 现在只剩 self pid 这一条路（其余 pid 一律失败，原因见 km_proc_lookup_blocker）。
 * 这是刻意的安全态 —— 恢复它们需要 ptov_table 的等价物，
 * 而不是给这条闭环打洞。
 */

/// 按 pid 找 struct proc 的内核地址。找不到 / 定位不了均返回 0。
///
/// **返回 0 的契约**：含义是「无法定位」，**不等于「该进程不存在」**。
/// 区分办法：km_proc_lookup_blocker() 非 NULL 时，除 self pid 外的一切查询
/// 都必然返回 0，与目标进程的状态无关；它为 NULL 时，0 才是"真的没找到"。
///
/// 注意上层现状（本轮不动 MemoryProbe.swift / SilentProbe.swift）：
/// 它们把 0 一律渲染成「内核里找不到 pid 的 proc」，在当前配置下那是误报。
/// 面板还有一条独立的出口 —— km_self_test 报告里的 procForPid 行常驻首行，
/// 那里写的是真实原因。
uint64_t km_proc_for_pid(int32_t pid);

/// 按 pid 定位 proc 的能力当前是否被编译期开关整体停用。
/// 返回 NULL 表示未被停用；非 NULL 即可直接显示的原因文本，也是 km_proc_for_pid
/// 返回 0 时唯一合法的解释来源（静态字符串，不需要释放）。
const char *km_proc_lookup_blocker(void);

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
