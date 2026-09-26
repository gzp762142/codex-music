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

/// XPF 从设备上那份 kernelcache 里**现读**出来的链接基址：kernelcache 的 Mach-O
/// 头所在 vmaddr（libxpf/xpf/xpf.c:563 的 `gXPF.kernelBase = macho_get_base_address(...)`；
/// 实现是扫 LC_SEGMENT_64 取最小 vmaddr、排除 __PRELINK / __PLK / __PAGEZERO，
/// 见 libxpf/choma/MachO.c:517-537）。
///
/// 为什么需要它：链接基址**不是**跨机型常量 —— ARM_LARGE_MEMORY 内核（本项目目标机
/// iPad14,3 / iPadOS 16.4.1 属于这一类）链接在 0xfffffe0007004000，而老配置链接在
/// 0xfffffff007004000，两者差整 2 TB（0x1f000000000）。上游 libkfd 把后者抄成了
/// static_info.h:12 的 ARM64_LINK_ADDR，那一份在本类机型上是错的。所以拼 kernel_base
/// 必须以设备上这份为准，常量只能当兜底。
///
/// 返回 0 表示不可用：XPF 未就绪，或字段仍是失败哨兵（xpf.c:587 判的 UINT64_MAX）。
/// 本函数只读内存里的解析结果，**不碰内核**。
uint64_t km_xpf_kernel_base(void);

#pragma mark - 「建页表窗口」那条路要的键（KernelPhysMap 用）

/*
 * 为什么要有这一段，而不让调用方直接调 km_xpf_resolve_symbol()：
 *
 * ① 语义分流。XPF 的 item 表里两类键的**返回值含义完全不同**，混用一次就是把
 *    一个地址当常量、或把一个常量的位模式当地址去 kread（后者直接彩屏）：
 *      · `kernelSymbol.*`     —— finder 解析出的是**链接期 vmaddr**
 *        （xpf.c:697 的 xpf_item_resolve 只是调 finder，不加 slide；
 *         PatchFinder_arm64.c:52-75 的 resolve_adrp_..._reference 返回
 *        section 的链接期地址）。要用它必须自己 + slide。
 *      · `kernelConstant.*`   —— finder 直接算出一个**数值**（例如
 *        common.c:129-176 的 PT_INDEX_MAX：数出来的表项条数），**不能**再加
 *        slide、也不能当地址解引用。
 *    这条区分在 KernelSlide.m:1073 已经用掉过一次（`symbol + slide`），
 *    但那处是调用方自己记得；这里把它变成类型上的区分。
 *
 * ② 三种"没有值"必须分开。`xpf_item_resolve` 对「键没注册」与「finder 失败」
 *    一律返回 0（xpf.c:710），而这两者的处置完全不同：前者是"这份 XPF 快照
 *    不含这个键"，后者是"含，但这次没找到"。所以取值结果带 registered 标志。
 *
 * ③ 一次取齐。7 个键分 7 次调用会被人误会成"7 个独立步骤"，而实际上它们是
 *    建表这一个动作的**同一组输入**；一次取齐也让诊断能把它们并列显示。
 *
 * ── 为什么这里**没有** kernelConstant.ARM_TT_L1_INDEX_MASK ──
 *
 * 它曾经在这个集合里（KernelPhysMap 用它当页表几何的 L1 索引掩码），真机验证
 * （iPad14,3 / M2 / iPadOS 16.4.1）把它否掉了：common.c:113-127 的那个键按
 * kernelConstant.T1SZ_BOOT 选值，而 T1SZ_BOOT 是**内核侧**（TTBR1）的 VA 位宽 ——
 * 该机上实读 17，于是它给 11 位 0x00007ff000000000（与 libkfd 快照
 * static_info.h:65 的 ARM_16K_TT_L1_INDEX_MASK 同值，那一份也是为 T1SZ = 17 的
 * 内核写的）。而 KernelPhysMap 建的是**用户 pmap** 的窗口，要的是**用户侧**
 * （T0SZ = 25）几何：上界 2^39 ÷ L1 块 2^36 = 8 块 → 3 位 0x0000007000000000。
 * 两个语义在 T0SZ == T1SZ == 25 的老机型上重合，在目标机上分家 —— 于是预检在
 * "掩码推出的块数"那条自洽判据上停住（详见 KernelPhysMap.m 文件头部那段）。
 *
 * 所以取值侧**不再取它**、诊断侧**不再显示它**：留着就是一个"取了但不用"的键，
 * 而它正是最容易被人顺手拿回去当几何用的那一个。用户侧几何是常量（由架构与页
 * 大小定死，不来自任何一次读取），不需要经过这里。KernelPhysMap 只保留
 * kernelConstant.T1SZ_BOOT 作诊断（说明这台设备内核侧几何长什么样），
 * 它不参与几何计算。
 */
typedef struct {
    /// 键在 XPF 的 item 链表里注册过（xpf_item_register 走过一次）。
    bool registered;
    /// finder 返回了非 0 值。
    ///
    /// **注意时效**：XPF 会把 finder 的返回值（包括 0）连同 cached 标志一起写在
    /// 节点上（xpf.c:702-705），只有 xpf_stop()（即 km_xpf_deinit()）才清链表。
    /// 所以 `fetched == false` 的含义不是"这一次没找到"，而是
    /// "**本进程内该键的 finder 至今返回 0**" —— 同一个进程里重试不会改变它。
    bool fetched;
    /// 取到的值。仅 fetched 为 true 时有意义。
    uint64_t value;
} km_xpf_item_result;

/// 「建页表窗口」这条路一次要用到的全部 XPF 键。
/// 字段名即键名（下划线换点），注释标出返回值是哪一类。
///
/// **顺序即 km_xpf_physmap_key_name() 的下标**（XpfBridge.m 里那组 offsetof
/// 静态断言把字段顺序钉住）。ARM_TT_L1_INDEX_MASK 不在这里，理由见上面那一节。
typedef struct {
    km_xpf_item_result pv_head_table;        /* kernelSymbol.pv_head_table   → 链接期地址 */
    km_xpf_item_result vm_first_phys;        /* kernelSymbol.vm_first_phys   → 链接期地址 */
    km_xpf_item_result vm_last_phys;         /* kernelSymbol.vm_last_phys    → 链接期地址 */
    km_xpf_item_result cpu_ttep;             /* kernelSymbol.cpu_ttep        → 链接期地址 */
    km_xpf_item_result pt_index_max;         /* kernelConstant.PT_INDEX_MAX  → 数值 */
    km_xpf_item_result kernel_el;            /* kernelConstant.kernel_el     → 数值 */
    km_xpf_item_result t1sz_boot;            /* kernelConstant.T1SZ_BOOT     → 数值（仅诊断） */
} km_xpf_physmap_keys;

/// 一次取齐上面那 7 个键（同一个临界区内完成，避免中途 deinit 让结果自相矛盾）。
///
/// 返回 false 只有两种含义：out 为 NULL，或 **XPF 未初始化**（此前置不成立）。
/// **不含**"某个键取不到" —— 那要看逐键的 registered / fetched（两者要分开报告，
/// 因为"键没注册"与"finder 没解析出来"要求的动作完全不同）。
///
/// 失败时 `*out` 会被清零（入口先 memset），所以即使调用方忘了初始化自己的结构体，
/// 也不会把栈垃圾读成"某个键取到了值"。
bool km_xpf_physmap_keys_fetch(km_xpf_physmap_keys *out);

/*
 * 刻意**不导出**「只取一个键」的公开版本：上面的 fetch 已经一次取齐全部 7 个
 * （同一个临界区），另开一个单键入口会是一条谁都不走的路 —— 工程里不要
 * "看起来能跑的空壳"。逐键形状的取值由 fetch 内部的 item_get_locked 承担。
 */

/// 一个键的键名（给诊断文本用）。返回**静态 C 字符串**，永不返回 NULL
/// （下标越界时返回 ""）。
///
/// 为什么返回 const char * 而不是 NSString *：它只用来填 `%s`。返回 NSString
/// 会在每个无 autorelease pool 的调用线程上漏一个对象（KernelSlide.m:622-626
/// 记着这条），而这里一毛钱好处都换不来。
const char *km_xpf_physmap_key_name(int index);

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
