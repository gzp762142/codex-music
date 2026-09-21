# libmemrw / kfd 只读分析报告

## 1. 完整调用链

`km_init`（`KernelMemory.m:370`）→ 版本门 `km_version_is_listed`（:382）→ `km_version_is_supported`（:517）→ `kfd_try_open`（:544）→ `kopen`（`libkfd.h:169`）。

`kopen` 内部：`kfd_init`（:181）建对象，随后

| 序 | 阶段 | 失败处理 |
|---|---|---|
| 1 | `puaf_run`（:182） | 无守卫，失败即 `assert`→longjmp |
| 2 | `krkw_run`（:183） | 同上；`krkw.h:222` 搜索失败即 `assert_false` |
| 3 | `info_run`（:184） | 版本未命中 → `assert_false("unsupported osversion")`（`info.h:126`） |
| 4 | `perf_run`（:185） | `perf.h:92` 首行 early-return（全表 false），**不会失败** |
| 5 | `puaf_cleanup`（:186） | 只在 1–4 全部正常返回后执行 |

参数断言在 `libkfd.h:173-179`：pages 16–2048、`puaf_method<=landa`、`kread_method<=kread_IOSurface`、**`kwrite_method<=kwrite_sem_open`**。

之后：`km_scan_kernel_base`（`KernelMemory.m:563`，锚点 `kernel_proc`，步长 16 KB 后撤，比 `0xFEEDFACF`，上限 64 MB：:193）→ `km_locate_linear_map`（:578 → :1148）。

**关键**：`kopen` 返回后 `g_kopen_jmp_armed` 已复位（:107），而 :563 起仍在调 `kread`。此刻若库内再遇 `assert`，`common.h:139` 会走 `sleep(30)+exit(1)`，`km_assert_fallback` 不再接管。

## 2. dynamic_info.h 实际条目（共 6 条）

| # | Darwin | 声明机型 | perf_supported | ios__ 五项 | thread__thread_id | kernelcache__* |
|---|---|---|---|---|---|---|
| 0 | 21.0.0 | iOS 15.x | false | **有值** 0x360/ac/a4/c0/14 | 0 | 全 0 |
| 1 | 22.1.0 | iOS 16.1 | false | 同上 | 0 | 全 0 |
| 2 | 22.2.0 | iOS 16.2 | false | 同上 | 0 | 全 0 |
| 3 | 22.3.0 | iOS 16.3 | false | 同上 | 0 | 全 0 |
| 4 | 22.4.0 | iOS 16.4.1 | false | 同上 | **0x418** | 全 0 |
| 5 | 22.5.0 | iPhone 14 Pro Max | false | 同上 | 0 | 全 0 |
| 6 | 22.6.0 | iPhone 12 Pro | false | 同上 | 0 | 全 0 |

`proc__object_size`：22.1→0x530，22.2/22.3→0x538，22.4 起→0x730。缺失 Darwin 22.0.0（iOS 16.0）。`thread__thread_id=0` 无影响（唯一消费者 kqueue_workloop_ctl 后端被 :128/:153/… 的 `false` 禁用）。

## 3. PUAFF / KRKW 选择

- `kfd_puaf_pages = 2048`（`KernelMemory.m:190`），恰为 `libkfd.h:174` 的上界。
- PUAFF：`@available(iOS 16.4)` → `landa`，否则 `physpuppet`（:442-446）；smith 全弃。
- kread：iOS 16+ → `sem_open`，否则 `IOSurface`（:474-478）；kwrite 跟随（:496）。
- 实际可达组合仅为 **(landa|physpuppet, sem_open=1, sem_open=1)**。iOS 15 分支产 `(2,2)` 被 `libkfd.h:179` 挡住，是死分支。

## 4. 未提交改动评估

`km_bootstrap_linear_delta`（:1069）自洽：`tte`(KVA) − `ttep`(PA) 即线性映射常量，与上游 `perf.h:166-168` 同源，且顺序上先于全部 walk 路径，**真解开了「walk 要 delta、delta 要 walk」的死结**。`table = tte`（:945、:1018）与 `(entry & PA_MASK) + g_linear_delta`（:991、:1050）分工也正确（顶层是 KVA，下级表项是 PA）。

但两处隐患：① `km_page_table_walk` 只有三级 L1/L2/L3，缺 `ARM_16K_TT_L0_INDEX_MASK`（`static_info.h:60`），内核实址（L0 索引 0x180）永远走不进去 —— 原注释把症状归给「PA 掩码截断 KVA」，只修对了一半；② 该函数用 `current_pmap`（:1187）而上方 :1161-1171 刚论证内核 VA 必须用 `kernel_pmap`，自相矛盾，且 `kpmap` 现为未使用变量。

**后续更正（安全止损）**：本节原先判 `km_bootstrap_linear_delta` "自洽、真解开了死结"，这个判断**不成立** —— `tte − ttep` 只是顶层表所在**那一段**映射的偏移，不是全地址恒定的 delta（上游 `perf.h:232-248` 用的是 8 项分段 `ptov_table`，只有全部落空才退回单一偏移）。用段内差值换算段外物理页会得到映射区外的地址，而 `km_read_process` 会把它当内核 VA 送进 `kread` —— 那正是 bug_type 210 那次 panic 的形态（`far = x8 + 8` 低于 `VM_MIN_KERNEL_ADDRESS`，`esr DFSC=5`）。现在该函数只回传诊断读数（`tte`/`ttep`/`delta`），**不再置 `g_linear_map_valid`**；`g_linear_map_valid` 只由「walk 出真实 (VA, PA) 观测」的四条 `km_compute_linear_delta` 路径置位，且在基准未验通时 `km_translate` / `km_read_process` / `km_write_process` / `km_self_test` 的 PTE 自检一律直接失败。代价是段内 delta 的实际后果要另作评估：bootstrap 不再提供 delta 之后，四条 walk 路径彼此互为前提（walk 需要 delta 才能下钻到 L2/L3），因此在设备上很可能整体落到 `linear=unresolved`。这是刻意选择的安全态（读不出数据可以接受，彩屏不可以）；要真正恢复可读，得实现 `ptov_table` 的等价物。

## 5. 已知未解决问题

- **T1SZ_BOOT=17**（`static_info.h:22`）：经 `PTR_MASK`（:97）→ `PAC_MASK`（:98）→ `UNSIGN_PTR`（:100）作用于 `info.h:145/152/167/174` 的 `current_pmap`/`kernel_pmap`/`kernel_map`。设备 t1sz 为 25 时高位去符号出错，**连锁破坏全部寻址且无任何运行期检查**（自检 `p_pid` 路径不走 `UNSIGN_PTR`，`KernelMemory.m:756`）。全工程只此一处定义，`dynamic_info.h:304` 的"另见"提示没有对应实现，备份中的 `T1SZ_BOOT must be changed to 25` 原注也已丢失。
- **iOS 15 条目偏移已填、门未开、注释三处不一致**：`dynamic_info.h:89-93` 五项非 0，而 `KernelMemory.m:299-301` 仍写"全是 0"，`tools/verify_dynamic_info.py:213` 仍称"未修完"。
- `KM_L1_MASK` 之外的遗留：`km_compute_linear_delta` 的 kernel-VA 四路（:1195/:1207/:1218/:1226）受 ① 阻挡，**全是死代码**；`g_current_pmap` 仅采样一次不重取；delta 只有 `(delta>>40)==0` 一道弱校验。

## 6. 缺陷与风险清单

| 级别 | 问题 | 位置 |
|---|---|---|
| P0 | 内核实址三级 walk 缺 L0，永远走不通 | `KernelMemory.m:1000-1050` / `static_info.h:60` |
| P0 | T1SZ_BOOT 硬编码 17 污染全部内核指针解符号 | `static_info.h:22,97-100` |
| P0 | `kopen` 返回后 jmp 已解除，后续 `kread` 失败即 `exit(1)` | `KernelMemory.m:107,563` |
| P1 | delta 弱校验 → 错 delta 会污染全部 `pa + g_linear_delta` | `KernelMemory.m:1099,1134` |
| P1 | 若 `krkw_run` 抛断言，`puaf_cleanup` 被跳过，内核侧留 PUAFF 残留 | `libkfd.h:182-186` / `common.h:147` |
| P2 | 注释与代码不符（三处 iOS 15 / 过期的 perf 描述 / "先扫 base 再定位"与实际顺序相反） | `dynamic_info.h:88-93,225`；`KernelMemory.m:299,560` |
| P2 | `KM_PMAP_TTE_OFFSET` 重复定义（:161 与 :927），触发 `-Wmacro-redefined` | `KernelMemory.m:161,927` |
| P2 | kernel base 扫描最大 64 MB，miss 后静默降级 | `KernelMemory.m:193,347` |
| P3 | major==21 死分支；仅覆盖 Darwin 22.1–22.6，缺 22.0.0 与 23+ | `KernelMemory.m:312`；`dynamic_info.h` |
