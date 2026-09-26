# physrw 改造 · 交接文档

> 写于 2026-09-22。目的：新对话读完这一份就能接上，不必回溯上下文。
> 本文所有结论都有证据，证据位置在最后一节。

---

## 一、要做什么，为什么换路线

Aether（注入 `com.apple.Music`）要读目标进程内存。原路线是「页表翻译 + kread」：
用 kread 遍历目标进程页表拿到 PA，再把 PA 转成内核 VA 去读。

**这条路死在 `g_linear_delta`**：PA → KVA 需要一个可信的换算基准，而 Aether 拿不到。
它试过两条来源，都行不通：

- **kfd 的 `perf`** —— 需要 `dynamic_info.h` 里 8 个 `kernelcache__*` 静态地址。那些值是**按机型**给的（16.5 那份只保证 iPhone 14 Pro Max/T8120），而版本匹配只比 Darwin 前缀，等于一台设备的地址套用到同版本所有设备上。算错就在未映射地址上做 kread，直接内核 panic。所以 Aether 把它们全填 0 并把 `perf_supported` 置 false。
- **`km_scan_kernel_base`** —— 已被 `KM_ENABLE_KBASE_SCAN 0` 关闭。

于是 `g_linear_delta` 无解，`km_translate` / `km_read_process` 全废。

**换的路线**：参考样本（下称"样本"，本地只读分析件，不随仓库分发）走的是
**physrw**（物理读写）——不翻译虚拟地址，而是拿到页表页之后直接写 PTE，
把任意物理页映射进自己的地址空间。这条路**不依赖 PA→KVA**，绕开了 Aether 的死结。

---

## 二、样本逆向结论（这是整件事的依据）

样本 = **上游 libkfd 的直接移植 + 静态链接的 XPF + physrw 路线**。

### 1. 它是 libkfd 移植（铁证）
VA `0x101af00d0` 有明文 **`p0up0u was here`**，那是 libkfd `info.h` 的 `info_copy_sentinel[]`。
连哨兵字符串都没改。三个 PUAFF 方法（`landa` / `physpuppet` / `smith`）全在，
kread/kwrite 四个后端（`sem_open` / `kqueue_workloop_ctl` / `dup` / `IOSurface`）全在。

### 2. 它静态链接了 XPF（这解释了「为什么它能跨设备」）
样本里有字符串 **`src/xpf/src/common.c`** 和 XPF 的内部字段名（`beforeLdrAddr` / `xrefAddr` / `decRet`），
它的惰性键值链节点布局 `{next+0, name+8, finder+0x10, ctx+0x18, cached+0x20, cache+0x28}`
与 XPF `xpf.h` 的 `XPFItem` **逐字段一致**。

**关键**：XPF 是**静态**编进去的，所以查动态导入表查不到它——之前有一轮逆向因此误判「样本没用 XPF」。

**这就是你最初那个问题的答案**（「样本按不同设备加载不同代码，Aether 怎么做到」）：
**样本没有按设备分派代码。** 它运行时从本机 kernelcache 解析出全部内核符号，
所以同一份二进制在任何设备、任何 iOS 版本上都自适配。`hw.cpufamily` 那 13 处只用来调参数，不切代码路径。

### 3. 它的完整链路
```
读 kernelcache（/private/preboot/<uuid>/... 枚举得到）
  → mmap 内核 Mach-O 映像
  → XPF 按「内核源码字符串 × 引用」定位 78 个内核符号
  → 用符号算 kernel slide
  → 拿 ptov_table / gVirtBase / gPhysBase / gPhysSize
  → physrw：写 PTE 把物理页映射进自己地址空间
  → 遍历物理内存找目标数据
```
**它不识别目标进程**（437 个导入里没有 `task_for_pid` / `proc_pidinfo` / `kern.proc*`），
**也不遍历页表**（全 `__text` 没有 `MRS TTBR0_EL1` / `TTBR1_EL1` / `TPIDR_EL1`）。
「没有目标进程，只有目标物理内存。」

### 4. 它确实在写 PTE（确证）
函数 `0x101048e78` 内：
```
mov x8,#0xe43 / movk x8,#0x60,lsl#48 / orr x21,x20,x8 / str x21,[x8,w22,utw#3]
```
写入 `arg0 | 0x0060000000000e43`。该常量 = `ARM_PTE_PNX|ARM_PTE_NX`（高半）
+ `TYPE_VALID|AP[1]|SH[1]|AF|nG`（低 12 位），是一条合法 ARM64 PTE。
配套的 `and x8, x8, #0xfffffffff000`（`ARM_TTE_PA_MASK`）用于从现有 PTE 提 PA 域。

**写 PTE 用的是普通用户态 `str`** ——因为 PUAF 让页表页落进了用户可写的窗口，
写它不经过 PPL 管辖的内核映射路径。这就是这条路能绕开 PPL 的原因。

### 5. 它不使用 PPL 绕过（重要，决定了工程量）
12 个 `ppl_*` / `pmap_*_ppl` 键（`ppl_enter`、`ppl_handler_table`、`pmap_enter_options_ppl` …）
的 resolver **0 个调用者**、函数内部 **`blr` 数 = 0**，唯一引用点是注册段（只登记不调用）。

**所以那些 PPL 符号是随 XPF 整库进来、注册了却从未查询的**——XPF 本身有 `ppl.c` / `sptm_txm.c`，
样本把整个库编了进去。**移植时不需要实现 PPL 绕过。**

### 6. 目标机上这条路成立
目标是 iPad14,3 / iPadOS 16.4.1，属于 **Pre-SPTM**（SPTM 是 iOS 17+ / A15+ 才引入）。
Pre-SPTM 下 `PUAF → physrw → 改页表 → 完全控制` 成立。

---

## 三、Aether 当前进度

### 已完成（三个提交，全部已推送、CI 绿）

| 提交 | 内容 |
|---|---|
| `bf7160e` | XPF 集成：`Aether/libxpf/`（上游快照，74 文件零修改）+ `Aether/libmemrw/xpf/`（三个文件的适配层）+ `project.yml` |
| `f7935e0` | 接线：`Bridging-Bridge.h` 导入 + 面板「XPF」按钮与常驻状态行 |
| `dc7e1e9` | `KernelSlide.{h,m}`：算 kernel slide + 读 ptov_table 等 + PA→KVA（`km_phystokv`） |

### 设备已验证
点「XPF」按钮，**8/8 符号全部解析成功**：
```
kernelcache: /private/preboot/99A2ECFB1708C10BEF2AF6D2F1AA214CA31E764821...
darwin: 22.4.0   xnu: 8796.102.5~1        init took 0.17 s

kernelSymbol.ptov_table = 0xfffffe00079d3180      kernelSymbol.phystokv = 0xfffffe00080bae34
kernelSymbol.gVirtBase  = 0xfffffe0007a86198      kernelSymbol.cpu_ttep = 0xfffffe0007a5c010
kernelSymbol.gPhysBase  = 0xfffffe0007a87fc0      kernelSymbol.allproc  = 0xfffffe000aad17e8
kernelSymbol.gPhysSize  = 0xfffffe0007a87fc8      kernelConstant.T1SZ_BOOT = 0x11 (=17)
```
注意 kernelcache 是从 **`/private/preboot/<boot-uuid>/`** 枚举到的，不是 `/System/Library/Caches/`。

### 尚未验证
`dc7e1e9` 的 slide 计算**还没上机跑过**。这是下一步第一件事。

---

## 四、下一步

### 第 1 步：上机验证 slide（当前卡在这一步）
面板点「Slide」按钮（**会做 kread，需要内核层就绪**；XPF 未就绪它会自己初始化）。
看三处：

1. `⑤ 自检通过：slide=… kernel_base=… 头部=feedfacf/100000c`
2. 首行摘要含 `换算表=ready`
3. `== phystokv 抽样 ==` 落回内核地址范围

**最可能失败的点**：`kernelSymbol.vn_kqfilter` 在目标设备上没有实测记录（XPF 面板那 8 键不含它）。
它是 slide 链的唯一输入，若解析不出，整条链断在这里——诊断会直接指出。

失败时摘要行会写「卡在哪一步」，下面每行带地址与读到的值（含「头部实际读到 vs 期望」）。

### 第 2 步：把 slide 接进读路径
目前 slide 与 `g_linear_delta` 是**两套并存**的（子代理刻意没混改）。
下一步是用 `km_phystokv()` 取代 `km_bootstrap_linear_delta` 那条链，
让 `km_translate` / `km_read_process` 复活。注意 `KernelMemory.m` 里的闸门
（`g_linear_map_valid`）与不变式（`!valid ⟹ delta == 0`）不要破坏。

### 第 3 步：physrw（PTE 写入）
样本的 `0x101048e78` 模式：在 PUAF 页上写 `pa | 0x0060000000000e43`。
需要的零件：
- **页表遍历器**：样本用 4×0x30 参数表，16KB 页时 L3 掩码 `0x1ffc000`、L2 掩码 `0xffe000000`（已逆清）
- **PUAF 页强制重分配**：样本在 `physpuppet_run`(0x100f763f8) 里用
  `_mach_memory_object_memory_entry_64` + `_vm_map` 循环制造页表分配压力

---

## 五、已知风险 / 未决项

1. **`kernelSymbol.vn_kqfilter` 未实测**（见上，第 1 步的成败关键）
2. `KernelSlide.m` 里三个结构体偏移（`fileproc+0x10` / `fileglob+0x28` / `fileops+0x30`）
   来自 `static_info.h` 的布局推导，**不是 16.4.1 第一手读数**。错了只会安全失败。
3. **kread 未映射地址 = 内核 panic**（彩屏，不是 app 崩）。已用三道形态检查降低风险，
   但那是内核行为，不能数学归零。**改动读路径前务必记住这条。**
4. 三次设备 panic 的历史：根因是 `bootstrap` 写入错误的 `g_linear_delta` →
   拿 `PA + delta` 去 kread 未映射地址。相关止损注释在 `KernelMemory.m` 里，不要删。
5. 刻意**未启用** kfd 的 `perf`：`perf_run` 后半段要改 `/dev/aes_0` 的 `si_rdev` 伪装成 perfmon，
   失败会跳过 `puaf_cleanup` → 残留 vm_map 被后续操作踩中 → panic。

---

## 六、参考资料在哪

| 内容 | 位置 |
|---|---|
| 各路逆向报告与脚本 | `D:\工作区\_Aether_rev\_rev\`（`能力边界` / `数据平面上游` / `读进程层` / `内核常量来源` / `页表掩码用途` / `physrw页表页` / `XPF集成` / `XPF接线` / `Slide与phystokv`） |
| XPF 上游源码（含 ChOma/img4lib 子模块） | `D:\工作区\_Aether_rev\xpf_src\` |
| 样本本体（只读，勿改） | `<本地样本可执行文件路径>` |
| 样本 PUAFF 原理（上游作者 writeup） | `D:\工作区\kfd_ref\writeups\`（`landa.md` / `smith.md` / `physpuppet.md`） |
| physrw 理论 | https://tin-z.github.io/ios-exploit-starterpack/en/physical-rw/ |
| XPF 上游仓库 | https://github.com/opa334/XPF |

**注意**：`<本地样本目录>\` 目录下的 `.md`/`.txt` 文档**不要读**——内容有大量错误言论，
逆向时必须只从二进制取证。上面表格里的 `kfd_ref/writeups` 是另一回事，那是权威原理材料。
