# Slide 彩屏崩溃 · 取证报告

> 2026-09-22 03:36:38 那一次重启。证据源是设备导出的 panic 全文
> （`panic-full-2026-09-22-033638.000.ips`，727791 字节）。本文只写**能从日志直接读出
> 或能从日志数值直接算出**的东西；推断单独标出，不混在事实里。
> 代码基线：`dc7e1e9`（HEAD `9f891d5`）。

---

## 一、一句话

点「Slide」之后，崩溃发生在**我们自己的线程**里（`aether.autotracker`，
tid 6570 / pid 371），指令在内核文本段，故障地址落在 **zone 堆区 GEN0** ——
也就是说某一次 kread 的地址算错了，内核按内核语义去解引用，命中未映射页。

---

## 二、日志里的事实（可直接复核）

### 1. 崩溃进程与线程

```
Panicked task 0xfffffe13eda96920: 9856 pages, 7 threads: pid 371: Music
Panicked thread: 0xfffffe113cf14a00, backtrace: 0xfffffe4ef8712c80, tid: 6570
```

pid 371 = `Music`（我们的 App），崩溃线程 tid 6570。该线程在
`processByPid["371"].threadById["6570"]` 里：

```
"dispatch_queue_label": "aether.autotracker",
"qosRequested": "QOS_CLASS_USER_INITIATED",
"state": ["TH_RUN"]
```

`aether.autotracker` 就是 `AutoTracker.shared.syncExternal {}` 那条串行队列；
`DebugProcView` 里「Slide」按钮正是挂在这条队列上跑的（`DebugProcView.swift:1026`）。
**结论：这一次引导动作就是点「Slide」。**

### 2. 故障现场

```
panic(cpu 5 caller 0xfffffe0020bb4c24): Kernel data abort.
at pc 0xfffffe002097c370, lr 0xc28e7e0020988808
  pc:  0xfffffe002097c370  cpsr: 0x60401208
  esr: 0x96000007          far: 0xfffffe113d540000
```

`esr = 0x96000007`：EC = 0x25（Data Abort 取自更低 EL）、IL = 1、
DFSC = 0b000111 = **translation fault, level 3** —— 走到 L3 表项发现无效，
也就是**该地址未映射**（不是权限问题）。

`far = 0xfffffe113d540000` 落在：

```
. GEN0  : 0xfffffe113bb18000 - 0xfffffe122217c000
```

`far` 距 GEN0 起点 `0x1a28000`。GEN0 是 zone allocator 的堆区 ——
**这块地址属于内核堆，不属于内核映像。**

### 3. 这次启动的内核映像真值（交叉验证的基准，全部来自同一份日志）

```
KernelCache slide:      0x000000001855c000
KernelCache base:       0xfffffe001f560000
Kernel slide:           0x0000000018564000
Kernel text base:       0xfffffe001f568000
Kernel text exec slide: 0x00000000194b4000
Kernel text exec base:  0xfffffe00204b8000
Fileset Kernelcache UUID: DD3296640AAAC379C87A292839B3B6B7
```

### 4. 崩溃线程的内核回溯（`lr` 相对 `Kernel text base` 的偏移）

```
0x75dc, 0x163f34, 0x557664, 0x4ccfb0, 0x4ce9b4,
0x4d0808, 0x4d0808, 0x75dc, 0x1640ec, 0x165340,
0x4c4370 (pc), 0x6fcc24, 0x6f34e4, 0x418e0
```

`0x4d0808` 出现两次、其余都是单次 —— 与 backtrace 里那两行重复的
`lr: 0xfffffe0020988808` 对得上。这一串都在内核文本段内。

---

## 三、能算出来的关系（算术，不含推断）

正确的 kernel_base（自检想验证的那个值）应当是：

```
kernel_base = Kernel text base = 0xfffffe001f568000
```

自检实际要读的地址（若候选值 = X）：

```
待读地址 = ARM64_LINK_ADDR + X
```

而 `far = 0xfffffe113d540000`。用工程里写死的
`KM_SLIDE_LINK_ADDR = 0xfffffff007004000`（`KernelSlide.m:51`）反推：

```
X = far - LINK_ADDR
  = 0xfffffe113d540000 - 0xfffffff007004000   (mod 2^64)
  = 0x1143dfc000   ≈ 72.2 GB
```

**这个 X 越过了 64 GB 上界**，而 `KernelSlide.m:581` 的两道形态检查里
第二道正是「`candidate >= KM_SLIDE_MAX_VALUE(0x1000000000 = 64 GB)` 就拒绝」。

> 反过来说：如果自检那一步真的走到读地址，那么**从 `far` 反推出的候选值
> 必然被形态检查挡下**，根本不会发那一次读。这两件事不能同时成立。
> 所以崩溃**不能**归因于「自检读了 kernel_base 这个动作本身」——
> 如果崩在读地址上，那个待读地址就不该是 `LINK_ADDR + X` 这个形式，
> 或者这次的 `candidate` 压根没经过那两道检查。
> 这条矛盾是下面「未决项」的第 1 条。

### 3.1 主线：链接基址应当由 XPF 动态给出，不该是工程里那个写死的常量

先把链路摆清楚（每一步都有代码位置）：

```
km_xpf_init()                       XpfBridge.m:104
  └─ 遍历设备上的 kernelcache 候选路径   XpfKernelcacheLocator.m:66
     └─ 探测 + 加载                    XpfBridge.m:85-100（xpf_start_with_kernel_path）
        └─ gXPF.kernelBase = macho_get_base_address(gXPF.kernel)   xpf.c:563
             └─ MachO.c:517-537：扫 LC_SEGMENT_64，取「非 __PRELINK / __PLK /
                __PAGEZERO」的最小 vmaddr —— 也就是这份镜像的**链接期基址**
```

**这就是本次崩溃的要害**：`kernelBase` 是 XPF 在设备上从真实 kernelcache 里
动态读出来的，而 Aether 自检时拼 `kernel_base` 用的却是工程里写死的
`KM_SLIDE_LINK_ADDR`（`KernelSlide.m:51`）。两者本该是同一个数，
工程却从上游抄了一个常量来替代它。

> 为什么上游能抄：`libkfd/perf.h:108` 也用
> `ARM64_LINK_ADDR + kernel_slide` 这个形式（常量在 `static_info.h:12`）。
> 但 kfd 那条路是给**同一批机型**用的静态表，而 Aether 已经明确不走
> 按机型分派的路子（见 `docs/physrw改造交接.md` 第二节）——
> 既然链接基址可以由 XPF 现读，就不该再留一个写死的副本。

### 3.2 常量确实是错的 —— 三条独立证据已经闭合（不再需要第一手读数）

**证据一：上游 XPF 自己把这个值硬编码过。**

```c
// Aether/libxpf/xpf/common.c:187
// On ARM_LARGE_MEMORY kernels, the second bl is phystokv
uint32_t n = gXPF.kernelBase == 0xfffffe0007004000 ? 2 : 1;
```

上游拿 `gXPF.kernelBase` 与 `0xfffffe0007004000` 比较来判 ARM_LARGE_MEMORY 内核
——也就是说**这类机型上 `kernelBase` 实测就是它**。XPF 是全平台工具，这个常量
必然来自它对真实 kernelcache 的观察。

**证据二：panic 日志里的三对字段各自独立地反解出同一个值。**

```
KernelCache   base - slide = 0xfffffe001f560000 - 0x1855c000 = 0xfffffe0007004000
Kernel text   base - slide = 0xfffffe001f568000 - 0x18564000 = 0xfffffe0007004000
text exec     base - slide = 0xfffffe00204b8000 - 0x194b4000 = 0xfffffe0007004000
```

三对是三个不同的段、三个不同的 slide，全部收敛到同一个基址。而工程里写死的
`KM_SLIDE_LINK_ADDR = 0xfffffff007004000` 与它相差 `0x1f000000000`（**正好 2 TB**）

**证据三：域归属。** XPF 面板在设备上实测的符号值全落在 `0xfffffe0007xxxxxx`
（例如 `kernelSymbol.ptov_table = 0xfffffe00079d3180`），与反解值同域，
与工程常量不同域。

再加上 `static_info.h:8-12` 自陈那个常量来自 xnu 的 `makedefs/MakeInc.def`
（构建期派生值，所以历史上有两个域），**结论已经无悬念：ARM_LARGE_MEMORY 机型
链接在 `0xfffffe0007004000`，老的静态表抄的是另一种构建配置的值。**

> 保留一次点击的验证仍然值得：修复后 XPF 诊断会多打一行 `kernelBase: 0x…`，
> 与常量并列。那是回归哨兵——万一将来这台机器换了构建配置，两行不一致会立刻
> 看得见。

### 3.2.1 修法与它的边界

修复不写成"把常量改成正确值"，而是**改成从 XPF 现取**（`km_xpf_kernel_base()`，
读 `gXPF.kernelBase`，XPF 未就绪或字段是 `UINT64_MAX` 哨兵时返回 0），
常量退居兜底。理由：写成另一个常量只是把同一个错换个写法，而这台设备上 XPF
本来就已经解析出了权威值。诊断里三行并列：`link_const=` / `link_xpf=` /
`链接基址采用=…（来源：…）`。

### 3.3 另一处仍未解的矛盾（修复前就存在，修复后要靠落盘分开）

`far` 反推出的候选值 `0x1143dfc000` 超过 64 GB 上界，本该被形态检查拦下。
所以「崩在自检那一次读」与「候选值经过了两道形态检查」不能同时成立。
要么崩在别处，要么 `far` 不是我们请求的地址。这一条仍未区分开。

**这一条不因 §3.2 的修复而消失。** 3.2 修的是「基址取错域」这一类，
它证明的只是：过去每一次自检读**必然**打在 2 TB 之外的未映射地址上，
不管候选值对不对。而这次崩的到底是自检读、还是别处的一次 kread，
下一次上机靠新加的落盘文件才能分开——那里有 `kernel_base_pending`、
`fo_kqfilter_raw`、`candidate` 的现场数值，与 panic 日志的 `far` 一对就清楚。

---

## 四、未决项（不知道，别猜）

1. **为什么形态检查没拦住。** 按 `far` 反推的候选值超上界，本该拦下。
   可能：① 崩在另一处 kread（`far` 不是自检读的那个地址）；
   ② `far` 是内核自己内部访问的地址，不是我们请求的地址；
   ③ 候选值另有来源（不经 `slide_verify_kernel_base`）。
   这三种都还没被区分开。
2. ~~**工程常量 `KM_SLIDE_LINK_ADDR` 与日志基址的关系。**~~ **已解开，见 §3.1**：
   正确值 `0xfffffe0007004000`。XPF 8/8 解析成功与这条无关 ——
   XPF 取符号值时用的是**它自己**从 kernelcache 里读到的链接基址
   （`libxpf/xpf/xpf.c:563` `macho_get_base_address(gXPF.kernel)`），
   从不读工程里那个写死的常量，所以常量错了也不影响它取值。
   受影响的只有 Aether 自己用常量拼地址的那一处：`KernelSlide.m:521`。
3. **`far` 为什么在 GEN0 堆区。** 未映射的堆页 —— 是 zone 尚未分配、
   还是 `zap` 过的页，日志答不了。
4. **上机前"应该看到什么"没有留存。** 面板诊断文本是否打出过
   `④ vn_kqfilter：运行时=… 链接期(XPF)=…`、有没有走到 `⑤ 自检`，
   目前没有证据（崩溃瞬间的画面没人截图，`KernelSlide` 也没落盘）。
   **这是本次最大的信息损失，也是下一版必须先修的东西。**

---

## 五、结论：按证据能确定的与不能确定的

**能确定**（日志直接支撑）：
- 引导动作是点「Slide」，崩溃在我们的 `aether.autotracker` 队列上；
- 崩因是内核在某处访问了一个**未映射的内核堆页**（`far` 在 GEN0）；
- 这次启动的真值：`slide = 0x18564000`、`kernel_base = 0xfffffe001f568000`；
- XPF 的 `kernelBase` 是**设备上现读**的（`xpf.c:563` → `MachO.c:517`），
  与工程里写死的 `KM_SLIDE_LINK_ADDR`（`KernelSlide.m:51`）是**两份可能不一致**的数；
- 日志反推的链接基址落在 `0xfffffe0007004000`，与工程常量差 2 TB（§3.2）。

**不能确定**：
- 工程常量到底是错、还是日志反推的前提有问题 —— 要 `gXPF.kernelBase` 的第一手读数；
- 崩在哪一次 kread、那一次的请求地址是多少（§3.3）。

---

## 六、下一版必须做的四件事（按优先级）

### 1. 让 XPF 把自己的 `kernelBase` 打出来（一次点击定案）

`XpfBridge.m:216` 的 `km_xpf_diagnostic()` 已在输出 kernelcache 路径等信息，
加一行 `gXPF.kernelBase`（以及可选的 `kernelEntry`）。同时把这行也带进
XPF 面板那 8 个键的旁边。

**理由**：§3.2 那个 2 TB 的疑点只有第一手读数能定案，而这是零风险的一次点击
（只读面板、不碰内核）。定案之后才知道 `KernelSlide.m:51` 该改成什么 ——
或者该改成「直接用 XPF 的 `kernelBase`，不再留常量副本」。

### 2. 自检之前先落盘（最高优先，代价最低）

现在 `KernelSlide.m` 全程只有内存里的 `g_diagText`，彩屏就随重启一起没了。
`MemoryProbe` 已经有现成的做法可抄（`MemoryProbe.swift:1226-1264`：
异步落盘 + 「观测工具不能长在被观测的路径上」那条教训）。

要写进文件的是：`candidate`、`ARM64_LINK_ADDR`、算出来的待读地址、
两条（或多条）路径各自的候选值、`foKqfilter` 原始读数、`linkedVnKqfilter`、
`T1SZ_BOOT`、以及 `/private/preboot/<uuid>/` 那个 kernelcache 路径。

**写完文件再读内核。** 这样即使下一次照样彩屏，也能像本文一样把
「崩之前那一刻的全部数值」捞回来。

### 2. 自检不许拿单个候选值去赌

现有设计：算出一个候选值 → 直接读 `ARM64_LINK_ADDR + X` → 对就对、错就彩屏。
改进方向（两条独立路径 **都算出且相等** 才允许读）：

- **路径 A**：现有那条 `fo_kqfilter`（fd → fileproc → fp_glob → fg_ops）；
- **路径 B**：`current_proc.le_prev` → allproc 头（零件已在，
  见 `KernelMemory.h` 的 `km_proc_p_list_le_prev_offset()`；
  `current_proc` 是 kfd 反查出来的已证地址，只需一次 KVA 内读+取值）。

两条路相等 → 交叉证据成立，才读一次；不等或只有一条 → **拒绝，不读**。
这就把「候选值形态合法但错」这一类从「彩屏」降级成「失败」。

### 3. 用已实测符号给候选值加一道独立约束

`kernelSymbol.ptov_table` / `gVirtBase` / `cpu_ttep` 这三个在设备上是**实测解析成功过的**。
候选值要同时满足：把它们加到候选值上，结果必须落在本次启动的
genuine 内核映像范围内（该范围可从 panic 日志取得；上机时的近似判据是
「落在内核映像基址上下 2 GB 内、且不与 GEN0 堆区重叠」）。
不满足 → 不发读。

---

## 七、这份报告的证据在哪

- panic 全文：`C:\Users\34698\.dsh\attachments\v1\files\6f\…\panic-full-2026-09-22-033638.000(1).ips`
  - `panicString` 字段：PC/LR/`esr`/`far`、四个基址与两个 slide、Zone 图、Panicked task/thread、完整 backtrace；
  - `processByPid["371"]`：Music 进程；
  - `processByPid["371"]["threadById"]["6570"]`：崩溃线程，`dispatch_queue_label` 在这里。
- 被验证的代码：`Aether/libmemrw/KernelSlide.m`（`519-544` 自检、`546-598` 求 slide、`51` 常量）、
  `Aether/FangUI/UI/DebugProcView.swift:1024-1047`（Slide 按钮走 AutoTracker）。
- 既有交接：`docs/physrw改造交接.md`、`docs/当前任务.md`。
