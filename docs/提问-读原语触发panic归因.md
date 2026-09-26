# 内核读原语触发 panic：请帮忙区分两条候选路径

> 用法：整篇直接发给对方。要的是**归因方法**，不是安慰性结论。
> 每处请明确给出「成立 / 不成立 / 证据不足」，附最小反例；不要用"通常""一般"代替结论。
> 回答用简体中文；标识符 / 寄存器名 / 位值保留原形。

---

## 一句话核心问题

一个用户态进程通过公开读原语读内核地址时触发 `Kernel data abort` 整机 panic。
panic 线程的 `dispatch_queue_label` 确认是本进程跑内核操作的那条串行队列，所以**是我们干的**。
但我算出的"该次读取的目标地址"与 panic 记录的 `far` **相差 1.08 GB、不在同一页**，
所以**无法确定是哪一笔读触发的**。请给出可操作的归因路径。

---

## 背景（通用事实）

平台：Darwin 22.4.0 / xnu 8796.102.5 / arm64e / 16 KB 页 / iPad14,3 (socId 8112) / iOS 16.4.1。

读取原语：公开项目 libkfd 的 `kread_sem_open` 后端。要读内核地址 `kaddr`，先把本进程持有的一个
内核对象的指针字段改写成 `kaddr − delta`，再 `syscall(SYS_proc_info, PROC_INFO_CALL_PIDFDINFO, ...)`，
由内核按内核语义从那个指针开始解引用，把结构体拷回用户态。这条路径**没有 fault-recovery handler**：
踩到未映射地址 = 整机 panic。

已知的两个 delta（来自上游源码）：

```
读路径  kread_sem_open.h:147   new_pinfo = kaddr − offsetof(struct pseminfo, psem_uid) = kaddr − 0x0C
写路径  kwrite_dup.h:126       new_fp_guard = kaddr − offsetof(struct fileproc_guard, fpg_guard) = kaddr − 0x08
```

本进程在 panic 前一次动作的意图：读 `kernel_base + 0x10` 处 8 字节（校验 Mach-O 头的
`ncmds` / `sizeofcmds`），其中

```
kernel_base（算出来的候选）= 0xfffffe0011598010 − 0x10 = 0xfffffe0011598000
目标 T                      = 0xfffffe0011598010
按读路径推算：x8 应为 T − 0x0C = 0xfffffe0011598004，其后访问 x8 + 8 = 0xfffffe001159800c
```

## panic 日志里的权威值（同一次启动）

```
KernelCache slide: 0x0000000012b04000
KernelCache base:  0xfffffe0019b08000
Kernel slide:      0x0000000012b0c000
Kernel text base:  0xfffffe0019b10000
Kernel text exec slide: 0x0000000013a5c000
Kernel text exec base:  0xfffffe001aa60000
Fileset Kernelcache UUID: DD3296640AAAC379C87A292839B3B6B7
Kernel UUID:              F252D9D1-9D79-35E5-81FC-4B4F64ED3231

esr = 0x96000006     (EC = same-EL data abort, DFSC = 0b000110 → level-2 translation fault)
far = 0xfffffe005647c034
x8  = 0xfffffe005647c02c     (far == x8 + 8)
pc  = 0xfffffe001af24350
caller = 0xfffffe001b15cc24
Panicked task 0xfffffe14d551dbb0: 9807 pages, 8 threads: pid 425
Panicked thread: 0xfffffe130db58a00, tid: 11512
  dispatch_queue_label = "aether.autotracker"    ← 本进程的串行队列
  qosRequested = QOS_CLASS_USER_INITIATED
Zone map: 0xfffffe100cae0000 - 0xfffffe160cae0000
```

已核对：`KernelCache base − KernelCache slide = Kernel text base − Kernel slide
= Kernel text exec base − Kernel text exec slide = 0xfffffe0007004000`（三者相等）。

**注意**：同一份日志里，另一个候选 kernel_base（`0xfffffe0011598000`）比真实值
`0xfffffe0019b08000` 低 `0x8570000`。这个差值与 slide 的差值 `0x12b04000 − 0xa594000`
完全相等（链接基址无误差），即**偏差 100% 来自 slide 的推导**，见最后一节。

---

## Q1. 这次 panic 到底是不是"读 T"引起的？

**Q1.1** 若 panic 由读 `T = 0xfffffe0011598010` 引起，按给定 delta 推算 `x8` 应为
`0xfffffe0011598004`、随后访问 `0xfffffe001159800c`。而日志是 `x8 = 0xfffffe005647c02c`、
`far = 0xfffffe005647c034`。**这个矛盾是否足以排除"panic 由读 T 引起"？** 还是存在某种
合法的执行路径能让"读 T"产生一个比 T 高 1.08 GB 的 `x8`？如果有，请给出该路径（要具体到
是哪一步计算把地址抬高了）。

**Q1.2** 反过来：`far = 0xfffffe005647c034` 属于什么区域？相对同一次启动的已知值：

```
far − KernelCache base(0xfffffe0019b08000) = 0x3c974034 ≈ 969 MiB（比内核映像高）
far 相对 Zone map 起点(0xfffffe100cae0000) = −0xfb6663fcc ≈ −62.85 GiB（远低于 zone 区）
```

也就是说它落在"内核映像之上、zone 区之下"的那一大段里。在内核 VA 布局里这一段通常是什么？
（这些是**同一次启动**的实际数值，请与 kernel base / zone map 一起判断。）

**Q1.4（附：内核帧的绝对地址）** `kernelFrames` 共 14 项，形如 `[imageIndex, value]`，
其中 `imageIndex` 有 13 项为 `1`、最后一项为 `2`。按 `Kernel text base = 0xfffffe0019b10000`
加上第二个值换算，得到：

```
[ 0] 0xfffffe0019b518e0    [ 1] 0xfffffe001a203664    [ 2] 0xfffffe001a20ce64
[ 3] 0xfffffe0019c75400    [ 4] 0xfffffe0019c7402c    [ 5] 0xfffffe0019b175dc
[ 6] 0xfffffe0019fe0808    [ 7] 0xfffffe0019fe0808    [ 8] 0xfffffe0019fdfdf4
[ 9] 0xfffffe0019fdd0b0    [10] 0xfffffe001a0675e4    [11] 0xfffffe0019c73ff4
[12] 0xfffffe0019b175dc    [13] （image 2, value 0）
```

换算方式是否正确（第二个值就是相对 kernel text base 的偏移）？若正确，这些地址能否
用来判断"这次 panic 是从哪个内核入口进去的"（例如 `syscall` / `mach_msg` / 具体在内核里
走的是哪条路径）？

**Q1.3** 如果 `x8` 是 `new_pinfo` 那一类"被改写过的结构体指针"，那么从 `x8` 反推
`kaddr` 是否成立（`kaddr = x8 + 0x0C` = `0xfffffe005647c038`）？这个 `kaddr` 的页内偏移是
`0x38`，是否与 `struct pseminfo` 里某个字段的偏移相符？若相符，是哪个字段？

**Q1.4** 归因方法：在**只能拿到 panic 日志**（拿不到当时的寄存器现场、也无法重放）的前提下，
有没有一套**可操作**的步骤能把"哪一笔读触发了 panic"钉下来？例如利用 `kernelFrames`
（14 帧，值形如 `[1, 268512]`，第二个数疑似相对 `Kernel text base` 的偏移）反查内核函数。
请给出你认为最可靠的一到两条路径，并说明各自需要什么额外数据。

**Q1.5** 同一份日志里 `pc = 0xfffffe001af24350` 与 `caller = 0xfffffe001b15cc24`，
而 `Kernel text exec base = 0xfffffe001aa60000`。这两个地址落在哪个区域内？

---

## Q2. slide 推导偏了 0x8570000（133 MB）：最可能的成因与判别

已知（同一次启动、同一坐标系）：

```
真实 KernelCache slide      = 0x12b04000
我们推出的 slide            = 0xa594000
差                          = 0x8570000
链接基址（XPF 给出）        = 0xfffffe0007004000  ← 与日志三组配对减法的结果完全一致，无误差
```

推导方式：`slide = vn_kqfilter(运行时) − vn_kqfilter(链接期)`，
其中运行时值是从 `proc → fd_ofiles → fileglob → fileops → fo_kqfilter` 读出来的
（前几步都成功了，能打印出 `fd_ofiles=0xfffffe8211098000`、`fileproc=0xfffffe1300abc240` 等），
链接期值来自公开 patch finder 在 kernelcache 上解析的 `kernelSymbol.vn_kqfilter`。

**Q2.1** `0x8570000` 这个偏差有一个可用性质：它 **mod 2^47 不为 0**（`0x8570000 < 2^47`），
所以它**不能**由"只改 bit 47..63 的 PAC 高位处理错误"单独解释。这个推论成立吗？

**Q2.2** 请按**可操作性**排序下列假设，并对每一条给出**判别方法**（不要只说"可能错"）：
  - 链接期符号地址来自**另一个 kernelcache 变体**（同 SoC / 同版本是否可能存在多份 fileset）；
  - 运行时 `fo_kqfilter` 实际指向一个 **thunk / 转发桩**而不是函数本体（误差恰为 `T − F`）；
  - `fd_ofiles → fileglob → fileops → fo_kqfilter` 这条链上**取错了条目或字段偏移**；
  - 该字段**不参与 PAC**，而"去 PAC"步骤引入了偏差；
  - 其他。

**Q2.3** 若假设是"thunk"，误差 `= T − F`（`T` = 实际入口、`F` = 函数本体）。
在没有该设备 kernelcache 符号的离线环境下，能否只凭 `T`、`F` 两个运行时值判断它们是
"同一函数的两个入口"还是"两个不同函数"？例如依据两个地址的差值特征、对齐、或它们
是否落在同一段内。

**Q2.4** 要证实/排除上面这些假设，**最少需要收集哪些数据**？（我在下一次复现里可以加日志。
请给出一个清单，例如：原始 64 位读数、去 PAC 前后、两个层级的 UUID、
`fo_kqfilter` 所在 fileops 表项下标、相邻表项的值、以及同一次启动标识。）

**Q2.5** 有没有一条**不依赖"读候选地址做自检"**的独立路径来得到内核 slide，
且它的失败模式是"静默算错"而不是"整机 panic"？请给出具体做法与所需前提。

---

## Q3. 读原语的安全边界（这一节想确认我理解得对不对）

**Q3.1** 已知底层把指针改成 `kaddr − 0x0C` 再让内核解引用。那么对"读 `kaddr` 处 8 字节"这个动作，
安全条件应当是什么？我目前的理解是：必须保证内核实际访问的**每一处**地址都落在**已映射**的页上，
而由于 delta 的存在，`kaddr` 的页内偏移小于 `0x0C` 时会触及前一页。请核对这条理解，
并指出它是否**充分**（我怀疑不充分，因为内核实际访问范围可能超出所请求的 8 字节）。

**Q3.2** 一个"当前有效、但之后被撤销"的映射会让这个原语以什么形式失败？
如果 panic 频率远低于触发次数，最可能的原因是什么（TLB 残留、地址恰好映射到别处、
还是别的）？

**Q3.3** `esr = 0x96000006`（DFSC `0b000110`）与之前另一次 panic 的 `0x96000007`
（DFSC `0b000111`）的区别是什么？在同一个 16 KB 三级页表体系下，这两者分别意味着
"哪一级翻译失败"？给定 `far = 0xfffffe005647c034`，`0b000110` 是否与它"落在
某个未建立中间级表的区域"相符？

---

## 输出格式

每问先给 `成立 / 不成立 / 证据不足`，再给推理，再给最小反例或精确条件。
能用具体十六进制地址或位型说明的，不要用文字描述代替。
