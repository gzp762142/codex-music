# slide 求值链的可信性问题：已确证的现场 + 需要判定的三处

> 用法：整篇直接发给对方。要的是**判定**与**可验证的下一步**，不是"可能有两种原因"。
> 每问请先给「成立 / 不成立 / 证据不足」，再给推理，再给最小反例或精确条件。
> 回答用简体中文；标识符 / 十六进制值保留原形。
>
> **本文所有数值都标了来源。标「日志」的直接来自设备 panic 全文（可复核）；
> 标「代码」的来自仓库源码行号。没有标来源的数字我都没写。**

---

## 一、已确证的现场（两条独立启动，同一台设备）

两台设备的 panic 全文各留下一份内核真值。两份都是**同一台设备、同一份 kernelcache**
（下文会证明），只是 KASLR 不同：

```
                        ① 日志（第 1 次启动）      ② 日志（第 2 次启动）
KernelCache slide       0x000000001855c000         0x000000001b078000
KernelCache base        0xfffffe001f560000         0xfffffe002207c000
Kernel slide            0x0000000018564000         0x000000001b080000
Kernel text base        0xfffffe001f568000         0xfffffe0022084000
Kernel text exec slide  0x00000000194b4000         0x000000001bfd0000
Kernel text exec base   0xfffffe00204b8000         0xfffffe0022fd4000
```

从这两组能**纯算术**得到的、两次都成立的恒等式：

```
KernelCache base  − KernelCache slide  =  0xfffffe0007004000
Kernel text base  − Kernel slide       =  0xfffffe0007004000
text exec base    − text_exec slide    =  0xfffffe0007004000
Kernel text base  − KernelCache base   =  0x8000
KernelCache slide − Kernel slide       =  −0x8000
text_exec slide   − KernelCache slide  =  0xf58000
```

三点结论（我据此认为链接基址这条已经解决）：

1. **`0xfffffe0007004000` 就是本机的链接基址**（= `VM_MIN_KERNEL_ADDRESS` 口径），
   三条独立路径都得到它；
2. `linkBase + slide = KernelCache base`（不是 `Kernel text base`）；
3. `KernelCache base ≠ Kernel text base`，**差固定 `0x8000`** —— kernelcache 的映射基址
   比 `__TEXT` 段低 0x8000。这是我目前唯一没搞懂的结构性问题，见 Q2。

---

## 二、代码现状（用于定位我可能做错的地方）

`slide` 的求法与上游 libkfd 的 `perf.h` 同型，四步：

1. 打开本进程自己的可执行文件，拿 fd；
2. 沿 `current_proc → p_fd → fd_ofiles → fileproc(fd) → fp_glob(0x10) → fg_ops(0x28)
   → fo_kqfilter(0x30)` 逐级读，每步过「高 16 位 0xFFFF + 8 字节对齐 + 非 0」形态门；
3. `candidate = fo_kqfilter(运行时读) − vn_kqfilter(XPF 链接期值)`；
4. 自检：`kernel_base = 链接基址 + candidate`，读该地址页首两个 32 位字，要求
   `magic == 0xfeedfacf`（MH_MAGIC_64）且 `cputype == 0x0100000c`（arm64|ABI64）；
   **通过才采信**。

链接基址的取值顺序（代码）：XPF 现读优先，取不到才用兜底常量。两处都得到
`0xfffffe0007004000`（与上面日志反推的一致）。

**已排除的一种错法**：工程里曾把这个常量写成 `0xfffffff007004000`，与真值差
`0x1f000000000`（2 TB）。该错误会让 `linkBase + slide` 落到完全不同的域。
**当前代码里这个常量已经是 `0xfffffe0007004000`，所以 2 TB 那类错误不再成立。**

---

## Q1. XPF 的 `kernelBase` 是哪个口径？

代码用 XPF 报出的 `kernelBase` 当"链接基址"。请确认它的口径：

**Q1.1** XPF 的 `kernelBase`（`libxpf/xpf/xpf.c` 里 `gXPF.kernelBase`）是
**链接基址**（Mach-O 的 `__TEXT` 段 `vmaddr`，`VM_MIN_KERNEL_ADDRESS` 口径），
还是**已加载段的运行时地址**（含 slide）？

**Q1.2** 它是从 Mach-O 头/段表**直接读出**的，还是经过某种推导？如果是推导，
推导依赖什么（是否依赖 `kernelTextSection` 之类的另一个量）？

**Q1.3** 在 iOS 16 的 **fileset kernelcache** 上，`kernelBase` 指的是哪个东西的
`vmaddr`：
  - (甲) 整个 fileset 的映射基址（即 `KernelCache base − slide`）；
  - (乙) `__TEXT` 段的 `vmaddr`（即 `Kernel text base − Kernel slide`）；
  - (丙) 别的。
这两者在本机相差 `0x8000`（见上文恒等式），所以**答案会直接决定我用它拼 kernel_base
时是偏高还是偏低 0x8000**。XPF 报出的值是多少？请与 `0xfffffe0007004000` 对照。

---

## Q2. `KernelCache base` 与 `Kernel text base` 为什么差 0x8000？

本机两次启动都差 `0x8000`（半页，16 KB 页上是半个页）。

**Q2.1** 这是什么造成的？`__TEXT` 段在 kernelcache 文件里的 `vmaddr` 就是比基址高
`0x8000`，还是有别的机制（例如 `__TEXT` 前面有一个 `__PRELINK_TEXT` / 头页 / 对齐填充）？

**Q2.2** 自检应当拼哪一个？代码现在拼的是 `linkBase + candidate`。请确认这个结果
**应当等于 `KernelCache base` 还是 `Kernel text base`**。如果应当等于后者，那我可能
一直差了 `0x8000` —— 虽然 `0x8000` 远小于 `MH_MAGIC_64` 自检能容忍的范围，
但这会连带影响后面所有基于 `kernel_base` 的读。

**Q2.3** 更重要的是：`candidate` 的定义。上游 `perf.h` 里的 `slide` 指的是
「`__TEXT` 段运行时地址 − `__TEXT` 段链接期 vmaddr」，还是
「映射基址运行时 − 映射基址链接期」？我算的 `candidate = fo_kqfilter − vn_kqfilter` 得到的
是 **KASLR 位移**本身（与段无关），所以它与上面哪个口径都能配 —— 但请确认这一点
在 fileset kernelcache 上仍然成立。

---

## Q3. 自检为什么可能在一个错的地址上通过？

自检的判据是页首 8 字节等于 `0xfeedfacf` / `0x0100000c`。我想知道这个判据的**排他性**：

**Q3.1** 在同一个内核映像窗口（`[VM_MIN_KERNEL_ADDRESS, +64 GB)`）里，有多少个地址的
页首满足这两个字？例如 fileset kernelcache 里的各个子映像、`__PRELINK_INFO`、
或 dyld shared cache 的映像，是否各自都有一份 Mach-O 头？

**Q3.2** `cputype = 0x0100000c`（`CPU_TYPE_ARM64 | CPU_ABI64`）这个值，在
**所有 arm64/arm64e 的 Mach-O**（包括本 App 自己的二进制、dyld cache 里的每个 dylib）
里是否都相同？如果是，那么"magic + cputype"这两个字实际上只能排除极少情况 —— 请确认。

**Q3.3** 建议补什么判据能让这个自检真正有排他性，且**不引入新的盲读**？
候选字段：`mh_header` 里的 `ncmds` / `sizeofcmds` / `flags`、或 `__TEXT` 段的
`fileoff == 0`。请评估：多读一个 32 位字会多一次"猜地址"的机会，代价是否值得？
如果值得，读哪个字段最稳（值域窄、跨版本稳定）？

---

## Q4. `fo_kqfilter` 链上的偏移在 T8112 上是否成立？

链上的四个偏移（**代码里的值**，来源是我按目标机口径填的）：

```
p_fd         = 版本表条目里的 fd_ofiles 偏移（本机取到的条目标的是 RELEASE_ARM64_T8101）
fp_glob      = 0x10
fg_ops       = 0x28
fo_kqfilter  = 0x30
```

**Q4.1** 请逐一核对这四个偏移在 **Darwin 22.4.0 / xnu-8796.102.5~1 / T8112** 上的正确性。
我特别怀疑 `fp_glob = 0x10`（`struct fileproc` 的布局改过）与 `fo_kqfilter = 0x30`
（`struct fileops` 开头几个字段的顺序改过）。

**Q4.2** 若某个偏移偏了，症状会是"读到一个像内核地址但不是目标字段的值"，
于是 `candidate` 得到一个**形态合法但数值错误**的值。这种错法会不会**恰好仍让自检通过**
（例如偏出的值让 `linkBase + candidate` 落到另一个有 Mach-O 头的页上）？

**Q4.3** 有没有办法在不依赖 `struct fileops` 内部布局的前提下算 `slide`？
（例如用另一个"链接期已知、运行时可读"的量代替 `vn_kqfilter`；注意不能直接用
`kernelSymbol.X` 的运行时地址，那本身就要 slide。）

---

## 附：为什么每个数字都必须有来源（如果你要建议更深的读法，请先看这一节）

本工程的读原语**不是**"直接读那个地址"：它把一个本进程持有的内核对象的指针字段改写成
`目标地址 − delta`，再让内核按内核语义从那个指针开始解引用。内核实际碰到的最低地址是
`addr − delta`，两条路径的 delta 不同（`0x0C` 与 `0x04`）。读一个没映射的地址 =
内核态 same-EL data abort = **整机重启**，没有 fault-recovery。

典型现场（来自 panic 全文）：

```
esr = 0x96000007   (EC = same-EL data abort, DFSC = level-3 translation fault)
far = 0xfffffe113d540000
```

`far` 落在 zone 堆区 GEN0（`0xfffffe113bb18000 - 0xfffffe122217c000`）内，**不是内核映像区**
—— 说明那次 kread 的目标地址算错了。

**所以：任何"猜一个地址然后读它"的建议，请明确标注风险并给出替代。**
本工程目前的纪律是：每一步只读"由已确认对象 + 已知偏移"拼出的地址，读出值必须先过形态
检查才能用于下一次拼地址；自检不通过就停，**不换地址重试**。

---

## 输出格式

每问先给 `成立 / 不成立 / 证据不足`，再给推理，再给最小反例或精确条件。
能用具体十六进制值或位型说明的，不要用文字描述代替。
若结论是"必须在本机实测才能定"，请给出**要读哪几个值、以及判定它们的判据**。
