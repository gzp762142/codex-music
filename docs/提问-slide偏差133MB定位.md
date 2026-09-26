# 内核 slide 求值链：133 MB 偏差的定位请求

> 用法：整篇直接发给对方。要的是**判定**与**可验证的下一步**。
> 每问先给「成立 / 不成立 / 证据不足」，再给推理，再给最小反例或精确条件。
> 回答用简体中文；标识符 / 十六进制值保留原形。
>
> **本文每个数值都标了来源标签，请只按标签采信：**
>   `[日志]` = 设备 panic 全文里的权威字段（可逐字复核）
>   `[诊断]` = 设备诊断文件 / 面板输出里我们程序自己打印的值
>   `[推算]` = 从上述两类做算术得到的，标了算式
>   `[代码]` = 仓库源码行号

---

## 一句话核心问题

我用「运行时函数指针 − 链接期符号地址」推内核 slide，再拼 `kernel_base`。设备 panic
全文给出了权威值，两相对账后 `kernel_base` **偏 `0x8570000`（133 MB）**：

```
真实 kernel_base（= KernelCache base）  = 0xfffffe0019b08000   [日志]
我算出的 kernel_base                    = 0xfffffe0011598000   [诊断]
差                                      = 0x8570000 = 133 MB
```

**这笔偏差整体落在 `candidate` 这一项上**，因为链接基址本身是对的 —— panic 日志里
**每一组 base 减它自己的 slide 都等于同一个值**：

```
KernelCache base − KernelCache slide = 0xfffffe0007004000
Kernel text base − Kernel slide      = 0xfffffe0007004000
text exec base  − text exec slide    = 0xfffffe0007004000
我用的链接基址                       = 0xfffffe0007004000   ← 与上面三条一致
```

所以 `kernel_base = 链接基址 + candidate` 里，**只有 `candidate` 可能错**。
而 `candidate = fo_kqfilter(运行时读) − vn_kqfilter(XPF 链接期)`，两个输入里至少一个错。

**请判定是哪一个错，以及怎么在不冒 panic 风险的前提下确定。**
（我原来写过一个"偏差可拆成 0x8000 + 0x8578000 两笔"的说法，那是错的：
它把 `KernelCache base` 与 `Kernel slide` 这两个**不同对象**的字段相减了。
按正确配对，0x8000 那一笔不存在。特此更正。）

**同时请看本文末尾新增的「对称判据」一节** —— 它把"猜哪端错"变成一个可判定的等式。

---

## 二、`[日志]` 权威值（09-27 那次 panic 全文，崩溃线程就是我们的读取队列）

```
KernelCache slide:      0x0000000012b04000
KernelCache base:       0xfffffe0019b08000
Kernel slide:           0x0000000012b0c000
Kernel text base:       0xfffffe0019b10000
Kernel text exec slide: 0x0000000013a5c000
Kernel text exec base:  0xfffffe001aa60000
Fileset Kernelcache UUID: DD3296640AAAC379C87A292839B3B6B7
Kernel UUID:              F252D9D1-9D79-35E5-81FC-4B4F64ED3231
OS version: 20E252 / Darwin 22.4.0 / xnu-8796.102.5~1/RELEASE_ARM64_T8112
设备: iPad14,3 / socId 8112 (T8112)
```

崩溃现场（同一份日志）：

```
panic(cpu 4 caller 0xfffffe001b15cc24): Kernel data abort
  pc  = 0xfffffe001af24350
  lr  = 0x9ea3fe001af30808        (带 PAC 签名，最低位不是 0 是 lr 的正常形态)
  esr = 0x96000006                 (EC = 0x25 same-EL data abort, DFSC = 0b000110 = level-2)
  far = 0xfffffe005647c034
  x8  = 0xfffffe005647c02c         (far == x8 + 8)
崩溃线程: dispatch_queue_label = "aether.autotracker"   ← 就是发出 kread 的那条队列
```

从这些权威值**纯算术**得到的恒等式（用于后面对账）：

```
KernelCache base − KernelCache slide = 0xfffffe0007004000
Kernel text base − Kernel slide      = 0xfffffe0007004000
text exec base  − text exec slide    = 0xfffffe0007004000
KernelCache base − Kernel text base   = −0x8000          ← 即 text base 比 base 高 0x8000

pc  − KernelCache base = 0x141c350         ← 崩溃指令在映像内
far − KernelCache base = 0xfffffe005647c034 − 0xfffffe0019b08000
                       = −0x13b973fc0      （64 位回绕后的有符号差）← 故障地址远离映像
```

> 另有一次启动的日志（同一台设备、同一份 kernelcache）给出
> `KernelCache slide = 0x1b078000 / base = 0xfffffe002207c000`，上面那四条恒等式**全部同样成立**。

## 三、`[诊断]` 我们程序自己算出并采信的值

```
链接基址（来源：XPF 从 kernelcache 现取的 gXPF.kernelBase；另一路兜底常量相同）
                                   = 0xfffffe0007004000
kernel_base 候选                    = 0xfffffe0011598000
推出的 slide                        = 0x0A594000
自检：读该 kernel_base 处头部 → 失败
```

其余环节都读出来了（`fd_ofiles` / `fileproc` / 链接期 `vn_kqfilter` 均取得），
所以**读取原语本身可用**，断在自检那一次读。

## 四、`[推算]` 对账

```
候选 kernel_base = 链接基址 + 推出 slide
                 = 0xfffffe0007004000 + 0x0A594000
                 = 0xfffffe0011598000                    ✓ 与 [诊断] 一致

真实 kernel_base                       = 0xfffffe0019b08000   [日志]
候选 kernel_base                       = 0xfffffe0011598000   [诊断]
差                                     = 0x8570000            （133 MB）

拆成两笔：
  A: 真实 kernel_base − 真实 slide     = 0xfffffe0006ffc000
     我用的链接基址                    = 0xfffffe0007004000
     A                                 = 0x8000
  B: 真实 slide − 推出 slide           = 0x8578000
  A 与 B 相抵（B − A）                 = 0x8570000            ✓ 与上面总数一致
```

**误差 A 的性质值得注意**：`0x8000` 恰好等于 `[日志]` 里 `Kernel text base` 与
`KernelCache base` 之差（两次启动都是这个值）。这似乎说明 `gXPF.kernelBase`
给的不是 Mach-O 头那一处，而是往后 `0x8000` 的 `__TEXT`。**如果成立，那它是个固定
偏移，不是随机误差。**

---

## Q0. 请先判定这个拆法

**Q0.1** 上面 A / B 的拆法成立吗？有没有别的拆法能把 `0x8570000` 解释得更自然？

**Q0.2（误差 A）** `macho_get_base_address` 取的是"非 `__PRELINK`/`__PLK`/`__PAGEZERO`
段中最小的 `vmaddr`"。在内核 64 位 Mach-O / **fileset kernelcache** 上，这个最小
`vmaddr` 是**文件头所在地址**，还是 `__TEXT` 段的 `vmaddr`（头之后 `0x8000`）？
两者在标准布局下是否相同？如果 `__PAGEZERO` 被排除、而头本身不属于任何段，
"头地址"应当怎么求？—— 请给出**能直接对照的判据**。

**Q0.3（误差 B，最要紧）** `slide = 运行时 fn − 链接期 fn` 在什么情况下会**系统性**
偏掉 133 MB 这种量级？请按可能性排序，并给出**判别方法**（要能证实，不能只说"可能"）：

  - 链接期地址来自**另一个 kernelcache 变体**（同一 SoC 的多个 fileset）；
  - 运行时 `fo_kqfilter` 实际指向 **thunk / 桩**而不是函数本体；
  - 该字段本身不签名或有别的编码，导致"还原 PAC"引入了偏差；
  - 取的是 fileops 表里**不同条目**（偏移错位）；
  - 其他。

**Q0.4** 版本串里带 `RELEASE_ARM64_T8112`，设备 SoC 也是 T8112，这一处一致。
那么 kernelcache 的选择是否还存在"同 SoC 多份fileset"的坑？16.4.1 上应以哪个路径为准，
如何用 UUID 校验（日志给了 `Fileset Kernelcache UUID: DD3296640AAAC379C87A292839B3B6B7`）？

**Q0.5** 除了 panic 日志，运行时（不依赖 panic）有没有受支持的方式拿到
`KernelCache base` / `Kernel slide` 的等价信息？例如 `sysctl kern.kernel_slide`、
`OSKext` 系列接口、`kern.bootargs` 里的线索？它是否对所有进程可见？

---

## Q1. 算法与它的隐含约束

**Q1.1** `slide` 在 arm64e / 16 KB 页 / `T1SZ_BOOT = 17` 下必须满足哪些约束？
(a) 对齐要求（是否 `0x200000` 的倍数？依据是什么）；
(b) 取值上界由什么决定；
(c) `0x0A594000`（≈166 MB）与 `0x12b04000`（≈300 MB）是否都落在约束内。

**Q1.2** 「运行时函数指针 − 链接期函数地址」成立的前提请逐条列出，特别是：
  - 两个符号必须是**同一个**函数（`vn_kqfilter` 的运行时地址是否可能是 thunk / stub？
    若可能，误差量级是多少）；
  - 链接期地址必须来自**与当前运行内核完全同一份构建**，这个约束怎么验证。

**Q1.3** 链接基址（`0xfffffe0007004000`）在 arm64e 上是怎么定义的 —— 它是内核映像的
链接 `vmaddr`，还是 `__TEXT` 段起始，还是别的？这个常量是否随 SoC / 构建变化？
请给出判定"它对本机正确"的方法。

**Q1.4** 从 `kernel_base` 读 `MH_MAGIC_64 + cputype` 做自检，**挡不住**哪一类错？
具体地：如果链接基址取错域（例如偏整 2 TB），自检会以什么形式失败 —— 读到错的值，
还是内核在未映射地址上 data abort？

**Q1.5（本次特别问）** 本机的两个地址分别是：

```
真实 kernel_base = 0xfffffe0019b08000    [日志]
候选 kernel_base = 0xfffffe0011598000    [诊断]   （偏 0x8570000 = 133 MB）
```

两者**都落在内核映像窗口内**。请判定：在这样的前提下，自检
（读页首两个 32 位字，要求 `0xfeedfacf` / `0x0100000c`）**有没有可能通过**？
如果可能，是"该处确实有另一个 Mach-O 头"，还是"读到了垃圾但恰好匹配"？
按本机这次是**失败**（触发 data abort），请说明这更支持哪一种解释。

---

## Q2. PAC 还原与"低 21 位自洽"

**Q2.1** 内核结构里的函数指针字段（`fo_kqfilter` 这种）在 arm64e 上是否**参与指针认证**？
若参与，用的是哪个 key（`IA` / `IB` / `DA` / `DB`）与什么样的 discriminator？

**Q2.2** 我们用「把高 17 位按地址符号扩展补齐」的方式做还原：
`p & BIT55 ? p | ~((1<<47)-1) : p & ((1<<47)-1)`。请说明这个做法在什么情况下
**会**引入偏差、什么情况下是安全的。特别地：如果该字段其实**没有**签名，这个操作
会不会反而改坏它？

**Q2.3** 有没有一条**纯算术**的自洽判据，能在只看到原始读数与还原值的情况下，
区分"这是一个签名过的内核函数指针"与"这是一个碰巧合法的别的地址"？

---

## Q3. 我们手上还有的诊断数据（请告诉我该看哪几行）

`[诊断]` 里我们同时打印了这些量（都是程序实际输出）：

```
link_const / link_xpf / 链接基址采用的结果与来源
current_proc、fd_ofiles 偏移
③ 链：fd_ofiles / fileproc / fp_glob / fg_ops / fo_kqfilter（含 fo_kqfilter 的原始读数）
④ 运行时 vn_kqfilter / 链接期(XPF) vn_kqfilter → slide
⑤ 自检读到的那两个 32 位字（magic / cputype）与待读地址 kernel_base
⑥⑦ ptov_table / gVirtBase / gPhysBase / gPhysSize
```

**Q3.1** 为了定位这 133 MB，请指出**上述哪几个量之间的等式必须成立**，以及
哪一对**一旦不等就唯一指向链接期符号取错**、哪一对**唯一指向运行时读错**。

**Q3.2** 如果只能再看三行诊断输出，你选哪三行？

---

## 附：为什么每个数字都必须有来源（若要建议更深的读法，请先看这一节）

本工程的读原语**不是**"直接读那个地址"：它把一个本进程持有的内核对象的指针字段改写成
`目标地址 − delta`，再让内核按内核语义从那个指针开始解引用。内核实际碰到的最低地址是
`addr − delta`，两条路径的 delta 不同（`0x0C` 与 `0x04`）。读一个没映射的地址 =
内核态 same-EL data abort = **整机重启**，没有 fault-recovery。

本机已因此重启**五次**。最近一次现场即本文第二节（`esr = 0x96000006`、`far` 远离映像）。

**所以：任何"猜一个地址然后读它"的建议，请明确标注风险并给出替代。**
现有纪律是：每一步只读"由已确认对象 + 已知偏移"拼出的地址；读出值必须先过形态检查
才能用于下一次拼地址；自检不通过就停，**不换地址重试**。

---

## 对称判据（把"猜哪端错"变成可判定的等式）

`slide = 运行时符号 − 链接期符号` 这个式子**对任意一个符号都成立**，前提是两端
真的是同一个符号。所以可以让**两个独立符号**各算一次 slide，二者必须相等：

```
(甲) slide_A = fo_kqfilter(运行时读)     − XPF(kernelSymbol.vn_kqfilter)
(乙) slide_B = 运行时地址(符号 X)         − XPF(kernelSymbol.X)
     slide_A == slide_B 必须成立。不等 ⟺ 至少一端的符号解析错了。
```

**为什么这条能定位：** 这两个式子共用同一个 `slide`，但用的是**两条独立的解析链**。
`XPF` 把每个符号的链接期值都打印出来了（面板与诊断文本都有），所以 (乙) 的 XPF 那端
是现成的，只缺"符号 X 的运行时地址"。

**可用的 X**：`kernelSymbol.ptov_table` / `gVirtBase` / `gPhysBase` / `gPhysSize` /
`vn_kqfilter`。其中只有**函数符号**（`vn_kqfilter`）可以两端直接相减 —— 因为
`XPF(gVirtBase)` 给的是**变量自身的地址**，而第 ⑥⑦ 步读到的是**变量里存的值**，
两者口径不同，不能直接减。**请确认这个区分，并指出还能用哪些符号做 (乙)。**

**我还想知道**：`XPF` 内部有没有一个"自校验"的口子？例如
`xpf.c:722-730` 的 `xpfsec_decode_pointer()` 在还原 chained fixups 指针时用了
`macho_get_base_address(section->macho)`，而 `common.c:895-919` 的
`xpf_find_vn_kqfilter()` 是一条**纯启发式链**（找字符串 → 找交叉引用 → 取函数起始
→ 再往前 4 字节取另一个函数起始），**没有符号表校验**。同库的
`xpf_find_ptov_table` 有已知的同类问题。所以：

**Q** `xpf_find_vn_kqfilter()` 这条链在本机（Darwin 22.4.0 / T8112）上抓到的
是不是真正的 `vn_kqfilter`？有没有**不依赖可信 slide** 的办法验证它？

（我先试着自己答了两种，都失败，请你判断它们是否真的不成立：
&nbsp;
· **形态法**：看返回地址的高位是否落在内核域。失败 —— 抓错邻近函数时返回值**仍然
是个合法内核地址**，形态上完全分不出来。
&nbsp;
· **段范围法**：断言它必须落在 `__TEXT_EXEC` 的链接期范围内。失败 —— 求那个范围
需要 `__TEXT_EXEC` 的链接期起始，而 `Kernel text exec base − Kernel text exec slide`
也依赖 slide。**用运行时地址减 slide 去判，用的是待求量本身，是循环。**
&nbsp;
所以我想知道是否有一条真正独立的判据，还是说这个问题本身只能靠"两个符号交叉验证
必须一致"来间接发现异常（即上文 (甲)/(乙) 那条），而不能直接证明单端正确。）

## 输出格式

每问先给 `成立 / 不成立 / 证据不足`，再给推理，再给最小反例或精确条件。
能用具体十六进制值或位型说明的，不要用文字描述代替。
若结论是"必须在本机实测才能定"，请给出**要读哪几个值、以及判定它们的判据**。
