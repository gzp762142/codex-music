# 从 proc 推到 task：固定间距不成立，请给出不依赖间距的关联方式

> 用法：整篇直接发给对方。要的是**可操作的关联路径**与**判别方法**，不是安慰性结论。
> 每处请明确给出「成立 / 不成立 / 证据不足」，附最小反例；不要用"通常""一般"代替结论。
> 回答用简体中文；标识符 / 寄存器名 / 位值保留原形。

---

## 一句话核心问题

我按 `task = current_proc + proc__object_size`（`proc__object_size` 取自一张按 Darwin
版本前缀匹配的偏移表，本机取到 `0x730`）推出的 `task` 地址**不是本进程的 task**：
在该地址起的 `0x00..0xF8` 共 32 个槽里，**没有任何一个等于 `current_proc`**，而其中
13 个槽确实是**合法的内核地址**（说明那一带确实躺着某个内核结构，只是不是我们的 task）。

而 `current_proc` 本身是**正确的**（`proc->p_pid` 读出来等于本进程 pid）。

请回答：**在不依赖"proc 与 task 的固定间距"的前提下，如何从 `current_proc` 得到本进程的
`task`**，以及如何**判定**得到的 task 是正确的。

---

## 背景（通用事实）

平台：Darwin 22.4.0 / xnu 8796.102.5~1 / arm64e / **16 KB 页** / iPad14,3（socId 8112，即 T8112）。
用户态进程，通过公开内核漏洞获得的内核读原语（libkfd 的 `kread_sem_open` 后端）。

读取原语：把一个本进程持有的内核对象的指针字段改写成 `kaddr − delta`，再让内核按内核语义
从那个指针开始解引用，把结构体拷回用户态。**踩到未映射地址 = 整机 panic**（无 fault-recovery）。
读路径 `delta = 0x0C`（`psem_uid`）；另有一条 32 位路径 `delta = 0x04`（`psem_usecount`），
它的源访问从目标地址本身开始，所以**页首可读**。

`current_proc` 的来源：libkfd 的 `info_run` 反查 —— 它从一个 psemnode 的 `pinfo` 出发，
经 `pseminfo → semaphore.owner → task`，再用 `proc = task − dynamic_info(proc__object_size)`
**反着**推回 proc；随后用 `proc->p_pid` 与自身 pid 比对来确认。本机这一步**通过了**：

```
[i] current_proc = 0xfffffe130d8261f0
[i] current_proc->p_pid = 422 (expect 422) OK
```

也就是说：**`proc` 是对的，而"同一个 `proc__object_size` 正着用（`task = proc + size`）得到的
task 是错的"**。注意上游对这条等式是**双向使用**的（正方向 `current_task = current_proc +
proc__object_size`，反方向 `proc_kaddr = task_kaddr − proc__object_size`），所以库自身不矛盾；
问题在于这个 size 对本机构建是否适用。

偏移表按 **Darwin 版本字符串的 29 字符前缀**匹配，本机匹配到的条目写的是
`RELEASE_ARM64_T8101`（M1），而本机是 `T8112`（M2）——前缀在第 29 字符处正好落在
`RELEASE_ARM64_T81` 中间，SoC 后缀被忽略。该条目里：

```
proc__object_size = 0x0730
task__map         = 0x0028
```

---

## 实测现场（同一次运行、同一台设备）

用的探针是**只读**的：它从候选 `task` 地址起，以 `+0x00` 到 `+0xF8`、步长 8 逐槽读 8 字节，
**只读一级、绝不顺着槽里的值再解引用**（理由见最后一节：on-device 出过一次 panic）。

```
== 2. task address under test ==
proc=0xfffffe130d8261f0 · object_size=0x730 = task=0xfffffe130d826920

== 3. task readability ==
task+0x0 = 0xdd22000000 (read twice, agreed): the task object is readable

== 4. slot scan: task+0x0 .. task+0xF8, step 8 ==
（每槽打印 raw -> 经 PAC 还原后的值。**下表有 7 行在转录时损坏**，见紧随其后的
「数据可用性分级」；行尾带 ✗ 的即为损坏行，其数值不要引用）
task+0x00 = 0xdd22000000   -> 0x0dd22000000   [other]        ✗
task+0x08 = 0              -> 0               [small int]
task+0x10 = 0x10100000013  -> 0x10100000013   [other]
task+0x18 = 0              -> 0               [small int]
task+0x20 = 0x5ec           -> 0x5ec           [small int]
task+0x28 = 0xb0effe10080dc0c0 -> 0xfffffe10080dc0c0 [kernel domain]
task+0x30 = 0xfffffe130da45170 -> 0xfffffe130da45170 [kernel domain]
task+0x38 = 0xfffffe130bdfc4e0 -> 0xfffffe130bdfc4e0 [kernel domain]
task+0x40 = 0 -> 0 [small int]
task+0x48 = 0 -> 0 [small int]
task+0x50 = 0 -> 0 [small int]
task+0x58 = 0xfffffe130a7dc34d -> 0xfffffe130a7dc340 [kernel domain]  ✗
task+0x60 = 0xfffffe130a5c2bc0 -> 0xfffffe130a5c2bc0 [kernel domain]
task+0x68 = 0xfffffe13efa05300 -> 0xfffffe13efa05300 [kernel domain]
task+0x70 = 0xfffffe001a1241a0 -> 0xfffffe001a1241a0 [kernel domain]
task+0x78 = 0 -> 0 [small int]
task+0x80 = 0xbb                -> 0xbb              [other]
task+0x88 = 0 -> 0 [small int]
task+0x90 = 0x3f001f00000000   -> 0x1f00000000       [other]
task+0x98 = 0 -> 0 [small int]
task+0xa0 = 0x101db7           -> 0x101db7           [other]
task+0xa8 = 0xffffffe16d894d80 -> 0xfffffe16d894d80  [kernel domain]  ✗
task+0xb0 = 0xffffffe14d08ce14c -> 0xfffffe14d08ce140 [kernel domain] ✗
task+0xb8 = 0x6e2200000        -> 0x6e2200000        [other]
task+0xc0 = 0 -> 0 [small int]
task+0xc8 = 0x30dfe113ce27310  -> 0xfffffe113ce27310 [kernel domain]  ✗
task+0xd0 = 0 -> 0 [small int]
task+0xd8 = 0 -> 0 [small int]
task+0xe0 = 0xbafa21136dc05930 -> 0xfffffe1136dc05930 [kernel domain] ✗
task+0xe8 = 0xe2fe2f113ce27310 -> 0xfffffe113ce27310 [kernel domain]  ✗
task+0xf0 = 0xd9e57e113d37cd60 -> 0xfffffe113d37cd60 [kernel domain]
task+0xf8 = 0 -> 0 [small int]

== 5. verdict ==
slots scanned=32  read failures=0  kernel-domain values=13  small ints/others=19
slots == current_proc: **0**
values changed by km_unsign_ptr=6
```

---

## 数据可用性分级（判读槽表前先看这一节）

上表是从真机输出**手工转录**的，逐行复算后发现 **7 行**在抄写时损坏。复算只用代码里
已核过的语义，不引入任何外部假设：

- `KernelSlide.m:387-395` — `slide_unsign_ptr = (p & BIT55) ? (p | pacMask) : (p & ptrMask)`，
  `pacMask = ~((1 << (64 − T1SZ)) − 1)`，本机 `T1SZ_BOOT = 17` ⟹ `pacMask` 高 17 位全 1，
  `ptrMask` 是低 47 位全 1；
- `KernelSlide.m:2493-2496` — 内核地址 bit55 恒为 1 → 走 `| pacMask` → 高位本已全 1 →
  **对已经是干净 KVA 的值是恒等**；只有 PAC 签名值（bit55 = 0）才会被 `& ptrMask` 丢掉
  最高 17 位、从而**真正改变**；
- `KernelStructScan.m:105-108` — `km_ss_is_kva(v) = ((v >> 48) == 0xFFFF)`，作用在还原后的值上；
- `KernelStructScan.m:404-410` — `unsign = km_unsign_ptr(raw)`，`unsign != raw` 才计 `changed`。

**损坏是怎么发生的（这条解释了全部 7 行）**：`%#llx` **不左补零**。对 PAC 签名值而言，
其 bit55 是签名位而非地址位，还原时要把它连同高 17 位一起清掉，所以**左列的理想形态是
带前导 `0` 的 17 位串**（如 `0x0fffffe16d894d80`）。抄写时若把那个前导 `0` 错写成 `f`
或 `3`，就会得到一个"位数看着合法、但与右列对不上"的串：

  | 槽 | 表里抄的 | 能对上右列的左列形态 | 症状 |
  |---|---|---|---|
  | `0x00` | `0xdd22000000` | `0xdd22000000`（两列本该相等） | 右列 `0x0dd22000000` 恰是左列**左移一个 hex 位**，多出一个前导 `0` |
  | `0x58` | `0xfffffe130a7dc34d` | 必须是签名形态 | 两侧高 15 位相同、只差最低 4 位（`0xd`→`0x0`），而两个分支都动不了低 4 位 |
  | `0xa8` | `0xffffffe16d894d80` | `0x0fffffe16d894d80` | 前导 `0` 被写成 `f` |
  | `0xb0` | `0xffffffe14d08ce14c` | `0x0fffffe14d08ce140` | 前导 `0` 被写成 `f`，且末位 `c` 应为 `0` |
  | `0xc8` | `0x30dfe113ce27310` | `0x030dfe113ce27310` | 前导 `0` 被写成 `3`（右列去掉前导 `f` 后与左列内层逐位相同） |
  | `0xe0` | `0xbafa21136dc05930` | 同形（签名位续签名） | 右列 17 位，超出 u64 |
  | `0xe8` | `0xe2fe2f113ce27310` | `0x02fe2f113ce27310` | 签名位 `0` 被写成 `e`（右列去掉前导 `f` 后与左列内层逐位相同） |

**而且无法唯一回填**：同一个右列可以被多个不同的左列候选还原得到，所以不能靠算术猜出
原始读数。这正是必须重新采样的原因。

**A 级（25 行，逐位自洽，可引用）**：除上表 7 行之外的每一行。
判定方式：`raw` 与还原列的字面量长度都等于各自数值的最短 hex 长度，且按上式复算的
`unsign(raw)` 与右列**逐位相等**。其中 `0x28`（`0xb0effe10080dc0c0` → `0xfffffe10080dc0c0`）
与 `0xf0` 这类槽 `unsign(raw) != raw`，那是 PAC 签名指针被正确还原，属正常形态。

**C 级（7 行，上述损坏行）**：`task+0x00 / 0x58 / 0xa8 / 0xb0 / 0xc8 / 0xe0 / 0xe8`。

**这些损坏行的存在恰好交叉验证了 verdict 行**：按代码语义逐行算 `unsign(raw) != raw`
的槽，在未损坏的读数里应恰为 6 个左右（PAC 签名指针槽），而损坏行在复算时会被随机算成
「改变了」或「没改变」，于是逐行统计与 `changed=6` 出现 ±1 的偏差。
**`values changed by km_unsign_ptr=6` 与 `kernel-domain values=13` 这两个计数来自程序输出
而非逐槽表，可以引用；只有那 7 行的数值不可引用。**

**哪些结论完全不依赖槽表数值**（结构性事实）：

- 读取范围 `task+0x00 .. task+0xF8`、步长 8、共 32 槽，`read failures=0`（计数器输出）；
- 每槽读两次并要求一致（`KernelStructScan.m:317/327`），故「该对象可读」这个判定有效；
- **没有任何槽等于 `current_proc`**（按值比较得出，只依赖比较结果、不依赖打印格式）；
- 探针只读一级、不把槽里的值当地址再解引用（`KernelStructScan.m:412-416` 的纪律），
  故本次采样未引发 panic。

**要问的重点是下面各节的路径判据，槽表数值只作旁证。** 若判读用到了上表具体数值，
请只用 A 级那 25 行。

**结论（探针自己的判定）**：`km_scan_task_map_offset() = 0`，即
「在 `task+0x00..0xF8` 这个窗口里没有任何槽等于 `current_proc`」。

---

## Q1. 这个"无命中"能不能证明"候选 task 地址是错的"？

**Q1.1** 我用的判据是「结构体里存在一个槽，其值等于 `current_proc`（即 `task` 回指 `proc`
的那个字段）」。这个判据在 arm64e / 这个 xnu 上**是否成立**？如果 `struct task` 里并没有
这样一个直接回指 `proc` 的指针字段，那我的判据本身就错了——请直接说明，
并给出**应该用哪一个字段**来判定"这个地址是不是本进程的 task"。

**Q1.2** 若该字段**存在但不在 `[+0x00, +0xF8)` 窗口内**，请给出它在本构建上可能的位置区间
（或说明不能给）。

**Q1.3** 反过来：如果 32 个槽里一个都不命中、而其中 13 个是合法内核地址，
你更倾向于下面哪一种解释？请给出**区分方法**（不要只说"可能"）：
  - (甲) 候选 `task` 地址算错了（`proc + 0x730` 不是 task）；
  - (乙) 候选地址对，但 `struct task` 里没有回指 proc 的字段（判据错）；
  - (丙) 候选地址对，回指字段存在，但它的值**不是** `current_proc` 的裸值
    （例如带 PAC 签名、或指向 `bsd_info` 而不是进程 proc、或指向 `task` 自身）；
  - (丁) 其他。

**Q1.4** 关于 (丙)：如果那个字段其实是 **`task->bsd_info`**（指回 proc），那么它的值应当
**等于 `current_proc`**；但如果它是**签名指针**且我的还原方式不对，还原后就会是一个
"看起来合法的内核地址但数值不对"的值。请说明：
  - 在这个 (Darwin 22 / arm64e) 上，`task->bsd_info` 是否**参与指针认证**；
  - 若参与，正确的还原方式是什么（key / discriminator 层面的依据）；
  - 以及一个**纯算术**的自洽判据：在只能看到 raw 值与还原值的情况下，
    怎么区分"这是签名过的 `current_proc`"与"这是一个碰巧合法的别的地址"。

---

## Q2. 不依赖固定间距：从 `current_proc` 得到 task 的可行路径

请对下面每条给出「可行 / 不可行 / 证据不足」，以及**它的失败模式**（是崩，还是静默算错）：

  - (a) 从 `current_proc` 的某个**已知字段**直接取 task（若有这样的字段，请指出其名称与
    在本构建上的偏移，以及你判断该偏移的方法）；
  - (b) 走 `proc->p_list` 链表（`le_next` / `le_prev`）遍历 `allproc`，用
    `proc->p_pid == self_pid` 定位到自己的 proc，再取它的 task。注意：外部复核已指出
    `struct proc` 条目**不含自引用指针**，所以不能靠"指回自己"来定位；但本进程自己的
    `p_list.le_prev` 是否指向前一个节点的 `p_list.le_next` 字段，从而可以**反推**
    "包含自身地址的那个结构"？（请核对这是否成立，以及成立需要什么前提。）
  - (c) 用 Mach port：`task_for_pid(self)` / `mach_task_self()` 一类的机制能否在
    **无越狱**环境下拿到本进程 task 的内核地址（不是 port name，而是内核对象地址）；
  - (d) 从 `current_thread`（如 `mach_absolute_time` 之外的可读来源）→ `thread->task`；
  - (e) 其它你认可的路径。

**Q2.1** 上列路径里，哪一条**不需要读任何"未经确认的地址"**（即每一步的目标地址都由
"已确认的对象 + 已知字段偏移"推出）？这是我最关心的性质——因为读未验证地址 = 整机 panic。

**Q2.2** 如果最终仍然必须依赖"某个偏移"，那么**有没有办法在本机把它测出来**？
即：给定一个**已确认正确**的 `current_proc`，能否通过只读扫描/自洽判据确定
`proc → task` 的间距，而**不冒 panic 风险**？（我现在的探针就是干这个的，但它依赖
Q1.1 那个"task 回指 proc"的判据；如果那个判据可用，这条路就能走通。）

**Q2.3（我认为最关键的一问）** 「自证式闭包」这条路成立吗？
有人建议我走 `proc −─p_proc_ro──→ proc_ro −─pr_task──→ task`。我理解他给的判据是：

  1. 读 `proc + O1` 得到候选 `R`（他给的 `O1 = 0x18`）；
  2. 读 `R + 0x00`，**要求它等于 `current_proc`**（`pr_proc` 回指，形成闭包）；
  3. 只有当第 2 步成立，才读 `R + 0x08`（`pr_task`），与候选 task 比对。

请判定：

  - 这个**闭包判据**（"`R + 0` 回指 `proc` ⟹ `R` 就是 `proc_ro`"）在 arm64e / 这个
    xnu 上是否成立？回指字段是 `pr_proc` 吗、它是否带 PAC 签名？
  - `O1 = 0x18`、以及 `pr_task` 在 `proc_ro` 内的偏移 `0x08`，在 **Darwin 22.4.0 /
    xnu-8796.102.5~1 / T8112** 上是否就是这两个值？如果不是，权威值从哪来
    （`kernelSymbol` / XPF 快照里能否解析出 `proc_ro` 结构描述）？
  - 更重要的是：**这条路径的第一步之后，每一步都是"把上一步读出来的值当地址再读"**。
    在我的读取原语下（`kread_sem_open`，踩未映射地址 = 整机 panic、无 fault-recovery），
    第 1 步读出的 `R` 在**第 2 步被当地址用**之前，有没有任何可判定的形态条件能让它
    安全？如果 `proc + 0x18` 那个位置其实不是指针（而是某个数或已释放值），
    读 `R + 0x00` 就是一次盲读 → 整机 panic。
  - 因此：**有没有一条路径，能只用"已确认对象 + 已知偏移"的地址，全程不出现
    "把读到的值当地址读"**？如果不存在这样的路径，请直接说"不存在"。

**Q2.4** 如果 Q2.3 的闭包判据成立，它能否**同时**给我 `O1` 与 `pr_task` 偏移？
即：我能否只固定 `proc`（已知正确），把 `O1` 当未知量，在 `proc + 0x00..0xF8` 里
逐一验证闭包、从而在**本机实测**出这两个偏移？这个扫描每个候选都要读一次候选地址
（仍是盲读），所以我的疑问同上：**有没有零盲读的变体**？

---

## Q3. 关于"版本前缀匹配"的既有缺陷（想确认我的判断）

偏移表按 Darwin 版本串的 **29 字符前缀**比，本机匹配到的是
`...root:xnu-8796.102.5~1/RELEASE_ARM64_T8101`（M1），而本机实际是 `T8112`（M2）。

**Q3.1** 29 字符前缀是否足以区分 T8101 / T8110 / T8112 / T8120 这些 SoC 变体？
请给出这几个构建的版本串在**多少个字符之后**才分家。

**Q3.2** 在 iOS 16.x 上，`proc__object_size` 与 `task__map` 这两个量**是否会随 SoC 变**？
若会，请给出 T8112 / Darwin 22.4.0（xnu-8796.102.5~1）上的权威值（或指出它必须实测）。

**Q3.3** 更一般地：**有哪些内核结构偏移是"随构建变"的**，哪些是"跨构建稳定"的？
我想知道该把哪些量当成"必须实测/必须按构建表取"，哪些可以放心当常量。

---

## 附：为什么这个探针**只读一级**（如果你要建议更深的读法，请先看这一节）

在这台设备上已经发生过**四次整机 panic（彩屏重启）**。最近一次的关键现场：

```
esr = 0x96000007 (EC = same-EL data abort, DFSC = 0b000111 → level-3 translation fault)
far = 0xfffffe1009577ffc
x8  = 0xfffffe1009577ff4     (far == x8 + 8)
Zone map: 0xfffffe100f10e4000 - 0xfffffe1610f10e4000
Kernel text base: 0xfffffe0022084000
```

其中 `x8` 是"被改写过的结构体指针"，它可以被解释成 `kaddr − delta` 之后内核开始解引用的
起点。因为**kread 是让内核去解引用**，所以"猜一个地址然后读它"这类做法在这里的代价是
整机重启而不是进程报错。这也是为什么本次探针只做一级读、不对槽里的值再解引用。

若你建议的路径需要读一个"未经确认的地址"，请明确标注这一步的风险，并给出**有没有替代**。

---

## 输出格式

每问先给 `成立 / 不成立 / 证据不足`，再给推理，再给最小反例或精确条件。
能用具体十六进制地址或位型说明的，不要用文字描述代替。
