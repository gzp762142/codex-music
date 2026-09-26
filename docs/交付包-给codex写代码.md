# 交付包：请直接写代码（iOS 16.4.1 / arm64e 内核读写模块）

> 这份是**干活用的**，不是提问。请按第五节的要求产出补丁或完整函数体。
> 简体中文回答；标识符 / 寄存器 / 十六进制值保留原形。
> **凡是你判断"信息不足、不能安全实现"的地方，请直接说，并给出你需要什么才能写。**
> 不要为了交差写一个你无法论证其安全性的版本 —— 这里的错误代价是整机重启。

---

## 一、工程与平台（全部为已核实事实）

- 平台：iPad14,3 / socId 8112（T8112）/ iOS 16.4.1 (20E252) /
  Darwin 22.4.0 / xnu-8796.102.5~1 / **arm64e** / **16 KB 页** / 无越狱。
- 语言：Objective-C（MRC 编译单元，非 ARC）+ C。**没有本地 Xcode**，编译只能靠 CI。
- 读原语：libkfd 的 `kread_sem_open` 后端。原理是**把本进程持有的一个内核对象的
  指针字段改写成 `kaddr − delta`**，再让内核按内核语义从那个指针开始解引用，
  把结构体拷回用户态。
- 两条路径的 delta 不同（已实测）：
  - 64 位路径 `delta = 0x0C`（`pseminfo.psem_uid`）⇒ 内核最低源访问地址 = `addr − 0x08`；
  - 32 位路径 `delta = 0x04`（`pseminfo.psem_usecount`）⇒ 源访问从 `addr` 本身开始，
    所以**页首可读**。
- **这条路径没有 fault-recovery**：踩到未映射地址 = 内核态 same-EL data abort =
  **整机 panic（彩屏重启）**。本机已因此重启五次。

## 二、硬约束（违反任一条 = 整机重启，请当成不可协商）

1. **零盲读**：任何送进读原语的地址，必须能回溯到「已确认正确的对象 + 已确认的字段偏移」。
   不允许"猜一个地址然后读它"，不允许"读失败就换个偏移再试"。
2. **不拿读出来的值继续当地址读**，除非该值已过形态检查**且**有独立证据说明它是已映射对象。
   （本工程当前把它定为纪律，但下面第三节第 2 条正需要你判断是否必须放宽 —— 见那里。）
3. 每一步都要过形态检查：内核地址域（高 16 位 `0xFFFF`）+ 8 字节对齐 + 非 0。
4. **失败就停**，不许兜底常量把失败包装成成功，不许静默重试。
5. 诊断文本永不返回 nil；`%#llx` 的实参一律 `(unsigned long long)` 强转；
   定义必须在使用之前（C 无前向）。
6. 只读探针模块不许有写操作。

## 三、需要你产出的三件事（按优先级）

### 第 1 件（最高优先）：把 slide 的 133 MB 偏差定位并修掉

**现象**（数据全部有来源，`[日志]` = 设备 panic 全文，`[诊断]` = 程序自己打印）：

```
[日志] KernelCache slide = 0x12b04000   KernelCache base = 0xfffffe0019b08000
[日志] Kernel slide      = 0x12b0c000   Kernel text base  = 0xfffffe0019b10000
[日志] text exec slide   = 0x13a5c000   text exec base    = 0xfffffe001aa60000
[诊断] 链接基址（XPF 现取 gXPF.kernelBase；另一路兜底常量相同）= 0xfffffe0007004000
[诊断] kernel_base 候选 = 0xfffffe0011598000
[诊断] 推出的 slide     = 0x0A594000
[诊断] 自检：读该 kernel_base 处页首两个 32 位字 → 失败
```

对账（可逐条验算）：

```
[日志] 三条恒等式都成立：base − 自己的 slide = 0xfffffe0007004000
[日志] KernelCache base 比 Kernel text base 低 0x8000（两次不同启动都是这个值）

真实 kernel_base − 真实 slide = 0xfffffe0006ffc000
我用的链接基址              = 0xfffffe0007004000   ⇒ 误差 A = 0x8000
真实 slide − 推出 slide      = 0x8578000            ⇒ 误差 B（主因）
B − A = 0x8570000 = 133 MB   ← 净差
```

算 slide 的链（现状，逐步读、每步过形态门）：

```
current_proc
  + p_fd 偏移（版本表条目，本机 = 0xf8）→ filedesc
    + 0                                 → fd_ofiles（fd_ofiles 在 filedesc 内偏移 0）
      + fd * 8                          → fileproc
        + 0x10                          → fp_glob
          + 0x28                        → fg_ops
            + 0x30                      → fo_kqfilter
candidate = fo_kqfilter(运行时) − vn_kqfilter(XPF 链接期)
kernel_base = 链接基址 + candidate
自检：kernel_base 页首两字须为 MH_MAGIC_64(0xfeedfacf) / cputype(0x0100000c)
```

**请你做**：

- (a) 判断这 133 MB 出在**链接期符号**还是**运行时读数**，并给出**判别方法**
  （要能证实，不能只说"可能"）。如果必须再取一个读数才能判定，说明取哪个、判据是什么。
- (b) 检查上面四个偏移（`0x10` / `0x28` / `0x30` 与版本表的 `0xf8`）在
  **Darwin 22.4.0 / T8112** 上是否正确。若某个偏了，给出正确值与依据。
- (c) 关于误差 A：`0x8000` 恰好等于 `Kernel text base − KernelCache base`。
  自检应当拼到 `KernelCache base` 还是 `Kernel text base`？如果链接基址应当用
  `__TEXT` 的 vmaddr，那现在的常量是不是本身就该 +0x8000 或 −0x8000？
- (d) 给出**修好的算法**（含自检的改进判据）。自检现在只查 `magic + cputype`，
  而候选地址与真实地址都在映像窗口内（相差 133 MB），所以它**挡不住**这种错。
  请给出能把它挡住、又不引入新盲读的判据。

### 第 2 件：确认某一个内核对象的身份，但不能用盲读

**已有事实**：

- `current_proc = 0xfffffe130d8261f0`，且 `current_proc->p_pid` 读出来等于本进程 pid
  ⇒ **proc 已确认正确**。
- 按上游等式 `task = proc + proc__object_size`（本机版本表给 `0x730`，条目标签是
  `RELEASE_ARM64_T8101` 而本机是 T8112）推出的候选
  `task = 0xfffffe130d826920`。
- 在该候选地址起 `+0x00 .. +0xF8`、步长 8 共 32 槽逐槽读，**没有任何一个槽等于
  `current_proc`**；`read failures = 0`；其中 13 个槽是合法内核地址。
- 注：那条 32 槽输出是手工转录的，其中 7 行已确认抄坏（左右两列对不上）。
  但**上面三条结论不依赖那些行**：扫描计数器、每槽读两次必须一致、以及"无命中"
  都来自程序而非转录。

**现在的死结**：要确认候选 task 是不是本进程的 task，唯一可靠判据是读 task 内回指
`proc` 的字段。一级读已穷尽（32 槽，无命中）。再往下就必须**二级读**，而第二节第 2 条
纪律禁止这么做。

**请你做**：

- (e) 给出**一条不需要任何盲读**的路径来确认这个对象的身份。若不存在这样的路径，
  请直接说"不存在"，并说明在只能承担"零次或一次整机重启风险"的前提下，
  你会选哪一次读、读什么地址、判断条件是什么。
- (f) 关于 `proc → task`：能否用 `p_proc_ro` / `pr_task` 这条路径？若能，给出
  这两个字段在 **T8112 / Darwin 22.4.0** 上的**权威偏移**及其依据（不要给 macOS 的值）。
  并说明这条路径的每一步是否需要盲读、风险多大。
- (g) 上游对 `task = proc + proc__object_size` 是**双向使用**的
  （正方向 `current_task = current_proc + size`；反方向
  `proc_kaddr = task_kaddr − size`）。既然反向用它能读出正确的 `current_proc`，
  那这个 `size` 对本机到底对不对？请给出判定方式。

### 第 3 件：把"崩之前的现场"可靠落盘

现状：自检那次 kread 是可能重启整机的操作，所以在其**之前**要把当时的全部数值写进
沙盒 `Documents/kernelslide-diag.txt`（异步写 + 有界等待 2 秒，不阻塞读链）。

已修的缺陷：原来落盘函数失败时静默 `return`，而面板依据"异步块跑完了"就报告"已写完"
→ 真机上出现过"面板说已写完、文件管理器里根本没有"。

**请你做**：

- (h) 审查这套落盘逻辑还有什么会**静默丢现场**的路径。特别注意：如果流程在 ⑤ 之前
  就失败（①②③④ 任一步），当前实现**根本不会写文件** —— 请给一个方案，
  让"任何一次失败"都留下可读的现场，且不违反第二、四节。
- (i) 现场内容够不够反推？现在写的头部键有：`candidate` / `link_const` / `link_xpf` /
  `link_used(from)` / `kernel_base_pending` / `fo_kqfilter_raw` / `fo_kqfilter_unsign` /
  `linked_vn_kqfilter` / `t1sz_boot` / `current_proc` / `fd_ofiles_offset` /
  `kernelcache 路径`，之后接诊断正文。请指出**还缺哪些键**才能把第三节第 1 件的
  (a) 一锤定音。

## 四、读取原语与页闸门（写代码时必须遵守的地形）

页闸门要求：对 64 位路径，每个 8 字节字满足 `页内偏移 >= 0x0C` 且
`末字节 <= 页大小 − 0x28 − 1`；对写路径 `>= 0x08` / `<= 页大小 − 0x08 − 1`。
32 位路径没有这个下溢要求（`delta = 0x04`，源访问从目标地址本身开始）。

**注意**：内核结构的偏移不总是 8 的倍数。当某个字段落在 8 字节字的下沿时，
64 位路径的读取必须从 `addr − 8` 起读、再取高 4 字节；且该字偏移需 `>= 0x0C`。
请在你写的代码里遵守这一点。

## 五、交付格式

- **只给 diff 或完整函数体**，标明要改哪个文件的哪个函数；不要给"大致思路"。
- 每个改动说明：为什么安全（哪一步不构成盲读）、失败时会怎样（必须停在失败，不许兜底）。
- 若某处你无法论证安全性，写 `// NEEDS-DEVICE-VERIFICATION: <要测什么>` 并说明判据。
- 不要重构既有代码的风格与注释语言（注释是中文）。
- 不要动这三个模块的对外接口：`KernelSlide.h` / `KernelPhysWindow.h` /
  `KernelPhysMap.h`（它们是旁路探针，面板按固定签名调用）。

## 六、可用的参考（不用向我索取）

- 上游同款算法：`Aether/libmemrw/kfd/libkfd/perf.h`（slide 与自检都是照它做的）。
- 版本表：`Aether/libmemrw/kfd/libkfd/info/dynamic_info.h`（按 Darwin banner 前 29 字符匹配）。
- 本工程相关文件：`Aether/libmemrw/KernelSlide.{h,m}`、`KernelStructScan.{h,m}`、
  `KernelMemory.{h,m}`、`KernelPhysWindow.{h,m}`、`KernelPhysMap.{h,m}`。
- CI：GitHub Actions，macOS-14，`push` 到 main 触发；工程无本地编译能力，
  所以请保证代码在语法与类型上自洽。
