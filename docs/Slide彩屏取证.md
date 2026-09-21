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

## 六、下一步（前四项的落地情况）

> 状态：**1、2、3 已在 `4da6cf8` 落地**（CI #142 绿），第 4 项的备用路径尚未做，
> 第 5 项（窗口层）是 §7.5 那三条定位路线的共同前提。

### 已完成 · 链接基址改从 XPF 现取（不是改成一个新常量）

原先 `KernelSlide.m:51` 那份硬编码副本已退居兜底（改名 `_FALLBACK`），
优先取 `km_xpf_kernel_base()`（读 `gXPF.kernelBase`，XPF 未就绪或字段是
`UINT64_MAX` 哨兵时返回 0）。这样设备换了构建配置也不会再错——
写成另一个常量只是把同一个错换个写法。

诊断里三行并列：`link_const=` / `link_xpf=` / `链接基址采用=…（来源：…）`，
面板与落盘各一份。这既是回归哨兵，也是 §3.2 那个疑点的第一手读数。

### 已完成 · 自检之前先落盘

`slide_verify_kernel_base()` 在发出那次 kread **之前**，把全部数值写进
`Documents/kernelslide-diag.txt`：`candidate`、两个链接基址与采用值、待读地址、
`fo_kqfilter` 原始读数与还原值、`linked_vn_kqfilter`、`T1SZ_BOOT`、`current_proc`、
`fd_ofiles` 偏移、kernelcache 路径，外加诊断正文快照。

落盘实现绕开了当初撞上的那对矛盾（「必须先写后读」vs「观测不许挂在被观测路径上」）：
I/O 全在后台队列，同步段只做一次 malloc+memcpy，然后**有界等待**（2 秒上限），
超时**不**阻断流程、只在诊断里记一句。

### 已完成 · 候选值的纯算术约束

`slide_candidate_fits_image()`：链接基址 + candidate 必须落在内核映像窗口内，
再加一条软判据（已实测的链接期符号必须压在基址之上 1 GB 内）。
不通过就**一次 kread 都不发**。这条把「基址取错域」从彩屏降级成干净失败——
也正是本次彩屏最容易命中的那一类。

### 待做 · 自检加第二条独立路径（allproc）

现有自检只拿一个候选值去赌那一次读。改进方向是两条独立路径**都算出且相等**
才允许读：

- **路径 A**：现有那条 `fo_kqfilter`（fd → fileproc → fp_glob → fg_ops）；
- **路径 B**：`current_proc.le_prev` → allproc 头（零件已在，
  见 `KernelMemory.h` 的 `km_proc_p_list_le_prev_offset()`；
  `current_proc` 是 kfd 反查出来的已证地址，只需一次 KVA 内读+取值）。

不等或只有一条 → 拒绝，不读。

### 待做 · physrw 窗口层（建窗 → 改 PTE → 本地读）

这是 §7.5 那三条定位路线**共同的前提**，也是「照样本做」里样本唯一
真的给了答案的一环（形态已逐地址掌握）：

```
建窗    mach_vm_allocate(flags=0x4002 PURGABLE)
        vm_remap(copy=FALSE, src=target=self)     样本用页大小 0x4000，不是 vm_page_size
        mlock
改 PTE  km_pte_for(窗口 VA) 拿 PTE 地址 → km_write(pte, 目标PA | 权限位)
        TLB 刷新：用户态没有 tlbi，靠 mach_vm_protect 翻权限触发
数据面  vm_copy 进出窗口（样本形态：两张 5 条目的「页地址+长度」表）
```

**第二步单独上机、单独验证**，且只改一页、立刻读回——
写坏自己的 PTE 比读错地址更难恢复。

> **这一层已经有可直接抄的开源实现**：`0x7ff/golb` 的 `golb_map()` / `golb_find_phys()`
> / `golb_unmap()`，只需 `kbase + kread + kwrite` 三样输入（Aether 全有），
> 还带了 PTE 地址的反查（`pv_head_table`）与 TLB 刷新做法。
> 详见 §7.6 / §7.7。


---

## 七、样本未确证三题的结果（2026-09-22 补，独立取证 + 复核）

来源：`D:\工作区\_Aether_rev\_rev\样本未确证\`（`报告_未确证三题.md` +
`verify_all.py`，一键复现 `python verify_all.py` → 32 ok / 0 bad）。
A/B 两条我另做了独立取证（读原始指令字与 `bl` 目标），结论与它一致。

### 1. 数据面（原先"未解"）—— 已确证

`0x100f76da4` 是 kread/kwrite 的**分段搬运器**。那组没接上的偏移属于
`[x19+0x3e0]` 指向的 0x80 字节描述符，里面是**两张 5 条目的「窗口内 16KB 页地址 +
长度」表**（读路径 `0x08/0x18/0x28/0x38/0x48`，写路径 `0x10/0x20/0x30/0x40/0x50`）。
两个消费端就是那两次 `vm_copy`（`0x100f770f0` 读、`0x100f77154` 写）。

### 2. `hw.memsize` 的角色 —— 已确证，且**推翻了此前的一个判断**

`hw.memsize >> 14`（`0x100f84c50`，我独立核对：`0xd34efd15` 的 imms=0x2e → 移 14）
**既不是 PUAFF 占页压力上界，也不是物理内存遍历边界**。我独立扫了循环体
（`0x100f84bc0..0x100f84d90`）的全部 `bl`，只有两个目标：

```
0x100f84c44  bl 0x1010b15fc   ← sysctlbyname（hw.memsize 取值）
0x100f84d00  bl 0x1010b16d4   ← vm_copy
```

**没有 `mach_memory_object_memory_entry_64`、没有 `vm_map`、没有 `mlock`** ——
所以它不是占页压力；循环体唯一的内存动作是一次 `vm_copy`，紧接着对
`[x19+0x3d8]` 做**哨兵字符串比较**（游标 `0x100f84d6c add x26,x26,x21` 推进）。
即：**这是一个探页循环，按 16KB 页粒度找带内部哨兵的那一页。**

顺带一条值得记的取证经验：那句哨兵 `p0up0u was here` 在这个位置**以立即数折在指令里**
（我逐条解过 `movz/movk`，`0x100f86cd0..` 拼出 `p0up0u w` / `as here\0`），
所以**明文 grep 永远搜不到它**。

`[x19+0x3d0]` 页数的唯一写入点是 `0x100f79f1c str x1,[x0,#0x3d0]`（函数第 2 参数），
紧跟 `calloc(页数×8)` 落到 `[x19+0x3d8]` —— 数据来源是**上层参数**，非常量、
也非由 `hw.memsize` 推出。

### 3. 跨进程访问权 —— 已确证，且边界明确

样本**只对自己有访问权**：`task_for_pid` / `task_name_for_pid` / `proc_listpids` /
`proc_pidinfo` / `pid_for_task` / `mach_vm_read` / `mach_vm_write` 等既不在具名导入里，
字面量也不在 `__LINKEDIT` 符号串与 `__TEXT,__text` 全段（lazy bind 必须留符号名，
所以「缺字符串」比「搜不到」强）；唯一任务端口全局 `0x101b68468` 全 `__text`
**54 处 load、0 处 store**。

**能确证的**：这份二进制里读/写原语的被操作对象**必然是本进程地址空间**；
对某个外部 App 的数据的访问权，**不可能由它自己取得**——必须由把代码放进那个进程的
宿主提供。**不能确证的**是目标数据具体属于谁：二进制里没有任何读开机时间、进程列表、
目标 bundle id 的痕迹，它是库形态。

### 4. 这条对 Aether 的意义 —— **一次自我修正**

我先前据这条写下「Aether 是独立进程的悬浮窗，拿不到这一层，所以不能照抄样本直接读自己
地址空间」——**这句推论不成立，在此改正。**

理由：样本的读写原语确实只操作自己的地址空间，但那正是 **physrw 窗口**的含义——
窗口页被改过 PTE 之后，形式上仍是「自己的 VA」，实际指向的是**任意物理页**。
所以这条结论区分不了「样本运行在目标进程内」与「样本在外面读物理内存」两种情况：
前者用自己的 VA 直接定位数据，后者得在物理页里找。**哪一种是没被证实的**
（见"未能证实"里那条「目标数据具体属于谁无法判定」）。

对 Aether 来说，只要把 physrw 做出来，它同样能读写自己的地址空间、进而读写任意物理页
——这一点与样本没有差别。**真正的差别只可能在「定位」那一环，不在读写能力这一环。**

> 所以「照样本做」这条路线**没有被这条结论否掉**。它只是把问题重新推回到
> 「怎么知道该读哪一页」，而那一环样本自己也还没给出答案。

### 5. 「该读哪一页」——公开资料能给的和给不了的

网上能查到的 physrw 材料（[iOS Exploit Starterpack · Physical Read/Write](https://tin-z.github.io/ios-exploit-starterpack/en/physical-rw/)）
讲到「改 PTE → 映射整个 DRAM → 拿到任意物理读写」就结束了，
**没有一篇讲拿到 physrw 之后怎么定位自己要的数据**——那一层是各家自己的东西。
所以本节不引用外部结论，只把可选路线列清楚，供下一步决策。

**路线 A · 页表定位（推荐优先验证）**

用内核读+符号把目标进程的**页表**读出来，得到「它的哪个虚拟地址落在哪个物理页」，
再用 physrw 把那些物理页映射进窗口。这条路：

- 不需要 task port（走内核结构，不走用户态跨进程 API）——与样本符号画像并不冲突；
- 不需要把 128 GB 物理内存扫一遍；
- **复用 Aether 已有的东西**：`km_page_table_walk`（VA→PA）与 `km_pte_for` 服务的就是这件事，
  那批 L3 判据修复在这里是主干而非兜底。

需要的输入：目标进程的 `task → vm_map → pmap → tte`，以及各段 `vm_map_entry` 的范围。
样本解析过 `kernelStruct.vm_map.pmap` 与 `task.itk_space` 这两个键，
**这暗示它走的正是这条路**（但它的 `pmap.tte` 没被解析过，所以这仍是推断，不是结论）。

**路线 B · 按页播种 + 哨兵验证**

就是样本那个探页循环的形态：从某个基址开始 `基址 + (i<<14)` 逐页推进，
每页 `vm_copy` 进来对着哨兵比较（`p0up0u was here`），命中即停。
它证明样本确实会做「按页串行查找」，但它证明的是**库自检**，
不能推出这就是它定位游戏数据的方式。

**路线 C · 物理内存盲扫 + 特征匹配**

把 `hw.memsize` 范围内的页逐页映射进来，用特征值/结构体签名匹配。
对 6 GB 内存、16 KB 页是约 39 万页；如果每页要走一次映射+匹配，代价很大。
**目前没有任何证据支持样本这么做**——它的探页循环里没有逐页内容匹配的循环体。

> Aether 的取舍：**A 优先**。它把已有的页表下钻能力直接变成产出，
> 而 B/C 都需要先盲找、再验证，且都要先有 physrw 窗口层才谈得上。
> 三者都建立在同一件事上：**physrw 窗口层必须先做出来**（见 §6）。

### 7.6 找到了参考实现（2026-09-22 补）

前面说「公开资料不讲这一层」要修正：**physrw 的定位与建窗，有开源实现**，
两个都是 C、都是 Apache-2.0：

| 项目 | 它给什么 |
|---|---|
| [`0x7ff/golb`](https://github.com/0x7ff/golb)（81★，"Mapping physical memory to user space (EL0) on iOS"） | `golb_init(kbase, kread, kwrite)` → `golb_find_phys(virt)` 拿物理地址；`golb_map(ctx, phys, sz, prot)` 把任意物理页映射进用户态；`golb_unmap` 还原；`golb_flush_core_tlb_asid` 刷 TLB；另外自带一套 pfinder 自动定内核符号 |
| [`0x7ff/maphys`](https://github.com/0x7ff/maphys)（"Accessing physical memory on iOS"） | 同一族：pfinder 定符号 → `kcall`（能调内核函数）→ `phys_copy` 做物理内存搬运 |

**为什么对着我们的项目特别有用**：`golb_init()` 只吃 `kbase + kread + kwrite` 三样，
而这三样 **Aether 现在全有**（`km_kernel_base` / `km_read` / `km_write`）。
它不依赖 task port、不依赖 PUAFF 之外的任何东西。

**建窗的真实做法**（`golb_map`，读出来和我们的设想对齐但更细）：

```
1  mach_vm_allocate(ANYWHERE) 一出虚拟范围
2  kread our_map + vm_map_flags_off → 置 VM_MAP_FLAGS_NO_ZERO_FILL → kwrite 回去
3  往这段 VA 每页写 FAULT_MAGIC，逼内核真的建立 PTE（否则只是保留虚拟地址）
4  它自己查 vm_map_entry → vm_page 链，核 vmp_offset，拿到物理页号
5  查 pv_head_table[(phys - phys_base) >> page_shift] → 反查出 ptep
6  读出旧 PTE 存档 → 改写：phys | VALID | ATTRINDX(禁用缓存) | AF | AP | PNX | NG
7  写回 + 刷 TLB（golb 的做法是临时改自己 pmap 的 sw_asid 再切回，做局部刷新）
```

第 5 步是关键细节，也是我们原先不知道的：**PTE 的地址要靠 `pv_head_table` 反查**，
不是「算出窗口 VA 在第几级表里」推出来的——因为一页物理内存可能被多处映射。

### 7.7 这些参考实现用的符号，XPF 全都给（含我们已实测的）

| golb 用的符号 | 它干什么 | Aether 怎么拿 |
|---|---|---|
| `pv_head_table` | 从物理页号反查 PTE 地址（第 5 步） | **XPF 有** —— 样本的 `kernelSymbol.pv_head_table` 同一把键；`dynamic_info.h` 里注释着那句内核串 |
| `pmap_find_phys` | 内核函数：pmap 内 VA→PA | XPF 有（`kernelSymbol` 族） |
| `vm_map.pmap` / `task.itk_space` / `proc.struct_size` | 找目标进程的地址空间 | **样本解析过这三个键**，XPF 同一批 |
| `boot_args`（`phys_base` / `mem_sz`） | 物理内存范围 | 走 XPF 或 `hw.memsize` |
| `phystokv` / `ptov_table` / `gVirtBase` / `gPhysBase` / `cpu_ttep` | 换算与页表根 | **已在设备上实测 8/8 解析成功** |

也就是说：**golb 那条路的每一块零件，Aether 手上都已经有或能拿到**——
XPF 负责符号（替代 golb 自带的 pfinder），kfd 负责 kread/kwrite，
缺的只有把 golb 那 7 步移植过来。

> 有待确认：`golb`/`maphys` 的目标版本偏老（2020–2023），跑的是更早的 iOS；
> 它用的 `pmap` / `vm_map` / `pv_head_table` 布局在 iOS 16.4.1 上是否一致，
> 必须逐项核对（`vm_map_pmap_off` / `pmap_sw_asid_off` 这些在它的代码里
> 是按版本分档硬编码的，见 `golb.c:1027-1061`）。




### 该路明确未证实的（不等于证否）

**样本究竟运行在目标进程内、还是在外面读物理内存 —— 未判定**（这一条直接决定它怎么定位数据：
在目标进程内就能用自己的 VA 直接定位，在外面就只能从物理页里找）。

循环内 `vm_copy` 的 `x1/x2/x3` 相对增量未全解出；`0x100f76da4` 再上层的业务调用方未追；
`0x101b68468` 的初始化写入点未定位；`0x101cbd478` 处 0x60 字节 `__data` 密文未解出；
`[x21+0x38..0x50]` 里 `x8` 的绝对数值依赖运行期 `vm_region_64` 输出，`region` 是哪一段解不了。


## 八、这份报告的证据在哪

- panic 全文：`C:\Users\34698\.dsh\attachments\v1\files\6f\…\panic-full-2026-09-22-033638.000(1).ips`
  - `panicString` 字段：PC/LR/`esr`/`far`、四个基址与两个 slide、Zone 图、Panicked task/thread、完整 backtrace；
  - `processByPid["371"]`：Music 进程；
  - `processByPid["371"]["threadById"]["6570"]`：崩溃线程，`dispatch_queue_label` 在这里。
- 被验证的代码：`Aether/libmemrw/KernelSlide.m`（`519-544` 自检、`546-598` 求 slide、`51` 常量）、
  `Aether/FangUI/UI/DebugProcView.swift:1024-1047`（Slide 按钮走 AutoTracker）。
- 链接基址的旁证：`Aether/libxpf/xpf/common.c:187`（上游自己拿 `0xfffffe0007004000` 判机型）。
- 样本未确证三题：`D:\工作区\_Aether_rev\_rev\样本未确证\`（`报告_未确证三题.md` + `verify_all.py`）。
- 既有交接：`docs/physrw改造交接.md`、`docs/当前任务.md`。
