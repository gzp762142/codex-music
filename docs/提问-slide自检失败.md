# 内核基址推导自检失败：请复核算法与判据

> **状态：本文已被 `docs/提问-slide偏差133MB定位.md` 取代，请用那一份。**
>
> 取代原因：本文写于拿到完整 panic 全文之前，当时缺两块数据，现已补齐并核验：
>
>   1. **权威值已全量核实**。本文第 55-61 行引用的那份日志已找到（设备导出、
>      09-27 00:04 那次），字段逐字吻合。其 `Kernel text exec slide` 是
>      `0x13a5c000`（本文早期版本里有一处抄成 `0x194b4000`，那是**另一次启动**的值，
>      两次启动的该字段不同，勿混用）。
>   2. **对账已精确闭合**。偏差可拆成两笔：链接基址高 `0x8000`（误差 A，恰好等于
>      panic 里 `Kernel text base − KernelCache base`），slide 少 `0x8578000`
>      （误差 B，主因）；`0x8578000 − 0x8000 = 0x8570000` 即净差。
>      新版给出了完整的拆法表与每一条等式的恒等式验证。
>   3. 新版的每个数值都带来源标签（`[日志]` / `[诊断]` / `[推算]` / `[代码]`），
>      并新增了 Q1.5（两个 kernel_base 都落在映像窗口内时自检的可通过性）。
>
> 本文保留的理由：Q1 / Q2 / Q3 三节的提问角度与措辞仍然可用，新版没有重复它们。
> 若要一次问完，把两份一起发即可；但**对账数据以新版为准**。

> 用法：整篇直接发给对方。问题各自独立，可以只答其中一处。
> 每处请明确给出「成立 / 不成立 / 证据不足」，附最小反例或反证；不要用"通常""一般"代替结论。
> 回答用简体中文；标识符 / 寄存器名 / 位值保留原形。

---

## 一句话核心问题

我用「运行时函数地址 − 链接期函数地址」推内核 slide，再用它拼 `kernel_base`。
一次 panic 日志给出了**权威值**，两相对账后发现：**`kernel_base` 偏了 133 MB**，
而偏差可以拆成两笔 —— 链接基址高 `0x8000`、slide 少 `0x8578000`。
请复核这个拆法，并指出 `slide` 系统性偏掉 133 MB 这种量级**最可能的成因与判别方法**。
（关键数据在背景之后的「一次 panic 日志给出权威值」一节。）

---

## 背景（全部为通用事实）

平台：Darwin 22.4.0 / xnu 8796.102.5 / arm64e / **16 KB 页** / 用户态进程（无越狱、通过公开内核漏洞获得内核读原语）。

读取原语：官方公开项目 libkfd 的 `kread_sem_open` 后端 —— 要读内核地址 `kaddr`，先把自己持有的一个内核对象的**指针字段**改写成 `kaddr - delta`，再调 `syscall(SYS_proc_info, PROC_INFO_CALL_PIDFDINFO, ...)`，由内核按内核语义从那个指针开始解引用，把结构体内容拷回用户态。这条路径上内核没有 fault-recovery handler：一旦踩到未映射地址，结果是**整机 panic**，不是本进程报错。

为了拿到"内核基址"（后面所有符号地址都靠它加偏移算出来），我用的是公开项目 Dopamine 在 `perf.h:97-118` 里的同一条思路：

```
① 打开一个自己的 vnode 文件描述符（publish 一个 .plist），
   从 proc 的 fd 表一路读到 fileglob，再从 fileops 表取 fo_kqfilter —— 这是一个
   运行时的内核函数指针；
② slide = fo_kqfilter(运行时) − vn_kqfilter(链接期)；
③ kernel_base = 链接基址 + slide；
④ 自检：读 kernel_base 处的两个 32 位字，必须是 MH_MAGIC_64(0xfeedfacf) 与
   cputype(0x0100000c = CPU_TYPE_ARM64|CPU_ARCH_ABI64)。
```

本机实测（这是**唯一一次失败记录**，之后设备重启、内存里的诊断已丢）：

```
T1SZ_BOOT = 17
链接基址（来源：XPF 从 kernelcache 现取的 gXPF.kernelBase 值，另一路常量兜底相同）
    = 0xfffffe0007004000
kernel_base 候选 = 0xfffffe0011598000        ⇒  推出的 slide = 0xA594000
自检结果：读 kernel_base 处头部失败
```

其余环节都读出来了（`fd_ofiles=0xfffffe8211098000`、`fileproc=0xfffffe1300abc240`、`vn_kqfilter` 链接期=0xfffffe0008121… 均取得），所以**读取原语本身可用**，断在自检那一次读。

### 补充：一次 panic 日志给出了权威值（这一节是后加的关键数据）

随后那次自检读触发内核 data abort（`esr = 0x96000006`，DFSC = 0b000110 **level-2** translation fault；
`far = 0xfffffe005647c034`，`x8 = 0xfffffe005647c02c`，`far == x8 + 8`）。panic 日志本身给出了权威地址：

```
KernelCache slide: 0x0000000012b04000
KernelCache base:  0xfffffe0019b08000
Kernel slide:      0x0000000012b0c000
Kernel text base:  0xfffffe0019b10000
Kernel text exec slide: 0x0000000013a5c000
Kernel text exec base:  0xfffffe001aa60000
Fileset Kernelcache UUID: DD3296640AAAC379C87A292839B3B6B7
Kernel UUID: F252D9D1-9D79-35E5-81FC-4B4F64ED3231
Zone map: 0xfffffe100cae0000 - 0xfffffe160cae0000
设备：iPad14,3 / socId 8112 / iPhone OS 16.4.1 (20E252) / xnu-8796.102.5~1/RELEASE_ARM64_T8112
内核参数：Kernel text base = KernelCache base + Kernel slide = 0xfffffe0019b08000 + 0x12b0c000 ✓
```

与上面那次推算对账：

```
真实 kernel_base − 真实 slide = 0xfffffe0006ffc000     ← 由这两个权威值算出的"链接期基址"
手上用的链接基址              = 0xfffffe0007004000
差                            =            0x8000     ← 误差 A
真实 slide − 推出的 slide     = 0x8578000 = 133 MB     ← 误差 B（主因）

两者相抵后：真实 kernel_base − 候选 kernel_base = 0x8570000 = 133 MB
```

请注意 `0x8000` 那个差：panic 里 `KernelCache base` 与 `Kernel text base` 正好差 `0x8000`，
而 `Kernel text base = KernelCache base + Kernel slide` 是定义。这似乎说明
`gXPF.kernelBase` 给的不是 Mach-O 头那一处，而是往后 `0x8000` 的 `__TEXT`。

**Q0.1** 上面对账的三条推论（误差 A = `0x8000`、误差 B = `0x8578000` 为主因）成立吗？有没有别的拆法？

**Q0.2** `0x8000` 这个偏移。`macho_get_base_address` 取的是"非 `__PRELINK`/`__PLK`/`__PAGEZERO`
段中最小的 `vmaddr`"。在内核 64 位 Mach-O 里，这个最小 `vmaddr` 是**文件头所在地址**，还是
`__TEXT` 段的 `vmaddr`（即头之后 `0x8000`）？两者在标准布局下是否相同？如果 `__PAGEZERO`
被排除而头本身不属于任何段，那"头地址"该怎么求？

**Q0.3** 误差 B 是最要紧的：`slide = 运行时 fn − 链接期 fn` 这个式子，在什么情况下会**系统性**
偏掉 133 MB 这种量级？请按可能性排序，并给出**判别方法**（不要只说"可能错"，要说怎么证实）：
  - 链接期地址来自**另一个 kernelcache 变体**（同一 SoC 可能存在多个 fileset）；
  - 运行时 `fo_kqfilter` 实际指向 **thunk / 桩**而不是函数本体；
  - 该字段本身不签名或有别的编码，导致"还原 PAC"步骤引入了偏差；
  - 取的是 fileops 表里**不同条目**（偏移错位）；
  - 其他。

**Q0.4** 内核版本串里带 `RELEASE_ARM64_T8112`，而 `iPad14,3` 的 SoC 也是 T8112，
所以这一处是一致的。那么 kernelcache 的选择是否还存在"同 SoC 多份 fileset"的坑？
公开的 kernelcache 路径（`/System/Library/Caches/com.apple.kernelcaches/` 与
`/private/preboot/<uuid>/...` 那几处）在 16.4.1 上应当以哪一个为准，如何用 UUID 校验？

**Q0.5** 既然 panic 日志能给出 `KernelCache base` / `Kernel slide` 这类**权威值**，
那么在**运行时**（不依赖 panic），有没有受支持的方式拿到等价信息？例如
`sysctl kern.kernel_slide`、`OSKext` 系列接口、或 `kern.bootargs` 里的线索？
如果有，它是否对所有进程可见？

---

## 第一处：`kernel_base = 链接基址 + slide` 这个算法与它的两个隐含约束

**Q1.1** `slide`（内核映像的加载偏移）在 arm64e / 16 KB 页 / T1SZ_BOOT=17 的配置下，**必须满足哪些约束**？请分别说明：
  (a) 对齐要求（是否是 `0x200000` 的倍数？依据是什么 —— 页表层级、`__TEXT` 段的 `vmaddr` 对齐、还是别的）；
  (b) 取值范围（slide 的上界由什么决定？内核 VA 空间大小、还是可用物理内存）；
  (c) `0xA594000`（≈166 MB）是否落在这些约束内。

**Q1.2** 用「运行时函数指针 − 链接期函数地址」推 slide，成立的前提是什么？请把前提逐条列出，特别是：
  - 那两个符号必须是**同一个**函数（`vn_kqfilter` 的运行时地址是否可能指向一个 thunk / stub / 重定向桩，而不是函数本体？若可能，这个方法的误差是多少）；
  - 链接期地址必须来自**与当前运行内核完全同一份构建**的这个约束，具体该怎么验证（是比对 kernelcache 的 UUID、`kern.osversion`、还是别的）。

**Q1.3** 如果 `slide` 是对的，那 `kernel_base = 链接基址 + slide` 成立的前提又是什么？链接基址（这里是 `0xfffffe0007004000`）在 arm64e 上是怎么定义的 —— 它是内核镜像的链接 `vmaddr`，还是 `__TEXT` 段的起始，还是别的？这个常量在不同 SoC / 不同 iOS 构建上是否会变？请给出判定"这个常量对本机正确"的方法（不要只说"实测"）。

**Q1.4** 从 `kernel_base` 读 `MH_MAGIC_64 + cputype` 做自检，这个判据**挡不住**哪一类错？请具体列举。特别是：如果链接基址本身取错域（例如偏了整 2 TB），自检会以什么形式失败 —— 是读到错的值、还是内核在未映射地址上 data abort？

---

## 第二处：PAC 还原与"低 21 位自洽"

`fo_kqfilter` 是**函数指针**，在 arm64e 上会被指针认证签名。要从它推出 slide，必须先去掉签名。上游库的做法（`static_info.h:96-100`）：

```c
ONES(x)       = (1ULL << (x)) - 1
PTR_MASK      = ONES(64 - T1SZ_BOOT)      /* T1SZ_BOOT = 17 → 0x00007fffffffffff */
PAC_MASK      = ~PTR_MASK                 /* 0xffff800000000000 */
SIGN(p)       = ((p) & BIT(55))
UNSIGN_PTR(p) = SIGN(p) ? ((p) | PAC_MASK) : ((p) & ~PAC_MASK)
```

**Q2.1** 对 `T1SZ_BOOT = 17` 的 arm64e 内核指针，`UNSIGN_PTR` 是恒等变换吗？请给出理由，并指出在什么情况下**不是**。

**Q2.2** `SIGN(p)`（只看 bit 55）能不能用来判断"这个值是否被签名过"？请给出一个**未被签名、canonical、但 `SIGN(p)` 为真**的具体地址作反例；然后说明它**能**正确回答的是哪个问题。

**Q2.3** 我有一条自洽判据：**`slide` 的低 21 位必须为 0**（因为 slide 是 2 MB 的倍数），并且 **`运行时` 与 `链接期` 的低 21 位必须相同**。请问：
  (a) 第二条（低 21 位相同）在 PAC 未正确还原时会怎样表现？签名位落在 bit 47 以上，是否可能**同时**保持"低 21 位相同"和"2 MB 对齐"，从而让这两条判据都失效？请给具体位型。
  (b) 有没有一条**纯算术**的判据，能在不读内核内存的前提下，区分"slide 算错了"与"链接期地址来源不对"？

**Q2.4** `fo_kqfilter` 的**原始读数**（未还原 PAC 之前的值）应该长什么样？请给出该配置下合法签名的位型特征（哪些位是签名、哪些位是地址），并说明：如果原始读数的 bit 47..63 不是全 1 且也不是合法签名形态，最可能的来源是什么（读取环节错 / 字段偏移错 / 该字段本来就不签名）。

---

## 第三处：失败区分（这一条是当前最卡的地方）

我的读路径分两层：

```c
static bool read_bulk(uint64_t addr, void *out, size_t len) {
    if (!out || len == 0) return false;
    if (!kernel_ptr_shape_ok(addr)) return false;   /* 形态检查：高 16 位必须是 0xFFFF、8 字节对齐 */
    return km_read(addr, out, len);                 /* 底层 kread */
}
```

而 `km_read` 里还有一道"页闸门"：它要求目标区间内每个 8 字节字的**页内偏移 ≥ 0x0C**（因为底层把指针改写成 `addr − 0x0C` 之后再让内核解引用，页内偏移小于 0x0C 就会踩到前一页 → 整机 panic）。同时还有上界：读 `len` 字节时要求页内偏移不超过 `0x4000 − len`。

失败现象：`kernel_base=0xfffffe0011598000` 这个地址（16 KB 对齐、页内偏移 0）**读不出来**。

**Q3.1** 对这个地址，上述闸门会怎么判？请逐步算（`addr & 0x3FFF`、与 0x0C 和 `0x4000−8` 的比较），明确给出"会被拒"还是"会放行"。

**Q3.2** `kread` 这个原语在内核侧失败时**不返回错误**（它返回 void，失败时要么静默、要么内核 panic）。所以在用户态，能区分的情形只有："没发出读"、"被自己的闸门拒了"、"发出了读但内核没 panic 也没给回正确数据"。请回答：**在不能读到目标地址的前提下，有没有办法判断"这个地址是否已映射"？** 如果有，给出手段；如果没有，明说没有。

**Q3.3** 如果 `kernel_base` 的候选值算错了，它会落到什么区域？在内核 VA 空间里，"离正确值偏了几十 MB 到几百 MB"的地址，通常是未映射的、还是可能落在别的已映射段上？这决定了失败形态是"panic"还是"静默读到垃圾"。

**Q3.4** 最后是关于方法本身：**`kernel_base` 有没有不依赖"读候选地址做自检"的独立推导路径？** 例如从 `cpu_ttep`（TTBR1 的值）、从 `kernel_proc` 的 `vm_map`、从某个已知的固定符号反向推算。请给出可行的路径，并说明各自的失败模式（是崩，还是静默算错）。

---

## 输出格式

每问先给 `成立 / 不成立 / 证据不足`，再给推理，再给最小反例或精确条件。能用具体十六进制位型说明的，不要用文字描述代替。
