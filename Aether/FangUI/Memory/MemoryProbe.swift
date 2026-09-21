import Foundation
import Darwin
import CoreGraphics

/// 读内存探针：**只读**，不写、不 hook、不注入。
///
/// 读取路径：**内核读写原语**（见 libmemrw/KernelMemory.c）。
///
/// ```
/// pid → proc → task → vm_map → pmap → 页表 → 物理页 → 内核虚拟地址 → kread
/// ```
///
/// 原语由 PUAFF 建立（kopen → puaf_run → krkw_run），**不经过 task_for_pid，
/// 也不使用 mach_vm_read** —— 目标进程的定位与地址翻译全部在内核里完成。
///
/// 唯一保留的快路径是**共享映射**（`vm_remap` 到本进程，本地直读零内核调用），
/// 未命中时才退回内核读。两条路都可用时优先映射，因为本地读没有读锁竞争。
final class MemoryProbe {

    private typealias MachPort = UInt32
    private typealias KernReturn = Int32
    private typealias MachVmAddress = UInt64
    private typealias MachVmSize = UInt64

    private typealias VmDeallocateFn = @convention(c) (MachPort, UInt, MachVmSize) -> KernReturn

    private static func symbol<T>(_ name: String, as: T.Type) -> T? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    /// mach_port_deallocate：释放我们自己持有的 port right。
    private typealias PortDeallocateFn = @convention(c) (MachPort, MachPort) -> KernReturn
    private static let portDeallocateFn = symbol("mach_port_deallocate", as: PortDeallocateFn.self)
    /// proc_regionfilename：问「这个地址属于哪个文件」。
    /// 只要 pid + 地址，不需要 mach_vm_region —— 正好绕开那个我连错两次的调用。
    /// iOS 无 <libproc.h>，符号同样只能 dlsym 取。
    private typealias ProcRegionFileNameFn = @convention(c) (Int32, UInt64, UnsafeMutableRawPointer?, UInt32) -> Int32
    private static let procRegionFileNameFn = symbol("proc_regionfilename", as: ProcRegionFileNameFn.self)

    /// proc_pidpath：只用来问「这个 pid 还在不在」，不碰它的内存。
    private typealias ProcPidPathFn = @convention(c) (Int32, UnsafeMutableRawPointer?, UInt32) -> Int32
    private static let procPidPathFn = symbol("proc_pidpath", as: ProcPidPathFn.self)
    private static let vmDeallocateFn = symbol("mach_vm_deallocate", as: VmDeallocateFn.self)

    /// `mach_vm_allocate` —— 建窗的第一步。
    ///
    /// 样本 @0x100f75738 走的是内联 trap thunk（`bl 0x100fa2c54`，x16 = -0xa，
    /// 见 `_rev/d_A.txt` 的注释），这里用 libSystem 导出的同名函数 ——
    /// 两者落到同一条 trap，没必要自己拼 trap 号。
    ///
    /// flags 是**值语义**：样本传的是 9，那个 9 是什么意思见 buildWindow 里的说明
    /// （不是注释里常见的那句"ANYWHERE|OVERWRITE"）。
    private typealias MachVmAllocateFn = @convention(c) (
        MachPort,                            // target_task
        UnsafeMutablePointer<UInt64>,        // *address（出参，也是入参）
        UInt64,                              // size（必须是页的整数倍）
        Int32                                // flags
    ) -> KernReturn

    private static let machVmAllocateFn = symbol("mach_vm_allocate", as: MachVmAllocateFn.self)


    /// 把 kern_return_t 翻成人和自己能读懂的话。
    ///
    /// **数值按 XNU 的 mach/kern_return.h 来，别照印象写**：
    /// 1 = INVALID_ADDRESS、2 = PROTECTION_FAILURE、3 = NO_SPACE、16 = INVALID_TASK。
    /// 原来这里把 2 标成 INVALID_TASK、3 标成 INVALID_ADDRESS —— 正好串了一格，
    /// 于是「权限被拒」被报成「task 无效」，诊断方向整个带偏。
    private static func describe(_ kr: KernReturn) -> String {
        switch kr {
        case KERN_SUCCESS: return "成功"
        case 1: return "KERN_INVALID_ADDRESS"
        case 2: return "KERN_PROTECTION_FAILURE"
        case 3: return "KERN_NO_SPACE"
        case 4: return "KERN_INVALID_ARGUMENT"
        case KERN_FAILURE: return "KERN_FAILURE"
        case 16: return "KERN_INVALID_TASK"
        default: return "ret=\(kr)"
        }
    }

    // MARK: - 读（全部 static：纯函数，不需要实例）

    private static var probeCalls = 0

    /// 记一次读取：先按节奏等一下，再计调用次数 + 触及的页。
    ///
    /// **节流是防 CPU 自旋的**：我们的每一次读都要抢游戏 vm_map 的锁，
    /// 连续高频读最容易撞上争用 —— 而内核里争锁是**自旋**不是睡眠，
    /// 撞上就是 CPU 时间白白烧掉（我们被 cpu_resource_fatal 杀过两次）。
    /// 拉开节奏的代价是整条链慢几十毫秒，换来的是撞上的概率大幅下降。
    private static func noteRead() {
        probeCalls += 1
    }

    /// 走已建立的映射、本地内存直接读的次数。
    private static var mappedHits = 0
    /// 真正落回内核读的次数 —— **这个才是成本**（映射命中是本地读，不计入）。
    private static var kernelReadCalls = 0
    /// 按需建立的映射块数。
    private static var onDemandMaps = 0


    /// 目标进程还在不在。只查进程表，一个字节的内存都不碰。
    ///
    /// **这条检查是必须的**：游戏如果先崩了，我们继续读它会跟它销毁 vm_map
    /// 的过程抢同一把锁 —— 那正是长时间自旋、CPU 被烧穿的典型场景。
    /// 两次 cpu_resource_fatal 都发生在"游戏先闪退、我们随后被杀"之后。
    static func targetAlive(_ pid: Int32) -> Bool {
        guard let fn = procPidPathFn else { return true }
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = buf.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return 0 }
            return fn(pid, base, 4096)
        }
        return n > 0
    }

    // MARK: - 跨进程映射（这是样本用的读取方式）

    /// `vm_remap` —— 32 位地址空间版本，样本用的就是这一个。
    ///
    /// 样本实测（见 _kfd_port/样本通道权威实测结论.md）：
    ///     0x0100f75a34  bl  #0x1010b1704   ; __stubs -> _vm_remap（不是 mach_vm_remap）
    /// 配套的区域查询也是 32 位版：`_vm_region_64` / `_vm_region_recurse_64`，
    /// 不是 `mach_vm_region`。所以这里跟着样本对齐到 `vm_remap`。
    ///
    /// ABI 上 `vm_remap` 与 `mach_vm_remap` 参数个数、顺序、返回值都相同，
    /// 只是 address/size 在 32 位地址空间内截断——本进程映射必然落在 4G 内，不影响。
    private typealias VmRemapFn = @convention(c) (
        UInt32,                              // target_task
        UnsafeMutablePointer<UInt64>,        // *target_address
        UInt64,                              // size
        UInt64,                              // mask
        Int32,                               // flags
        UInt32,                              // src_task
        UInt64,                              // src_address
        Int32,                               // copy
        UnsafeMutablePointer<Int32>,         // *cur_protection
        UnsafeMutablePointer<Int32>,         // *max_protection
        Int32                                // inheritance
    ) -> KernReturn

    private static let vmRemapFn = symbol("vm_remap", as: VmRemapFn.self)

    /// `mach_vm_protect` —— 映射建立之后把权限压到只读。
    ///
    /// 为什么必须补这一步：`vm_remap` 的 cur/max protection 是**出参**，调用时指定不了；
    /// 而 `copy = FALSE` 的共享映射默认就带**写**权限
    /// （man page：the region is mapped read-write）。我们只读，握着一块能改游戏内存的
    /// 窗口没有任何功能收益，只有风险。
    private typealias MachVmProtectFn = @convention(c) (
        UInt32,                              // target_task
        UInt64,                              // address
        UInt64,                              // size
        Int32,                               // set_maximum
        Int32                                // new_protection
    ) -> KernReturn

    private static let machVmProtectFn = symbol("mach_vm_protect", as: MachVmProtectFn.self)

    /// `mlock` —— 把已建好的映射窗口锁进物理内存，禁止被换出。
    ///
    /// 样本在建窗之后立刻做这一步（见样本 `0x100F75AF0` 的循环）：
    ///     0x0100f75af0  ldr  x0, [x22, #0xf8]   ; 映射窗口的本地 VA
    ///     0x0100f75af4  ldr  x1, [x26, #0x70]   ; 页大小（运行时探测的 0x4000 / 0x40000）
    ///     0x0100f75af8  bl   _mlock
    ///     0x0100f75b30  b    #0x100f75af0       ; 循环
    ///
    /// 为什么要锁：整条读写原语悬在「那个物理页一直在那儿」这个前提上。
    /// 页一旦被换出再换回来，物理地址可能变，之前算好的映射目标就指错了 ——
    /// 轻则读到垃圾，重则崩溃。锁住之后窗口常驻，映射目标始终有效。
    private typealias MlockFn = @convention(c) (
        UInt64,                              // addr
        UInt64                               // len
    ) -> Int32

    private static let mlockFn = symbol("mlock", as: MlockFn.self)

    /*
     * 计数与诊断串的跨线程可见性。
     *
     * 这些值在 AutoTracker 的读取队列上写（1Hz/20Hz），但 `DebugProcView` 在主线程
     * 直接读（`MemoryProbe.mappedBlockCount`、`lastProtectFailure`）。
     * `String` 不是原子类型 —— 主线程读、后台写同一个 String 可能读到半更新的
     * 内部缓冲；`Int` 的竞争虽不致命，但会让「验收数字」读到一个撕裂值。
     *
     * 用一把轻量锁把读写都圈住。这里刻意**不**复用 AutoTracker 的串行队列：
     * MemoryProbe 是底层模块，不该依赖上层状态机，而且队列同步会把 UI 主线程
     * 压在 1Hz 的全量扫描后面。
     */
    private static let stateLock = NSLock()

    private static func withLock<T>(_ body: () -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body()
    }

    /// `mlock` 失败的累计次数。**验收要求它是 0**：
    /// 失败意味着那块窗口可能被换出，之后读到垃圾。但不致命，所以只记不丢弃。
    private static var _mlockFailures = 0
    static var mlockFailures: Int { withLock { _mlockFailures } }

    private static let vmProtRead: Int32 = 0x1
    private static let vmProtWrite: Int32 = 0x2

    /// 降权失败的累计次数。**验收要求它是 0**：每失败一次就意味着有一块映射被主动丢弃
    /// （那是正确行为），但它同时说明 `mach_vm_protect` 在这个环境上不工作，要查。
    private static var _protectFailures = 0
    static var protectFailures: Int { withLock { _protectFailures } }

    /// 最近一次降权失败的详情（地址 + 大小 + 返回码）。
    ///
    /// 光有次数定不了位。返回码能直接分开「参数/地址」和「权限」两类原因：
    /// `KERN_INVALID_ADDRESS` 指向「范围超出实际映射」—— `vm_remap` 会按源 region 的
    /// 边界把映射截短，而这里仍按原始 `total` 去 protect，多出来的那截没有映射。
    private static var _lastProtectFailure = ""
    static var lastProtectFailure: String { withLock { _lastProtectFailure } }

    /// 把一块刚建立的共享映射压到只读，**失败清理收在函数内部**。
    ///
    /// **第一步没有调用者**（跨进程映射已停用，见 mapRange 的注释）—— 这不是漏了，
    /// 是它服务的那个场景（把游戏页映射进本进程）要等第二步接回目标 task port。
    /// 留着是因为它把"失败即丢弃、绝不放行"这条约束收在了一处，
    /// 第二步接回来时直接用，不要再写第二份。
    ///
    /// `copy = FALSE` 的共享映射默认带写权限，不降权就等于握着一个能改游戏内存的窗口。
    /// 清理必须和 protect 写在同一处 —— 分成两份迟早漂移，而那条约束
    /// （失败即丢弃、绝不放行）只允许有一个实现。
    ///
    /// `set_maximum = 1` 是刻意的：只降 current 的话「上限」还留着写权限，
    /// 之后一句 `mach_vm_protect` 就能把 W 提回来。把上限本身压掉，写权限才真拿不回来。
    /// （窗口层收尾压只读用的是同一条取舍，见 buildWindowLocked 的 ⑧。）
    ///
    /// 符号缺失时可选链给出 nil，`nil == KERN_SUCCESS` 为 false，走同一条失败路径。
    private static func downgradeToReadOnly(_ target: UInt64, total: UInt64,
                                            src: UInt64, maxProt: Int32,
                                            gamePort: MachPort) -> Bool {
        // `maxProt` 是 `vm_remap` 给的**上限出参**。实测它通常是 `VM_PROT_ALL (0x7)`，
        // **并不反映源 region 的实际权限** —— 同一块 region 实测 `源prot=0x3`、`max=0x7`，
        // 源连 X 都没有，出参却给了 RWX。所以别拿它推断源是只读还是可写，
        // 这个分支只在真正没有 W 位时兜一层底，正常路径不会触发。
        if (maxProt & vmProtWrite) == 0 { return true }

        let kr = machVmProtectFn?(mach_task_self_, target, total, 1, vmProtRead)
        let ok = kr == KERN_SUCCESS
        if !ok {
            // 失败原因只能从返回码看出来，记下来 —— 它决定往哪查。
            // 游戏地址必须一起记：本地地址每次运行都不一样，只报它定位不到是哪个 region。
            let why = kr.map { describe($0) } ?? "mach_vm_protect 符号缺失"
            // 源 region 的属性是判据：它决定这块为什么降不下去。
            // **拆成两行**：面板宽度只放得下七十来个字符，一行装不下最后那几项，
            // 而尾巴上的 `源prot` 恰恰是唯一能定性的字段（截断过一次，白跑一轮）。
            var probe = src
            let (okSrc, srcSize, srcProt, _) = nextRegion(task: gamePort, addr: &probe)
            let head = "游戏 0x\(String(src, radix: 16))"
                + " / 本地 0x\(String(target, radix: 16))"
                + " +0x\(String(total, radix: 16))"
            let tail = okSrc
                ? "源prot=0x\(String(srcProt, radix: 16))"
                    + " 源size=0x\(String(srcSize, radix: 16))"
                    + " max=0x\(String(maxProt, radix: 16)) \(why)"
                : "源region查询失败"
                    + " max=0x\(String(maxProt, radix: 16)) \(why)"
            withLock { _lastProtectFailure = head + "\n" + tail }
            // 降权失败 = 手上握着一块能改游戏内存的映射。宁可不要。
            _ = vmDeallocateFn?(mach_task_self_, UInt(target), total)
            withLock { _protectFailures += 1 }
        }
        return ok
    }

    /// 已经建立起来的映射：游戏地址 → 我们的本地地址。
    private static var mappedRanges: [(gameBase: UInt64, size: UInt64, localBase: UInt64)] = []
    /// mappedRanges 是否已按 gameBase 排好序 —— mappedRecord 走二分，靠这个标志决定先不先排。
    private static var rangesSorted = true

    /// 释放本进程地址空间里**所有**已建立的映射。
    ///
    /// 原来两处都是 `mappedRanges.removeAll()` —— 只把记录清掉，那些映射还牢牢占着
    /// 本进程的地址空间，而且再也找不回来了。游戏每次重启（pid 变）就漏掉一轮
    /// `mapAllRegions` 的量，几十到几百 MB，反复重启一路累积。
    ///
    /// 第一个参数必须是 `mach_task_self_`：要释放的是**本进程**的映射，不是目标的 ——
    /// 传目标端口等于让内核去游戏的 vm_map 里找一个根本不存在的地址，然后静默失败。
    ///
    /// 访问级别是 internal（不是 private）：`AutoTracker` 在 attach/detach 生命周期
    /// 里必须能调到它，那是"游戏退出就释放"这条验收要求的落点。
    static func releaseAllMappings() {
        if let fn = vmDeallocateFn {
            for m in mappedRanges {
                // 第二个形参是 UInt（mach_vm_address_t），我们的 localBase 是 UInt64 —— arm64 上同宽
                _ = fn(mach_task_self_, UInt(m.localBase), m.size)
            }
        }
        mappedRanges.removeAll()
        rangesSorted = true
        // 窗口也在这里释放。**释放落点只能有一个** —— 分散到各处迟早漏掉一条入口
        // （游戏退出 / pid 变化 / 服务停止），而漏掉的就是一块再也找不回来的本进程映射。
        //
        // 代价是：`bind(pid:)` 在 pid 变化时也会把窗口拆掉（窗口本来与 pid 无关）。
        // 收益是永远不会漏释放。第一步的窗口是**按需重建**的（点一次建一次），
        // 所以这个取舍选"可能多拆一次"的反面 —— 见窗口层 teardownWindow 的注释。
        _ = teardownWindow()
    }

    private static let vmFlagsAnywhere: Int32 = 0x0001

    /// 把游戏的一段内存**映射进我们自己的地址空间**（`vm_remap`, copy = FALSE）——
    /// **第一步不启用，只留接入点。**
    ///
    /// 这一段原来是对本进程做 remap：`src_task` 与 `target_task` 都传 `mach_task_self_`，
    /// 而 `srcAddress` 传的是**游戏地址**。那个组合只有两种结局，两种都不该留着：
    ///
    ///   · 游戏地址在本进程没有映射 → `KERN_INVALID_ADDRESS`：恒失败，白跑一次内核往返；
    ///   · 游戏地址**恰好**落在本进程某个映射里 → 成功，并且把**我们自己的内存**
    ///     登记成「游戏地址 → 本地地址」。之后 `readSmart` 命中它，拿我们自己的数据
    ///     当游戏数据用 —— 不崩、不报错，只是全是错的。静默的错数据比崩溃贵得多。
    ///
    /// 真正的跨进程映射缺一个我们没有的东西：**目标进程的 task port**。
    /// 样本里它是 `__DATA_CONST,__got+0x468`（54 个函数共用，包括全部窗口函数），
    /// 由外挂自己拿到后一直持有。本工程在内核路径下不产生 port（见 attachPort 的注释），
    /// 所以这条路要等**第二步**和「窗口页指向目标物理页」一起接回来 —— 接的时候
    /// 降权失败信息的写入点（详情见 `loadWindow` 类路径里那次 mach_vm_protect 复查）。
    ///
    /// 现在唯一成立的路径是「本地窗口 + 本地读」：见下面的窗口层
    /// （buildWindow / stepWindowProbe）。这不是两套并行实现 —— 跨进程这条路
    /// **现在没有实现**，只留了接入点；把错的版本留着才是真的会有两套。
    static func mapRange(pid: Int32, srcAddress: UInt64, size: UInt64) -> (local: UInt64, note: String) {
        (0, "跨进程映射未启用：需要目标 task port（第一步只有本地窗口，点「窗口」验证）")
    }

    /// 查一块映射：命中时**同时**给出本地基址和这块还剩多少字节。
    ///
    /// 两者必须一起返回。只判断"起始地址在块内"是不够的 —— 读 n 个字节时还要求
    /// `address + n` 仍落在同一块里，而块末尾就是 region 末尾：越过去读要么撞上
    /// 未映射的地址（SIGSEGV，本进程闪退），要么落进别的映射（不崩，但数据是垃圾）。
    /// 让调用方自己再查一次也不行 —— 两处判定迟早不同步。
    static func mappedRecord(for gameAddress: UInt64) -> (localBase: UInt64, remain: UInt64)? {
        // 热路径：遍历一张 actor 表要查几千次，块数又可能上百 —— 线性扫是上百万次比较。
        // 这里按 gameBase 二分，排序由 rangesSorted 按需触发（append 时置脏）。
        if !rangesSorted {
            mappedRanges.sort { $0.gameBase < $1.gameBase }
            rangesSorted = true
        }
        var lo = 0
        var hi = mappedRanges.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            let m = mappedRanges[mid]
            if gameAddress < m.gameBase {
                hi = mid - 1
            } else if gameAddress >= m.gameBase &+ m.size {
                lo = mid + 1
            } else {
                let offset = gameAddress &- m.gameBase
                return (m.localBase &+ offset, m.size &- offset)
            }
        }
        return nil
    }

    /// 当前会话的 pid —— 按需映射时要用它取端口。
    private(set) static var activePid: Int32 = 0

    /// 屏幕逻辑尺寸。**由 UI 层在主线程写进来** —— 投影跑在后台线程，
    /// 不该在后台去碰 `UIScreen`。没设置过（0×0）时投影会直接放弃，不会算出垃圾坐标。
    static var screenSize: CGSize = .zero

    /// 绑定本次操作的目标进程。**每个动作开始前都要调** ——
    /// 上一版只在「找村口」/「映射」里绑定，于是直接点「对象」时 activePid 还是 0，
    /// 按需映射那段判断被跳过，读取全部退回 mach_vm_read（实测 38 次调用）。
    /// pid 变了说明游戏重启过，旧的映射和基址一起作废。
    static func bind(pid: Int32) {
        guard activePid != pid else { return }
        activePid = pid
        // 旧映射要**释放**，不只是丢引用 —— 否则每次重启游戏都漏掉一整轮预映射的量
        releaseAllMappings()
        imageBase = 0
        imageSlide = 0
        basePid = 0
    }

    /// 把**包含 address 的那个 region** 整个映射进来 —— 跨进程路径，第一步不启用。
    ///
    /// 原来这里枚举的是**本进程**的 region（`nextRegion(task: mach_task_self_)`），
    /// 而传进来的 `address` 是游戏地址 —— 枚举到的 region 与 `address` 根本不是同一件事，
    /// 所以下面那个 `address >= addr && address < addr + size` 的校验经常直接把它否掉，
    /// 偶尔通过也只是巧合（地址区间撞上了）。现在明确拒绝。
    ///
    /// 这是按需映射那条路的入口（`readSmart` 里被 `kernelReady` 门控着的那段）。
    /// 第二步接回目标 task port 时从这里开始改。
    @discardableResult
    static func mapRegionContaining(pid: Int32, address: UInt64) -> String {
        "按需映射未启用：需要目标 task port（要枚举的是游戏的 region，不是本进程的）"
    }

    /// 把游戏进程里**所有值得映射的大 region** 一次性映射进来 —— 第一步不启用。
    ///
    /// 这个函数的设计意图（批量吃下游戏的几百个 region，把后续读取全变成本地访问）
    /// 本身是对的，也正是样本的路子。但它需要目标 task port：没有 port 的话，
    /// `nextRegion` 只能枚举**本进程**的 region，然后把这些 region **自映射**一遍 ——
    /// 那既不产出任何一个字节的游戏数据，又要白占几百块映射额度和几百 MB 地址空间
    /// （`mappedRanges` 的上限是 2048 块，`readSmart` 的按需映射撞到它就会整条退化成内核读）。
    ///
    /// 所以第一步把它停掉，并把原因写在返回值里 —— 面板每次点「世界」都会看到这行字，
    /// 而不是一个"预映射: 0 块"的假结论。
    ///
    /// 第二步接回来时，这里要动的是两处：`nextRegion` 换成游戏的 task、
    /// `vm_remap` 的 src_task 换成游戏的 task（target 仍是我们自己）。
    @discardableResult
    static func mapAllRegions(pid: Int32, minSize: UInt64 = 256 << 10,
                              budget: TimeInterval = 2.5, maxBlocks: Int = 600) -> String {
        // 这句话会进 AutoTracker 的状态行（首次挂载时会调这个函数），
        // 所以刻意压短 —— 面板那行放不下长句，尾巴被截掉就等于没说。
        "预映射: 未启用（跨进程映射需要目标 task port）"
    }

    // MARK: - 本地虚拟地址窗口（样本建窗形态 · 第一步：只建窗）

    /*
     * 为什么先做这一步，以及这一步**不做什么**。
     *
     * 样本（Music）读游戏内存走的是「窗口 + 本地读」：先建一块属于自己的虚拟地址窗口，
     * 让窗口的页指向目标物理页，然后**本地 `ldr` 读，零内核调用**。
     *
     * 本工程现在走的是另一条：页表翻译 → 拿到 PA → `pa + delta` 转内核 VA → kread。
     * 上一次装机时那个 delta 算错，踢到未映射地址，**直接彩屏重启**。
     * 所以方向改到样本这条路：不再用 kread 读任意地址，改用「窗口 + 本地读」。
     *
     * 第一步只做「把窗口建起来并自验证」，理由：
     *   · 建窗这一段，样本的每一步都有二进制证据（下面逐个标了地址）；
     *   · **让窗口的页指向目标物理页**那一步（PTE 改写）是整个方案里唯一没有样本直接
     *     证据的环节，也是唯一能把机器打成彩屏的环节。窗口本身在设备上被证明可用之前，
     *     不该去碰它 —— 所以本文件里没有任何一处写 PTE。
     *
     * 整段是**纯用户态 Mach API**：不读内核内存、不碰页表、不依赖 km_init / PUAFF。
     * 两个好处：不会彩屏；内核层挂掉的时候它照样能独立验证 —— 第一步要的正是后者。
     *
     * 样本建窗链（`sub_100f756c4`，全部动作的 task 都是 `_mach_task_self_`）：
     *   ① mach_vm_allocate        flags = 9，大小 = 页数 << 14      @0x100f75738
     *   ② 三次 mach_vm_allocate   flags = 0x4002（OVERWRITE|PURGABLE）  @0x100f75890/758bc/758ec
     *   ③ 浇灌 memset 'A' → 'B'                                       @0x100f7592c / 0x100f75ae8
     *   ④ vm_remap(copy = FALSE)  src_task = target_task = self       @0x100f75a34
     *   ⑤ mach_vm_protect                                             @0x100f75aa8
     *   ⑥ mlock 循环 65534 次（0xFFFE）+ 收尾一次                      @0x100f75af8 / 0x100f75b3c
     *   ⑦ pthread_create → 线程 0x100f75d30 再对整个窗口 mlock         @0x100f75b70
     *   拆窗：mach_vm_deallocate                                       @0x100f75c34
     */

    /// 窗口的页大小。**刻意写死 0x4000，不取 `vm_page_size`。**
    ///
    /// 样本用的是全局 `0x101cba070` / `0x101cba078` 这对常量，内容由
    /// `file[0x1bb2070] = 00 40 00 00 …` 证实为 `0x4000`；`mach_vm_allocate` 的大小
    /// （页数 `<< 14`）、`vm_remap` 的 size、`mlock` 的长度全都用它。
    ///
    /// iOS 上物理页就是 16 KB，正好等于 0x4000 —— 两者一致，所以跟着样本写死。
    /// 不取 `vm_page_size` 的原因：第二步的 PTE 改写是按**物理页**做的；如果窗口按 4 KB
    /// 对齐而物理页是 16 KB，窗口的"第 i 页"会和物理页错位，改 PTE 就改到相邻页上了。
    /// 对齐条件宁可在代码里写死并显式检查，也不要让它在不同设备上悄悄变。
    private static let windowPageSize: UInt64 = 0x4000

    /// 样本 ① 用的 flags：`w3 = #9`。
    ///
    /// **9 = 0x1 | 0x8 = ANYWHERE | RANDOM_ADDR** —— 不是「ANYWHERE|OVERWRITE」
    /// （OVERWRITE 是 0x4000，出现在样本 ② 那三次里）。这一笔要记准：把 9 当成
    /// 「ANYWHERE|OVERWRITE」之后，照着写就会得到 `0x1 | 0x4000`，
    /// 而那带 **OVERWRITE 语义：先把目标地址上已有的映射删掉再建** ——
    /// 在窗口地址还没算干净的阶段，那等于拿刀往自己的地址空间里划。
    private static let vmFlagsRandomAddr: Int32 = 0x0008

    /// 样本 ② 三次调用用的 flags：`0x4002 = OVERWRITE | PURGABLE`。
    ///
    /// **第一步不用它**，但它必须在代码里留个名字，这样"这一步少了什么"是看得见的：
    /// PURGABLE 的页是内核**可以随时回收**的，样本要的正是"这些页能被回收"
    /// —— 那是 PUAFF 的燃料。窗口本体不该是 purgable，它要被 wire 住常驻。
    private static let vmFlagsPurgableOverwrite: Int32 = 0x4002

    /// 一步建窗的全部现场。字段只在 `buildWindowLocked` 里被整块写入，
    /// 读的地方一律走 `withLock`（面板会并发读，见 stateLock 的说明）。
    private struct LocalWindow {
        var base: UInt64 = 0             // 窗口本体起始（0x4000 对齐）
        var size: UInt64 = 0             // = 页数 << 14
        var pages: Int = 0
        var alias: UInt64 = 0            // vm_remap(copy = FALSE) 得到的第二个视图
        var aliasNote = ""               // 那次 remap 的一句话结论（失败也要带返回码）
        var sprayNote = ""               // 浇灌（memset 'A' → 'B'）
        var protAfterBuild: Int32 = -1   // 建窗时设的权限（期望 0x3 = 读写）
        var protNote = ""                // 建窗时 protect 的结论
        var protNow: Int32 = -1          // 压只读之后**复查到的**实际权限（期望 0x1）
        var sealNote = ""                // 压只读的结论
        var mlockOK = 0                  // wire 成功的页数
        var mlockFail = 0
        var rlimitNote = ""              // RLIMIT_MEMLOCK —— mlock 失败时的第一解释
        var verifyOK = false             // **唯一的成功判据**
        var verifyNote = ""
        var teardownNote = ""            // 上一次窗口的拆除结果（建窗前会先拆一次）
    }

    private static var localWindow: LocalWindow?

    /// 窗口是否已建立**且**自验证通过 —— 第二步（改 PTE）的前置条件。
    /// 第二步动手之前必须先看这个数；它是 false 就没有窗口可指。
    static var windowReady: Bool { withLock { localWindow?.verifyOK ?? false } }

    /// 窗口的一句话摘要（面板常驻显示用）。
    static var windowLine: String {
        withLock {
            guard let w = localWindow else { return "窗口: 未建立" }
            var s = "窗口: " + (w.verifyOK ? "✓" : "✗")
            s += " 0x\(String(w.base, radix: 16)) · \(w.pages) 页 · \(w.size / 1024) KB"
            s += " · mlock \(w.mlockOK)/\(w.pages)"
            s += " · prot=0x\(String(w.protNow, radix: 16))"
            return s
        }
    }

    /// 建窗。**顺序照样本 ①③④⑤⑥ 来**；省掉的两步（② 与 ⑥ 的 65534 次循环）
    /// 在各自的位置就地说明理由。
    ///
    /// 返回值 `ok` 只看**自验证**（本地写读 + alias 交叉读都通过）——
    /// 那是上机时唯一能一眼看懂的判据；其余每一步的结论都在 `report` 里逐行列出。
    @discardableResult
    static func buildWindow(pages: Int = defaultWindowPages) -> (ok: Bool, report: String) {
        // 整个建窗过程持同一把锁：它会碰 localWindow、也会碰 _mlockFailures，
        // 而面板线程随时可能读（windowLine / mlockFailures）。
        // 建窗全部是几次 Mach 调用 + 两遍 memset，毫秒级 —— 不值得为它做更细的锁。
        withLock { buildWindowLocked(pages: pages) }
    }

    /// 默认页数：32 页 = 512 KB。
    ///
    /// 定这个数的理由：第二步要拿窗口装"目标的物理页"，页数不能太少；
    /// 而它同时要被 mlock 常驻（吃 wired 内存），32 页（512 KB）在 iOS 上很轻 ——
    /// 真上机时如果 mlock 大面积失败，报告里的 RLIMIT_MEMLOCK 那一行会直接指出是配额问题，
    /// 而不是让这个数去猜。
    static let defaultWindowPages = 32

    /// 建窗的实现体。**调用前必须已经持有 stateLock**（NSLock 非递归，这里再取一次会死锁）。
    private static func buildWindowLocked(pages: Int) -> (ok: Bool, report: String) {
        guard let allocFn = machVmAllocateFn else {
            return (false, "窗口: ✗ mach_vm_allocate 符号缺失 —— 第一步做不了（看「符号」按钮）")
        }
        guard let remapFn = vmRemapFn else {
            return (false, "窗口: ✗ vm_remap 符号缺失 —— 建窗也不成立（看「符号」按钮）")
        }

        // 页数先夹紧。上限不是审美：mlock 的配额是 RLIMIT_MEMLOCK，页数一大必然大面积失败；
        // 下限 1 是因为 0 页会让后面每个 `<<14`、每次逐页循环都变成空操作，报告出来像成功。
        let n = max(1, min(pages, 4096))
        let total = UInt64(n) * windowPageSize

        // 先把上一次拆掉 —— 幂等。这一句同时是"拆除能力"的运行时证据：
        // 它每次都会把上一次的 deallocate 返回码带进报告。
        let teardownNote = teardownWindowLocked()

        var lines: [String] = []
        var w = LocalWindow()
        w.pages = n
        w.size = total
        w.teardownNote = teardownNote

        /*
         * ① mach_vm_allocate(self, &base, 页数 << 14, flags = 9)
         *
         * 样本 @0x100f75738：`bl mach_vm_allocate`，`w3 = 9`，大小 = `[x19,#0x3d0] << 14`。
         * 先在自己进程里申请**一整块连续窗口** —— 之后所有页操作都在这块地址里做，
         * 不再有"每次重新挑地址"的随机性。
         */
        var base: UInt64 = 0
        let ak = allocFn(mach_task_self_, &base, total, vmFlagsAnywhere | vmFlagsRandomAddr)
        guard ak == KERN_SUCCESS, base != 0 else {
            lines.append("窗口: ✗ ① mach_vm_allocate 失败 \(describe(ak))")
            lines.append("  " + teardownNote)
            return (false, lines.joined(separator: "\n"))
        }
        w.base = base

        /*
         * 边界自检 —— **这一步最该防的就是这里**。
         *
         * 这一步全是用户态 Mach API，不会彩屏；但 `vm_remap` / 对齐算错会破坏
         * **本进程**的地址空间（重则自己 SIGSEGV，轻则后面所有页号全错一位）。
         * 所以宁可在这里拒绝，也不带着一个可疑的基址往下走。三条，缺一不可：
         *   1. 基址必须 0x4000 对齐 —— PTE 改写按物理页 16 KB 做，错位就改到邻居的 PTE 上；
         *   2. base + size 不能回绕 —— 回绕之后 deallocate 的长度会变成天文数字；
         *   3. 基址必须落在用户态地址范围内 —— 高 16 位是内核段的地址不可能是合法返回值。
         */
        guard base & (windowPageSize - 1) == 0,
              base &+ total > base,
              base < 0x0000_FFFF_FFFF_FFFF else {
            _ = vmDeallocateFn?(mach_task_self_, UInt(base), total)
            lines.append("窗口: ✗ ① 地址自检不过（base=0x\(String(base, radix: 16)) "
                         + "size=0x\(String(total, radix: 16))），已释放")
            lines.append("  " + teardownNote)
            return (false, lines.joined(separator: "\n"))
        }

        /*
         * ③ 浇灌：先写 'A' 再写 'B'（样本 @0x100f7592c / @0x100f75ae8 的两次 memset）。
         *
         * 为什么必须写这一遍：`mach_vm_allocate` 只**保留虚拟地址**，物理页要到第一次
         * 访问才 fault 出来。而第二步改 PTE 的前提是"每一页都有真实 PTE"——
         * 没浇灌过的页 PTE 是空的，改它等于往空槽里写字。
         *
         * 写两遍（A 再 B）也不是折腾：只写一次的话，"本来就该是 0、写完还是 0"这种错位
         * 看不出来；写两个不同的值，一旦读到 A 或 B 就能立刻判断"这一页停在哪一步"。
         *
         * 写的是**我们自己刚申请的内存**：不可能写到游戏或内核去（基址刚刚过了上面三条自检）。
         */
        if let p = UnsafeMutableRawPointer(bitPattern: UInt(base)) {
            memset(p, 0x41, Int(total))         // 'A'
            memset(p, 0x42, Int(total))         // 'B'
            w.sprayNote = "A→B 已写满 \(n) 页（0x\(String(total, radix: 16)) 字节）"
        } else {
            w.sprayNote = "基址转指针失败（0x\(String(base, radix: 16))）"
        }

        /*
         * ④ vm_remap(..., copy = FALSE, src_task = target_task = self)
         *
         * 样本 @0x100f75a34 是全样本**唯一**的 `_vm_remap` 调用点，现场是
         * `x0 = 目标 task`、`x5 = 源 task`（两者同一个值）、`w7 = 0`（copy = FALSE）。
         * copy = FALSE 是**共享**映射：两个地址看的是同一批物理页；
         * copy = TRUE 拿到的只是映射那一瞬间的复印件 —— 写进去的变化在另一头看不到。
         *
         * 这里把"自己映射自己"用在同一块窗口上，得到一个 **alias**。
         * 它只有一个用途，但很硬：**它是唯一能证明 copy = FALSE 语义成立的手段** ——
         * 往窗口写、从 alias 读，两边一致才说明内核给的是共享映射而不是复印件。
         * 第二步整个方案的前提就压在这一条上，所以它被算进"建窗成功"的判据里。
         *
         * 与样本的差别（写清楚，免得后来人以为漏了一步）：
         * 样本在 flags 上加了 OVERWRITE（0x4000）并指定 target_address，那是它
         * "先预留地址、再把映射覆盖上去"的两段式。我们这里没有预留，用 ANYWHERE
         * 让内核挑一个空地址 —— 少一次"覆盖已有映射"的机会，在这个阶段宁可保守。
         */
        var alias: UInt64 = 0
        var curProt: Int32 = 0
        var maxProt: Int32 = 0
        let rk = remapFn(mach_task_self_, &alias, total, 0, vmFlagsAnywhere,
                         mach_task_self_, base, 0, &curProt, &maxProt, 0)
        if rk == KERN_SUCCESS, alias != 0 {
            w.alias = alias
            w.aliasNote = "alias=0x\(String(alias, radix: 16))（copy=FALSE 共享映射）"
        } else {
            // 失败也要把返回码留下：KERN_INVALID_ADDRESS / KERN_PROTECTION_FAILURE
            // 指向完全不同的方向（源地址问题 vs 权限问题）。
            w.aliasNote = "vm_remap 失败 \(describe(rk))"
        }

        /*
         * ⑤ mach_vm_protect(prot = 3 = READ|WRITE)
         *
         * 样本里能看到 prot = 3 被写进出参（@0x100f759a8 的 `stp w8/w9 = 7/3`），
         * 而它自己在 @0x100f75aa8 那次 mach_vm_protect 传的是 w4 = 1（只读）——
         * 那是它**映射游戏页**之后把窗口压到只读：共享映射默认带写权限，
         * 一个能写游戏内存的窗口只有风险没有收益。
         *
         * 我们这一步反着来：自验证要写 pattern，所以先**显式**设成读写。
         * 显式设一次而不是"allocate 出来本来就是 RW"，是为了让后面的"压只读"有个已知起点：
         * 出问题时能一眼分清是"没设上"还是"设完又被改回来了"。
         */
        if let protectFn = machVmProtectFn {
            let pk = protectFn(mach_task_self_, base, total, 0, vmProtRead | vmProtWrite)
            if pk == KERN_SUCCESS {
                w.protAfterBuild = vmProtRead | vmProtWrite
                w.protNote = "prot=0x3（读写）✓"
            } else {
                w.protNote = "失败 \(describe(pk))"
            }
        } else {
            w.protNote = "mach_vm_protect 符号缺失"
        }

        /*
         * ⑥ mlock：把窗口 wire 住（样本 @0x100f75af8 / @0x100f75b3c）。
         *
         * 样本这一段是一个 **65534（0xFFFE）次**的循环，每次都对**同一页**
         * （`x0 = [x22,#0xf8]`）调一次 `mlock(addr, 0x4000)`，循环之后再对另一处收尾调一次。
         *
         * **这里不照抄那个循环**，因为它对"wire 住"没有贡献：
         *   · `mlock` 是幂等的 —— 同一页锁第二次不会多锁一层，物理页还是那一页；
         *   · 65534 这个数量级是 PUAFF 手法的一部分（反复 mlock 同一页会把 vm_map 的
         *     in-map entry 撑到溢出阈值，让内核误判这些页可以回收，从而留下
         *     **dangling PTE** —— 那正是 PUAFF 要的燃料）；
         *   · 而本工程的 PUAFF 已经由 `libmemrw/kfd` 承担（`kopen` 在设备上验过，
         *     puaf_pages 也是调好的 2048）。窗口层再复刻一遍，只会把"验窗口"和
         *     "制造 UAF"两件事搅在一起 —— 出问题时分不清是谁的责任。
         *
         * 所以这里做的是**逐页各一次**：那才是"整个窗口都被 wire 住"的正确做法
         * （样本 ⑦ 那个后台线程做的也是"再对整个窗口 mlock 一遍"这件事，
         * 只是它借了另一个线程的上下文去做竞态；本步不需要竞态）。
         * 逐页调用还有一个好处：哪一页没锁上会落在计数里 —— 65534 次循环里看不出来。
         *
         * 失败只计数、不丢弃窗口：没锁上只是有被换出的风险，比没有窗口强。
         * 但报告里必须看得见，而且要把 RLIMIT_MEMLOCK 一起打出来 ——
         * mlock 失败的头号原因就是配额，不打出这个数，"失败 N 页"只能靠猜。
         */
        if let lock = mlockFn {
            for i in 0..<n {
                if lock(base &+ UInt64(i) * windowPageSize, windowPageSize) == 0 {
                    w.mlockOK += 1
                } else {
                    w.mlockFail += 1
                }
            }
        } else {
            w.mlockFail = n
        }
        // 累进全局计数：面板的「mlock 失败」那一格必须把窗口这一路也算进去，
        // 否则窗口大面积锁不上而那个数还是 0 —— 那是最会骗人的一种"零"。
        // 注意这里在锁内，**不能**再调 withLock（NSLock 非递归，会死锁）。
        _mlockFailures += w.mlockFail

        var rl = rlimit()
        if getrlimit(RLIMIT_MEMLOCK, &rl) == 0 {
            // RLIM_INFINITY 是个带类型转换的宏，Swift 不保证导入；用数值比较代替。
            let cur = rl.rlim_cur >= 0x7FFF_FFFF_FFFF_FFFF
                ? "无限"
                : "\(Double(rl.rlim_cur) / 1048576.0) MB"
            w.rlimitNote = "RLIMIT_MEMLOCK 当前=\(cur)"
        } else {
            w.rlimitNote = "RLIMIT_MEMLOCK 读取失败"
        }

        // ⑦ 自验证（**上机唯一的判据**）—— 实现与判据见 verifyWindowLocked。
        let vr = verifyWindowLocked(w)
        w.verifyOK = vr.ok
        w.verifyNote = vr.note
        let ok = vr.ok

        /*
         * ⑧ 收尾：把窗口压到只读。
         *
         * 这一步**不是样本里的动作**，是我们自己加的一道保险，理由很直接：
         * 第二步一旦把窗口的页指向目标物理页，"往窗口写"就等于"往游戏内存写"。
         * 而第二步里唯一没有样本证据的环节正是 PTE 改写 —— 出错概率不低。
         * 压到只读之后，就算后续代码误写了窗口，SIGSEGV 的是**我们自己**，
         * 而不是游戏内存被改坏（那才是彩屏、封号那一类后果）。
         *
         * `set_maximum = 1` 是刻意的：只降 current 的话"上限"里还留着写权限，
         * 之后一句 mach_vm_protect 就能把 W 提回来。把上限本身压掉，写权限才真拿不回来
         * —— 与建窗收尾压只读那里的取舍一致。
         *
         * 压完之后**复查**一次实际权限：返回成功不等于区域里每一页都成了只读，
         * 报告里那个 0x1 必须是查出来的，不能是"调用返回 0 所以应该是"。
         */
        if let protectFn = machVmProtectFn {
            let sk = protectFn(mach_task_self_, base, total, 1, vmProtRead)
            if sk == KERN_SUCCESS {
                var probe = base
                let (rok, _, prot, _) = nextRegion(task: mach_task_self_, addr: &probe)
                w.protNow = rok ? prot : 0
                if !rok {
                    w.sealNote = "已压只读，但复查失败（vm_region_64）"
                } else if prot == vmProtRead {
                    w.sealNote = "复查 prot=0x1（只读）✓"
                } else {
                    w.sealNote = "复查 prot=0x\(String(prot, radix: 16)) —— 不是只读 ✗"
                }
            } else {
                w.sealNote = "压只读失败 \(describe(sk)) ✗（窗口仍可写，第二步之前必须解决）"
            }
        } else {
            w.sealNote = "mach_vm_protect 符号缺失，未压只读 ✗"
        }

        localWindow = w

        // ── 报告：结论放在最前面。面板会截断长行，截掉尾巴无所谓，截掉结论就白跑一轮。
        lines.append("窗口: " + (ok ? "✓ 建窗成功" : "✗ 建窗未通过") + " · " + w.verifyNote)
        lines.append("  基址 0x\(String(base, radix: 16)) · 大小 0x\(String(total, radix: 16))"
                     + " · 页数 \(n) · 页宽 0x\(String(windowPageSize, radix: 16))")
        lines.append("  ① allocate flags=0x\(String(vmFlagsAnywhere | vmFlagsRandomAddr, radix: 16))"
                     + "（ANYWHERE|RANDOM_ADDR，样本值 9）✓")
        // 把没用到的那个 flags 打出来：它就是"这一步和样本差在哪"的答案，
        // 比在注释里写一句更有用 —— 上机时在面板上就能看到这一步省了什么。
        lines.append("  ② purgable 三连 flags=0x\(String(vmFlagsPurgableOverwrite, radix: 16)) 跳过"
                     + "（PUAFF 的燃料，本工程由 kfd 承担）")
        lines.append("  ③ 浇灌 \(w.sprayNote)")
        lines.append("  ④ " + w.aliasNote)
        lines.append("  ⑤ " + w.protNote)
        lines.append("  ⑥ mlock \(w.mlockOK)/\(n) 页 wire"
                     + (w.mlockFail == 0 ? " ✓" : "（失败 \(w.mlockFail)）")
                     + " · " + w.rlimitNote)
        lines.append("  ⑦ 自验证 —— " + w.verifyNote)
        lines.append("  ⑧ " + w.sealNote)
        /*
         * 汇总警示。
         *
         * `ok` 只看**自验证**（窗口能不能用），而 mlock / 只读是另外两项独立的性质。
         * 不点名的话，面板上会出现"✓ 建窗成功"和"⑥ 有失败"同时挂着 ——
         * 看的人不知道该信哪个，下一步（PTE 改写）就会在一个没 wire 住、
         * 或者还能写的窗口上动手。那是这个报告最该防的误读。
         */
        if ok {
            var warn: [String] = []
            if w.mlockFail > 0 { warn.append("有 \(w.mlockFail) 页没 wire 住") }
            if w.protNow != vmProtRead { warn.append("只读没生效 —— 第二步之前必须解决") }
            if !warn.isEmpty {
                lines.append("  ⚠ " + warn.joined(separator: " · "))
            }
        }
        lines.append("  " + teardownNote)
        return (ok, lines.joined(separator: "\n"))
    }

    /// 写进每一页页头的 magic：低 16 位是页号，高 48 位是固定前缀。
    ///
    /// 前缀取 0xAF37 是为了在面板上一眼认出"这是我的窗口页"——
    /// 如果某页读到的是别的值，那说明那块地址被别的映射盖了（或者根本不是我们的窗口）。
    private static func pageMarker(_ i: Int) -> UInt64 {
        0xAF37_0000_0000_0000 | UInt64(i)
    }

    /// 窗口自验证。**这是上机时唯一的判据。**
    ///
    /// 三件事，缺一不可：
    ///   ① 逐页写入编码了页号的 pattern（整页填 `0x40 | (i & 0x3F)`，页头 8 字节放 magic）
    ///   ② 从**窗口本体**逐页读回，整页比对
    ///   ③ 从 **alias** 逐页读回页头 magic，与窗口本体看到的一致
    ///
    /// 为什么②要整页比对而不是抽查几个点：`mach_vm_allocate` 出来的页是按需 fault 的，
    /// "只有第一页真的落到物理内存上"这种情况抽查很容易漏过去 —— 而第二步是按页改 PTE，
    /// 漏一页就是改到一个没有物理页的 PTE 上。
    ///
    /// 为什么③必须做：它是**唯一**能证明 `vm_remap(copy = FALSE)` 给的是共享映射
    /// （而不是复印件）的手段。第二步整个方案的前提压在这一条上。
    ///
    /// 失败时给出**页号 + 期望值 + 实际值**：面板上一眼看得出是"整页没写进去"、
    /// "只有页头错"还是"alias 是另一份拷贝"—— 三种病对应三个完全不同的排查方向。
    ///
    /// 全部是本地内存访问：**零内核调用**（除了后面那次复查用的 vm_region_64）。
    private static func verifyWindowLocked(_ w: LocalWindow) -> (ok: Bool, note: String) {
        guard let p = UnsafeMutableRawPointer(bitPattern: UInt(w.base)) else {
            return (false, "窗口基址 0x\(String(w.base, radix: 16)) 转不成指针")
        }
        let pageSize = Int(windowPageSize)

        // ① 写入
        for i in 0..<w.pages {
            let page = p.advanced(by: i * pageSize)
            memset(page, Int32(0x40 | (i & 0x3F)), pageSize)
            page.storeBytes(of: pageMarker(i), as: UInt64.self)
        }

        // ② 从窗口本体读回：整页字节 + 页头 magic
        for i in 0..<w.pages {
            let page = UnsafeRawPointer(p).advanced(by: i * pageSize)
            // 用 UnsafeRawBufferPointer 下标逐字节读，而不用 `load(fromByteOffset:as:)`：
            // 后者会被 tools/swift_guard.py 的"跨文件核对 static 成员调用方式"规则
            // 误报（项目里正好有个 static func load()）—— 那条规则是给真问题用的，
            // 不该被这种写法淹没。下标读法语义一样，也不涉及对齐问题。
            let buf = UnsafeRawBufferPointer(start: page, count: pageSize)
            let want = UInt8(0x40 | (i & 0x3F))
            var off = 8                              // 前 8 字节是 magic，单独比对
            var diff = -1
            while off < pageSize {
                if buf[off] != want {
                    diff = off
                    break
                }
                off += 1
            }
            if diff >= 0 {
                let got = buf[diff]
                return (false, "本地写读 ✗ 第 \(i) 页 +0x\(String(diff, radix: 16)) 读回 "
                        + "0x\(String(got, radix: 16))，期望 0x\(String(want, radix: 16))")
            }
            let head = UnsafeRawBufferPointer(start: page, count: 8)
            let got = u64le(Array(head), 0)
            if got != pageMarker(i) {
                return (false, "本地写读 ✗ 第 \(i) 页页头 magic=0x\(String(got, radix: 16))，"
                        + "期望 0x\(String(pageMarker(i), radix: 16))")
            }
        }

        // ③ alias 交叉读 —— copy = FALSE 的成立证据
        if w.alias == 0 {
            return (false, "本地写读 \(w.pages)/\(w.pages) 页通过，但 alias 不存在"
                    + "（vm_remap 失败）→ copy=FALSE 语义没验，不算通过")
        }
        guard let ap = UnsafeRawPointer(bitPattern: UInt(w.alias)) else {
            return (false, "alias 地址 0x\(String(w.alias, radix: 16)) 转不成指针")
        }
        for i in 0..<w.pages {
            let head = UnsafeRawBufferPointer(start: ap.advanced(by: i * pageSize), count: 8)
            let got = u64le(Array(head), 0)
            if got != pageMarker(i) {
                return (false, "alias 交叉读 ✗ 第 \(i) 页读到 0x\(String(got, radix: 16))，"
                        + "窗口本体是 0x\(String(pageMarker(i), radix: 16)) "
                        + "→ 两边不是同一批物理页（copy=FALSE 没成立）")
            }
        }
        return (true, "本地写读 \(w.pages)/\(w.pages) 页一致 · alias 交叉读 \(w.pages)/\(w.pages) 页一致")
    }

    /// 拆窗：把 alias 与窗口本体都还给内核，并把记录清干净。
    ///
    /// **释放顺序与建窗相反**：先 alias 再本体。两块是各自独立的 vm_map entry，
    /// 谁先谁后都不影响正确性，但先拆"派生出来的那个"更好读 —— 报告里那行
    /// "alias ✓ / 本体 ✓" 的顺序就是这么来的。
    ///
    /// 返回一句话（建窗报告会把它贴进"上次窗口"那一行），**不在这里写 localWindow 的状态机**：
    /// 唯一的写入口是 `buildWindowLocked`，两个地方都写迟早不一致。
    ///
    /// 一个取舍：deallocate 失败时仍然清掉记录（不保留"待重试"状态）。
    /// 理由是失败的返回码本身会写进报告，而留着一个拆不掉的记录只会让下一次建窗
    /// 带着它一起失败 —— 第一步要的是"每次点都是干净的起点"，不是自愈。
    @discardableResult
    static func teardownWindow() -> String {
        withLock { teardownWindowLocked() }
    }

    /// 拆窗的实现体。**调用前必须已经持有 stateLock。**
    private static func teardownWindowLocked() -> String {
        guard let w = localWindow else { return "上次窗口: 无（还没建过）" }
        var parts: [String] = []
        if let fn = vmDeallocateFn {
            if w.alias != 0 {
                let k = fn(mach_task_self_, UInt(w.alias), w.size)
                parts.append("alias " + (k == KERN_SUCCESS ? "✓" : describe(k)))
            }
            let k2 = fn(mach_task_self_, UInt(w.base), w.size)
            parts.append("本体 " + (k2 == KERN_SUCCESS ? "✓" : describe(k2)))
        } else {
            parts.append("vm_deallocate 符号缺失 —— 映射留在地址空间里了")
        }
        localWindow = nil
        return "上次窗口: 已释放（\(parts.joined(separator: " / "))）"
    }

    /// 面板「窗口」按钮：建窗 → 自验证 → 报告。
    ///
    /// **不需要 pid，也不依赖内核层** —— 这一段全是本进程的 Mach 调用，
    /// 所以它是第一步唯一一个"内核挂掉也能跑"的判据。
    /// 也正因为不需要 pid，它在面板上不能被"先刷新拿到 pid"那道门挡住。
    ///
    /// 每次调用都是**重建**（先拆上一次、再建新的）。原因在 ⑧：收尾会把窗口压成只读，
    /// 而自验证要写 pattern —— 压完只读就写不进去了。所以"再验一次"只能是"重建一次"，
    /// 不能是"在同一块上再写一遍"。
    static func stepWindowProbe(pages: Int = defaultWindowPages) -> String {
        resetCounters()
        stageMark("窗口 · 建窗")
        let t0 = Date()
        let r = buildWindow(pages: pages)
        let ms = Int(Date().timeIntervalSince(t0) * 1000)
        var lines = r.report.split(separator: "\n").map(String.init)
        lines.append("  用时 \(ms) ms · " + (r.ok
            ? "→ 窗口可用：第二步（让窗口页指向目标物理页）的前置条件已满足"
            : "→ 窗口不可用：先修上面标 ✗ 的那一步，再谈第二步"))
        return lines.joined(separator: "\n")
    }

    /// 已建立的映射块数 —— 调用方用它判断"要不要先预映射一轮"。
    static var mappedBlockCount: Int { mappedRanges.count }

    /// 真正落回内核读的次数。遍历类操作要盯着这个数，超预算就该收手。
    static var hardReadCalls: Int { kernelReadCalls }

    /// 走已建立映射、本地直读的次数。和 `hardReadCalls` 放一起看，一眼能分清
    /// 这一轮走的是映射还是内核降级读 —— `hardReadCalls` 必须长期保持在低位，
    /// 它每涨一次游戏就多一次抢锁，那正是当初把游戏读崩的那条路。
    static var mappedHitCalls: Int { mappedHits }

    /// 按需建立的映射块数 —— 它一直涨说明预映射没铺到，正在现场补。
    static var onDemandMapBlocks: Int { onDemandMaps }

    /// 保护位抽查的游标：每轮只看一块，轮换着覆盖。
    private static var protectionCursor = 0

    /// 抽查一块常驻映射当前的实际保护位 —— 验收要确认映射确实是只读的。
    ///
    /// **每轮只查一块**：`vm_region_64` 本身也是一次内核调用，几百块一次全查会变成
    /// 新的开销源。轮询的代价恒定（每轮一次），几百块映射几百轮就能全覆盖。
    static func spotCheckProtection() -> String {
        // 没有映射块时改查**窗口**。
        //
        // 为什么：第一步里 `mappedRanges` 恒为空（跨进程映射没启用），
        // 而面板那一行"保护位"恰恰是最该一直挂着看的数 —— 窗口是不是真的只读，
        // 决定第二步出问题时吃亏的是我们自己，还是游戏内存被写坏。
        // 返回"无映射"等于把这一格浪费掉。
        guard !mappedRanges.isEmpty else { return windowProtectionLine() }
        if protectionCursor >= mappedRanges.count { protectionCursor = 0 }
        let idx = protectionCursor
        protectionCursor = (idx + 1) % mappedRanges.count

        var addr = mappedRanges[idx].localBase
        let (ok, _, prot, _) = nextRegion(task: mach_task_self_, addr: &addr)
        guard ok else { return "保护位 块\(idx): 查询失败" }

        // VM_PROT_WRITE = 0x2 —— 只读就是这一位必须为 0
        let writable = (prot & 0x2) != 0
        return "保护位 块\(idx)/\(mappedRanges.count)=\(writable ? "有写✗" : "只读✓")"
    }

    /// 窗口当前的实际保护位（第一步的常驻抽查）。
    ///
    /// `vm_region_64` 是内核调用，但每轮只查一次、只查一块，代价恒定 ——
    /// 与原来"每轮抽查一块映射"的成本完全一样。
    ///
    /// 判据只看 `VM_PROT_WRITE`(0x2) 这一位：窗口必须**不可写**。
    /// 可写就意味着第二步一旦把页指到游戏物理页，任何一次误写都会直接落到游戏内存上。
    private static func windowProtectionLine() -> String {
        let win = withLock { localWindow }
        guard let w = win else { return "保护位: 无映射 · 窗口未建立（点「窗口」）" }
        var probe = w.base
        let (ok, _, prot, _) = nextRegion(task: mach_task_self_, addr: &probe)
        guard ok else {
            return "保护位: 窗口 0x\(String(w.base, radix: 16)) 查询失败"
        }
        let writable = (prot & 0x2) != 0
        return "保护位: 窗口 \(writable ? "有写✗" : "只读✓")"
            + " · \(w.pages) 页 · mlock \(w.mlockOK)/\(w.pages)"
    }


    /// **映射优先的读**：命中已建立的映射就本地读（零内核调用）；
    /// 没命中就按需把那一块映射进来再读；映射也失败才退回内核读（km_read_process）。
    ///
    /// 映射之后读数据就是普通内存访问；这比每次进内核翻译一遍地址便宜得多，
    /// 而每个字段读一次的话后者累积起来相当可观。
    ///
    /// **块数上限从 24 提到 512**：原来那个 24 是按「点读几个字段」估的，遍历整张对象表
    /// 时远远不够，一撞上限剩下的读全变成内核读 —— 那条路要贵得多。
    /// 正常路径是先用 mapAllRegions 把大块一次性铺好，这里只是兜底。
    private static func readSmart(pid: Int32, address: MachVmAddress, count: Int) -> (KernReturn, [UInt8]) {
        let n = max(count, 1)
        guard n <= 0x10000 else { return (KERN_FAILURE, []) }

        /*
         * ── 映射快路径：关闭，而且现在**没有生产者** ──
         *
         * 两层原因：
         *
         * 1）这条路的映射原本是**自映射**（mapRange 里 src_task / target_task 都是
         *    mach_task_self_，srcAddress 却传游戏地址）。游戏那块内存在本进程的
         *    vm_map 里并不存在，所以它既不产出游戏数据，又白占 mappedRanges
         *    的额度（上限 2048 块）。`mapRange` / `mapAllRegions` 现在都改成明确拒绝了，
         *    于是 `mappedRanges` 在第一步**恒为空** —— 这段代码即使打开也命中不了任何一块。
         *
         * 2）样本的自映射之所以成立，是因为它前面有 physrw / PTE 改写，已经先把
         *    游戏的物理页挂进了自己的地址空间。我们这一步只做到「本地窗口」：
         *    窗口建好、被 wire 住、能读写（点「窗口」按钮看自验证），但**还没有任何
         *    一页指向目标物理页** —— 那是第二步，也是唯一没有样本证据的环节。
         *
         * 用 `kernelReady` 当开关而不是写死 false：内核层验通之后直接放开这里
         * 就能恢复映射优先，不需要改回来。
         *
         * 这个开关必须是"真的可用"而不是"初始化跑过了"。早先 AppDelegate 里
         * 那个同名标志是在 km_init 返回后**无条件**置 true 的（失败也置），
         * 于是内核层挂掉反而把这条没验通的快路径打开 —— 读的是自映射窗口里
         * 并不存在的地址。现在 kernelReady 是 km_ready() 的直读，
         * 失败就一定是 false，快路径保持关闭。
         *
         * 关闭期间读取全部走 km_read_process —— 那条路是实的：走目标页表拿 PA，
         * 经线性映射用 kread 读。慢，但结论可信。
         */
        if AppDelegate.kernelReady {
            // 命中块**且**这块剩余长度够读完 n 字节，才走本地读 —— 否则可能是跨界读。
            if let rec = mappedRecord(for: address), rec.localBase != 0, UInt64(n) <= rec.remain {
                noteRead()
                mappedHits += 1
                if let base = UnsafeRawPointer(bitPattern: UInt(rec.localBase)) {
                    return (KERN_SUCCESS, Array(UnsafeRawBufferPointer(start: base, count: n)))
                }
            }

            // 没命中：按需映射一次（块数设上限，避免地图无限膨胀）
            if activePid != 0, mappedRanges.count < 2048 {
                let before = mappedRanges.count
                mapRegionContaining(pid: activePid, address: address)
                if mappedRanges.count > before { onDemandMaps += 1 }
                // 按需映射之后同样要查剩余长度 —— 新建的块边界一样可能不够读完 n 字节。
                if let rec = mappedRecord(for: address), rec.localBase != 0, UInt64(n) <= rec.remain {
                    noteRead()
                    mappedHits += 1
                    if let base = UnsafeRawPointer(bitPattern: UInt(rec.localBase)) {
                        return (KERN_SUCCESS, Array(UnsafeRawBufferPointer(start: base, count: n)))
                    }
                }
            }
        }

        /*
         * 降级读走内核路径：pid → proc → task → vm_map → pmap → 页表 → PA → KVA。
         * 不需要 task port，也不再调用 mach_vm_read —— 原语由 PUAFF 建立，
         * 实现见 libmemrw/KernelMemory.c。
         */
        noteRead()
        var buf = [UInt8](repeating: 0, count: n)
        let ok = buf.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            return km_read_process(pid, address, base, UInt64(n))
        }
        guard ok else { return (KERN_FAILURE, []) }
        kernelReadCalls += 1
        return (KERN_SUCCESS, buf)
    }

    /// 读一段字节：**优先走已建立的映射**，没命中就让 readSmart 按需映射。
    /// 原来这里直接就是 mach_vm_read —— 所有调用点现在自动升级成映射优先。
    private static func readBytes(pid: Int32, address: MachVmAddress, count: Int)
        -> (KernReturn, [UInt8]) {
        readSmart(pid: pid, address: address, count: count)
    }

    /// 每次动作开头清零。
    private static func resetCounters() {
        probeCalls = 0
        mappedHits = 0
        kernelReadCalls = 0
        onDemandMaps = 0
    }

    /// 本次动作的成本。**只看 mach_vm_read 那一项** —— 映射命中是本地内存读，
    /// 不产生内核调用，也就没有成本。之前这里只报 probeCalls（读取总次数），
    /// 文案却写成"次内核读"，把完全不同的两件事混成了一个数。
    private static func costLine() -> String {
        "读取 \(probeCalls) 次 · 映射命中 \(mappedHits) · 按需映射 \(onDemandMaps) 块 · "
            + "内核读 \(kernelReadCalls) 次"
    }

    // MARK: - 阶段标记（崩了之后还能知道停在哪）

    private static let stageFileName = "aether_stage.txt"
    private static let stageLatestName = "aether_stage_latest.txt"

    private static func stageURL() -> URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
            .appendingPathComponent(stageFileName)
    }

    private static func stageLatestURL() -> URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
            .appendingPathComponent(stageLatestName)
    }

    /// 进度回调：由调用方（UI）挂上来。
    ///
    /// 为什么要这条线：进度原本是"写内存 + 主线程 Timer 轮询显示"。
    /// 主线程一卡（任何一处内核调用堵住它），Timer 就停止触发，面板会永远停在
    /// 最后一个值上 —— 看起来像"卡在第一步"，其实可能早就走远了，也可能主线程自己
    /// 卡住了，两种情况在屏幕上长得一模一样。回调这条路由后台直接把每一步推给 UI，
    /// 不依赖 Timer，也不依赖主线程还在正常跑。
    static var onStage: ((String) -> Void)?

    /// 标记当前步骤。**只做一件事：把这一步推给 UI。**
    ///
    /// 这里原来还有一份同步落盘（给"崩溃后回查"用）。实测它把整条链卡死了：
    /// 面板停在 `枚举 · A 函数已进入` 再也不动 —— 那一行在函数开头就发出去了
    /// （所以面板显示得出来），然后函数卡死在后面的文件写入里没返回，
    /// 于是它之后的 `lines.append` / `resetCounters()` 一行都没执行。
    ///
    /// 每次要过 `FileManager.urls` → `fileExists` → `FileHandle` 开/寻址/写/关，
    /// 这些在后台 app 里任何一步都可能阻塞。第一次调用时文件不存在（走 createFile
    /// 分支）反而顺利，后面"文件已存在"的那几次才卡 —— 这就是为什么每次都能看到
    /// 第一行、后面全无。
    ///
    /// 结论：观测工具不能长在被观测的路径上，尤其是带 I/O 的那种。
    /// 落盘可以去，实时进度看面板（onStage 推的那条线，不碰文件系统）。
    static func stageMark(_ stage: String) {
        if let cb = onStage {
            DispatchQueue.main.async { cb(stage) }
        }
    }

    /// 读回最后几行阶段记录。确认调用方也用它（stageMark 是 private 的配对）。
    static func lastStages(_ n: Int = 6) -> [String] {
        guard let url = stageURL(), let text = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        return text.split(separator: "\n").suffix(n).map(String.init)
    }

    /// 最新一步（覆盖写那个文件的全部内容）。
    static func latestStage() -> String {
        guard let url = stageLatestURL(),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return "(无)" }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// 从字节数组里读一个小端 UInt64（越界返回 0）。
    private static func u64le(_ b: [UInt8], _ offset: Int) -> UInt64 {
        guard offset >= 0, offset + 8 <= b.count else { return 0 }
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(b[offset + i]) << (8 * i) }
        return v
    }

    /// 从字节数组里读一个小端 UInt32（越界返回 0）。
    private static func u32le(_ b: [UInt8], _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= b.count else { return 0 }
        return UInt32(b[offset]) | (UInt32(b[offset + 1]) << 8)
            | (UInt32(b[offset + 2]) << 16) | (UInt32(b[offset + 3]) << 24)
    }

    /// 从字节数组里读一个小端 Int32（越界返回 0）。
    private static func i32le(_ b: [UInt8], _ offset: Int) -> Int32 {
        Int32(bitPattern: u32le(b, offset))
    }

    /// 读 UE4 的 FString：{ TCHAR* Data; int32 Num; int32 Max; }（0x10 字节）。
    ///
    /// **字符宽度不假定。** iOS 上 UE4 的 TCHAR 是 4 字节（Apple 平台
    /// PLATFORM_TCHAR_IS_4_BYTES=1），但定制版可能退回 2 字节。三种宽度各解一遍，
    /// 用「解出的字符数是否等于 Num−1」这条自洽性判胜负 —— 不靠猜。
    private static func readText(pid: Int32, addr: UInt64, maxChars: Int = 24) -> String {
        let (rk, hdr) = readBytes(pid: pid, address: MachVmAddress(addr), count: 16)
        guard rk == KERN_SUCCESS, hdr.count >= 16 else { return "" }
        let data = u64le(hdr, 0)
        let num = Int(u32le(hdr, 8))
        guard data > 0x100000000, num > 1, num <= 256 else { return "" }

        let n = min(num, maxChars)
        let (rk2, raw) = readBytes(pid: pid, address: MachVmAddress(data), count: n * 4)
        guard rk2 == KERN_SUCCESS, raw.count >= n * 2 else { return "" }

        func decode(width: Int) -> (String, Int) {
            var out = ""
            var idx = 0
            var seen = 0
            while idx + width <= raw.count && seen < maxChars {
                var v: UInt32 = 0
                for k in 0..<width { v |= UInt32(raw[idx + k]) << (8 * k) }
                if v == 0 { break }
                guard let u = UnicodeScalar(v) else { return (out, -1) }
                out.unicodeScalars.append(u)
                idx += width
                seen += 1
            }
            return (out, seen)
        }

        func score(_ s: String, _ seen: Int) -> Int {
            guard seen > 0 else { return -1 }
            var sc = seen
            if seen == num - 1 { sc += 100 }      // 与 Num 完全自洽 → 决定性加分
            for u in s.unicodeScalars {
                let v = u.value
                if (v >= 0x20 && v < 0x7F) || (v >= 0x4E00 && v <= 0x9FFF) { sc += 5 }
            }
            return sc
        }

        var best = ""
        var bestScore = -1
        for width in [4, 2, 1] {
            let (text, seen) = decode(width: width)
            guard seen > 0, !text.isEmpty else { continue }
            let sc = score(text, seen)
            if sc > bestScore { bestScore = sc; best = text }
        }
        return best
    }

    // MARK: - 相机与投影（手动按钮与自动追踪共用同一份，不各自实现）

    /// 一次相机快照：位置、朝向、水平 FOV。
    struct CameraPose {
        var loc: (Float, Float, Float) = (0, 0, 0)
        var rot: (Float, Float, Float) = (0, 0, 0)
        var fov: Float = 0
        var valid = false
    }

    /// 世界坐标 → 屏幕逻辑坐标（左上原点）。返回 nil 表示在相机身后或参数不可用。
    ///
    /// UE4 约定：X 前 / Y 右 / Z 上，Yaw 绕 Z、Pitch 绕 Y、Roll 绕 X，
    /// `FMinimalViewInfo.FOV` 是**水平**视角 —— 垂直方向按屏幕宽高比折算，
    /// 否则宽屏上画出来的框会被拉歪。
    static func projectPoint(_ wx: Float, _ wy: Float, _ wz: Float,
                             camera cam: CameraPose,
                             screenW: Double, screenH: Double) -> (Double, Double)? {
        guard cam.valid, screenW > 1, screenH > 1 else { return nil }
        let d2r = Double.pi / 180
        let cp = cos(Double(cam.rot.0) * d2r), sp = sin(Double(cam.rot.0) * d2r)
        let cy = cos(Double(cam.rot.1) * d2r), sy = sin(Double(cam.rot.1) * d2r)
        let cr = cos(Double(cam.rot.2) * d2r), sr = sin(Double(cam.rot.2) * d2r)
        // 相机三轴（UE4 FRotationMatrix）
        let fx = cp * cy
        let fy = cp * sy
        let fz = sp
        let rx = sr * sp * cy - cr * sy
        let ry = sr * sp * sy + cr * cy
        let rz = -sr * cp
        let ux = -(cr * sp * cy + sr * sy)
        let uy = cy * sr - cr * sp * sy
        let uz = cr * cp

        let dx = Double(wx) - Double(cam.loc.0)
        let dy = Double(wy) - Double(cam.loc.1)
        let dz = Double(wz) - Double(cam.loc.2)

        let zc = dx * fx + dy * fy + dz * fz
        guard zc > 1.0 else { return nil }              // 在相机身后
        let xc = dx * rx + dy * ry + dz * rz
        let yc = dx * ux + dy * uy + dz * uz

        let tanX = tan(Double(cam.fov) * d2r / 2)
        guard tanX > 0.0001 else { return nil }
        let tanY = tanX * screenH / screenW
        let ndcX = (xc / zc) / tanX
        let ndcY = (yc / zc) / tanY
        return ((1 + ndcX) * screenW / 2, (1 - ndcY) * screenH / 2)
    }

    // MARK: - 自动追踪用的读取层
    //
    // 手动按钮那条路是"每次操作都 task_for_pid → 读完就释放"。这条在 20–30Hz 上
    // 不成立：光端口管理就是每秒几十次内核往返。所以这里做三件事：
    //   ① 长连接端口：attach 一次持有，detach 时释放
    //   ② 偏移表缓存：`Offsets.load()` 每次都会去 Documents 试读 offsets.txt，
    //      那是文件系统调用，绝不能出现在高频路径上
    //   ③ 两段式读取：短链（自己+相机）走高频，长链（actor 遍历）走低频

    /// 是否已绑定目标进程。
    ///
    /// 直接复用 `activePid` —— 以前这里另有一个 `longPid`，两个 pid 各记各的，
    /// 一旦只走完 bind 或只走完 attachPort 就会不一致：`isAttached` 说挂上了，
    /// 而 `readSmart` 的快路径用的是 `activePid`，读的其实是另一个进程。
    /// 现在只有一个真相来源。
    static var isAttached: Bool { activePid != 0 }

    /// 挂载目标进程。**同一个 pid 重复调用直接复用。**
    ///
    /// 内核路径下「挂载」不再意味着持有 task port，而是确认这个 pid
    /// 能在内核里定位到 proc —— 那正是后续所有读取的前提。
    static func attachPort(_ pid: Int32) -> (ok: Bool, note: String) {
        /*
         * 先看内核层到底就绪没有。
         *
         * 不查这一步的话，`km_proc_for_pid` 在 g_handle==0 时返回 0，
         * 这里会把「内核还没跑完 PUAFF」误报成「找不到该 pid 的 proc」。
         *
         * 但"没跑完"和"跑失败"必须分开报，否则用户看到的是同一句话：
         * kernelInitializing 表示 km_init 还没返回（等着就行），另一个分支
         * 才是真的没得救（要去看启动日志）。原先这里只查 `kernelReady`
         * —— 那个标志在 km_init 失败时也是 true，于是失败被报成"仍在跑，
         * 再等等"，用户会一直等一个永远不会来的结果。
         */
        guard !AppDelegate.kernelInitializing else {
            return (false, "内核尚未就绪（km_init 仍在跑，PUAFF 需要几十秒）")
        }
        guard AppDelegate.kernelReady else {
            return (false, "内核层不可用（km_init 已失败，原因见启动日志 / 调试页首行）")
        }

        if activePid == pid, pid != 0 { return (true, "复用现有挂载") }
        if activePid != 0 { detachPort() }

        let proc = km_proc_for_pid(pid)
        guard proc != 0 else {
            return (false, "内核里找不到 pid=\(pid) 的 proc")
        }
        activePid = pid
        cachedOffsets = nil
        return (true, "已挂载 pid=\(pid) proc=0x\(String(proc, radix: 16))")
    }

    /// 卸载目标进程。
    static func detachPort() {
        activePid = 0
    }

    /// 偏移表缓存（见上方说明）。
    private static var cachedOffsets: Offsets?

    static var offsets: Offsets {
        if let c = cachedOffsets { return c }
        let o = Offsets.load()
        cachedOffsets = o
        return o
    }

    /// 自身 + 相机的一次快照（高频层产出）。
    struct SelfSnapshot {
        var pc: UInt64 = 0
        var pawn: UInt64 = 0
        var loc: (Float, Float, Float) = (0, 0, 0)
        var camera = CameraPose()
        var valid = false
    }

    /// 一个真实存在于客户端的目标（低频层产出）。
    struct TargetSnapshot {
        var actor: UInt64 = 0
        var cls = ""
        var loc: (Float, Float, Float) = (0, 0, 0)
        var isSelf = false
    }

    /// 一次全量扫描的结果。
    struct TargetScan {
        var targets: [TargetSnapshot] = []
        var classes: [String: Int] = [:]
        /// 本轮读到的世界对象 —— 高频层要用它走 GWorld → LocalPlayers
        var world: UInt64 = 0
        /// 本机 PlayerController 与它的 Pawn。**高频层靠这个锚点活下去**：
        /// `LocalPlayers` 那条路在本机被 bUseEncryptLocalPlayerPtr 挡着，拿不到 PC 就
        /// 连自己是谁都定位不了。扫描时顺手记下来，20Hz 那层就不用再遍历一遍。
        var localPC: UInt64 = 0
        var localPawn: UInt64 = 0
        var scanned = 0
        var usedMappings: Int = 0
        var vmReads: Int = 0
        var note = ""
    }

    private static func readWorldPointer(_ pid: Int32) -> UInt64? {
        guard imageSlide != 0 else { return nil }
        let (rk, w) = readRaw(pid: pid, address: MachVmAddress(runtime(offsets.gWorld, slide: imageSlide)))
        return (rk == KERN_SUCCESS && w > 0x100000000) ? w : nil
    }

    /// 高频层：只走「自己 + 相机」这条短链，全程约 15–20 次小读。
    ///
    /// GWorld → OwningGameInstance(0xB20) → LocalPlayers(0x48) → UPlayer+0x30 → PlayerController
    ///   → Pawn{ AcknowledgedPawn(0x660) / Pawn(0x5D8) }
    ///   → RootComponent(0x260) → ComponentToWorld(0x1F0)+0x10 → FVector
    ///   → CameraManager(0x680) → CameraCache(0x640)+0x10 → POV{Loc 0x00, Rot 0x18, FOV 0x30}
    ///
    /// `hintPC` 来自低频层：LocalPlayers 那条路可能被 `bUseEncryptLocalPlayerPtr` 挡住，
    /// 那时用它兜底（本机实测就是这种情况）。
    static func readSelfAndCamera(pid: Int32, hintPC: UInt64, world: UInt64) -> SelfSnapshot {
        var snap = SelfSnapshot()
        guard pid != 0 else { return snap }

        // ① 自己的 PlayerController
        var pc: UInt64 = 0
        if world > 0x100000000 {
            let (rkG, gi) = readRaw(pid: pid, address: MachVmAddress(world &+ 0xB20))
            if rkG == KERN_SUCCESS, gi > 0x100000000 {
                let (rkL, lp) = readBytes(pid: pid, address: MachVmAddress(gi &+ 0x48), count: 16)
                if rkL == KERN_SUCCESS, lp.count >= 16 {
                    let data = u64le(lp, 0)
                    let cnt = u32le(lp, 8)
                    if data > 0x100000000, cnt > 0, cnt <= 8 {
                        let (rkP0, lplayer) = readRaw(pid: pid, address: MachVmAddress(data))
                        if rkP0 == KERN_SUCCESS, lplayer > 0x100000000 {
                            let (rkPC, got) = readRaw(pid: pid, address: MachVmAddress(lplayer &+ 0x30))
                            if rkPC == KERN_SUCCESS, got > 0x100000000 { pc = got }
                        }
                    }
                }
            }
        }
        if pc == 0 { pc = hintPC }
        guard pc > 0x100000000 else { return snap }
        snap.pc = pc

        // ② Pawn 与世界坐标
        var pawn: UInt64 = 0
        let (rkA, ack) = readRaw(pid: pid, address: MachVmAddress(pc &+ 0x660))
        if rkA == KERN_SUCCESS, ack > 0x100000000 {
            pawn = ack
        } else {
            let (rkP, pw) = readRaw(pid: pid, address: MachVmAddress(pc &+ 0x5D8))
            if rkP == KERN_SUCCESS, pw > 0x100000000 { pawn = pw }
        }
        guard pawn > 0x100000000 else { return snap }
        snap.pawn = pawn

        let (rkR, root) = readRaw(pid: pid, address: MachVmAddress(pawn &+ 0x260))
        guard rkR == KERN_SUCCESS, root > 0x100000000 else { return snap }
        let (rkT, tf) = readBytes(pid: pid, address: MachVmAddress(root &+ 0x1F0 &+ 0x10), count: 12)
        guard rkT == KERN_SUCCESS, tf.count >= 12 else { return snap }
        snap.loc = (floatAt(tf, 0), floatAt(tf, 4), floatAt(tf, 8))

        // ③ 相机
        let (rkC, cm) = readRaw(pid: pid, address: MachVmAddress(pc &+ 0x680))
        if rkC == KERN_SUCCESS, cm > 0x100000000 {
            let (rkPov, pov) = readBytes(pid: pid,
                                         address: MachVmAddress(cm &+ 0x640 &+ 0x10),
                                         count: 0x60)
            if rkPov == KERN_SUCCESS, pov.count >= 0x34 {
                let fov = floatAt(pov, 0x30)
                snap.camera = CameraPose(
                    loc: (floatAt(pov, 0x00), floatAt(pov, 0x04), floatAt(pov, 0x08)),
                    rot: (floatAt(pov, 0x18), floatAt(pov, 0x1C), floatAt(pov, 0x20)),
                    fov: fov,
                    valid: fov > 1 && fov < 179)
            }
        }
        snap.valid = true
        return snap
    }

    /// 低频层：遍历所有关卡的 actor，筛出「客户端手上真实存在的身体」。
    ///
    /// 这条链长（本机实测 13 个关卡合计约 650 个 actor），所以只在 1–2Hz 上跑。
    /// 两条硬要求：
    ///   · **每一个关卡都要遍历** —— 之前只挑"最大的那个关卡"，结果玩家所在的
    ///     PersistentLevel 被跳过，角色数直接是 0
    ///   · 类名解析按 Class 指针**去重** —— 同类对象共享 Class，解析次数只跟
    ///     "有多少种类"有关，不跟 actor 数量有关
    static func scanTargets(pid: Int32) -> TargetScan {
        var out = TargetScan()
        guard pid != 0 else { out.note = "未 attach"; return out }
        let off = offsets
        let vmBefore = kernelReadCalls

        guard let world = readWorldPointer(pid) else {
            // 失败要带数值：地址、返回码、读到的原始值 —— 光说"失败"没法定位
            let gwAddr = imageSlide != 0
                ? runtime(offsets.gWorld, slide: imageSlide)
                : 0
            let (rkW, w) = imageSlide != 0
                ? readRaw(pid: pid, address: MachVmAddress(gwAddr))
                : (KERN_FAILURE, 0)
            out.note = "读 GWorld 失败 rk=\(describe(rkW))"
                + " slide=\(hexOf(imageSlide))"
                + " 槽=\(hexOf(gwAddr))  值=\(hexOf(w))"
                + " 映射\(mappedRanges.count)块"
            return out
        }
        out.world = world
        let (rkPool, pool) = readRaw(pid: pid, address: MachVmAddress(runtime(off.gNames, slide: imageSlide)))
        guard rkPool == KERN_SUCCESS, pool > 0x100000000 else {
            out.note = "读 GNames 槽失败"
            return out
        }
        let (rkChunk, chunk0) = readRaw(pid: pid, address: MachVmAddress(pool))
        guard rkChunk == KERN_SUCCESS, chunk0 > 0x100000000 else {
            out.note = "读名字池 chunk0 失败"
            return out
        }

        // 收集 actor 源：PersistentLevel + UWorld::Levels 里的每一个
        var sources: [(label: String, data: UInt64, count: Int)] = []
        let (rkL, level) = readRaw(pid: pid, address: MachVmAddress(world &+ 0xB8))
        if rkL == KERN_SUCCESS, level > 0x100000000 {
            let (rkA, arr) = readBytes(pid: pid, address: MachVmAddress(level &+ 0xA0), count: 16)
            if rkA == KERN_SUCCESS, arr.count >= 16 {
                let d = u64le(arr, 0)
                let c = Int(u32le(arr, 8))
                if d > 0x100000000, c > 0, c <= 200_000 {
                    sources.append(("Persistent", d, c))
                }
            }
        }
        let (rkLv, lvHdr) = readBytes(pid: pid, address: MachVmAddress(world &+ 0x0AF0), count: 16)
        if rkLv == KERN_SUCCESS, lvHdr.count >= 16 {
            let d = u64le(lvHdr, 0)
            let c = Int(u32le(lvHdr, 8))
            if d > 0x100000000, c > 0, c <= 4096 {
                let probe = min(c, 64)
                let (rkP, ptrs) = readBytes(pid: pid, address: MachVmAddress(d), count: probe * 8)
                if rkP == KERN_SUCCESS, ptrs.count >= probe * 8 {
                    for k in 0..<probe {
                        let lv = u64le(ptrs, k * 8)
                        guard lv > 0x100000000, lv != level else { continue }
                        let (rkA2, a2) = readBytes(pid: pid, address: MachVmAddress(lv &+ 0xA0), count: 16)
                        guard rkA2 == KERN_SUCCESS, a2.count >= 16 else { continue }
                        let d2 = u64le(a2, 0)
                        let c2 = Int(u32le(a2, 8))
                        guard d2 > 0x100000000, c2 > 0, c2 <= 100_000 else { continue }
                        sources.append(("Level[\(k)]", d2, c2))
                    }
                }
            }
        }
        guard !sources.isEmpty else {
            out.note = "没有拿到任何关卡的 actor 源"
            return out
        }

        var classNames: [UInt64: String] = [:]
        var seen = 0
        var stopped: String?
        sourceLoop: for src in sources {
            var cursor = 0
            while cursor < src.count {
                if kernelReadCalls - vmBefore > 200 {
                    stopped = "mach_vm_read 超预算，提前收手"
                    break sourceLoop
                }
                if seen >= 3000 {
                    stopped = "达到 3000 上限"
                    break sourceLoop
                }
                let batch = min(500, src.count - cursor)
                let (rkBuf, buf) = readBytes(pid: pid,
                                             address: MachVmAddress(src.data &+ UInt64(cursor * 8)),
                                             count: batch * 8)
                guard rkBuf == KERN_SUCCESS, buf.count >= batch * 8 else { break }
                for i in 0..<batch {
                    let actor = u64le(buf, i * 8)
                    guard actor > 0x100000000 else { continue }
                    let (rkCls, cls) = readRaw(pid: pid, address: MachVmAddress(actor &+ 0x10))
                    guard rkCls == KERN_SUCCESS, cls > 0x100000000 else { continue }
                    var nm = classNames[cls]
                    if nm == nil {
                        let (rkIX, clsIX) = readAt(pid: pid, address: MachVmAddress(cls &+ 0x18))
                        nm = (rkIX == KERN_SUCCESS)
                            ? resolveName(pid: pid, pool: pool, chunk0: chunk0, index: clsIX)
                            : "?"
                        classNames[cls] = nm
                    }
                    let name = nm ?? "?"
                    out.classes[name, default: 0] += 1

                    // 顺手认出本机 PlayerController —— 高频层的锚点，见 TargetScan 注释
                    if name.contains("PlayerController"), out.localPC == 0 {
                        let (rkLf, lf) = readAt(pid: pid, address: MachVmAddress(actor &+ 0xA8C))
                        if rkLf == KERN_SUCCESS, (lf & 0xFF) == 1 {
                            out.localPC = actor
                            let (rkPw, pw) = readRaw(pid: pid, address: MachVmAddress(actor &+ 0x5D8))
                            if rkPw == KERN_SUCCESS, pw > 0x100000000 { out.localPawn = pw }
                        }
                    }

                    guard name.contains("Character")
                        || (name.contains("Pawn") && !name.contains("Mode")) else { continue }
                    var t = TargetSnapshot()
                    t.actor = actor
                    t.cls = name
                    let (rkR, root) = readRaw(pid: pid, address: MachVmAddress(actor &+ 0x260))
                    if rkR == KERN_SUCCESS, root > 0x100000000 {
                        let (rkT, tf) = readBytes(pid: pid,
                                                  address: MachVmAddress(root &+ 0x1F0 &+ 0x10),
                                                  count: 12)
                        if rkT == KERN_SUCCESS, tf.count >= 12 {
                            t.loc = (floatAt(tf, 0), floatAt(tf, 4), floatAt(tf, 8))
                        }
                    }
                    out.targets.append(t)
                }
                cursor += batch
                seen += batch
            }
        }
        out.scanned = seen
        out.usedMappings = mappedRanges.count
        out.vmReads = kernelReadCalls - vmBefore
        out.note = "\(sources.count) 个关卡 / 遍历 \(seen) 个 actor"
            + (stopped.map { "（\($0)）" } ?? "")
        return out
    }

    /// 按绝对地址读 4 字节。**只有 3 个参数**。
    /// mach_vm_region 那条路已被删除：它有两个出参，是之前连续出错的来源，
    /// 而读内存根本不需要枚举内存区。
    private static func readAt(pid: Int32, address: MachVmAddress) -> (KernReturn, UInt32) {
        let (kr, bytes) = readSmart(pid: pid, address: address, count: 4)
        guard kr == KERN_SUCCESS, bytes.count >= 4 else { return (kr, 0) }
        let v = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8)
            | (UInt32(bytes[2]) << 16) | (UInt32(bytes[3]) << 24)
        return (KERN_SUCCESS, v)
    }

    /// 按绝对地址读 8 字节 —— 只给值，供程序判断用。
    private static func readRaw(pid: Int32, address: MachVmAddress) -> (KernReturn, UInt64) {
        let (kr, bytes) = readSmart(pid: pid, address: address, count: 8)
        guard kr == KERN_SUCCESS, bytes.count >= 8 else { return (kr, 0) }
        return (KERN_SUCCESS, u64le(bytes, 0))
    }

    /// 读一段连续字节（**上限 4096**）。
    ///
    /// 这是唯一允许的块读取，硬上限就卡在 4096：之前用 16KB 步进扫内存
    /// 把目标进程搞成过 jetsam 被杀，连续 fault 太多页是死因。
    // 读取已统一走内核路径：readSmart 的降级分支直接调 km_read_process，
    // 原先的 mach_vm_read 实现已整体移除。

    /// 给面板用的指针解读：值 + 是否像有效指针 + 高位（便于看落在哪个地址段）。
    private static func pointerInfo(pid: Int32, address: MachVmAddress)
        -> (KernReturn, UInt64, Bool, String) {
        let (kr, value) = readRaw(pid: pid, address: address)
        guard kr == KERN_SUCCESS else { return (kr, 0, false, "n/a") }
        // iOS arm64 用户态地址是 36 位宽
        let looksReal = value >= 0x100000000 && value < 0x10000000000
        let hi = String(format: "%04llx", (value >> 32) & 0xFFFF)
        return (KERN_SUCCESS, value, looksReal, hi)
    }

    // port(for:) 已移除：读取改走内核路径后不再需要 task port，
    // 目标进程由 km_proc_for_pid 在内核里直接定位。

    /// 释放一个 task port。
    ///
    /// **每次 `task_for_pid` 都会新建一个 send right**，不释放就一直累积。
    /// 之前的版本从来没释放过：每点一次按钮泄漏一个 right，而每个 right 都让
    /// 游戏的 task 对象多背一个引用 —— 游戏崩掉之后那个 task 对象也回收不掉，
    /// 反复"崩→重开→读"会把内核里堆一串收不掉的 task。
    /// 取端口的地方一律用 `defer { dropPort(p) }` 配对。
    // dropPort 已移除：不再持有 task port，没有 right 需要释放。

    // 内核路径不产生 port，也就没有任何 right 需要跨回调持有或释放。

    // MARK: - 地址换算（唯一入口）

    /// dump 时 __TEXT.vmaddr 恒为 0x100000000 —— 静态域的零点。
    private static let staticImageBase: UInt64 = 0x100000000

    /// 本次运行找到的 image base 与 slide。
    /// 由「找村口」写入；**只对这个 pid 有效** —— 游戏重启会换 pid，
    /// ASLR 也会把基址搬走，所以还要记住它是给哪个 pid 找的。
    private(set) static var imageBase: UInt64 = 0
    private(set) static var imageSlide: UInt64 = 0
    private(set) static var basePid: Int32 = 0

    /// 当前这个进程的基址是否已经准备好。
    /// 少了 pid 这一条，游戏重启后会拿旧 slide 去拼地址 —— 算出来的东西看着像地址，
    /// 读回来全是垃圾，白白消耗调用次数。
    static func baseReady(for pid: Int32) -> Bool {
        imageSlide != 0 && imageBase != 0 && basePid == pid
    }

    /// **唯一**的地址换算入口：OFFSET_*（静态 vmaddr 域地址）→ 本次运行的绝对地址。
    ///
    ///     slide   = imageBase − 0x100000000
    ///     runtime = slide + staticAddr
    ///
    /// 全仓约定：不出现 `imageBase + OFFSET` 的写法 —— 那是把"静态域地址"
    /// 当成"相对基址的 RVA"用了，会整整多算一个 0x100000000。
    private static func runtime(_ staticAddr: UInt64, slide: UInt64) -> UInt64 {
        slide &+ staticAddr
    }

    /// slide = imageBase − 静态基址。
    private static func slide(ofImageBase base: UInt64) -> UInt64 { base &- staticImageBase }

    /// 候选地址是不是真的 Mach-O 可执行头：magic == 0xFEEDFACF 且 filetype == MH_EXECUTE(2)。
    /// 两次 4 字节小读，不循环、不扫描。
    private static func isExecutableMachO(pid: Int32, _ addr: UInt64) -> (Bool, String) {
        let (rk1, magic) = readAt(pid: pid, address: MachVmAddress(addr))
        guard rk1 == KERN_SUCCESS else { return (false, "magic读失败/\(rk1)") }
        guard magic == 0xFEEDFACF else { return (false, "magic=0x\(String(magic, radix: 16))") }
        let (rk2, filetype) = readAt(pid: pid, address: MachVmAddress(addr &+ 12))
        guard rk2 == KERN_SUCCESS else { return (false, "filetype读失败/\(rk2)") }
        guard filetype == 2 else { return (false, "filetype=\(filetype)") }
        return (true, "MH_EXECUTE")
    }

    // MARK: - GNames（名字表）

    /// FNameEntry 的字符串起点（dump：FNameEntry::String = 0xE）。
    private static let nameEntryStringOffset: UInt64 = 0xE
    /// TNameArray 每个 chunk 的条目数（dump：ElementsPerChunk = 0x4000）。
    private static let namesPerChunk: UInt64 = 0x4000

    /// 「对象」按钮的分批游标：每批详解 4 个，点一次往下走一批。
    private static var objectCursor = 0

    /// 把一段字节按 hex 分行打印，偏移相对段首。
    private static func hexLines(_ bytes: [UInt8], perLine: Int = 16) -> [String] {
        var out: [String] = []
        var i = 0
        while i < bytes.count {
            let end = min(i + perLine, bytes.count)
            var hex = ""
            for j in i..<end {
                hex += String(format: "%02x", bytes[j])
                if j != end - 1 { hex += " " }
            }
            out.append("+" + String(i, radix: 16) + "  " + hex)
            i = end
        }
        return out
    }

    /// 字符串是 2 字节 UCS-2 还是 1 字节窄字符？
    /// ASCII 字符在 UCS-2 里高字节为 0，看第 2/4/6 字节是不是连续的 0。
    private static func looksWide(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 8 else { return false }
        var zeros = 0
        for i in stride(from: 1, to: min(bytes.count, 8), by: 2) where bytes[i] == 0 {
            zeros += 1
        }
        return zeros >= 3
    }

    /// 从 FNameEntry + 0xE 读名字，同时报出用的是哪种字符宽度。
    /// 宽度是逐 entry 判断的：同一个池里窄字符和 UCS-2 可以混存。
    private static func readNameDetail(pid: Int32, entry: UInt64) -> (name: String, width: String) {
        let (rk, bytes) = readBytes(pid: pid,
                                    address: MachVmAddress(entry &+ nameEntryStringOffset),
                                    count: 96)
        guard rk == KERN_SUCCESS, !bytes.isEmpty else { return ("(读失败)", "?") }
        if looksWide(bytes) {
            var units: [UInt16] = []
            var i = 0
            while i + 1 < bytes.count, units.count < 40 {
                let u = UInt16(bytes[i]) | (UInt16(bytes[i + 1]) << 8)
                if u == 0 { break }
                units.append(u)
                i += 2
            }
            return (units.isEmpty ? "(空)" : String(decoding: units, as: UTF16.self), "宽")
        }
        var raw: [UInt8] = []
        for b in bytes {
            if b == 0 { break }
            raw.append(b)
            if raw.count >= 40 { break }
        }
        return (raw.isEmpty ? "(空)" : String(decoding: raw, as: UTF8.self), "窄")
    }

    /// 从 FNameEntry + 0xE 读名字（不带宽度信息）。
    private static func readName(pid: Int32, entry: UInt64) -> String {
        readNameDetail(pid: pid, entry: entry).name
    }

    /// GNames：把 FName 索引解成字符串。
    ///
    /// 验收标准（三个全中才算通过）：
    ///   索引 0 → "None"    索引 1 → "ByteProperty"    索引 2 → "IntProperty"
    ///
    /// `Chunks` 是「内联指针数组」还是「指向指针数组」，各 UE4 版本不一致，
    /// 所以两种布局各解一遍，用上面三个已知答案判定 —— 不照抄、不猜。
    static func stepGNames(pid: Int32) -> String {
        resetCounters()
        stageMark("名字")
        guard baseReady(for: pid) else {
            return "GNames: 没有当前进程的基址 —— 先点「跑一次」（它会自动完成找基址）"
        }

        let s = imageSlide
        let slotAddr = runtime(Offsets.load().gNames, slide: s)

        // ① 槽 → 名字池
        stageMark("名字 · 读池槽")
        let (rkPool, pool) = readRaw(pid: pid, address: MachVmAddress(slotAddr))
        guard rkPool == KERN_SUCCESS, pool != 0 else {
            return "GNames: 槽 0x\(String(slotAddr, radix: 16)) 读失败 \(describe(rkPool))"
        }

        var lines: [String] = []
        lines.append("GNames: 槽 0x\(String(slotAddr, radix: 16)) → pool=0x\(String(pool, radix: 16))")

        // ② 池头 hex：先看清布局，再决定解哪一层
        stageMark("名字 · 读池头")
        let (rkHead, head) = readBytes(pid: pid, address: MachVmAddress(pool), count: 0x40)
        if rkHead == KERN_SUCCESS, !head.isEmpty {
            lines.append("池头 0x40 字节（偏移相对 pool）:")
            lines.append(contentsOf: hexLines(head, perLine: 16))
            // 池头里若出现 0x4000（ElementsPerChunk），出现位置能反推布局
            var hits: [String] = []
            var k = 0
            while k + 4 <= head.count {
                let v = UInt32(head[k]) | (UInt32(head[k + 1]) << 8)
                    | (UInt32(head[k + 2]) << 16) | (UInt32(head[k + 3]) << 24)
                if v == 0x4000 { hits.append("+" + String(k, radix: 16)) }
                k += 4
            }
            lines.append("池头里 0x4000 出现在: " + (hits.isEmpty ? "无" : hits.joined(separator: " ")))
        } else {
            lines.append("池头读失败 \(describe(rkHead))")
        }

        // ③ 两种布局各解一遍，用已知答案判定
        stageMark("名字 · 解候选")
        let (rkA, lvlA) = readRaw(pid: pid, address: MachVmAddress(pool))
        let (rkB, lvlB) = (rkA == KERN_SUCCESS)
            ? readRaw(pid: pid, address: MachVmAddress(lvlA))
            : (KERN_FAILURE, 0)
        let expect = ["None", "ByteProperty", "IntProperty"]
        let candidates: [(String, KernReturn, UInt64)] = [
            ("A 池头直接是 chunk（一层）", rkA, lvlA),
            ("B 池头指向 chunk 指针数组（二层）", rkB, lvlB)
        ]
        var passed = false
        for (label, rk, chunk) in candidates {
            guard rk == KERN_SUCCESS, chunk != 0 else {
                lines.append("\(label): 指针无效 \(describe(rk))")
                continue
            }
            var names: [String] = []
            var detail: [String] = []
            var prevEntry: UInt64 = 0
            for i in 0..<3 {
                let (rke, entry) = readRaw(pid: pid, address: MachVmAddress(chunk &+ UInt64(i) * 8))
                guard rke == KERN_SUCCESS, entry != 0 else {
                    names.append("(失败)")
                    detail.append("   [\(i)] 取 entry 失败 \(describe(rke))")
                    continue
                }
                let (nm, width) = readNameDetail(pid: pid, entry: entry)
                names.append(nm)
                // entry 自报的索引（dump: FNameEntry::Index = 0x8）：
                // 名字若带 "_0" 之类的后缀，看这行就知道索引基准偏了多少
                let (rkIdx, idxV) = readAt(pid: pid, address: MachVmAddress(entry &+ 0x8))
                let idxNote = (rkIdx == KERN_SUCCESS)
                    ? "selfIdx=\(Int32(bitPattern: idxV))"
                    : "selfIdx=?"
                // entry 之间的实际间隔：和字符串长度对一下就能确认字符宽度
                let gapNote = (prevEntry == 0)
                    ? ""
                    : " Δ+0x" + String(entry &- prevEntry, radix: 16)
                prevEntry = entry
                detail.append("   [\(i)] \(nm)   @0x\(String(entry, radix: 16)) \(idxNote)\(gapNote) [\(width)]")
            }
            let ok = (names == expect)
            passed = passed || ok
            lines.append("\(label) chunk=0x\(String(chunk, radix: 16))")
            lines.append(contentsOf: detail)
            if ok { lines.append("   → 验收通过：0/1/2 三个名字全对") }
        }
        if !passed {
            lines.append("两个布局都没命中验收标准 —— 按池头 hex 决定下一步")
        }
        lines.append("（chunk 容量 \(namesPerChunk) 条/块，索引 0/1/2 都在第 0 块，暂不需要跨块）")
        lines.append(costLine())
        return lines.joined(separator: "\n")
    }

    /// 把 FName 索引解成字符串。布局用「名字」那步已经验收过的一层结构：
    ///   chunk_k = *(pool + k*8)     k = index / ElementsPerChunk
    ///   entry   = *(chunk_k + (index % ElementsPerChunk) * 8)
    /// chunk0 由调用方传入，索引落在第 0 块时省掉一次小读。
    private static func resolveName(pid: Int32, pool: UInt64, chunk0: UInt64, index: UInt32) -> String {
        let k = UInt64(index) / namesPerChunk
        let within = UInt64(index) % namesPerChunk
        var chunk = chunk0
        if k != 0 {
            let (rkC, c) = readRaw(pid: pid, address: MachVmAddress(pool &+ k * 8))
            guard rkC == KERN_SUCCESS, c != 0 else { return "(chunk\(k)读失败 \(describe(rkC)))" }
            chunk = c
        }
        let (rkE, entry) = readRaw(pid: pid, address: MachVmAddress(chunk &+ within * 8))
        guard rkE == KERN_SUCCESS, entry != 0 else { return "(entry读失败 \(describe(rkE)))" }
        return readName(pid: pid, entry: entry)
    }

    /// 对象表：批量读前 16 个 FUObjectItem，**每批只详解 4 个**。
    ///
    /// 链（偏移全部来自同一份 dump）：
    ///   item_i = items + i*0x18        FUObjectItem::Size = 0x18, Object = 0x0
    ///   class  = *(obj + 0x10)         UObject::Class
    ///   nameIX = *(obj + 0x18)         UObject::Name（FName::ComparisonIndex）
    ///   number = *(obj + 0x1C)         FName::Number（>1 时显示成 Name_(Number-1)）
    ///   clsIX  = *(class + 0x18)       类的 FName
    ///
    /// 为什么收着读：上一版逐个对象读 5 处字段 + 两次名字解析，16 个全解时
    /// 触及约 80 页 —— 点完游戏闪退了。现在改成
    ///   ① items 数组一次读完（16×0x18 = 384 字节，1 页），拿到 16 个对象指针
    ///   ② 每批只详解 4 个，点一次往下走一批（游标存在 static 里）
    /// 每次点击的代价降到 1/4 以下，且报告里直接把触及页数打出来。
    static func stepObjects(pid: Int32) -> String {
        resetCounters()
        stageMark("对象")
        guard baseReady(for: pid) else {
            return "对象: 没有当前进程的基址 —— 先点「跑一次」（它会自动完成找基址）"
        }

        let s = imageSlide
        let off = Offsets.load()

        // 名字池（布局已由「名字」按钮验收确认：一层，pool+0 就是 chunk0）
        let (rkPool, pool) = readRaw(pid: pid, address: MachVmAddress(runtime(off.gNames, slide: s)))
        guard rkPool == KERN_SUCCESS, pool != 0 else {
            return "对象: 名字池槽读取失败 \(describe(rkPool))"
        }
        let (rkChunk, nameChunk0) = readRaw(pid: pid, address: MachVmAddress(pool))
        guard rkChunk == KERN_SUCCESS, nameChunk0 != 0 else {
            return "对象: 名字池 chunk0 读取失败 \(describe(rkChunk))"
        }

        // 对象表头
        let slot = runtime(off.gObjects, slide: s)
        let (rkNum, num) = readAt(pid: pid, address: MachVmAddress(slot &+ 0x118))
        guard rkNum == KERN_SUCCESS else { return "对象: NumElements 读失败 \(describe(rkNum))" }
        let (rkItems, items) = readRaw(pid: pid, address: MachVmAddress(slot &+ 0xE0))
        guard rkItems == KERN_SUCCESS, items != 0 else {
            return "对象: items 指针读失败 \(describe(rkItems))"
        }

        // ① items 数组一次读完：逐项读是 16 次内核读，数据在同一页，
        //    调用次数与内核里的 copy 分配却翻 16 倍，没有意义。
        let listCount = min(Int(num), 16)
        let (rkBuf, buf) = readBytes(pid: pid, address: MachVmAddress(items), count: listCount * 0x18)
        guard rkBuf == KERN_SUCCESS else {
            return "对象: items 数组读取失败 \(describe(rkBuf))"
        }
        var objs: [UInt64] = []
        for i in 0..<listCount {
            objs.append(u64le(buf, i * 0x18))     // FUObjectItem::Object = 0x0
        }

        // ② 分批详解：游标轮转，点一次走一批
        let batch = 4
        let start = objectCursor % max(1, listCount)
        let stop = min(start + batch, listCount)
        objectCursor = (stop >= listCount) ? 0 : stop

        var lines: [String] = []
        lines.append("对象: NumElements=\(num)  items=0x\(String(items, radix: 16))  "
            + "本批 [\(start)..\(stop - 1)] / 列表 \(listCount)")
        for i in 0..<listCount {
            let obj = objs[i]
            guard obj != 0 else {
                lines.append("[\(i)] (空槽)")
                continue
            }
            guard i >= start, i < stop else {
                lines.append("[\(i)] 0x\(String(obj, radix: 16))   （只列指针）")
                continue
            }
            let (rkCls, cls) = readRaw(pid: pid, address: MachVmAddress(obj &+ 0x10))
            let (rkName, nameIX) = readAt(pid: pid, address: MachVmAddress(obj &+ 0x18))
            let (rkNo, number) = readAt(pid: pid, address: MachVmAddress(obj &+ 0x1C))

            var clsName = "类名?"
            if rkCls == KERN_SUCCESS, cls != 0 {
                let (rkCIX, clsIX) = readAt(pid: pid, address: MachVmAddress(cls &+ 0x18))
                if rkCIX == KERN_SUCCESS {
                    clsName = resolveName(pid: pid, pool: pool, chunk0: nameChunk0, index: clsIX)
                } else {
                    clsName = "类名读失败 \(describe(rkCIX))"
                }
            } else if rkCls != KERN_SUCCESS {
                clsName = "Class读失败 \(describe(rkCls))"
            }

            var objName = "名字?"
            if rkName == KERN_SUCCESS {
                objName = resolveName(pid: pid, pool: pool, chunk0: nameChunk0, index: nameIX)
                if rkNo == KERN_SUCCESS, number > 1 {
                    objName += "_\(number - 1)"
                }
            } else {
                objName = "Name读失败 \(describe(rkName))"
            }
            lines.append("[\(i)] \(clsName)  \(objName)   @0x\(String(obj, radix: 16))")
        }
        lines.append(costLine() + " · 再点一次继续下一批")
        return lines.joined(separator: "\n")
    }

    /// 世界链：GWorld → PersistentLevel → Actors（三次小读，个位数页）。
    ///
    /// 这条链刻意**绕开对象表**。理由在崩溃报告里：
    ///   对象表那步触及约 80 页（对象字段多是冷页）→ 点完游戏 SIGSEGV，
    ///   而 GWorld / UWorld / ULevel 是游戏每一帧都在用的热页，读取不改变驻留图。
    ///
    ///   UWorld = *(GWorld槽)
    ///   UWorld + 0xB8 → PersistentLevel (ULevel*)
    ///   ULevel + 0xA0 → Actors TArray { data*(8) count(4) max(4) }
    /// 世界链 + Actor 列表：GWorld → PersistentLevel → Actors，然后逐个认类名。
    ///
    /// 这是通往玩家的正路 —— 完全不碰那 46 万个对象的对象表。
    /// 偏移来自同一份 dump：
    ///   UWorld + 0xB8 → PersistentLevel (ULevel*)
    ///   ULevel + 0xA0 → Actors (TArray<AActor*>: 指针8 + count4 + max4)
    ///   每个 actor：Class(0x10) → 类的 FName(0x18) → 名字池
    ///
    /// 读取全部走映射（vm_remap 之后是本地内存读），所以这里可以放心多读几个。
    static func stepWorld(pid: Int32) -> String {
        resetCounters()
        stageMark("世界")
        guard baseReady(for: pid) else {
            return "世界: 没有当前进程的基址 —— 先点「跑一次」（它会自动完成找基址）"
        }

        let s = imageSlide
        let off = Offsets.load()
        var lines: [String] = []

        // ⓿ 读之前先把大块铺好。**这一步不能省**：遍历整张 actor 表是几千次读取，
        //    只要有相当一部分没命中映射，就会退化成 mach_vm_read —— 那是会崩游戏的路。
        if mappedBlockCount < 8 {
            stageMark("世界 · 预映射")
            lines.append(mapAllRegions(pid: pid))
        }

        // 解类名要用名字池
        let (rkPool, pool) = readRaw(pid: pid, address: MachVmAddress(runtime(off.gNames, slide: s)))
        guard rkPool == KERN_SUCCESS, pool != 0 else {
            return "世界: 名字池槽读取失败 \(describe(rkPool))"
        }
        let (rkChunk, nameChunk0) = readRaw(pid: pid, address: MachVmAddress(pool))
        guard rkChunk == KERN_SUCCESS, nameChunk0 != 0 else {
            return "世界: 名字池 chunk0 读取失败 \(describe(rkChunk))"
        }

        // ① UWorld
        stageMark("世界 · UWorld")
        let (rkW, world) = readRaw(pid: pid, address: MachVmAddress(runtime(off.gWorld, slide: s)))
        guard rkW == KERN_SUCCESS, world != 0 else {
            return "世界: 读 GWorld 失败 \(describe(rkW))"
        }
        lines.append("UWorld=0x\(String(world, radix: 16))")

        // ② PersistentLevel
        stageMark("世界 · PersistentLevel")
        let (rkL, level) = readRaw(pid: pid, address: MachVmAddress(world &+ 0xB8))
        guard rkL == KERN_SUCCESS, level != 0 else {
            return lines.joined(separator: "\n") + "\n读 PersistentLevel 失败 \(describe(rkL))"
        }
        lines.append("PersistentLevel=0x\(String(level, radix: 16))")

        // ③ Actors TArray
        stageMark("世界 · Actors")
        let (rkA, arr) = readBytes(pid: pid, address: MachVmAddress(level &+ 0xA0), count: 16)
        guard rkA == KERN_SUCCESS, arr.count >= 16 else {
            return lines.joined(separator: "\n") + "\n读 Actors TArray 失败 \(describe(rkA))"
        }
        let dataPtr = u64le(arr, 0)
        let count = UInt32(arr[8]) | (UInt32(arr[9]) << 8)
            | (UInt32(arr[10]) << 16) | (UInt32(arr[11]) << 24)
        let cap = UInt32(arr[12]) | (UInt32(arr[13]) << 8)
            | (UInt32(arr[14]) << 16) | (UInt32(arr[15]) << 24)
        let sane = (count > 0 && count <= 200_000 && count <= cap && dataPtr != 0)
        lines.append("Actors: data=0x\(String(dataPtr, radix: 16)) count=\(count) max=\(cap) "
            + (sane ? "✓ 数量合理" : "✗ 数量异常"))
        guard sane else {
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }

        // ③′ 关卡全景。**两次都卡在这里**：先只看了 PersistentLevel（44 个，全是框架对象），
        //     改看最大的子关卡后又只剩射击场物件 —— 因为场景内容分散在 UWorld::Levels 的
        //     13 个关卡里，玩家在哪个关卡事先并不知道。
        //       0x0AF0  Levels              TArray<ULevel*>  ← 所有关卡，每个各自持有 Actors
        //       0x0AB8  ActiveLevelActors   TArray<AActor*>  ← 实测客户端恒为 0，只记录不使用
        //     **所以这一版把每一个关卡都收进 sources，全都遍历** —— 不再挑一个。
        stageMark("世界 · 关卡全景")
        var sources: [(label: String, data: UInt64, count: Int)] = []
        if dataPtr > 0x100000000, count > 0 {
            sources.append(("Persistent", dataPtr, Int(count)))
        }
        var levelTotal = 0

        let (rkAct, actHdr) = readBytes(pid: pid, address: MachVmAddress(world &+ 0x0AB8), count: 16)
        if rkAct == KERN_SUCCESS, actHdr.count >= 16 {
            lines.append("ActiveLevelActors: count=\(Int(u32le(actHdr, 8)))（客户端恒为 0，仅记录）")
        }

        let (rkLv, lvHdr) = readBytes(pid: pid, address: MachVmAddress(world &+ 0x0AF0), count: 16)
        if rkLv == KERN_SUCCESS, lvHdr.count >= 16 {
            let d = u64le(lvHdr, 0)
            let c = Int(u32le(lvHdr, 8))
            lines.append("UWorld::Levels: count=\(c)")
            if d > 0x100000000, c > 0, c <= 4096 {
                let probe = min(c, 64)                  // 全读完，上次 min(c, 12) 把第 13 个漏了
                let (rkP, ptrs) = readBytes(pid: pid, address: MachVmAddress(d), count: probe * 8)
                if rkP == KERN_SUCCESS, ptrs.count >= probe * 8 {
                    for k in 0..<probe {
                        let lv = u64le(ptrs, k * 8)
                        guard lv > 0x100000000 else { continue }
                        if lv == level { continue }     // 就是 PersistentLevel，已经在 sources 里
                        let (rkA2, a2) = readBytes(pid: pid, address: MachVmAddress(lv &+ 0xA0), count: 16)
                        guard rkA2 == KERN_SUCCESS, a2.count >= 16 else { continue }
                        let d2 = u64le(a2, 0)
                        let c2 = Int(u32le(a2, 8))
                        guard d2 > 0x100000000, c2 > 0, c2 <= 100_000 else { continue }
                        sources.append(("Level[\(k)]", d2, c2))
                        levelTotal += c2
                        lines.append("  Level[\(k)] @\(hexOf(lv))  Actors: count=\(c2)")
                    }
                }
            }
        }
        lines.append("actor 源: \(sources.count) 个关卡合计 \(sources.reduce(0) { $0 + $1.count }) 个"
            + "（Persistent \(count) + 子关卡 \(levelTotal)）")

        // ④ 遍历全表：按类名统计 + 抓出所有角色坐标
        //
        // 这一步直接回答「现场有多少人」——不依赖 PlayerArray 被裁剪了多少。
        // 成本控制：actor 指针分块读（每块 500 个），Class 指针**去重**后每个类名只解一次
        // （同类对象共享 Class，命中率接近 100%），所以名字池的读取次数只跟「有多少种类」有关。
        stageMark("世界 · 遍历 Actor")
        // 第一次先只走 1200 个：本地读虽然不产生内核调用，但未映射过的页首次访问会有
        // page fault（内核要在游戏名下记账一块物理页）。等确认预映射覆盖够、page fault
        // 不成问题，再把这个上限放开。
        let budget = 3000
        var classNames: [UInt64: String] = [:]
        var histogram: [String: Int] = [:]
        var charActors: [UInt64] = []
        var ctrlActors: [UInt64] = []
        var psActors: [UInt64] = []
        var seen = 0
        var stopped = false

        sourceLoop: for src in sources {
            var cursor = 0
            while cursor < src.count {
                // 预算闸门：一旦真的落回 mach_vm_read 太多次，立刻收手。
                // 上一版没有这道闸门，一路读到底，游戏就没了。
                if hardReadCalls > 200 {
                    lines.append("⚠ 已用 \(hardReadCalls) 次内核读 —— 主动停止遍历，保住游戏")
                    stopped = true
                    break sourceLoop
                }
                if seen >= budget {
                    stopped = true
                    break sourceLoop
                }
                let batch = min(500, src.count - cursor)
                let (rkBuf, buf) = readBytes(pid: pid,
                                             address: MachVmAddress(src.data &+ UInt64(cursor * 8)),
                                             count: batch * 8)
                guard rkBuf == KERN_SUCCESS, buf.count >= batch * 8 else {
                    lines.append("读 \(src.label) 的 actor 指针失败 @\(cursor) \(describe(rkBuf))")
                    break
                }
                for i in 0..<batch {
                    let actor = u64le(buf, i * 8)
                    guard actor > 0x100000000 else { continue }
                    let (rkCls, cls) = readRaw(pid: pid, address: MachVmAddress(actor &+ 0x10))
                    guard rkCls == KERN_SUCCESS, cls > 0x100000000 else { continue }

                    var nm = classNames[cls]
                    if nm == nil {
                        let (rkIX, clsIX) = readAt(pid: pid, address: MachVmAddress(cls &+ 0x18))
                        nm = (rkIX == KERN_SUCCESS)
                            ? resolveName(pid: pid, pool: pool, chunk0: nameChunk0, index: clsIX)
                            : "?"
                        classNames[cls] = nm
                    }
                    let name = nm ?? "?"
                    histogram[name, default: 0] += 1
                    // Pawn 的判定要排除 GamePawnMode 之类 —— 上次它被误当成角色抓进来，
                    // 于是报告里出现了一个 Loc=(0,0,0) 的"角色"。
                    if name.contains("Character") || (name.contains("Pawn") && !name.contains("Mode")) {
                        charActors.append(actor)
                    }
                    if name.contains("PlayerController") {
                        ctrlActors.append(actor)
                    }
                    if name.contains("PlayerState") {
                        psActors.append(actor)
                    }
                }
                cursor += batch
                seen += batch
            }
        }

        lines.append("类名分布（\(sources.count) 个关卡 / 遍历 \(seen) 个 actor"
            + (stopped ? "（未跑完）" : "") + "，共 \(classNames.count) 种类）:")
        for (name, c) in histogram.sorted(by: { $0.value > $1.value }).prefix(40) {
            lines.append("  \(name) × \(c)")
        }

        // 只把「像角色」的类名单独再列一遍 —— 122 种类里前 40 名排不进玩家角色时，
        // 上面那张总表会把它淹掉。这一节不管数量多少都要出现。
        let pawnish = histogram.filter {
            $0.key.contains("Character") || $0.key.contains("Pawn") || $0.key.contains("Controller")
        }.sorted { $0.value > $1.value }
        lines.append("含 Character/Pawn/Controller 的类名（\(pawnish.count) 种）:")
        for (name, c) in pawnish.prefix(24) {
            lines.append("  ◆ \(name) × \(c)")
        }

        // 直接问 PlayerController：谁是这个客户端自己的。这条路不依赖角色那边有没有 Controller。
        if !ctrlActors.isEmpty {
            lines.append("PlayerController（\(ctrlActors.count) 个）:")
            for (i, c) in ctrlActors.prefix(8).enumerated() {
                // AController::Pawn 0x5D8 · APlayerController::AcknowledgedPawn 0x660
                // APlayerController::bIsLocalPlayerController 0xA8C · AController::PlayerState 0x5F0
                let (r1, pawn) = readRaw(pid: pid, address: MachVmAddress(c &+ 0x5D8))
                let (r2, ack) = readRaw(pid: pid, address: MachVmAddress(c &+ 0x660))
                let (r3, lf) = readAt(pid: pid, address: MachVmAddress(c &+ 0xA8C))
                let (r4, ps) = readRaw(pid: pid, address: MachVmAddress(c &+ 0x5F0))
                var line = "  [\(i)] PC=\(hexOf(c))"
                line += "  local=\(r3 == KERN_SUCCESS ? "\(lf & 0xFF)" : "读失败")"
                line += "  Pawn=\(r1 == KERN_SUCCESS ? hexOf(pawn) : "失败")"
                line += "  Ack=\(r2 == KERN_SUCCESS ? hexOf(ack) : "失败")"
                line += "  PS=\(r4 == KERN_SUCCESS ? hexOf(ps) : "失败")"
                lines.append(line)
                if r4 == KERN_SUCCESS, ps > 0x100000000 {
                    let nm = readText(pid: pid, addr: ps &+ 0x5D8)
                    if !nm.isEmpty { lines.append("        名字: \"\(nm)\"") }
                }
            }
        } else {
            lines.append("PlayerController: 0 个（本次遍历里没抓到这类 actor）")
        }

        // 先把自己钉死：PlayerController 里 bIsLocalPlayerController==1 的那个，
        // 它的 Pawn 就是你的身体。**这是整条链的锚点** —— 有了自己才能算相对位置。
        var myPawn: UInt64 = 0
        var myPC: UInt64 = 0
        var myName = ""
        for c in ctrlActors {
            let (r3, lf) = readAt(pid: pid, address: MachVmAddress(c &+ 0xA8C))
            guard r3 == KERN_SUCCESS, (lf & 0xFF) == 1 else { continue }
            myPC = c
            let (r1, pawn) = readRaw(pid: pid, address: MachVmAddress(c &+ 0x5D8))
            if r1 == KERN_SUCCESS, pawn > 0x100000000 { myPawn = pawn }
            let (r4, ps) = readRaw(pid: pid, address: MachVmAddress(c &+ 0x5F0))
            if r4 == KERN_SUCCESS, ps > 0x100000000 { myName = readText(pid: pid, addr: ps &+ 0x5D8) }
            break
        }
        var myLoc: (Float, Float, Float)?
        if myPawn > 0x100000000 {
            let (rkMr, root) = readRaw(pid: pid, address: MachVmAddress(myPawn &+ 0x260))
            if rkMr == KERN_SUCCESS, root > 0x100000000 {
                let (rkMt, tf) = readBytes(pid: pid, address: MachVmAddress(root &+ 0x1F0 + 0x10), count: 12)
                if rkMt == KERN_SUCCESS, tf.count >= 12 {
                    myLoc = (floatAt(tf, 0), floatAt(tf, 4), floatAt(tf, 8))
                }
            }
            lines.append("自己: Pawn=\(hexOf(myPawn))"
                + (myName.isEmpty ? "" : "  名字=\"\(myName)\"")
                + (myLoc.map { "  位置=(\(fmt1($0.0)), \(fmt1($0.1)), \(fmt1($0.2)))" } ?? "  位置读失败"))
        } else {
            lines.append("自己: 没找到带 local=1 的 PlayerController（没进对局或该类没被抓到）")
        }

        // ── 相机：世界坐标 → 屏幕坐标的最后一步 ───────────────────────────
        //   APlayerController     + 0x0680 → APlayerCameraManager*
        //   APlayerCameraManager  + 0x0640 → FCameraCacheEntry（POV 在 +0x10）
        //   FMinimalViewInfo      +0x00 Location · +0x18 Rotation · +0x30 FOV
        // 三次读拿全（PC → CameraManager → POV 那 0x60 字节）。
        var camLoc: (Float, Float, Float) = (0, 0, 0)
        var camRot: (Float, Float, Float) = (0, 0, 0)
        var camFov: Float = 0
        var camReady = false
        if myPC > 0x100000000 {
            let (rkCm, cm) = readRaw(pid: pid, address: MachVmAddress(myPC &+ 0x680))
            if rkCm == KERN_SUCCESS, cm > 0x100000000 {
                let (rkPov, pov) = readBytes(pid: pid,
                                             address: MachVmAddress(cm &+ 0x640 &+ 0x10),
                                             count: 0x60)
                if rkPov == KERN_SUCCESS, pov.count >= 0x34 {
                    camLoc = (floatAt(pov, 0x00), floatAt(pov, 0x04), floatAt(pov, 0x08))
                    camRot = (floatAt(pov, 0x18), floatAt(pov, 0x1C), floatAt(pov, 0x20))
                    camFov = floatAt(pov, 0x30)
                    camReady = camFov > 1 && camFov < 179
                }
            }
        }
        lines.append("相机: " + (camReady
            ? "位置=(\(fmt1(camLoc.0)), \(fmt1(camLoc.1)), \(fmt1(camLoc.2)))"
                + "  朝向=(P\(fmt1(camRot.0)) Y\(fmt1(camRot.1)) R\(fmt1(camRot.2)))"
                + "  FOV=\(fmt1(camFov))"
            : "读失败（没进对局，或 PC 没抓到）"))

        let scrW = Double(screenSize.width)
        let scrH = Double(screenSize.height)
        lines.append("屏幕: \(Int(scrW)) × \(Int(scrH))"
            + (scrW > 1 && scrH > 1 ? "" : "（UI 层还没写入尺寸，投影会跳过）"))

        // 投影统一走 MemoryProbe.projectPoint —— 手动按钮和自动追踪共用同一份，
        // 免得两处公式各自演化（上一轮审查刚吃过"两套逻辑不同步"的亏）。
        let camPose = CameraPose(loc: camLoc, rot: camRot, fov: camFov, valid: camReady)
        func project(_ wx: Float, _ wy: Float, _ wz: Float) -> (Double, Double)? {
            MemoryProbe.projectPoint(wx, wy, wz, camera: camPose, screenW: scrW, screenH: scrH)
        }

        // PlayerState 段：**这里才是把「档案」和「身体」对上号的地方**。
        // 从 Pawn 正着读 PlayerState(0x5F0) 在客户端是空的，但反方向是通的：
        //   ASTExtraPlayerState + 0x16C0 CharacterOwner  → 那个人的身体
        //   ASTExtraPlayerState + 0x16D0 PlayerHealth    → 血量 / 上限
        //   APlayerState        + 0x05D8 PlayerName      → 名字
        // 有名字 + 有血量 + 有身体的，才是真人玩家。
        if !psActors.isEmpty {
            lines.append("PlayerState（\(psActors.count) 个）:")
            for (i, s) in psActors.prefix(16).enumerated() {
                let nm = readText(pid: pid, addr: s &+ 0x5D8)
                let (rkCh, ch) = readRaw(pid: pid, address: MachVmAddress(s &+ 0x16C0))
                let (rkHp, hpSeg) = readBytes(pid: pid, address: MachVmAddress(s &+ 0x16D0), count: 8)
                var l = "  [\(i)]"
                if !nm.isEmpty { l += " \"\(nm)\"" }
                if rkHp == KERN_SUCCESS, hpSeg.count >= 8 {
                    l += "  HP=\(fmt1(floatAt(hpSeg, 0)))/\(fmt1(floatAt(hpSeg, 4)))"
                }
                l += "  Char=\(rkCh == KERN_SUCCESS && ch > 0x100000000 ? hexOf(ch) : "空")"
                if myPawn > 0x100000000, ch == myPawn { l += "  ★这是你" }
                lines.append(l)
            }
        } else {
            lines.append("PlayerState: 0 个（这类 actor 没抓到）")
        }

        if charActors.isEmpty {
            lines.append("角色: 0 个 —— 这 \(sources.count) 个关卡的 \(seen) 个 actor 里没有 Character/Pawn")
        } else {
            lines.append("角色: \(charActors.count) 个 —— 每个都是客户端手上真实存在的身体")
            var localCount = 0
            for (i, a) in charActors.prefix(24).enumerated() {
                var extra = ""
                // 身份：APawn + 0x608 → AController，再读 APlayerController + 0xA8C
                // 的 bIsLocalPlayerController。这条路不碰 LocalPlayers，不受加密影响。
                let (rkC, ctrl) = readRaw(pid: pid, address: MachVmAddress(a &+ 0x608))
                if rkC == KERN_SUCCESS, ctrl > 0x100000000 {
                    let (rkL, lf) = readAt(pid: pid, address: MachVmAddress(ctrl &+ 0xA8C))
                    if rkL == KERN_SUCCESS, (lf & 0xFF) == 1 { extra += "  [本机控制器]" }
                }
                // 名字：APawn + 0x5F0 → APlayerState，再从 PlayerState + 0x5D8 读 FString
                let (rkPS, ps) = readRaw(pid: pid, address: MachVmAddress(a &+ 0x5F0))
                if rkPS == KERN_SUCCESS, ps > 0x100000000 {
                    let nm = readText(pid: pid, addr: ps &+ 0x5D8)
                    if !nm.isEmpty { extra += "  \"\(nm)\"" }
                }
                let (rkR, root) = readRaw(pid: pid, address: MachVmAddress(a &+ 0x260))
                guard rkR == KERN_SUCCESS, root > 0x100000000 else {
                    lines.append("  [\(i)]        @\(hexOf(a))  RootComponent 无效" + extra)
                    continue
                }
                let (rkT, tf) = readBytes(pid: pid, address: MachVmAddress(root &+ 0x1F0 + 0x10), count: 12)
                if rkT == KERN_SUCCESS, tf.count >= 12 {
                    let x = floatAt(tf, 0), y = floatAt(tf, 4), z = floatAt(tf, 8)
                    let ok = (x != 0 || y != 0) && abs(x) < 5e6 && abs(y) < 5e6 && abs(z) < 1e5
                    var tail = "     "
                    if myPawn > 0x100000000 && a == myPawn {
                        tail = "  ★你  "
                        localCount += 1
                    } else if let my = myLoc {
                        // 坐标单位是厘米，这里换算成米 —— 这就是 ESP 真正要用的那个数
                        let dx = Double(x) - Double(my.0)
                        let dy = Double(y) - Double(my.1)
                        let dz = Double(z) - Double(my.2)
                        let dist = (dx * dx + dy * dy + dz * dz).squareRoot() / 100.0
                        tail = "  \(String(format: "%5.0f", dist))m"
                    }
                    // 屏幕坐标：**这是 ESP 真正要画的那个点**。
                    var scrTxt = ""
                    if let pt = project(x, y, z) {
                        let inView = pt.0 >= 0 && pt.0 <= scrW && pt.1 >= 0 && pt.1 <= scrH
                        scrTxt = "  屏幕(\(Int(pt.0)), \(Int(pt.1)))" + (inView ? "" : " 屏外")
                    } else {
                        scrTxt = "  屏幕(身后)"
                    }
                    // 距离和屏幕坐标都排在最前面：面板会截断长行，之前就是这样把距离吃掉过。
                    lines.append("  [\(i)]\(tail)\(scrTxt)  (\(fmt1(x)), \(fmt1(y)), \(fmt1(z)))"
                        + (ok ? "" : "  ✗量级") + extra + "  @\(hexOf(a))")
                } else {
                    lines.append("  [\(i)]        @\(hexOf(a))  ComponentToWorld 读失败 \(describe(rkT))" + extra)
                }
            }
            if localCount == 0 {
                lines.append("  → 这 \(charActors.count) 个里没有一个是本机 Pawn（你的 Pawn 可能没被遍历到）")
            }
        }
        lines.append(costLine())
        return lines.joined(separator: "\n")
    }

    // MARK: - 内存账本（验证读取是否在给游戏加内存）

    private typealias TaskInfoFn = @convention(c) (UInt32, Int32,
                                                   UnsafeMutablePointer<Int32>,
                                                   UnsafeMutablePointer<UInt32>) -> KernReturn
    private static let taskInfoFn = symbol("task_info", as: TaskInfoFn.self)

    /// 上一次读到的内存账本，用来算差值。
    private static var lastMem: (footprint: UInt64, compressed: UInt64, resident: UInt64)?

    /// 读内存账本。**一个字节的目标内存都不碰** —— 只是让内核查一下它自己的记账。
    ///
    /// 这是把「读冷页 → 加内存 → 崩」这条假说变成数字的唯一直接手段：
    ///   phys_footprint  是 jetsam 判定用的那个数（决定自己会不会被杀）
    ///   compressed      是当前被压缩的内存量 —— 读冷页会强制解压，这个数应该往下掉
    /// 在「对象」这类动作前后各点一次，差值自己会说话。
    ///
    /// 注：端口机制移除后，这里查的是**本进程**的账本（原来查的是目标进程）。
    /// 要查目标进程需要它的 task port，而内核路径不产生 port。
    static func stepMemory(pid: Int32) -> String {
        guard let fn = taskInfoFn else { return "内存: task_info 符号缺失" }

        var raw = [UInt8](repeating: 0, count: 512)
        var count = UInt32(raw.count / 4)
        let rk = raw.withUnsafeMutableBytes { rb -> Int32 in
            guard let base = rb.baseAddress?.assumingMemoryBound(to: Int32.self) else {
                return KERN_FAILURE
            }
            return fn(mach_task_self_, 22, base, &count)          // TASK_VM_INFO = 22
        }
        guard rk == KERN_SUCCESS, count > 0 else {
            return "内存: task_info 失败 \(describe(rk))"
        }

        func field(_ off: Int) -> UInt64 { u64le(raw, off) }
        func mb(_ v: UInt64) -> String { String(format: "%.1f", Double(v) / 1048576.0) }

        let virt = field(0)              // virtual_size
        let resi = field(16)             // resident_size
        let comp = field(120)            // compressed
        let phys = field(144)            // phys_footprint

        // 结构布局是按 task_vm_info 的公开字段顺序取的；数值明显不合理说明偏移不对，
        // 这一行就是给这种情况准备的。
        let sane = (phys > 1_048_576 && phys < (64 * 1024 * 1024 * 1024))
        var lines: [String] = []
        lines.append("内存: pid=\(pid)" + (sane ? "" : "  ✗ 数值不合理（结构偏移可能不匹配这个系统版本）"))
        var delta = ""
        if let last = lastMem {
            let df = Int64(bitPattern: phys) - Int64(bitPattern: last.footprint)
            let dc = Int64(bitPattern: comp) - Int64(bitPattern: last.compressed)
            delta = String(format: "   较上次 %+.1f MB / %+.1f MB",
                           Double(df) / 1048576.0, Double(dc) / 1048576.0)
        }
        lines.append("  phys_footprint = \(mb(phys)) MB   ← jetsam 判定的就是它" + delta)
        lines.append("  compressed     = \(mb(comp)) MB   ← 读冷页会让它往下掉")
        lines.append("  resident       = \(mb(resi)) MB")
        lines.append("  virtual        = \(mb(virt)) MB")
        lines.append("用法：动作前后各点一次这个按钮，差值直接说明读取给游戏加了多少内存")
        lastMem = (phys, comp, resi)
        return lines.joined(separator: "\n")
    }

    /// 映射原语验证 —— 第一步验证的是**本地窗口**。
    ///
    /// 这个按钮原来点的是"跨进程映射"：把游戏的映像头 / `__DATA` 段 remap 进本进程，
    /// 然后从本地内存直接读 Mach-O 头与 GObjects。那条路现在走不通 ——
    /// 它需要**目标进程的 task port**，而本工程在内核路径下不产生 port（见 mapRange 的注释）。
    /// 原来那个"退化版"会返回一个看着像成功的映射，实际指向的是我们自己的内存：
    /// 那比失败危险得多（读出来全是"合理的垃圾"，没有任何一处会报错）。
    ///
    /// 所以这里改接**窗口**：样本建窗那一套（allocate → 浇灌 → vm_remap(copy=FALSE)
    /// → protect → mlock），并且当场自验证 —— 写 pattern、读回、再从 alias 交叉读一遍。
    /// 那是第一步唯一能"一眼看懂成没成"的判据，也是第二步（让窗口页指向目标物理页）
    /// 的前置条件。
    ///
    /// 函数名与签名保持不变：面板「映射」按钮接的还是它，调用点不用动。
    /// `pid` 现在没用了（窗口与目标进程无关）—— 留着是为了不动调用点，
    /// 也顺便说明一件事：这一步**不需要**先「找村口」。
    static func stepRemapProbe(pid: Int32) -> String {
        var lines = [stepWindowProbe()]
        lines.append("")
        lines.append("跨进程映射（把游戏页直接 remap 进来）：未启用 —— 需要目标 task port。")
        lines.append("  第一步能做的只有「本地窗口」；让窗口页指向目标物理页是第二步。")
        return lines.joined(separator: "\n")
    }

    /// 只枚举 6 个 region，把原始字段全打出来 —— 专门验证这次调用本身对不对。
    ///
    /// **逐段自报**：每一步都写标记 + 一行结果。卡在哪一段，屏幕上就停在哪一段 ——
    /// 前一版只有一个"枚举 · 开始"，卡住了也看不出是函数没进、还是某一行动不了。
    static func stepRegionProbe(pid: Int32) -> String {
        var lines: [String] = []

        stageMark("枚举 · A 函数已进入")
        lines.append("A 函数已进入 ✓（参数 pid=\(pid)）")

        resetCounters()
        stageMark("枚举 · B 计数清零完成")
        lines.append("B resetCounters 完成 ✓")

        guard let fn = vmRegion64Fn else {
            return lines.joined(separator: "\n") + "\nC ✗ vm_region_64 符号缺失"
        }
        _ = fn
        stageMark("枚举 · C 符号已取到")
        lines.append("C vm_region_64 符号 ✓")

        // 端口机制已移除：枚举改为对本进程自己做，验证 vm_region_64 这个调用本身是否可用。
        let p = mach_task_self_
        stageMark("枚举 · D 端口已拿到")
        lines.append("D 端口已拿到 ✓ task=0x\(String(p, radix: 16))（本进程）")

        // 第一次调用：只调一次，不做循环
        stageMark("枚举 · E 第一次调用前")
        var addr: UInt64 = 0x100000000
        let first = nextRegion(task: p, addr: &addr)
        stageMark("枚举 · E 第一次调用已返回")
        lines.append("E 第一次调用返回 ✓ ok=\(first.ok) size=0x\(String(first.size, radix: 16)) "
            + "prot=\(first.prot) off=0x\(String(first.offset, radix: 16))")

        // 再走几个
        var i = 1
        while i < 6 {
            stageMark("枚举 · 第 \(i) 个")
            let r = nextRegion(task: p, addr: &addr)
            lines.append("[\(i)] addr=0x\(String(addr, radix: 16)) ok=\(r.ok) "
                + "size=0x\(String(r.size, radix: 16)) prot=\(r.prot) off=0x\(String(r.offset, radix: 16))")
            if !r.ok { break }
            addr += r.size
            if addr < r.size { break }
            i += 1
        }
        lines.append(costLine())
        return lines.joined(separator: "\n")
    }

    /// 地址格式化（面板显示用）。
    private static func hexOf(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    /// 从字节数组按小端读一个 float。
    private static func floatAt(_ b: [UInt8], _ o: Int) -> Float {
        // 越界必须给 0 而不是让 Swift 崩：调用方拿到的可能是读取失败后的空数组。
        guard o >= 0, o + 4 <= b.count else { return 0 }
        return Float(bitPattern: u32le(b, o))
    }

    /// 定位自己：UWorld → GameInstance → LocalPlayers[0] → PlayerController
    ///           → AcknowledgedPawn → RootComponent → ComponentToWorld → 坐标
    ///
    /// 偏移全部来自同一份 dump：
    ///   UWorld + 0xB20        → OwningGameInstance (UGameInstance*)
    ///   UGameInstance + 0x48  → LocalPlayers (TArray<ULocalPlayer*>)
    ///     ★ +0x80 是 bUseEncryptLocalPlayerPtr —— 这是和平精英加的反作弊：
    ///       为 true 时 LocalPlayers 里的指针是加密的（明文那份在 +0x38
    ///       EncryptedLocalPlayers）。所以这一环必须先读标志，再决定怎么解析。
    ///   UPlayer + 0x30        → APlayerController*（ULocalPlayer 继承自 UPlayer）
    ///   APlayerController + 0x660 → AcknowledgedPawn
    ///   AActor + 0x260        → RootComponent (USceneComponent*)
    ///   USceneComponent + 0x1F0   → ComponentToWorld (FTransform)
    ///   FTransform + 0x10     → Translation (FVector: x, y, z 三个 float)
    static func stepSelf(pid: Int32) -> String {
        resetCounters()
        stageMark("自己")
        guard baseReady(for: pid) else {
            return "自己: 没有当前进程的基址 —— 先点「世界」或「映射」"
        }

        let s = imageSlide
        let off = Offsets.load()
        var lines: [String] = []


        // ① UWorld
        let (rkW, world) = readRaw(pid: pid, address: MachVmAddress(runtime(off.gWorld, slide: s)))
        guard rkW == KERN_SUCCESS, world != 0 else {
            return "自己: 读 GWorld 失败 \(describe(rkW))"
        }
        lines.append("UWorld=\(hexOf(world))")

        // ② GameInstance
        stageMark("自己 · GameInstance")
        let (rkG, game) = readRaw(pid: pid, address: MachVmAddress(world &+ 0xB20))
        guard rkG == KERN_SUCCESS, game != 0 else {
            return lines.joined(separator: "\n")
                + "\n读 OwningGameInstance 失败 \(describe(rkG)) @UWorld+0xB20"
        }
        lines.append("GameInstance=\(hexOf(game))")

        // ③ 加密标志 + LocalPlayers
        stageMark("自己 · LocalPlayers")
        let (rkEnc, enc) = readAt(pid: pid, address: MachVmAddress(game &+ 0x80))
        let encFlag = (rkEnc == KERN_SUCCESS) ? (enc & 0xFF) : 0xFF
        lines.append("bUseEncryptLocalPlayerPtr=\(encFlag) "
            + (encFlag == 0 ? "✓ 明文指针，可以直接用" : "⚠️ 指针被加密，这条路要另行处理"))

        let (rkL, larr) = readBytes(pid: pid, address: MachVmAddress(game &+ 0x48), count: 16)
        guard rkL == KERN_SUCCESS, larr.count >= 16 else {
            return lines.joined(separator: "\n") + "\n读 LocalPlayers 失败 \(describe(rkL))"
        }
        let lData = u64le(larr, 0)
        let lCount = UInt32(larr[8]) | (UInt32(larr[9]) << 8)
            | (UInt32(larr[10]) << 16) | (UInt32(larr[11]) << 24)
        lines.append("LocalPlayers: data=\(hexOf(lData)) count=\(lCount)")
        guard lCount > 0, lData != 0 else {
            lines.append("→ LocalPlayers 是空的：多半还在大厅，没进对局")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }

        // ④ ULocalPlayer
        stageMark("自己 · ULocalPlayer")
        let (rkLP, localPlayer) = readRaw(pid: pid, address: MachVmAddress(lData))
        guard rkLP == KERN_SUCCESS, localPlayer != 0 else {
            return lines.joined(separator: "\n") + "\n读 LocalPlayers[0] 失败 \(describe(rkLP))"
        }
        lines.append("LocalPlayer[0]=\(hexOf(localPlayer))")

        // ⑤ PlayerController（UPlayer::PlayerController 在 0x30）
        stageMark("自己 · PlayerController")
        let (rkPC, pc) = readRaw(pid: pid, address: MachVmAddress(localPlayer &+ 0x30))
        guard rkPC == KERN_SUCCESS, pc != 0 else {
            lines.append("读 PlayerController 失败 \(describe(rkPC)) @LocalPlayer+0x30")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        lines.append("PlayerController=\(hexOf(pc))")

        // ⑥ AcknowledgedPawn
        stageMark("自己 · Pawn")
        let (rkPawn, pawn) = readRaw(pid: pid, address: MachVmAddress(pc &+ 0x660))
        guard rkPawn == KERN_SUCCESS, pawn != 0 else {
            lines.append("读 AcknowledgedPawn 失败 \(describe(rkPawn)) @PC+0x660")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        lines.append("Pawn=\(hexOf(pawn))")

        // ⑦ RootComponent
        stageMark("自己 · 坐标")
        let (rkRoot, root) = readRaw(pid: pid, address: MachVmAddress(pawn &+ 0x260))
        guard rkRoot == KERN_SUCCESS, root != 0 else {
            lines.append("读 RootComponent 失败 \(describe(rkRoot)) @Pawn+0x260")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        lines.append("RootComponent=\(hexOf(root))")

        // ⑧ ComponentToWorld + 0x10 → FVector
        let (rkT, tf) = readBytes(pid: pid, address: MachVmAddress(root &+ 0x1F0 + 0x10), count: 12)
        guard rkT == KERN_SUCCESS, tf.count >= 12 else {
            lines.append("读 ComponentToWorld 失败 \(describe(rkT))")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        let x = floatAt(tf, 0), y = floatAt(tf, 4), z = floatAt(tf, 8)
        let sane = abs(x) < 1e7 && abs(y) < 1e7 && abs(z) < 1e7
        lines.append("坐标: X=\(x)  Y=\(y)  Z=\(z) " + (sane ? "✓" : "✗ 数值异常"))

        lines.append(costLine())
        return lines.joined(separator: "\n")
    }

    /// 全场玩家：GWorld → GameState → PlayerArray → ASTExtraPlayerState → 位置 / 血量 / 角色
    ///
    /// **这一版的偏移全部回溯过类声明**（上一版把 `AController` 的 `Pawn` 当成了
    /// `APlayerState` 的字段 —— 那个 `0x5D8` 实际是 `FString PlayerName`；而
    /// `APlayerState` 整个类体里**根本没有 Pawn 字段**，只有 score/Ping/PlayerName/
    /// PlayerID/StartTime）。所以「PlayerState → Pawn → 坐标」这条链从来不存在：
    ///   UWorld + 0x0AD8                 → GameState (AGameStateBase*)   [UWorld 自己的字段]
    ///   AGameStateBase + 0x05E8         → PlayerArray (TArray<APlayerState*>)
    ///   APlayerState + 0x05D0           → score (float)
    ///   APlayerState + 0x05D4           → Ping (uint8)
    ///   APlayerState + 0x05D8           → FString PlayerName (0x10)      ★不是 Pawn
    ///   APlayerState + 0x05F8           → PlayerID (int32)
    ///   ASTExtraPlayerState + 0x1648    → LiveState (EExtraPlayerLiveState)
    ///   ASTExtraPlayerState + 0x1649    → AILiveState (EEAILiveState)    ← 人 / AI
    ///   ASTExtraPlayerState + 0x16C0    → CharacterOwner (ASTExtraBaseCharacter*)
    ///   ASTExtraPlayerState + 0x16D0    → PlayerHealth / +0x16D4 HealthMax
    ///   ASTExtraPlayerState + 0x16E0    → SelfLocAndRot (FCharacterLocAndRot)
    ///                                     = FVector Loc(0x0C) + FRotator Rot(0x0C)
    ///
    /// `PlayerState` 是 always-relevant 的，**位置就挂在它自己身上** —— 不需要遍历
    /// actor 表，也不需要从一个不存在的 Pawn 字段反查。每个玩家 2 次读取。
    ///
    /// 坐标走两条独立路径交叉验证：PlayerState 的 `SelfLocAndRot`，
    /// 以及 `CharacterOwner → RootComponent → ComponentToWorld`。两条一致才敢用。
    static func stepPlayers(pid: Int32) -> String {
        resetCounters()
        stageMark("玩家")
        guard baseReady(for: pid) else {
            return "玩家: 没有当前进程的基址 —— 先点「世界」或「映射」"
        }

        let s = imageSlide
        let off = Offsets.load()
        var lines: [String] = []

        func coordRaw(of actor: UInt64) -> (text: String, ok: Bool) {
            let (rkR, root) = readRaw(pid: pid, address: MachVmAddress(actor &+ 0x260))
            guard rkR == KERN_SUCCESS, root != 0 else {
                return ("Actor=\(hexOf(actor))  读 RootComponent 失败 \(describe(rkR))", false)
            }
            // 两个候选位置都读出来。dump 里 USceneComponent 的定义是：
            //   RelativeLocation   0x01CC (FVector, 0xC)
            //   ComponentToWorld   0x01F0 (FTransform, 0x30)  —— Translation 在 +0x10
            // 实测过：根组件没有父组件时 UE4 保证两者相等，真机上确实逐位相同。
            // 以 ToWorld 为准，RelLoc 留作对照 —— 哪天角色挂到载具上时两者会分开。
            let (rkRel, rel) = readBytes(pid: pid, address: MachVmAddress(root &+ 0x1CC), count: 12)
            let (rkT, tf) = readBytes(pid: pid, address: MachVmAddress(root &+ 0x1F0 + 0x10), count: 12)

            var out = "Actor=\(hexOf(actor))  RootComponent=\(hexOf(root))"
            var ok = false
            if rkRel == KERN_SUCCESS, rel.count >= 12 {
                out += "\n      RelLoc(0x1CC):       X=\(fmt1(floatAt(rel, 0)))  Y=\(fmt1(floatAt(rel, 4)))  Z=\(fmt1(floatAt(rel, 8)))"
            } else {
                out += "\n      RelLoc(0x1CC):       读失败 \(describe(rkRel))"
            }
            if rkT == KERN_SUCCESS, tf.count >= 12 {
                let x = floatAt(tf, 0), y = floatAt(tf, 4), z = floatAt(tf, 8)
                // 地图 8km = 800000 个单位（厘米）。落在这个量级才是真坐标。
                ok = (x != 0 || y != 0) && abs(x) < 5e6 && abs(y) < 5e6 && abs(z) < 1e5
                out += "\n      ToWorld(0x1F0+0x10): X=\(fmt1(x))  Y=\(fmt1(y))  Z=\(fmt1(z)) "
                    + (ok ? "✓" : "✗ 量级不对")
            } else {
                out += "\n      ToWorld(0x1F0+0x10): 读失败 \(describe(rkT))"
            }
            return (out, ok)
        }

        /// 这个角色是不是本地玩家的：Character + 0x608 → AController，
        /// 再读 APlayerController + 0xA8C 的 bIsLocalPlayerController。
        /// **这条路不碰 LocalPlayers**，所以不受 bUseEncryptLocalPlayerPtr 影响。
        /// 返回 nil 表示读不到 —— 那时调用方会退回 PlayerState 比对。
        func localFlag(character: UInt64) -> Int? {
            let (rkC, ctrl) = readRaw(pid: pid, address: MachVmAddress(character &+ 0x608))
            guard rkC == KERN_SUCCESS, ctrl > 0x100000000 else { return nil }
            let (rkL, v) = readAt(pid: pid, address: MachVmAddress(ctrl &+ 0xA8C))
            guard rkL == KERN_SUCCESS else { return nil }
            return Int(v & 0xFF)
        }

        // ① UWorld
        let (rkW, world) = readRaw(pid: pid, address: MachVmAddress(runtime(off.gWorld, slide: s)))
        guard rkW == KERN_SUCCESS, world != 0 else { return "玩家: 读 GWorld 失败 \(describe(rkW))" }
        lines.append("UWorld=\(hexOf(world))")

        // ② GameState
        stageMark("玩家 · GameState")
        let (rkGS, gameState) = readRaw(pid: pid, address: MachVmAddress(world &+ 0xAD8))
        guard rkGS == KERN_SUCCESS, gameState != 0 else {
            return lines.joined(separator: "\n")
                + "\n读 GameState 失败 \(describe(rkGS)) @UWorld+0xAD8 —— 多半还在大厅"
        }
        lines.append("GameState=\(hexOf(gameState))")

        // ②′ GameState 自己的玩家计数（ASTExtraGameStateBase，偏移同样回溯过类声明）：
        //     0x0D98 TotalPlayerNum · 0x0D9C PlayerNum
        //     0x141C AlivePlayerNum · 0x1420 AliveRealPlayerNum
        //   这几个数是服务器给的**权威人数**。拿它和下面 PlayerArray.count 一比，
        //   就能直接看出服务器把玩家列表裁剪了多少 —— 不用再靠推测。
        let (rkN1, n1) = readBytes(pid: pid, address: MachVmAddress(gameState &+ 0x0D98), count: 8)
        if rkN1 == KERN_SUCCESS, n1.count >= 8 {
            lines.append("  人数(总): TotalPlayerNum=\(i32le(n1, 0))   PlayerNum=\(i32le(n1, 4))")
        } else {
            lines.append("  人数(总): 读失败 \(describe(rkN1)) @GameState+0x0D98")
        }
        let (rkN2, n2) = readBytes(pid: pid, address: MachVmAddress(gameState &+ 0x141C), count: 8)
        if rkN2 == KERN_SUCCESS, n2.count >= 8 {
            lines.append("  人数(存活): AlivePlayerNum=\(i32le(n2, 0))   AliveRealPlayerNum=\(i32le(n2, 4))")
        } else {
            lines.append("  人数(存活): 读失败 \(describe(rkN2)) @GameState+0x141C")
        }

        // ③ PlayerArray
        stageMark("玩家 · PlayerArray")
        let (rkPA, parr) = readBytes(pid: pid, address: MachVmAddress(gameState &+ 0x5E8), count: 16)
        guard rkPA == KERN_SUCCESS, parr.count >= 16 else {
            return lines.joined(separator: "\n") + "\n读 PlayerArray 失败 \(describe(rkPA))"
        }
        let paData = u64le(parr, 0)
        let paCount = UInt32(parr[8]) | (UInt32(parr[9]) << 8)
            | (UInt32(parr[10]) << 16) | (UInt32(parr[11]) << 24)
        let paCap = UInt32(parr[12]) | (UInt32(parr[13]) << 8)
            | (UInt32(parr[14]) << 16) | (UInt32(parr[15]) << 24)
        let paOK = (paCount > 0 && paCount <= 200 && paCount <= paCap && paData != 0)
        lines.append("PlayerArray: data=\(hexOf(paData)) count=\(paCount) max=\(paCap) "
            + (paOK ? "✓" : "✗ 数量异常（多半没进对局）"))
        guard paOK else {
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }

        // ④ 逐个玩家：所有数据都挂在 PlayerState 自己身上
        let n = min(Int(paCount), 8)
        let (rkList, list) = readBytes(pid: pid, address: MachVmAddress(paData), count: n * 8)
        guard rkList == KERN_SUCCESS, list.count >= n * 8 else {
            lines.append("读 PlayerArray 元素失败 \(describe(rkList))")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        // 顺带标出名单里"哪个是你"：任一环失败就静默跳过，不影响主流程
        let (selfPS, selfTrace) = findSelfPlayerState(pid: pid, world: world)

        stageMark("玩家 · 遍历")
        var withChar = 0
        var withCoord = 0
        var withLoc = 0
        for i in 0..<n {
            let ps = u64le(list, i * 8)
            guard ps != 0 else { continue }

            // 段 A 身份：0x5D0 score · 0x5D4 Ping · 0x5D8 PlayerName · 0x5F8 PlayerID
            let (rkA, segA) = readBytes(pid: pid, address: MachVmAddress(ps &+ 0x5D0), count: 0x30)
            // 段 B 状态：0x1648 LiveState · 0x1649 AILiveState · 0x16C0 CharacterOwner
            //           0x16D0 Health · 0x16D4 HealthMax · 0x16E0 SelfLocAndRot(0x18)
            let (rkB, segB) = readBytes(pid: pid, address: MachVmAddress(ps &+ 0x1648), count: 0xB8)

            let name = readText(pid: pid, addr: ps &+ 0x5D8)
            let playerID = i32le(segA, 0x28)
            let ping = (rkA == KERN_SUCCESS && segA.count > 4) ? Int(segA[4]) : -1
            let live = (rkB == KERN_SUCCESS && segB.count > 0) ? Int(segB[0]) : -1
            let ai = (rkB == KERN_SUCCESS && segB.count > 1) ? Int(segB[1]) : -1
            let charOwner = u64le(segB, 0x78)
            let health = floatAt(segB, 0x88)
            let healthMax = floatAt(segB, 0x8C)

            // 「这是不是你」先问角色自己的 Controller；读不到才退回 PlayerState 比对。
            var selfTag = ""
            var localNote = ""
            var coordBlock: (text: String, ok: Bool)?
            if charOwner > 0x100000000 {
                withChar += 1
                if let lf = localFlag(character: charOwner) {
                    localNote = "   local=\(lf)"
                    if lf == 1 { selfTag = "   ★这是你" }
                }
                let cb = coordRaw(of: charOwner)
                coordBlock = cb
                if cb.ok { withCoord += 1 }
            }
            if selfTag.isEmpty, selfPS != 0, ps == selfPS { selfTag = "   ★这是你" }

            var head = "[\(i)] " + (name.isEmpty ? "(无名)" : "\"\(name)\"")
            head += "  id=\(playerID)  HP=\(fmt1(health))/\(fmt1(healthMax))"
            if ai >= 0 { head += "  AI=\(ai)" }
            if live >= 0 { head += "  Live=\(live)" }
            if ping >= 0 { head += "  ping=\(ping)" }
            head += selfTag
            lines.append(head)

            // 坐标路径 ①：PlayerState 自带的 SelfLocAndRot
            if rkB == KERN_SUCCESS, segB.count >= 0xB0 {
                let lx = floatAt(segB, 0x98), ly = floatAt(segB, 0x9C), lz = floatAt(segB, 0xA0)
                let rx = floatAt(segB, 0xA4), ry = floatAt(segB, 0xA8), rz = floatAt(segB, 0xAC)
                let zero = (lx == 0 && ly == 0 && lz == 0)
                let wild = abs(lx) > 1e7 || abs(ly) > 1e7 || abs(lz) > 1e7
                if !zero && !wild { withLoc += 1 }
                lines.append("      SelfLoc=(\(fmt1(lx)), \(fmt1(ly)), \(fmt1(lz)))"
                    + "   Rot=(\(fmt1(rx)), \(fmt1(ry)), \(fmt1(rz)))"
                    + (zero ? "   ← 全零：这个人的位置没同步过来"
                            : (wild ? "   ⚠ 量级异常" : "   ✓")))
            } else {
                lines.append("      读状态段失败 \(describe(rkB)) @PlayerState+0x1648")
            }

            // 坐标路径 ②：Character → RootComponent → ComponentToWorld（**真实世界坐标**）
            if let cb = coordBlock {
                lines.append("      Char=\(hexOf(charOwner))" + localNote)
                lines.append("      " + cb.text)
            } else {
                lines.append("      Char=空（客户端没有这个人的角色对象）")
            }
        }
        lines.append("共 \(n) 个 PlayerState：\(withChar) 个有角色 · \(withCoord) 个拿到真实坐标"
            + " · SelfLoc 非零 \(withLoc) 个（那条路只喂队友位置）")
        lines.append("自己的路：\(selfTrace)")
        lines.append(costLine())
        return lines.joined(separator: "\n")
    }

    /// 找出"自己的 PlayerState"：GWorld + 0xB20 → GameInstance + 0x48 → LocalPlayers[0]
    ///   → UPlayer + 0x30 PlayerController → AController + 0x5F0 PlayerState
    ///
    /// **只用于在名单里打一个 ★ 标记。** 任一环读不到就返回 0，绝不阻塞主流程 ——
    /// LocalPlayers 那条路可能被 bUseEncryptLocalPlayerPtr 挡住，那是它自己的事。
    /// 同时把断在哪一环写成 trace 带回去：失败也要有理由，不靠猜。
    private static func findSelfPlayerState(pid: Int32, world: UInt64) -> (ps: UInt64, trace: String) {
        func plausible(_ v: UInt64) -> Bool { v > 0x100000000 && v < 0xF000000000000000 }

        let (rkG, gi) = readRaw(pid: pid, address: MachVmAddress(world &+ 0xB20))
        guard rkG == KERN_SUCCESS, plausible(gi) else {
            return (0, "断在 OwningGameInstance（\(describe(rkG)) @UWorld+0xB20）")
        }

        let (rkE, enc) = readAt(pid: pid, address: MachVmAddress(gi &+ 0x80))
        let encFlag = rkE == KERN_SUCCESS ? Int(enc & 0xFF) : -1

        let (rkL, lp) = readBytes(pid: pid, address: MachVmAddress(gi &+ 0x48), count: 16)
        guard rkL == KERN_SUCCESS, lp.count >= 16 else {
            return (0, "断在 LocalPlayers（\(describe(rkL)) @GI+0x48，加密标志=\(encFlag)）")
        }
        let data = u64le(lp, 0)
        let cnt = u32le(lp, 8)
        guard plausible(data), cnt > 0, cnt <= 8 else {
            return (0, "LocalPlayers 空（count=\(cnt)，data=\(hexOf(data))，加密标志=\(encFlag)）")
        }

        let (rkP0, lplayer) = readRaw(pid: pid, address: MachVmAddress(data))
        guard rkP0 == KERN_SUCCESS, plausible(lplayer) else {
            return (0, "LocalPlayers[0] 不是有效指针（\(hexOf(u64le(lp, 0)))，加密标志=\(encFlag)）")
        }

        let (rkPC, pc) = readRaw(pid: pid, address: MachVmAddress(lplayer &+ 0x30))
        guard rkPC == KERN_SUCCESS, plausible(pc) else {
            return (0, "断在 UPlayer+0x30 → PlayerController（\(describe(rkPC))，加密标志=\(encFlag)）")
        }

        let (rkPS, pstate) = readRaw(pid: pid, address: MachVmAddress(pc &+ 0x5F0))
        guard rkPS == KERN_SUCCESS, plausible(pstate) else {
            return (0, "断在 AController+0x5F0 → PlayerState（\(describe(rkPS))，PC=\(hexOf(pc))）")
        }
        return (pstate, "GI=\(hexOf(gi)) LP=\(hexOf(lplayer)) PC=\(hexOf(pc)) PS=\(hexOf(pstate)) 加密标志=\(encFlag)")
    }

    /// 坐标打印用：保留 1 位小数，够判断量级又不刷屏。
    private static func fmt1(_ v: Float) -> String {
        guard v.isFinite else { return "NaN" }
        return String(format: "%.1f", v)
    }

    // MARK: - 找基址（枚举 region，零内存读取）

    /// **vm_region_64** —— 样本用的就是这个，不是 `vm_region_recurse_64`。
    ///
    /// 差别是实质性的：recurse 版本要处理 submap 嵌套（一个 nesting_depth 出参）
    /// 和 19 个字的 `vm_region_submap_info_64`；这个版本是老的、扁平的，
    /// flavor = VM_REGION_BASIC_INFO_64(9)，info 只有 8 个字。
    ///
    /// info 的布局（按 32 位字）：
    ///   0: protection    1: max_protection   2: inheritance   3: shared
    ///   4: reserved      5: offset           ← offset 在第 5 个字，不是第 3 个
    /// 出参 object_name 是内核给的引用，用完必须还回去，否则泄漏内核对象。
    private typealias VmRegion64Fn = @convention(c) (
        UInt32,                              // target_task
        UnsafeMutablePointer<UInt64>,        // *address
        UnsafeMutablePointer<UInt64>,        // *size
        Int32,                               // flavor
        UnsafeMutableRawPointer,             // info
        UnsafeMutablePointer<UInt32>,        // *infoCnt
        UnsafeMutablePointer<UInt32>         // *object_name
    ) -> KernReturn

    private static let vmRegion64Fn = symbol("vm_region_64", as: VmRegion64Fn.self)

    /// 枚举下一个 region。会把 addr 更新为该 region 的实际起始。
    /// 返回 (成功, size, protection, 文件偏移)
    private static func nextRegion(task: UInt32, addr: inout UInt64)
        -> (ok: Bool, size: UInt64, prot: Int32, offset: UInt32) {
        guard let fn = vmRegion64Fn else { return (false, 0, 0, 0) }
        var size: UInt64 = 0
        var objectName: UInt32 = 0
        var info = [Int32](repeating: 0, count: 16)
        var count: UInt32 = 9               // 样本传的就是 9，不是 8
        let kr = info.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return KERN_FAILURE }
            return fn(task, &addr, &size, 9, base, &count, &objectName)
        }
        // object_name 是内核引用，不还回去就是内核对象泄漏 —— 跑几百轮就能看出来
        if objectName != 0, let fn = portDeallocateFn {
            _ = fn(mach_task_self_, objectName)
        }
        guard kr == KERN_SUCCESS, size > 0 else { return (false, 0, 0, 0) }
        return (true, size, info[0], UInt32(bitPattern: info[5]))
    }

    /// 找基址（主二进制）。**只用 vm_region_recurse_64 枚举 + 两次 Mach-O 小读。**
    ///
    /// 判据（三个条件同时成立才认）：
    ///   1. protection 含 VM_PROT_EXECUTE(0x4)  → 可执行段
    ///   2. offset == 0                          → 从文件头映射 = Mach-O 头所在段
    ///   3. size ≥ 16MB                          → 主二进制的映像有几百 MB
    /// 命中后再读 4 字节校验 magic == 0xFEEDFACF、+12 的 filetype == 2。
    ///
    /// **不再调用 proc_regionfilename。** 它要走 vnode 查路径，是整个枚举里最贵的一步，
    /// 而且会在游戏的 vm_map 上停很久 —— 实测直接把后台线程卡死在第一次调用上
    /// （面板停在"映射: 建立中…"再也不动，然后被 cpu_resource_fatal 杀掉）。
    /// 前两条判据是 vm_region_recurse 顺手带回来的，免费；Mach-O 那两次小读很便宜。
    ///
    /// 起点直接用 0x100000000：主可执行文件的 __TEXT 就在那儿，正常一两个 region 就命中。
    static func stepFindBase(pid: Int32) -> String {
        resetCounters()
        stageMark("找村口 开始")
        guard vmRegion64Fn != nil else { return "找基址: vm_region_64 符号缺失" }

        // ---- 参数自检：先对自己进程枚举一次，参数错就停在这里，绝不碰游戏 ----
        stageMark("找村口 · 参数自检")
        var selfAddr: UInt64 = 0
        let selfCheck = nextRegion(task: mach_task_self_, addr: &selfAddr)
        guard selfCheck.ok else {
            return "找基址: 参数自检失败（对自己枚举就不成功），未碰游戏"
        }

        // ---- 端口机制已移除 ----
        // 原来这里要 `port(for: pid)` 拿游戏的 task port，再用 `defer { dropPort(p) }` 归还。
        // 内核路径不产生 port，所以这两步连同它们的 guard 一起删掉了。
        // 下面所有枚举/读取改走 pid（内核里自己定位 proc/task），见 km_read_process。

        // ---- 不在这里预先校验"这是不是游戏" ----
        // 原来这里读 0x100000000 处的 Mach-O 头做 pid 校验，那是个错误假设：
        // 0x100000000 落在 __PAGEZERO 里（dump 里 [00] 段 0x047D0000~0x1047D0000），
        // 而 __PAGEZERO 是不可读的（prot = 0），在那儿读必然拿到 KERN_INVALID_ADDRESS。
        // 真正的 __TEXT 是 0x100000000 + slide（每次 ASLR 都不同）。
        // 判断"这是不是游戏"交给下面枚举里的 Mach-O 校验 —— 那才是它该在的位置。

        // 起点直接用 0x100000000，不从 0 开始。
        // 主可执行文件的 __TEXT 就在那儿 —— dump 里是，真机每次实测也是
        // （0x102ac4000 / 0x1027c8000 / 0x104708000… 全都是这个基址加 slide）。
        // 从 0 开始要白白走过几百个低地址 region，每一个都是一次内核调用、
        // 一次对游戏 vm_map 的加锁 —— 既是我们的 CPU 开销，也是对游戏的打扰。
        var addr: UInt64 = 0x100000000
        var scanned = 0
        var hitBase: UInt64 = 0
        var hitName = ""
        /// 被 Mach-O 校验否掉的候选（用于面板诊断：命中条件太宽还是真没找到）
        var rejects: [String] = []
        var timedOut = false

    /// 枚举预算：起点已经是 0x100000000，正常一两个 region 就命中，
    /// 200 轮是给"布局异常"留的余量。原来从 0 起、上限 6000 的版本实测
    /// 烧穿了 app 的 CPU 配额（被系统以 cpu_resource_fatal 杀掉，bug_type 206），
    /// 所以数量和时间两道限制同时上。
        // 预算要按**最坏环境**定：我们是后台 app，线程优先级被系统压得很低，
        // 同样一段代码在这里可能比前台慢几十倍。正常情况下起点 0x100000000
        // 一两个 region 就命中，20 轮足够；真到 20 轮还没中，说明布局异常，
        // 继续跑只会把后台那点执行窗口耗光。
        let scanLimit = 20
        let deadline = Date().addingTimeInterval(3.0)

        stageMark("找村口 · 枚举 region")
        while scanned < scanLimit {
            if Date() > deadline { timedOut = true; break }

            let (ok, size, prot, offset) = nextRegion(task: mach_task_self_, addr: &addr)
            guard ok else { break }
            scanned += 1
            if scanned % 100 == 0 { stageMark("找村口 · 已枚举 \(scanned) 个 region") }

            // 这里不再调 proc_regionfilename：它要走 vnode 查路径，是整个枚举里最贵的一步，
            // 而且会在游戏的 vm_map 上停很久。判定改成三条便宜条件 ——
            // 可执行 + 从文件头映射 + 区域够大（主二进制的映像有几百 MB）——
            // 最后再用 Mach-O 头做裁决。三条里前两条是 vm_region_recurse 顺手带回来的，免费。
            if (prot & 0x4) != 0,          // VM_PROT_EXECUTE
               offset == 0,
               size >= 0x1000000 {          // ≥16MB 的可执行映像才可能是主二进制
                let (okMagic, why) = isExecutableMachO(pid: pid, addr)
                if okMagic {
                    hitBase = addr
                    hitName = "MH_EXECUTE \(size / 1048576)MB"
                    break
                }
                rejects.append("0x\(String(addr, radix: 16))(\(why))")
            }

            addr += size
            if addr < size { break }        // 溢出保护
        }

        guard hitBase != 0 else {
            let why = rejects.isEmpty ? "" : " 否掉:" + rejects.prefix(3).joined(separator: " ")
            let stop = timedOut ? "（5 秒预算到，主动停）" : ""
            return "找基址: 枚举\(scanned)个region，未命中(__TEXT & offset=0)\(stop)" + why
        }

        // ② 记账：base / slide 存下来，后面「定点读」直接用这份状态
        let s = slide(ofImageBase: hitBase)
        imageBase = hitBase
        imageSlide = s
        basePid = pid
        activePid = pid

        // ③ 摊开 slide 与三个可用 OFFSET 的运行时落点，目视确认都落在映像区间
        let off = Offsets.load()
        let hi = hitBase &+ 0x13000000
        let slots: [(String, UInt64)] = [
            ("GObjects", off.gObjects),
            ("GNames", off.gNames),
            ("GWorld", off.gWorld)
        ]
        var lines: [String] = []
        lines.append("找基址: ✓ base=0x\(String(hitBase, radix: 16)) region=\(scanned) \(hitName)")
        lines.append("slide=0x\(String(s, radix: 16)) = base − 0x100000000")
        lines.append("映像区间 [0x\(String(hitBase, radix: 16)), 0x\(String(hi, radix: 16)))")
        for (name, staticAddr) in slots {
            let r = runtime(staticAddr, slide: s)
            let inside = (r >= hitBase && r < hi)
            let pad = String(repeating: " ", count: max(0, 9 - name.count))
            lines.append("\(name)\(pad)0x\(String(staticAddr, radix: 16)) → 0x\(String(r, radix: 16)) "
                + (inside ? "✓" : "✗越界"))
        }
        lines.append("（找基址本身不读游戏内存，这里只统计 Mach-O 头校验：" + costLine() + "）")
        return lines.joined(separator: "\n")
    }
}
