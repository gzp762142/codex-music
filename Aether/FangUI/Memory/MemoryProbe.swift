import Foundation
import Darwin

/// 读内存探针：**只读**，不写、不 hook、不注入。**只有一条路**。
///
/// ```
/// let fn  = dlsym(RTLD_DEFAULT, "task_for_pid")
/// let tfp = unsafeBitCast(fn, to: TaskForPidFn.self)
/// let kr  = tfp(mach_task_self_, pid, &port)
/// ```
///
/// **绝不使用 syscall()。** `syscall()` 只走 BSD syscall 表，而 task_for_pid 是
/// Mach trap，两套编号互不相通。把 mach trap 号（45）交给 syscall() 会让它按
/// BSD 表跳到第 45 号那个完全不同的调用上 —— 实测直接闪退。
/// 26 同理（BSD 表第 26 号是 ptrace，还有副作用）。
///
/// 这条路如果返回 KERN_FAILURE(5)，那是**权限**问题不是号错：
/// `Music.entitlements` 需要 `task_for_pid-allow`，重签重装后再试。
final class MemoryProbe {

    private typealias MachPort = UInt32
    private typealias KernReturn = Int32
    private typealias MachVmAddress = UInt64
    private typealias MachVmSize = UInt64

    private typealias TaskForPidFn = @convention(c) (MachPort, Int32,
                                                     UnsafeMutablePointer<MachPort>) -> KernReturn
    private typealias VmReadFn = @convention(c) (MachPort, MachVmAddress, MachVmSize,
                                                 UnsafeMutablePointer<UInt>,
                                                 UnsafeMutablePointer<MachVmSize>) -> KernReturn
    private typealias VmDeallocateFn = @convention(c) (MachPort, UInt, MachVmSize) -> KernReturn

    private static func symbol<T>(_ name: String, as: T.Type) -> T? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static let taskForPidFn = symbol("task_for_pid", as: TaskForPidFn.self)

    /// mach_port_deallocate：释放我们自己持有的 port right。
    private typealias PortDeallocateFn = @convention(c) (MachPort, MachPort) -> KernReturn
    private static let portDeallocateFn = symbol("mach_port_deallocate", as: PortDeallocateFn.self)
    /// vm_region_recurse_64：枚举目标地址空间里的 region（**不读内存内容**）。
    ///
    /// 比 mach_vm_region 少一个 flavor 参数、多一个 nesting_depth，
    /// info 是 vm_region_submap_info_64（19 个字）。
    /// 注意：mach_vm_region 因为在它上面配错过参数（count=0 / info 指针类型），
    /// 连崩两次，所以这里在真正枚举目标之前**先对自己进程枚举一次**做参数自检。
    private typealias VmRegionRecurseFn = @convention(c) (
        UInt32,                              // task
        UnsafeMutablePointer<UInt64>,        // &address (in/out)
        UnsafeMutablePointer<UInt64>,        // &size
        UnsafeMutablePointer<UInt32>,        // &nesting_depth
        UnsafeMutableRawPointer,             // info
        UnsafeMutablePointer<UInt32>         // &infoCnt（字数）
    ) -> Int32

    private static let vmRegionRecurseFn = symbol("vm_region_recurse_64", as: VmRegionRecurseFn.self)

    /// proc_regionfilename：问「这个地址属于哪个文件」。
    /// 只要 pid + 地址，不需要 mach_vm_region —— 正好绕开那个我连错两次的调用。
    /// iOS 无 <libproc.h>，符号同样只能 dlsym 取。
    private typealias ProcRegionFileNameFn = @convention(c) (Int32, UInt64, UnsafeMutableRawPointer?, UInt32) -> Int32
    private static let procRegionFileNameFn = symbol("proc_regionfilename", as: ProcRegionFileNameFn.self)

    /// proc_pidpath：只用来问「这个 pid 还在不在」，不碰它的内存。
    private typealias ProcPidPathFn = @convention(c) (Int32, UnsafeMutableRawPointer?, UInt32) -> Int32
    private static let procPidPathFn = symbol("proc_pidpath", as: ProcPidPathFn.self)
    private static let vmReadFn = symbol("mach_vm_read", as: VmReadFn.self)
    private static let vmDeallocateFn = symbol("mach_vm_deallocate", as: VmDeallocateFn.self)


    static var symbolSummary: String {
        let a = taskForPidFn != nil ? "tfp=OK" : "tfp=nil"
        let b = vmReadFn != nil ? "vm_read=OK" : "vm_read=nil"
        let c = vmDeallocateFn != nil ? "vm_dealloc=OK" : "vm_dealloc=nil"
        return "\(a) \(b) \(c)"
    }

    /// 把 kern_return_t 翻成人和自己能读懂的话。
    private static func describe(_ kr: KernReturn) -> String {
        switch kr {
        case KERN_SUCCESS: return "成功"
        case KERN_FAILURE: return "权限被挡 (KERN_FAILURE)"
        case 4: return "参数错 (KERN_INVALID_ARGUMENT)"
        case 2: return "KERN_INVALID_TASK"
        case 3: return "KERN_INVALID_ADDRESS"
        default: return "ret=\(kr)"
        }
    }

    // MARK: - 单步动作

    /// 第 1 步：只解析符号，不调用任何东西。
    /// 只取端口并返回它（**不读任何内存**），供静默测试用。
    /// 返回 nil 表示符号缺失或取端口失败。
    ///
    /// 注意返回值写 UInt32 而不是私有别名 MachPort：
    /// internal 函数的签名不能暴露 private typealias，否则编译报
    /// "method must be declared private because its parameter uses a private type"。
    static func acquirePort(pid: Int32) -> (port: UInt32, note: String)? {
        guard let fn = taskForPidFn else { return nil }
        var port: MachPort = 0
        let kr = fn(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else { return nil }
        return (port, "port=0x\(String(port, radix: 16))")
    }

    /// 第 1 步：只报告符号解析情况，不调用任何东西。
    static func stepSymbols() -> String { symbolSummary }

    /// 第 2 步：只调 libSystem 的 task_for_pid —— 唯一被允许的取端口方式。
    /// 不用 syscall：syscall() 只走 BSD 表，Mach trap 号交给它会跳到别的调用上。
    static func stepDlsym(pid: Int32) -> String {
        guard let fn = taskForPidFn else { return "dlsym: 符号缺失" }
        var port: MachPort = 0
        let kr = fn(mach_task_self_, pid, &port)
        defer { dropPort(port) }
        if kr == KERN_SUCCESS, port != 0 {
            return "dlsym: 成功 port=0x\(String(port, radix: 16))"
        }
        return "dlsym: \(describe(kr))"
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
    /// 真正落回 mach_vm_read 的次数 —— **这个才是成本**。
    private static var vmReadCalls = 0
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

    private typealias MachVmRemapFn = @convention(c) (
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

    private static let machVmRemapFn = symbol("mach_vm_remap", as: MachVmRemapFn.self)

    /// 已经建立起来的映射：游戏地址 → 我们的本地地址。
    private static var mappedRanges: [(gameBase: UInt64, size: UInt64, localBase: UInt64)] = []
    /// mappedRanges 是否已按 gameBase 排好序 —— localAddress 走二分，靠这个标志决定先不先排。
    private static var rangesSorted = true

    private static let vmFlagsAnywhere: Int32 = 0x0001

    /// 把游戏的一段内存**映射进我们自己的地址空间**。
    ///
    /// 这是样本（Music）用的原语，也是我们必须换过去的那一步：
    ///
    ///   `mach_vm_read`  每次都要进内核、抢游戏 vm_map 的**读锁**、再拷一份出来。
    ///   `mach_vm_remap` 只在**建立映射**时进一次内核，之后读数据就是普通内存访问
    ///                   —— 零内核调用、零锁、零拷贝。
    ///
    /// 游戏的 vm_map 锁是读写互斥的：它主线程每帧写坐标拿写锁，我们每读一次拿一次读锁，
    /// 两者不能同时进行。映射建立之后我们不再碰它的 map，读的是自己的页表。
    ///
    /// `copy = TRUE` 是写时复制 —— 我们只读，永远不会改到游戏的页。
    static func mapRange(pid: Int32, srcAddress: UInt64, size: UInt64) -> (local: UInt64, note: String) {
        guard let fn = machVmRemapFn else { return (0, "mach_vm_remap 符号缺失") }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return (0, "取端口失败 \(describe(kr))") }
        defer { dropPort(p) }

        // iOS 上物理页是 16KB，映射必须页对齐
        let pageSize: UInt64 = 0x4000
        let alignedStart = srcAddress & ~(pageSize - 1)
        let head = srcAddress - alignedStart
        let total = (head + size + pageSize - 1) & ~(pageSize - 1)

        var target: UInt64 = 0
        var curProt: Int32 = 0
        var maxProt: Int32 = 0
        let rk = fn(mach_task_self_, &target, total, 0, vmFlagsAnywhere,
                    p, alignedStart, 1, &curProt, &maxProt, 0)
        guard rk == KERN_SUCCESS, target != 0 else {
            return (0, "mach_vm_remap 失败 \(describe(rk))")
        }
        mappedRanges.append((alignedStart, total, target))
        rangesSorted = false
        return (target + head,
                "映射 0x\(String(alignedStart, radix: 16)) +0x\(String(total, radix: 16)) → 本地 0x\(String(target, radix: 16))")
    }

    /// 本地地址 → 游戏地址：查已建立的映射。
    /// 命中就说明这块内存已经在我们自己地址空间里，读它不需要任何内核调用。
    static func localAddress(for gameAddress: UInt64) -> UInt64? {
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
                return m.localBase &+ (gameAddress &- m.gameBase)
            }
        }
        return nil
    }

    /// 当前会话的 pid —— 按需映射时要用它取端口。
    private(set) static var activePid: Int32 = 0

    /// 绑定本次操作的目标进程。**每个动作开始前都要调** ——
    /// 上一版只在「找村口」/「映射」里绑定，于是直接点「对象」时 activePid 还是 0，
    /// 按需映射那段判断被跳过，读取全部退回 mach_vm_read（实测 38 次调用）。
    /// pid 变了说明游戏重启过，旧的映射和基址一起作废。
    static func bind(pid: Int32) {
        guard activePid != pid else { return }
        activePid = pid
        mappedRanges.removeAll()
        rangesSorted = true
        imageBase = 0
        imageSlide = 0
        basePid = 0
    }

    /// 把**包含 address 的那个 region** 整个映射进来。
    ///
    /// vm_region_64 从 address 起枚举时会直接返回包含它的那个 region（地址会被写回
    /// region 起始），所以这里一次枚举 + 一次映射就够 —— 不需要从头扫地址空间。
    @discardableResult
    static func mapRegionContaining(pid: Int32, address: UInt64) -> String {
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        var addr: UInt64 = address
        let (ok, size, _, _) = nextRegion(task: p, addr: &addr)
        guard ok else { return "枚举失败 @0x\(String(address, radix: 16))" }
        guard address >= addr, address < addr &+ size else {
            return "0x\(String(address, radix: 16)) 不在返回的 region(0x\(String(addr, radix: 16)) +0x\(String(size, radix: 16))) 里"
        }
        let (local, note) = mapRange(pid: pid, srcAddress: addr, size: size)
        return local != 0 ? note : note
    }

    /// 把游戏进程里**所有值得映射的大 region** 一次性映射进来。
    ///
    /// 为什么必须批量：`readSmart` 的按需映射每次要花 1 次 `vm_region_64` + 1 次
    /// `vm_remap` —— 两次都是内核调用，都要在游戏的 vm_map 上取锁。遍历整张 actor 表
    /// （几千个对象，散落在几百个 region 里）时块数很快撞上上限，**剩下的读全部退化成
    /// `mach_vm_read`**，而那正是实测会把游戏读崩的那条路（阈值 128 次）。
    /// 上一版就是这么崩的 —— 不是「读得多」崩，是「没映射上的读」崩。
    ///
    /// 批量映射的代价只有「region 数量」次 vm_remap，之后每次读都是我们自己的页表访问。
    /// 虚拟地址不心疼（64 位有 128TB），物理页按需 fault —— 只在我们真正碰到的页上分配。
    ///
    /// 三条自我约束：只映射 ≥ minSize 的块（避开碎片）、硬性时间预算、每若干轮确认目标还活着。
    @discardableResult
    static func mapAllRegions(pid: Int32, minSize: UInt64 = 256 << 10,
                              budget: TimeInterval = 2.5, maxBlocks: Int = 600) -> String {
        guard let fn = machVmRemapFn else { return "预映射: mach_vm_remap 符号缺失" }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "预映射: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let deadline = Date().addingTimeInterval(budget)
        let pageSize: UInt64 = 0x4000
        var probe: UInt64 = 0x100000000
        var mapped = 0
        var skipped = 0
        var failed = 0
        var bytes: UInt64 = 0
        var rounds = 0

        while rounds < 800, mapped < maxBlocks {
            if Date() > deadline { break }
            if rounds % 64 == 0, !targetAlive(pid) { break }
            rounds += 1

            let ask = probe
            let (ok, size, prot, _) = nextRegion(task: p, addr: &probe)
            guard ok, size > 0 else { break }
            let start = probe                      // nextRegion 会把 probe 写成 region 起始
            let next = start &+ size
            guard next > ask else { break }        // 防死循环
            probe = next

            guard (prot & 0x1) != 0, size >= minSize else { skipped += 1; continue }
            if localAddress(for: start) != nil { continue }

            // 映射内联在这里，复用同一个 task port —— mapRange 每次都重新 task_for_pid，
            // 那本身也是一次内核往返，批量做几百次不该这么花。
            let aligned = start & ~(pageSize - 1)
            let total = (start - aligned + size + pageSize - 1) & ~(pageSize - 1)
            var target: UInt64 = 0
            var curProt: Int32 = 0
            var maxProt: Int32 = 0
            let rk = fn(mach_task_self_, &target, total, 0, vmFlagsAnywhere,
                        p, aligned, 1, &curProt, &maxProt, 0)
            if rk == KERN_SUCCESS, target != 0 {
                mappedRanges.append((aligned, total, target))
                rangesSorted = false
                mapped += 1
                bytes += total
            } else {
                failed += 1
            }
        }
        if !rangesSorted {
            mappedRanges.sort { $0.gameBase < $1.gameBase }
            rangesSorted = true
        }

        let mb = String(format: "%.0f", Double(bytes) / 1048576.0)
        return "预映射: \(mapped) 块 / \(mb) MB（扫 \(rounds) 个 region，跳过小块 \(skipped)，失败 \(failed)）"
    }

    /// 已建立的映射块数 —— 调用方用它判断"要不要先预映射一轮"。
    static var mappedBlockCount: Int { mappedRanges.count }

    /// 真正落回 mach_vm_read 的次数。遍历类操作要盯着这个数，超预算就该收手。
    static var hardReadCalls: Int { vmReadCalls }


    /// **映射优先的读**：命中已建立的映射就本地读（零内核调用）；
    /// 没命中就按需把那一块映射进来再读；映射也失败才退回 mach_vm_read。
    ///
    /// 这是整个方案的核心。`mach_vm_read` 每次都要进内核、抢游戏 vm_map 的读锁，
    /// 而我们读的每个字段都是一次这样的操作；映射之后读数据就是普通内存访问。
    ///
    /// **块数上限从 24 提到 512**：原来那个 24 是按「点读几个字段」估的，遍历整张对象表
    /// 时远远不够，一撞上限剩下的读全变成 mach_vm_read —— 那就是崩游戏的那条路。
    /// 正常路径是先用 mapAllRegions 把大块一次性铺好，这里只是兜底。
    private static func readSmart(port: MachPort, address: MachVmAddress, count: Int) -> (KernReturn, [UInt8]) {
        let n = max(count, 1)
        guard n <= 0x10000 else { return (KERN_FAILURE, []) }

        if let local = localAddress(for: address), local != 0 {
            noteRead()
            mappedHits += 1
            if let base = UnsafeRawPointer(bitPattern: UInt(local)) {
                return (KERN_SUCCESS, Array(UnsafeRawBufferPointer(start: base, count: n)))
            }
        }

        // 没命中：按需映射一次（块数设上限，避免地图无限膨胀）
        if activePid != 0, mappedRanges.count < 2048 {
            let before = mappedRanges.count
            mapRegionContaining(pid: activePid, address: address)
            if mappedRanges.count > before { onDemandMaps += 1 }
            if let local = localAddress(for: address), local != 0 {
                noteRead()
                mappedHits += 1
                if let base = UnsafeRawPointer(bitPattern: UInt(local)) {
                    return (KERN_SUCCESS, Array(UnsafeRawBufferPointer(start: base, count: n)))
                }
            }
        }

        noteRead()
        vmReadCalls += 1
        return readBytesDirect(port: port, address: address, count: n)
    }

    /// 读一段字节：**优先走已建立的映射**，没命中就让 readSmart 按需映射。
    /// 原来这里直接就是 mach_vm_read —— 所有调用点现在自动升级成映射优先。
    private static func readBytes(port: MachPort, address: MachVmAddress, count: Int)
        -> (KernReturn, [UInt8]) {
        readSmart(port: port, address: address, count: count)
    }

    static var mappedSummary: String {
        mappedRanges.isEmpty ? "无映射" : "\(mappedRanges.count) 块"
    }

    /// 从已映射的本地内存读，**零内核调用**。
    /// 只有确认过地址落在映射区间内才允许调用 —— 传错地址会直接让我们自己 SIGSEGV。
    private static func readMapped(_ localAddr: UInt64, _ count: Int) -> [UInt8] {
        guard count > 0, count <= 4096 else { return [] }
        guard let base = UnsafeRawPointer(bitPattern: UInt(localAddr)) else { return [] }
        return Array(UnsafeRawBufferPointer(start: base, count: count))
    }

    /// 每次动作开头清零。
    private static func resetCounters() {
        probeCalls = 0
        mappedHits = 0
        vmReadCalls = 0
        onDemandMaps = 0
    }

    /// 本次动作的成本。**只看 mach_vm_read 那一项** —— 映射命中是本地内存读，
    /// 不产生内核调用，也就没有成本。之前这里只报 probeCalls（读取总次数），
    /// 文案却写成"次 mach_vm_read"，把完全不同的两件事混成了一个数。
    private static func costLine() -> String {
        "读取 \(probeCalls) 次 · 映射命中 \(mappedHits) · 按需映射 \(onDemandMaps) 块 · "
            + "mach_vm_read \(vmReadCalls) 次"
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

    /// 当前阶段：后台线程写、UI 轮询读 —— 面板上能实时看到走到哪一步。
    /// 加锁是因为它跨线程：`String` 是值类型，无锁并发读写可能读到撕裂的值。
    private static let stageLock = NSLock()
    private static var _currentStage = ""

    static var currentStage: String {
        stageLock.lock()
        defer { stageLock.unlock() }
        return _currentStage
    }

    /// 标记当前步骤：一份进内存（UI 实时看），一份**异步**落盘。
    ///
    /// 落盘必须异步 —— 它是给"崩了之后回查"用的，绝不能反过来拖住调用它的读取线程。
    /// 一旦文件 I/O 卡住，整个读取链就停在原地，而面板上只会看到进度停在第一步
    /// （实测就是这样：状态停在 "映射: 建立中…"，后台却一步都没往下走）。
    private static let stageQueue = DispatchQueue(label: "aether.stage", qos: .userInitiated)

    /// 进度回调：由调用方（UI）挂上来。
    ///
    /// 为什么要这条线：进度原本是"写内存 + 主线程 Timer 轮询显示"。
    /// 主线程一卡（任何一处内核调用堵住它），Timer 就停止触发，面板会永远停在
    /// 最后一个值上 —— 看起来像"卡在第一步"，其实可能早就走远了，也可能主线程自己
    /// 卡住了，两种情况在屏幕上长得一模一样。回调这条路由后台直接把每一步推给 UI，
    /// 不依赖 Timer，也不依赖主线程还在正常跑。
    static var onStage: ((String) -> Void)?

    /// 标记当前步骤。**只写内存 + 推 UI，一个文件系统调用都不做。**
    ///
    /// 这里原来还有一份同步落盘（给"崩溃后回查"用）。实测它把整条链卡死了：
    /// 面板停在 `枚举 · A 函数已进入` 再也不动 —— `_currentStage` 在函数开头就写好了
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
        stageLock.lock()
        _currentStage = stage
        stageLock.unlock()

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
    private static func readText(port: MachPort, addr: UInt64, maxChars: Int = 24) -> String {
        let (rk, hdr) = readBytes(port: port, address: MachVmAddress(addr), count: 16)
        guard rk == KERN_SUCCESS, hdr.count >= 16 else { return "" }
        let data = u64le(hdr, 0)
        let num = Int(u32le(hdr, 8))
        guard data > 0x100000000, num > 1, num <= 256 else { return "" }

        let n = min(num, maxChars)
        let (rk2, raw) = readBytes(port: port, address: MachVmAddress(data), count: n * 4)
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

    /// 按绝对地址读 4 字节。**只有 3 个参数**。
    /// mach_vm_region 那条路已被删除：它有两个出参，是之前连续出错的来源，
    /// 而读内存根本不需要枚举内存区。
    private static func readAt(port: MachPort, address: MachVmAddress) -> (KernReturn, UInt32) {
        let (kr, bytes) = readSmart(port: port, address: address, count: 4)
        guard kr == KERN_SUCCESS, bytes.count >= 4 else { return (kr, 0) }
        let v = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8)
            | (UInt32(bytes[2]) << 16) | (UInt32(bytes[3]) << 24)
        return (KERN_SUCCESS, v)
    }

    /// 按绝对地址读 8 字节 —— 只给值，供程序判断用。
    private static func readRaw(port: MachPort, address: MachVmAddress) -> (KernReturn, UInt64) {
        let (kr, bytes) = readSmart(port: port, address: address, count: 8)
        guard kr == KERN_SUCCESS, bytes.count >= 8 else { return (kr, 0) }
        return (KERN_SUCCESS, u64le(bytes, 0))
    }

    /// 读一段连续字节（**上限 4096**）。
    ///
    /// 这是唯一允许的块读取，硬上限就卡在 4096：之前用 16KB 步进扫内存
    /// 把目标进程搞成过 jetsam 被杀，连续 fault 太多页是死因。
    private static func readBytesDirect(port: MachPort, address: MachVmAddress, count: Int)
        -> (KernReturn, [UInt8]) {
        guard let vmRead = vmReadFn else { return (KERN_FAILURE, []) }
        guard count > 0, count <= 4096 else { return (KERN_FAILURE, []) }
        noteRead()
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = MachVmSize(count)
        let kr = vmRead(port, address, MachVmSize(count), &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen > 0 else { return (kr, []) }
        let n = min(Int(dataLen), count)
        var out = [UInt8](repeating: 0, count: n)
        if let src = UnsafeRawPointer(bitPattern: dataPtr) {
            out.withUnsafeMutableBytes { dst in
                if let d = dst.baseAddress {
                    d.copyMemory(from: src, byteCount: n)
                }
            }
        }
        _ = vmDeallocateFn?(port, dataPtr, dataLen)
        return (KERN_SUCCESS, out)
    }

    /// 给面板用的指针解读：值 + 是否像有效指针 + 高位（便于看落在哪个地址段）。
    private static func pointerInfo(port: MachPort, address: MachVmAddress)
        -> (KernReturn, UInt64, Bool, String) {
        let (kr, value) = readRaw(port: port, address: address)
        guard kr == KERN_SUCCESS else { return (kr, 0, false, "n/a") }
        // iOS arm64 用户态地址是 36 位宽
        let looksReal = value >= 0x100000000 && value < 0x10000000000
        let hi = String(format: "%04llx", (value >> 32) & 0xFFFF)
        return (KERN_SUCCESS, value, looksReal, hi)
    }

    /// 取目标进程的 task port。
    private static func port(for pid: Int32) -> (KernReturn, MachPort) {
        guard let tfp = taskForPidFn else { return (KERN_FAILURE, 0) }
        var p: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &p)
        return (kr, p)
    }

    /// 释放一个 task port。
    ///
    /// **每次 `task_for_pid` 都会新建一个 send right**，不释放就一直累积。
    /// 之前的版本从来没释放过：每点一次按钮泄漏一个 right，而每个 right 都让
    /// 游戏的 task 对象多背一个引用 —— 游戏崩掉之后那个 task 对象也回收不掉，
    /// 反复"崩→重开→读"会把内核里堆一串收不掉的 task。
    /// 取端口的地方一律用 `defer { dropPort(p) }` 配对。
    private static func dropPort(_ p: MachPort) {
        guard p != 0, let fn = portDeallocateFn else { return }
        _ = fn(mach_task_self_, p)
    }

    /// 给面板调用方用的释放入口（SilentProbe 这类需要跨回调持有端口的场景）。
    static func releasePort(_ p: UInt32) {
        dropPort(MachPort(p))
    }

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
    private static func isExecutableMachO(port: MachPort, _ addr: UInt64) -> (Bool, String) {
        let (rk1, magic) = readAt(port: port, address: MachVmAddress(addr))
        guard rk1 == KERN_SUCCESS else { return (false, "magic读失败/\(rk1)") }
        guard magic == 0xFEEDFACF else { return (false, "magic=0x\(String(magic, radix: 16))") }
        let (rk2, filetype) = readAt(port: port, address: MachVmAddress(addr &+ 12))
        guard rk2 == KERN_SUCCESS else { return (false, "filetype读失败/\(rk2)") }
        guard filetype == 2 else { return (false, "filetype=\(filetype)") }
        return (true, "MH_EXECUTE")
    }

    // MARK: - 面板动作

    /// 读证：在 dump 记录的模块基址处读 Mach-O 头。
    /// 一次读取，不扫描 —— 扫大范围是之前出问题的来源。
    static func stepReadProof(pid: Int32) -> String {
        let off = Offsets.load()
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "读证: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let (rk, magic) = readAt(port: p, address: MachVmAddress(off.moduleBase))
        guard rk == KERN_SUCCESS else {
            return "读证: 读 0x\(String(off.moduleBase, radix: 16)) 失败 \(describe(rk))"
        }
        let isMachO = (magic == 0xFEEDFACF)
        return "读证: 0x\(String(off.moduleBase, radix: 16)) magic=0x\(String(magic, radix: 16)) "
            + (isMachO ? "是Mach-O(基址正确,读通)" : "不是Mach-O(基址被ASLR搬了)")
    }

    /// 定点读：**第一次真实点读**，全部加起来约 20 字节，不写循环、不做扫描。
    ///
    /// ```
    /// slot = runtime(OFFSET_GOBJECTS)     // FUObjectArray
    /// slot + 0x118 → NumElements (UInt32)
    /// slot + 0xE0  → chunk0      (UInt64)
    /// chunk0       → 第一个 FUObjectItem 的 Object (UInt64, FUObjectItem::Object = 0)
    /// ```
    ///
    /// 验收：NumElements 是六位数（10 万 ~ 200 万）即表示 image base 与换算公式同时正确。
    /// 前提：先点过「找村口」—— base/slide 存在这份 static 状态里，不跨进程启动保留。
    static func stepFixedRead(pid: Int32) -> String {
        resetCounters()
        stageMark("定点读")
        guard baseReady(for: pid) else {
            return "定点读: 没有当前进程的基址 —— 先点「找村口」"
        }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "定点读: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let off = Offsets.load()
        let slot = runtime(off.gObjects, slide: s)

        // ① NumElements（UInt32）—— 唯一的验收数字
        let (rkNum, num) = readAt(port: p, address: MachVmAddress(slot &+ 0x118))
        guard rkNum == KERN_SUCCESS else {
            return "定点读: NumElements 读失败 \(describe(rkNum)) @0x\(String(slot &+ 0x118, radix: 16))"
        }
        // ② chunk0 指针（UInt64）
        let (rkChunk, chunk0) = readRaw(port: p, address: MachVmAddress(slot &+ 0xE0))
        // ③ 第一个 FUObjectItem 的 Object（UInt64）
        var obj0: UInt64 = 0
        var objNote = ""
        if rkChunk == KERN_SUCCESS, chunk0 != 0 {
            let (rkObj, v) = readRaw(port: p, address: MachVmAddress(chunk0))
            if rkObj == KERN_SUCCESS {
                obj0 = v
            } else {
                objNote = "obj0 读失败 \(describe(rkObj))"
            }
        } else {
            objNote = "chunk0 读失败 \(describe(rkChunk))"
        }

        let n = Int(num)
        let hit = (n >= 100_000 && n <= 2_000_000)
        var lines: [String] = []
        lines.append("定点读: NumElements=\(n) " + (hit ? "✓ 命中（六位数）" : "✗ 数量异常"))
        lines.append("base=0x\(String(imageBase, radix: 16)) slide=0x\(String(s, radix: 16))")
        lines.append("slot=0x\(String(slot, radix: 16)) = slide + OFFSET_GOBJECTS")
        lines.append(rkChunk == KERN_SUCCESS
            ? "chunk0=0x\(String(chunk0, radix: 16))"
            : "chunk0 读失败 \(describe(rkChunk))")
        lines.append(objNote.isEmpty
            ? "obj0=0x\(String(obj0, radix: 16))" + (obj0 == 0 ? "（空槽）" : "")
            : objNote)
        if !hit {
            // 数值异常时把两种病因分开：base/slide 错，还是字段偏移错。
            let hi = imageBase &+ 0x13000000
            let slotInRange = (slot >= imageBase && slot < hi)
            let chunkLooksHeap = (chunk0 >= 0x120000000 && chunk0 < 0x140000000)
            lines.append("诊断: slot" + (slotInRange
                ? " 在映像区间内 → base/slide 对得上，可疑点转到字段偏移 0x118/0xE0"
                : " 不在映像区间 → base 或换算公式错"))
            lines.append("诊断: chunk0" + (chunkLooksHeap
                ? " 像堆指针（0x12xxxxxxx 段）"
                : " 不像堆指针（不落在 0x120000000~0x140000000）"))
        }
        lines.append(costLine())
        return lines.joined(separator: "\n")
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
    private static func readNameDetail(port: MachPort, entry: UInt64) -> (name: String, width: String) {
        let (rk, bytes) = readBytes(port: port,
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
    private static func readName(port: MachPort, entry: UInt64) -> String {
        readNameDetail(port: port, entry: entry).name
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
            return "GNames: 没有当前进程的基址 —— 先点「找村口」"
        }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "GNames: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let slotAddr = runtime(Offsets.load().gNames, slide: s)

        // ① 槽 → 名字池
        stageMark("名字 · 读池槽")
        let (rkPool, pool) = readRaw(port: p, address: MachVmAddress(slotAddr))
        guard rkPool == KERN_SUCCESS, pool != 0 else {
            return "GNames: 槽 0x\(String(slotAddr, radix: 16)) 读失败 \(describe(rkPool))"
        }

        var lines: [String] = []
        lines.append("GNames: 槽 0x\(String(slotAddr, radix: 16)) → pool=0x\(String(pool, radix: 16))")

        // ② 池头 hex：先看清布局，再决定解哪一层
        stageMark("名字 · 读池头")
        let (rkHead, head) = readBytes(port: p, address: MachVmAddress(pool), count: 0x40)
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
        let (rkA, lvlA) = readRaw(port: p, address: MachVmAddress(pool))
        let (rkB, lvlB) = (rkA == KERN_SUCCESS)
            ? readRaw(port: p, address: MachVmAddress(lvlA))
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
                let (rke, entry) = readRaw(port: p, address: MachVmAddress(chunk &+ UInt64(i) * 8))
                guard rke == KERN_SUCCESS, entry != 0 else {
                    names.append("(失败)")
                    detail.append("   [\(i)] 取 entry 失败 \(describe(rke))")
                    continue
                }
                let (nm, width) = readNameDetail(port: p, entry: entry)
                names.append(nm)
                // entry 自报的索引（dump: FNameEntry::Index = 0x8）：
                // 名字若带 "_0" 之类的后缀，看这行就知道索引基准偏了多少
                let (rkIdx, idxV) = readAt(port: p, address: MachVmAddress(entry &+ 0x8))
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
    private static func resolveName(port: MachPort, pool: UInt64, chunk0: UInt64, index: UInt32) -> String {
        let k = UInt64(index) / namesPerChunk
        let within = UInt64(index) % namesPerChunk
        var chunk = chunk0
        if k != 0 {
            let (rkC, c) = readRaw(port: port, address: MachVmAddress(pool &+ k * 8))
            guard rkC == KERN_SUCCESS, c != 0 else { return "(chunk\(k)读失败 \(describe(rkC)))" }
            chunk = c
        }
        let (rkE, entry) = readRaw(port: port, address: MachVmAddress(chunk &+ within * 8))
        guard rkE == KERN_SUCCESS, entry != 0 else { return "(entry读失败 \(describe(rkE)))" }
        return readName(port: port, entry: entry)
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
            return "对象: 没有当前进程的基址 —— 先点「找村口」"
        }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "对象: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let off = Offsets.load()

        // 名字池（布局已由「名字」按钮验收确认：一层，pool+0 就是 chunk0）
        let (rkPool, pool) = readRaw(port: p, address: MachVmAddress(runtime(off.gNames, slide: s)))
        guard rkPool == KERN_SUCCESS, pool != 0 else {
            return "对象: 名字池槽读取失败 \(describe(rkPool))"
        }
        let (rkChunk, nameChunk0) = readRaw(port: p, address: MachVmAddress(pool))
        guard rkChunk == KERN_SUCCESS, nameChunk0 != 0 else {
            return "对象: 名字池 chunk0 读取失败 \(describe(rkChunk))"
        }

        // 对象表头
        let slot = runtime(off.gObjects, slide: s)
        let (rkNum, num) = readAt(port: p, address: MachVmAddress(slot &+ 0x118))
        guard rkNum == KERN_SUCCESS else { return "对象: NumElements 读失败 \(describe(rkNum))" }
        let (rkItems, items) = readRaw(port: p, address: MachVmAddress(slot &+ 0xE0))
        guard rkItems == KERN_SUCCESS, items != 0 else {
            return "对象: items 指针读失败 \(describe(rkItems))"
        }

        // ① items 数组一次读完：逐项读是 16 次 mach_vm_read，数据在同一页，
        //    调用次数与内核里的 copy 分配却翻 16 倍，没有意义。
        let listCount = min(Int(num), 16)
        let (rkBuf, buf) = readBytes(port: p, address: MachVmAddress(items), count: listCount * 0x18)
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
            let (rkCls, cls) = readRaw(port: p, address: MachVmAddress(obj &+ 0x10))
            let (rkName, nameIX) = readAt(port: p, address: MachVmAddress(obj &+ 0x18))
            let (rkNo, number) = readAt(port: p, address: MachVmAddress(obj &+ 0x1C))

            var clsName = "类名?"
            if rkCls == KERN_SUCCESS, cls != 0 {
                let (rkCIX, clsIX) = readAt(port: p, address: MachVmAddress(cls &+ 0x18))
                if rkCIX == KERN_SUCCESS {
                    clsName = resolveName(port: p, pool: pool, chunk0: nameChunk0, index: clsIX)
                } else {
                    clsName = "类名读失败 \(describe(rkCIX))"
                }
            } else if rkCls != KERN_SUCCESS {
                clsName = "Class读失败 \(describe(rkCls))"
            }

            var objName = "名字?"
            if rkName == KERN_SUCCESS {
                objName = resolveName(port: p, pool: pool, chunk0: nameChunk0, index: nameIX)
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
            return "世界: 没有当前进程的基址 —— 先点「找村口」"
        }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "世界: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

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
        let (rkPool, pool) = readRaw(port: p, address: MachVmAddress(runtime(off.gNames, slide: s)))
        guard rkPool == KERN_SUCCESS, pool != 0 else {
            return "世界: 名字池槽读取失败 \(describe(rkPool))"
        }
        let (rkChunk, nameChunk0) = readRaw(port: p, address: MachVmAddress(pool))
        guard rkChunk == KERN_SUCCESS, nameChunk0 != 0 else {
            return "世界: 名字池 chunk0 读取失败 \(describe(rkChunk))"
        }

        // ① UWorld
        stageMark("世界 · UWorld")
        let (rkW, world) = readRaw(port: p, address: MachVmAddress(runtime(off.gWorld, slide: s)))
        guard rkW == KERN_SUCCESS, world != 0 else {
            return "世界: 读 GWorld 失败 \(describe(rkW))"
        }
        lines.append("UWorld=0x\(String(world, radix: 16))")

        // ② PersistentLevel
        stageMark("世界 · PersistentLevel")
        let (rkL, level) = readRaw(port: p, address: MachVmAddress(world &+ 0xB8))
        guard rkL == KERN_SUCCESS, level != 0 else {
            return lines.joined(separator: "\n") + "\n读 PersistentLevel 失败 \(describe(rkL))"
        }
        lines.append("PersistentLevel=0x\(String(level, radix: 16))")

        // ③ Actors TArray
        stageMark("世界 · Actors")
        let (rkA, arr) = readBytes(port: p, address: MachVmAddress(level &+ 0xA0), count: 16)
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

        let (rkAct, actHdr) = readBytes(port: p, address: MachVmAddress(world &+ 0x0AB8), count: 16)
        if rkAct == KERN_SUCCESS, actHdr.count >= 16 {
            lines.append("ActiveLevelActors: count=\(Int(u32le(actHdr, 8)))（客户端恒为 0，仅记录）")
        }

        let (rkLv, lvHdr) = readBytes(port: p, address: MachVmAddress(world &+ 0x0AF0), count: 16)
        if rkLv == KERN_SUCCESS, lvHdr.count >= 16 {
            let d = u64le(lvHdr, 0)
            let c = Int(u32le(lvHdr, 8))
            lines.append("UWorld::Levels: count=\(c)")
            if d > 0x100000000, c > 0, c <= 4096 {
                let probe = min(c, 64)                  // 全读完，上次 min(c, 12) 把第 13 个漏了
                let (rkP, ptrs) = readBytes(port: p, address: MachVmAddress(d), count: probe * 8)
                if rkP == KERN_SUCCESS, ptrs.count >= probe * 8 {
                    for k in 0..<probe {
                        let lv = u64le(ptrs, k * 8)
                        guard lv > 0x100000000 else { continue }
                        if lv == level { continue }     // 就是 PersistentLevel，已经在 sources 里
                        let (rkA2, a2) = readBytes(port: p, address: MachVmAddress(lv &+ 0xA0), count: 16)
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
        var charHomes: [UInt64: String] = [:]
        var ctrlActors: [UInt64] = []
        var seen = 0
        var stopped = false

        sourceLoop: for src in sources {
            var cursor = 0
            while cursor < src.count {
                // 预算闸门：一旦真的落回 mach_vm_read 太多次，立刻收手。
                // 上一版没有这道闸门，一路读到底，游戏就没了。
                if hardReadCalls > 200 {
                    lines.append("⚠ 已用 \(hardReadCalls) 次 mach_vm_read —— 主动停止遍历，保住游戏")
                    stopped = true
                    break sourceLoop
                }
                if seen >= budget {
                    stopped = true
                    break sourceLoop
                }
                let batch = min(500, src.count - cursor)
                let (rkBuf, buf) = readBytes(port: p,
                                             address: MachVmAddress(src.data &+ UInt64(cursor * 8)),
                                             count: batch * 8)
                guard rkBuf == KERN_SUCCESS, buf.count >= batch * 8 else {
                    lines.append("读 \(src.label) 的 actor 指针失败 @\(cursor) \(describe(rkBuf))")
                    break
                }
                for i in 0..<batch {
                    let actor = u64le(buf, i * 8)
                    guard actor > 0x100000000 else { continue }
                    let (rkCls, cls) = readRaw(port: p, address: MachVmAddress(actor &+ 0x10))
                    guard rkCls == KERN_SUCCESS, cls > 0x100000000 else { continue }

                    var nm = classNames[cls]
                    if nm == nil {
                        let (rkIX, clsIX) = readAt(port: p, address: MachVmAddress(cls &+ 0x18))
                        nm = (rkIX == KERN_SUCCESS)
                            ? resolveName(port: p, pool: pool, chunk0: nameChunk0, index: clsIX)
                            : "?"
                        classNames[cls] = nm
                    }
                    let name = nm ?? "?"
                    histogram[name, default: 0] += 1
                    // Pawn 的判定要排除 GamePawnMode 之类 —— 上次它被误当成角色抓进来，
                    // 于是报告里出现了一个 Loc=(0,0,0) 的"角色"。
                    if name.contains("Character") || (name.contains("Pawn") && !name.contains("Mode")) {
                        charActors.append(actor)
                        charHomes[actor] = src.label
                    }
                    if name.contains("PlayerController") {
                        ctrlActors.append(actor)
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
                let (r1, pawn) = readRaw(port: p, address: MachVmAddress(c &+ 0x5D8))
                let (r2, ack) = readRaw(port: p, address: MachVmAddress(c &+ 0x660))
                let (r3, lf) = readAt(port: p, address: MachVmAddress(c &+ 0xA8C))
                let (r4, ps) = readRaw(port: p, address: MachVmAddress(c &+ 0x5F0))
                var line = "  [\(i)] PC=\(hexOf(c))"
                line += "  local=\(r3 == KERN_SUCCESS ? "\(lf & 0xFF)" : "读失败")"
                line += "  Pawn=\(r1 == KERN_SUCCESS ? hexOf(pawn) : "失败")"
                line += "  Ack=\(r2 == KERN_SUCCESS ? hexOf(ack) : "失败")"
                line += "  PS=\(r4 == KERN_SUCCESS ? hexOf(ps) : "失败")"
                lines.append(line)
                if r4 == KERN_SUCCESS, ps > 0x100000000 {
                    let nm = readText(port: p, addr: ps &+ 0x5D8)
                    if !nm.isEmpty { lines.append("        名字: \"\(nm)\"") }
                }
            }
        } else {
            lines.append("PlayerController: 0 个（本次遍历里没抓到这类 actor）")
        }

        if charActors.isEmpty {
            lines.append("角色: 0 个 —— 这 \(sources.count) 个关卡的 \(seen) 个 actor 里没有 Character/Pawn")
        } else {
            lines.append("角色: \(charActors.count) 个 —— 每个都是客户端手上真实存在的身体")
            var localCount = 0
            var ctrlZero = 0
            for (i, a) in charActors.prefix(24).enumerated() {
                let home = charHomes[a] ?? "?"
                var extra = ""
                // 身份：APawn + 0x608 → AController，再读 APlayerController + 0xA8C
                // 的 bIsLocalPlayerController。这条路不碰 LocalPlayers，不受加密影响。
                let (rkC, ctrl) = readRaw(port: p, address: MachVmAddress(a &+ 0x608))
                if rkC == KERN_SUCCESS, ctrl > 0x100000000 {
                    let (rkL, lf) = readAt(port: p, address: MachVmAddress(ctrl &+ 0xA8C))
                    if rkL == KERN_SUCCESS {
                        extra += "  local=\(lf & 0xFF)"
                        if (lf & 0xFF) == 1 { extra += " ★这是你"; localCount += 1 }
                    }
                } else {
                    ctrlZero += 1
                    extra += "  ctrl=0"
                }
                // 名字：APawn + 0x5F0 → APlayerState，再从 PlayerState + 0x5D8 读 FString
                let (rkPS, ps) = readRaw(port: p, address: MachVmAddress(a &+ 0x5F0))
                if rkPS == KERN_SUCCESS, ps > 0x100000000 {
                    let nm = readText(port: p, addr: ps &+ 0x5D8)
                    if !nm.isEmpty { extra += "  \"\(nm)\"" }
                }
                let (rkR, root) = readRaw(port: p, address: MachVmAddress(a &+ 0x260))
                guard rkR == KERN_SUCCESS, root > 0x100000000 else {
                    lines.append("  [\(i)] @\(hexOf(a)) [\(home)]  RootComponent 无效" + extra)
                    continue
                }
                let (rkT, tf) = readBytes(port: p, address: MachVmAddress(root &+ 0x1F0 + 0x10), count: 12)
                if rkT == KERN_SUCCESS, tf.count >= 12 {
                    let x = floatAt(tf, 0), y = floatAt(tf, 4), z = floatAt(tf, 8)
                    let ok = (x != 0 || y != 0) && abs(x) < 5e6 && abs(y) < 5e6 && abs(z) < 1e5
                    lines.append("  [\(i)] @\(hexOf(a)) [\(home)]  Loc=(\(fmt1(x)), \(fmt1(y)), \(fmt1(z))) "
                        + (ok ? "✓" : "✗ 量级不对") + extra)
                } else {
                    lines.append("  [\(i)] @\(hexOf(a)) [\(home)]  ComponentToWorld 读失败 \(describe(rkT))" + extra)
                }
            }
            if localCount == 0 {
                lines.append("  → 这 \(charActors.count) 个里没有一个 local=1；其中 Controller 为 0 的有 \(ctrlZero) 个"
                    + "（无主 Pawn —— 多半是训练场展示假人，不是真人玩家控制的）")
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

    /// 读游戏进程的内存账本。**一个字节的游戏内存都不碰** —— 只是让内核查一下它自己的记账。
    ///
    /// 这是把「读冷页 → 给游戏加内存 → 崩」这条假说变成数字的唯一直接手段：
    ///   phys_footprint  是 jetsam 判定用的那个数（决定游戏会不会被杀）
    ///   compressed      是当前被压缩的内存量 —— 我们读冷页会强制解压，这个数应该往下掉
    /// 在「对象」这类动作前后各点一次，差值自己会说话。
    static func stepMemory(pid: Int32) -> String {
        guard let fn = taskInfoFn else { return "内存: task_info 符号缺失" }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "内存: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        var raw = [UInt8](repeating: 0, count: 512)
        var count = UInt32(raw.count / 4)
        let rk = raw.withUnsafeMutableBytes { rb -> Int32 in
            guard let base = rb.baseAddress?.assumingMemoryBound(to: Int32.self) else {
                return KERN_FAILURE
            }
            return fn(p, 22, base, &count)          // TASK_VM_INFO = 22
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

    /// 映射读取的原型验证：把游戏内存映射进我们自己的地址空间，然后**从本地内存直接读**。
    ///
    /// 验收：本地读到的 Mach-O 头（magic + filetype）与 `mach_vm_read` 的结果一致，
    /// 且 GObjects 的 NumElements 是同一个六位数 —— 那就证明"共享书架"这条路通。
    /// 之后所有读取都可以走这里，调用次数从"每次读一次调用"降到"每块映射一次"。
    static func stepRemapProbe(pid: Int32) -> String {
        resetCounters()
        stageMark("映射 · 开始")
        guard baseReady(for: pid) else {
            return "映射: 没有当前进程的基址 —— 先点「找村口」"
        }
        mappedRanges.removeAll()
        rangesSorted = true
        let s = imageSlide
        let base = imageBase
        var lines: [String] = []

        // ① 映射映像头 1MB
        stageMark("映射 · 映像头")
        let (localHead, noteHead) = mapRange(pid: pid, srcAddress: base, size: 0x100000)
        guard localHead != 0 else { return "映射: \(noteHead)" }
        lines.append("① \(noteHead)")

        // ② 直接从本地内存读 Mach-O 头 —— 这一步零内核调用
        let header = readMapped(localHead, 16)
        guard header.count >= 16 else {
            lines.append("② 本地读失败")
            return lines.joined(separator: "\n")
        }
        let magic = UInt32(header[0]) | (UInt32(header[1]) << 8) | (UInt32(header[2]) << 16) | (UInt32(header[3]) << 24)
        let filetype = UInt32(header[12]) | (UInt32(header[13]) << 8) | (UInt32(header[14]) << 16) | (UInt32(header[15]) << 24)
        let headOK = (magic == 0xFEEDFACF && filetype == 2)
        lines.append("② 本地读头: magic=0x\(String(magic, radix: 16)) filetype=\(filetype) "
            + (headOK ? "✓ 映射读取成立" : "✗ 不对"))

        // ③ 映射 __DATA 那段窗口（GObjects / GNames / GWorld 都住在里面）
        //    只映射一个 32MB 窗口，物理页按需 fault —— 我们只碰其中几个地址。
        let off = Offsets.load()
        let gob = runtime(off.gObjects, slide: s)
        let mapStart = gob & ~0x1FFFFFF             // 32MB 向下对齐
        let mapSize: UInt64 = 0x2000000
        stageMark("映射 · __DATA 窗口")
        let (localData, noteData) = mapRange(pid: pid, srcAddress: mapStart, size: mapSize)
        guard localData != 0 else {
            lines.append("③ \(noteData)")
            return lines.joined(separator: "\n")
        }
        lines.append("③ \(noteData)")

        // ④ 从映射里读 GObjects 头 —— 零内核调用
        if gob >= mapStart, gob + 0x120 <= mapStart + mapSize {
            let buf = readMapped(localData + (gob - mapStart), 0x120)
            if buf.count >= 0x120 {
                let num = UInt32(buf[0x118]) | (UInt32(buf[0x119]) << 8)
                    | (UInt32(buf[0x11A]) << 16) | (UInt32(buf[0x11B]) << 24)
                let items = u64le(buf, 0xE0)
                let sane = (num > 100_000 && num < 2_000_000)
                lines.append("④ 映射读 GObjects: NumElements=\(num) items=0x\(String(items, radix: 16)) "
                    + (sane ? "✓ 应当与「定点读」的数字一致" : "✗ 数量异常"))
            } else {
                lines.append("④ 映射窗口读取不足（拿到 \(buf.count) 字节）")
            }
        } else {
            lines.append("④ GObjects 不在窗口内")
        }

        lines.append("已建立 \(mappedSummary) · " + costLine())
        lines.append("→ 映射建好之后，读这块内存不再产生任何 mach_vm_read 调用")
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

        stageMark("枚举 · D 取端口前")
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else {
            return lines.joined(separator: "\n") + "\nD ✗ 取端口失败 \(describe(kr))"
        }
        defer { dropPort(p) }
        stageMark("枚举 · D 端口已拿到")
        lines.append("D 端口已拿到 ✓ port=0x\(String(p, radix: 16))")

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
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "自己: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let off = Offsets.load()
        var lines: [String] = []


        // ① UWorld
        let (rkW, world) = readRaw(port: p, address: MachVmAddress(runtime(off.gWorld, slide: s)))
        guard rkW == KERN_SUCCESS, world != 0 else {
            return "自己: 读 GWorld 失败 \(describe(rkW))"
        }
        lines.append("UWorld=\(hexOf(world))")

        // ② GameInstance
        stageMark("自己 · GameInstance")
        let (rkG, game) = readRaw(port: p, address: MachVmAddress(world &+ 0xB20))
        guard rkG == KERN_SUCCESS, game != 0 else {
            return lines.joined(separator: "\n")
                + "\n读 OwningGameInstance 失败 \(describe(rkG)) @UWorld+0xB20"
        }
        lines.append("GameInstance=\(hexOf(game))")

        // ③ 加密标志 + LocalPlayers
        stageMark("自己 · LocalPlayers")
        let (rkEnc, enc) = readAt(port: p, address: MachVmAddress(game &+ 0x80))
        let encFlag = (rkEnc == KERN_SUCCESS) ? (enc & 0xFF) : 0xFF
        lines.append("bUseEncryptLocalPlayerPtr=\(encFlag) "
            + (encFlag == 0 ? "✓ 明文指针，可以直接用" : "⚠️ 指针被加密，这条路要另行处理"))

        let (rkL, larr) = readBytes(port: p, address: MachVmAddress(game &+ 0x48), count: 16)
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
        let (rkLP, localPlayer) = readRaw(port: p, address: MachVmAddress(lData))
        guard rkLP == KERN_SUCCESS, localPlayer != 0 else {
            return lines.joined(separator: "\n") + "\n读 LocalPlayers[0] 失败 \(describe(rkLP))"
        }
        lines.append("LocalPlayer[0]=\(hexOf(localPlayer))")

        // ⑤ PlayerController（UPlayer::PlayerController 在 0x30）
        stageMark("自己 · PlayerController")
        let (rkPC, pc) = readRaw(port: p, address: MachVmAddress(localPlayer &+ 0x30))
        guard rkPC == KERN_SUCCESS, pc != 0 else {
            lines.append("读 PlayerController 失败 \(describe(rkPC)) @LocalPlayer+0x30")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        lines.append("PlayerController=\(hexOf(pc))")

        // ⑥ AcknowledgedPawn
        stageMark("自己 · Pawn")
        let (rkPawn, pawn) = readRaw(port: p, address: MachVmAddress(pc &+ 0x660))
        guard rkPawn == KERN_SUCCESS, pawn != 0 else {
            lines.append("读 AcknowledgedPawn 失败 \(describe(rkPawn)) @PC+0x660")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        lines.append("Pawn=\(hexOf(pawn))")

        // ⑦ RootComponent
        stageMark("自己 · 坐标")
        let (rkRoot, root) = readRaw(port: p, address: MachVmAddress(pawn &+ 0x260))
        guard rkRoot == KERN_SUCCESS, root != 0 else {
            lines.append("读 RootComponent 失败 \(describe(rkRoot)) @Pawn+0x260")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        lines.append("RootComponent=\(hexOf(root))")

        // ⑧ ComponentToWorld + 0x10 → FVector
        let (rkT, tf) = readBytes(port: p, address: MachVmAddress(root &+ 0x1F0 + 0x10), count: 12)
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
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "玩家: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let off = Offsets.load()
        var lines: [String] = []

        func coordRaw(of actor: UInt64) -> (text: String, ok: Bool) {
            let (rkR, root) = readRaw(port: p, address: MachVmAddress(actor &+ 0x260))
            guard rkR == KERN_SUCCESS, root != 0 else {
                return ("Actor=\(hexOf(actor))  读 RootComponent 失败 \(describe(rkR))", false)
            }
            // 两个候选位置都读出来。dump 里 USceneComponent 的定义是：
            //   RelativeLocation   0x01CC (FVector, 0xC)
            //   ComponentToWorld   0x01F0 (FTransform, 0x30)  —— Translation 在 +0x10
            // 实测过：根组件没有父组件时 UE4 保证两者相等，真机上确实逐位相同。
            // 以 ToWorld 为准，RelLoc 留作对照 —— 哪天角色挂到载具上时两者会分开。
            let (rkRel, rel) = readBytes(port: p, address: MachVmAddress(root &+ 0x1CC), count: 12)
            let (rkT, tf) = readBytes(port: p, address: MachVmAddress(root &+ 0x1F0 + 0x10), count: 12)

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
            let (rkC, ctrl) = readRaw(port: p, address: MachVmAddress(character &+ 0x608))
            guard rkC == KERN_SUCCESS, ctrl > 0x100000000 else { return nil }
            let (rkL, v) = readAt(port: p, address: MachVmAddress(ctrl &+ 0xA8C))
            guard rkL == KERN_SUCCESS else { return nil }
            return Int(v & 0xFF)
        }

        // ① UWorld
        let (rkW, world) = readRaw(port: p, address: MachVmAddress(runtime(off.gWorld, slide: s)))
        guard rkW == KERN_SUCCESS, world != 0 else { return "玩家: 读 GWorld 失败 \(describe(rkW))" }
        lines.append("UWorld=\(hexOf(world))")

        // ② GameState
        stageMark("玩家 · GameState")
        let (rkGS, gameState) = readRaw(port: p, address: MachVmAddress(world &+ 0xAD8))
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
        let (rkN1, n1) = readBytes(port: p, address: MachVmAddress(gameState &+ 0x0D98), count: 8)
        if rkN1 == KERN_SUCCESS, n1.count >= 8 {
            lines.append("  人数(总): TotalPlayerNum=\(i32le(n1, 0))   PlayerNum=\(i32le(n1, 4))")
        } else {
            lines.append("  人数(总): 读失败 \(describe(rkN1)) @GameState+0x0D98")
        }
        let (rkN2, n2) = readBytes(port: p, address: MachVmAddress(gameState &+ 0x141C), count: 8)
        if rkN2 == KERN_SUCCESS, n2.count >= 8 {
            lines.append("  人数(存活): AlivePlayerNum=\(i32le(n2, 0))   AliveRealPlayerNum=\(i32le(n2, 4))")
        } else {
            lines.append("  人数(存活): 读失败 \(describe(rkN2)) @GameState+0x141C")
        }

        // ③ PlayerArray
        stageMark("玩家 · PlayerArray")
        let (rkPA, parr) = readBytes(port: p, address: MachVmAddress(gameState &+ 0x5E8), count: 16)
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
        let (rkList, list) = readBytes(port: p, address: MachVmAddress(paData), count: n * 8)
        guard rkList == KERN_SUCCESS, list.count >= n * 8 else {
            lines.append("读 PlayerArray 元素失败 \(describe(rkList))")
            lines.append(costLine())
            return lines.joined(separator: "\n")
        }
        // 顺带标出名单里"哪个是你"：任一环失败就静默跳过，不影响主流程
        let (selfPS, selfTrace) = findSelfPlayerState(port: p, world: world)

        stageMark("玩家 · 遍历")
        var withChar = 0
        var withCoord = 0
        var withLoc = 0
        for i in 0..<n {
            let ps = u64le(list, i * 8)
            guard ps != 0 else { continue }

            // 段 A 身份：0x5D0 score · 0x5D4 Ping · 0x5D8 PlayerName · 0x5F8 PlayerID
            let (rkA, segA) = readBytes(port: p, address: MachVmAddress(ps &+ 0x5D0), count: 0x30)
            // 段 B 状态：0x1648 LiveState · 0x1649 AILiveState · 0x16C0 CharacterOwner
            //           0x16D0 Health · 0x16D4 HealthMax · 0x16E0 SelfLocAndRot(0x18)
            let (rkB, segB) = readBytes(port: p, address: MachVmAddress(ps &+ 0x1648), count: 0xB8)

            let name = readText(port: p, addr: ps &+ 0x5D8)
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
    private static func findSelfPlayerState(port: MachPort, world: UInt64) -> (ps: UInt64, trace: String) {
        func plausible(_ v: UInt64) -> Bool { v > 0x100000000 && v < 0xF000000000000000 }

        let (rkG, gi) = readRaw(port: port, address: MachVmAddress(world &+ 0xB20))
        guard rkG == KERN_SUCCESS, plausible(gi) else {
            return (0, "断在 OwningGameInstance（\(describe(rkG)) @UWorld+0xB20）")
        }

        let (rkE, enc) = readAt(port: port, address: MachVmAddress(gi &+ 0x80))
        let encFlag = rkE == KERN_SUCCESS ? Int(enc & 0xFF) : -1

        let (rkL, lp) = readBytes(port: port, address: MachVmAddress(gi &+ 0x48), count: 16)
        guard rkL == KERN_SUCCESS, lp.count >= 16 else {
            return (0, "断在 LocalPlayers（\(describe(rkL)) @GI+0x48，加密标志=\(encFlag)）")
        }
        let data = u64le(lp, 0)
        let cnt = u32le(lp, 8)
        guard plausible(data), cnt > 0, cnt <= 8 else {
            return (0, "LocalPlayers 空（count=\(cnt)，data=\(hexOf(data))，加密标志=\(encFlag)）")
        }

        let (rkP0, lplayer) = readRaw(port: port, address: MachVmAddress(data))
        guard rkP0 == KERN_SUCCESS, plausible(lplayer) else {
            return (0, "LocalPlayers[0] 不是有效指针（\(hexOf(u64le(lp, 0)))，加密标志=\(encFlag)）")
        }

        let (rkPC, pc) = readRaw(port: port, address: MachVmAddress(lplayer &+ 0x30))
        guard rkPC == KERN_SUCCESS, plausible(pc) else {
            return (0, "断在 UPlayer+0x30 → PlayerController（\(describe(rkPC))，加密标志=\(encFlag)）")
        }

        let (rkPS, pstate) = readRaw(port: port, address: MachVmAddress(pc &+ 0x5F0))
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

    /// 单点区域归属：对 dump 基址问一次「这属于哪个文件」。

    /// 单点区域归属：对 dump 基址问一次「这属于哪个文件」。    ///
    /// 零风险探测：一次调用、不遍历、不写。
    /// 收益却很大 ——
    ///   返回 ShadowTrackerExtra 路径 → 该地址在游戏映像内，且符号可用
    ///   返回别的路径               → 那个地址属于别的映射
    ///   返回 0 / 符号缺失          → 这条路不通，及早知道
    static func stepRegionName(pid: Int32) -> String {
        let off = Offsets.load()
        guard let fn = procRegionFileNameFn else {
            return "区域归属: proc_regionfilename 符号缺失"
        }
        var buf = [UInt8](repeating: 0, count: 1024)
        // buf.count 必须在闭包外取：withUnsafeMutableBytes 已对 buf 取独占访问，
        // 闭包内再读 buf.count 会触发 "overlapping accesses" 编译错误。
        let cap = UInt32(buf.count)
        let addr = off.moduleBase
        let n = buf.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return 0 }
            return fn(pid, addr, base, cap)
        }
        guard n > 0 else {
            return "区域归属: 0x\(String(addr, radix: 16)) → 返回 \(n)（该地址不在任何区域?)"
        }
        let path = String(decoding: buf.prefix { $0 != 0 }, as: UTF8.self)
        let short = path.split(separator: "/").last.map(String.init) ?? path
        let isGame = path.lowercased().contains("shadowtracker")
        return "区域归属: 0x\(String(addr, radix: 16)) → \(short) \(isGame ? "是游戏映像" : "不是游戏")"
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
        if objectName != 0 { dropPort(objectName) }
        guard kr == KERN_SUCCESS, size > 0 else { return (false, 0, 0, 0) }
        return (true, size, info[0], UInt32(bitPattern: info[5]))
    }

    /// 问某地址属于哪个文件（proc_regionfilename 封装）
    private static func regionFile(pid: Int32, addr: UInt64) -> String? {
        guard let fn = procRegionFileNameFn else { return nil }
        var buf = [UInt8](repeating: 0, count: 1024)
        let cap = UInt32(buf.count)
        let n = buf.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return 0 }
            return fn(pid, addr, base, cap)
        }
        guard n > 0 else { return nil }
        // 不假定内核一定写 NUL 终止符：按 0 截断再解码。
        // 用 String(cString:) 的话，缓冲区被写满时它会一路读到越界。
        let s = String(decoding: buf.prefix { $0 != 0 }, as: UTF8.self)
        return s.isEmpty ? nil : s
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

        // ---- 拿游戏的 task port ----
        stageMark("找村口 · 取端口")
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else {
            return "找基址: 取端口失败 \(describe(kr))"
        }
        defer { dropPort(p) }

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

            let (ok, size, prot, offset) = nextRegion(task: p, addr: &addr)
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
                let (okMagic, why) = isExecutableMachO(port: p, addr)
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
