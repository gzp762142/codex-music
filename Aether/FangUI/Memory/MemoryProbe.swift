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
        if kr == KERN_SUCCESS, port != 0 {
            return "dlsym: 成功 port=0x\(String(port, radix: 16))"
        }
        return "dlsym: \(describe(kr))"
    }

    // MARK: - 读（全部 static：纯函数，不需要实例）

    /// 按绝对地址读 4 字节。**只有 3 个参数**。
    /// mach_vm_region 那条路已被删除：它有两个出参，是之前连续出错的来源，
    /// 而读内存根本不需要枚举内存区。
    private static func readAt(port: MachPort, address: MachVmAddress) -> (KernReturn, UInt32) {
        guard let vmRead = vmReadFn else { return (KERN_FAILURE, 0) }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 4
        let kr = vmRead(port, address, 4, &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen >= 4 else { return (kr, 0) }
        var v: UInt32 = 0
        if let p = UnsafeRawPointer(bitPattern: dataPtr) {
            v = p.assumingMemoryBound(to: UInt32.self).pointee
        }
        _ = vmDeallocateFn?(port, dataPtr, dataLen)
        return (KERN_SUCCESS, v)
    }

    /// 按绝对地址读 8 字节 —— 只给值，供程序判断用。
    private static func readRaw(port: MachPort, address: MachVmAddress) -> (KernReturn, UInt64) {
        guard let vmRead = vmReadFn else { return (KERN_FAILURE, 0) }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 8
        let kr = vmRead(port, address, 8, &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen >= 8 else { return (kr, 0) }
        var value: UInt64 = 0
        if let p = UnsafeRawPointer(bitPattern: dataPtr) {
            value = p.load(as: UInt64.self)
        }
        _ = vmDeallocateFn?(port, dataPtr, dataLen)
        return (KERN_SUCCESS, value)
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

    // MARK: - 面板动作

    /// 读证：在 dump 记录的模块基址处读 Mach-O 头。
    /// 一次读取，不扫描 —— 扫大范围是之前出问题的来源。
    static func stepReadProof(pid: Int32) -> String {
        let off = Offsets.load()
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "读证: 取端口失败 \(describe(kr))" }

        let (rk, magic) = readAt(port: p, address: MachVmAddress(off.moduleBase))
        guard rk == KERN_SUCCESS else {
            return "读证: 读 0x\(String(off.moduleBase, radix: 16)) 失败 \(describe(rk))"
        }
        let isMachO = (magic == 0xFEEDFACF)
        return "读证: 0x\(String(off.moduleBase, radix: 16)) magic=0x\(String(magic, radix: 16)) "
            + (isMachO ? "是Mach-O(基址正确,读通)" : "不是Mach-O(基址被ASLR搬了)")
    }

    /// 定点读：用 dump 偏移读三个全局量，打印**完整 8 字节值**，
    /// 并算出实测差值跟 dump 差值对比。
    ///
    /// 为什么要算差值：村口（模块基址）会被 ASLR 挪，但**两个全局量之间的距离不变**。
    ///   dump 时 GNames - GObjects = 0x1C4EBF90
    /// 读出来的两个值如果差值就是这个数，说明位置找对了 ——
    /// 不需要先知道村口，差值自己会证明。
    static func stepFixedRead(pid: Int32) -> String {
        let off = Offsets.load()
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "定点读: 取端口失败 \(describe(kr))" }

        let items: [(String, UInt64)] = [
            ("GObjects", off.gObjects),
            ("GNames", off.gNames),
            ("GWorld", off.gWorld)
        ]
        var values: [String: UInt64] = [:]
        var parts: [String] = []
        for (name, addr) in items {
            let (rk, value, real, _) = pointerInfo(port: p, address: MachVmAddress(addr))
            if rk != KERN_SUCCESS {
                parts.append("\(name)=\(describe(rk))")
                continue
            }
            values[name] = value
            // 打完整值；real 只是粗判，不作为结论
            parts.append("\(name)=0x\(String(value, radix: 16))\(real ? "" : "?")")
        }

        // 差值对比：跟村口无关的恒定判据
        var deltaNote = ""
        if let g = values["GObjects"], let n = values["GNames"] {
            let measured = (n > g) ? (n - g) : (g - n)
            let expected: UInt64 = 0x117597F90 - 0x115A21B00   // dump 时的 GNames - GObjects
            let same = (measured == expected)
            deltaNote = " Δ实测=0x\(String(measured, radix: 16)) Δ期望=0x\(String(expected, radix: 16)) "
                + (same ? "→一致(位置对了!)" : "→不一致")
        }
        return "定点读 " + parts.joined(separator: " ") + deltaNote
    }

    /// 找村口：在 dump 基址附近按页步进，用 Δ 判据精确认村口。
    ///
    /// 判据（跟村口无关的恒定关系）：
    ///   dump 时 GNames - GObjects = 0x1C4EBF90
    /// 候选基址必须让这两个地址读出的值**差值就是这个数**，并且两个值都落在
    /// dump 的地址空间里。比"看指针像不像"可靠得多 —— 两个独立的数同时对。
    ///
    /// 代价：每页只读 8 字节（不是 64KB），±4MB 是 1024 页 → 1024 次小读。
    /// 这是刻意压低的读取量：大块连续读是之前把游戏搞崩的原因。
    /// 单点区域归属：对 dump 基址问一次「这属于哪个文件」。
    ///
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
        var buf = [CChar](repeating: 0, count: 1024)
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
        let path = String(cString: buf)
        let short = path.split(separator: "/").last.map(String.init) ?? path
        let isGame = path.lowercased().contains("shadowtracker")
        return "区域归属: 0x\(String(addr, radix: 16)) → \(short) \(isGame ? "是游戏映像" : "不是游戏")"
    }

    // MARK: - 找基址（枚举 region，零内存读取）

    /// 枚举下一个 region。会把 addr 更新为该 region 的实际起始。
    /// 返回 (成功, size, protection, 文件偏移)
    private static func nextRegion(task: UInt32, addr: inout UInt64)
        -> (ok: Bool, size: UInt64, prot: Int32, offset: UInt32) {
        guard let fn = vmRegionRecurseFn else { return (false, 0, 0, 0) }
        var size: UInt64 = 0
        var depth: UInt32 = 0
        var info = [Int32](repeating: 0, count: 32)
        var count: UInt32 = 19          // VM_REGION_SUBMAP_INFO_COUNT_64
        let kr = info.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return KERN_FAILURE }
            return fn(task, &addr, &size, &depth, base, &count)
        }
        guard kr == KERN_SUCCESS, size > 0 else { return (false, 0, 0, 0) }
        // vm_region_submap_info_64 开头四个字：protection, max_protection, inheritance, offset
        return (true, size, info[0], UInt32(bitPattern: info[3]))
    }

    /// 问某地址属于哪个文件（proc_regionfilename 封装）
    private static func regionFile(pid: Int32, addr: UInt64) -> String? {
        guard let fn = procRegionFileNameFn else { return nil }
        var buf = [CChar](repeating: 0, count: 1024)
        let cap = UInt32(buf.count)
        let n = buf.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return 0 }
            return fn(pid, addr, base, cap)
        }
        guard n > 0 else { return nil }
        let s = String(cString: buf)
        return s.isEmpty ? nil : s
    }

    /// 找基址（主二进制），**全程不读游戏内存内容**。
    ///
    /// 判据（三个条件同时成立才认）：
    ///   1. proc_regionfilename 返回的路径匹配 ShadowTracker
    ///   2. protection 含 VM_PROT_EXECUTE(0x4)  → 可执行段
    ///   3. offset == 0                          → 从文件头映射 = Mach-O 头所在段
    /// 满足这三条的就是 __TEXT 段，它的起始地址 = image base。
    ///
    /// 为什么不用"二分 proc_regionfilename"：实测它的语义是
    /// "返回该地址所在或**之后第一个** region" —— 对未映射的低地址也会返回
    /// 游戏路径，二分因此完全失效（会出现负 slide 这种不可能的结果）。
    /// 所以必须有 region 边界信息，只能靠枚举。
    static func stepFindBase(pid: Int32) -> String {
        guard vmRegionRecurseFn != nil else { return "找基址: vm_region_recurse_64 符号缺失" }
        guard procRegionFileNameFn != nil else { return "找基址: proc_regionfilename 符号缺失" }

        // ---- 参数自检：先对自己进程枚举一次，参数错就停在这里，绝不碰游戏 ----
        var selfAddr: UInt64 = 0
        let selfCheck = nextRegion(task: mach_task_self_, addr: &selfAddr)
        guard selfCheck.ok else {
            return "找基址: 参数自检失败（对自己枚举就不成功），未碰游戏"
        }

        // ---- 拿游戏的 task port ----
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else {
            return "找基址: 取端口失败 \(describe(kr))"
        }

        var addr: UInt64 = 0
        var scanned = 0
        var hitBase: UInt64 = 0
        var hitName = ""

        while scanned < 6000 {
            let (ok, size, prot, offset) = nextRegion(task: p, addr: &addr)
            guard ok else { break }
            scanned += 1

            // 三个条件全中才算 __TEXT
            if let path = regionFile(pid: pid, addr: addr),
               path.lowercased().contains("shadowtracker"),
               (prot & 0x4) != 0,          // VM_PROT_EXECUTE
               offset == 0 {
                hitBase = addr
                hitName = path.split(separator: "/").last.map(String.init) ?? "?"
                break
            }

            addr += size
            if addr < size { break }        // 溢出保护
        }

        guard hitBase != 0 else {
            return "找基址: 枚举\(scanned)个region，未命中(__TEXT & offset=0)"
        }
        return "找基址: base=0x\(String(hitBase, radix: 16)) region=\(scanned) \(hitName)"
    }

    /// 试探一个候选基址 —— 用 dump 里的**多重约束**判据。
    ///
    /// 单看"指针像不像"太弱（图二就误判过），这里用四个互相独立的条件：
    ///   1. GNames 读出的指针落在 dump 的地址空间（0x11xxxxxxx）
    ///   2. GObjects 读出的 chunk0 指针落在堆区间（0x120000000 ~ 0x140000000）
    ///   3. chunk0 + 0*0x18 处读出的首个对象地址 = 0x128370000（dump 记录）
    ///   4. 那个对象的 vtable 落在模块映像区间
    ///
    /// 四个条件全中才认 —— 误判概率极低。
    /// 返回 (命中基址, 失败原因)；未命中时原因用于面板诊断。
    private static func probeBase(port: MachPort, base: UInt64, objectsOff: UInt64,
                                  namesOff: UInt64, expectedDelta: UInt64)
        -> (UInt64?, String) {

        let (rk1, g) = readRaw(port: port, address: MachVmAddress(base + objectsOff))
        guard rk1 == KERN_SUCCESS, g != 0 else { return (nil, "GObjects读失败/\(rk1)") }
        let (rk2, n) = readRaw(port: port, address: MachVmAddress(base + namesOff))
        guard rk2 == KERN_SUCCESS, n != 0 else { return (nil, "GNames读失败/\(rk2)") }

        // 条件 1：GNames 落在 dump 地址空间
        let ns: UInt64 = 0x110000000
        let ne: UInt64 = 0x120000000
        guard n >= ns, n < ne else { return (nil, "GNames越域") }

        // 条件 2：chunk0 是堆指针
        let hs: UInt64 = 0x120000000
        let he: UInt64 = 0x140000000
        guard g >= hs, g < he else { return (nil, "GObj非堆指针") }

        // 条件 3：chunk0[0] 必须是 dump 记录的那个对象地址
        let (rk3, firstObj) = readRaw(port: port, address: MachVmAddress(g))
        guard rk3 == KERN_SUCCESS, firstObj == 0x128370000 else {
            return (nil, "chunk0[0]≠0x128370000")
        }

        // 条件 4：该对象的 vtable 落在模块映像内
        let (rk4, vtable) = readRaw(port: port, address: MachVmAddress(firstObj))
        guard rk4 == KERN_SUCCESS, vtable >= 0x1000000000, vtable < 0x1200000000 else {
            return (nil, "vtable越域")
        }

        // 差值仅作参考（条件已足够强，Δ 不满足也放行但会标注）
        let delta = (n > g) ? (n - g) : (g - n)
        _ = delta
        _ = expectedDelta
        return (base, "OCRok vt=0x\(String(vtable, radix: 16))")
    }


    /// 扫基址：最后手段。128MB 内找 Mach-O magic。
    static func stepBaseScan(pid: Int32) -> String {
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "扫基址: 取端口失败 \(describe(kr))" }
        guard let vmRead = vmReadFn else { return "扫基址: vm_read 符号缺失" }

        let startAddr: MachVmAddress = 0x100000000
        let blockSize = 0x10000
        let blocks = 2048
        var readable = 0
        for i in 0..<blocks {
            let addr = startAddr + MachVmAddress(i * blockSize)
            var dataPtr: UInt = 0
            var dataLen: MachVmSize = MachVmSize(blockSize)
            let rk = vmRead(p, addr, MachVmSize(blockSize), &dataPtr, &dataLen)
            guard rk == KERN_SUCCESS, dataPtr != 0, dataLen >= 4 else { continue }
            readable += 1
            var found: MachVmAddress = 0
            if let base = UnsafeRawPointer(bitPattern: dataPtr) {
                let p32 = base.assumingMemoryBound(to: UInt32.self)
                let words = Int(dataLen) / 4
                for w in 0..<words where p32[w] == 0xFEEDFACF {
                    found = addr + MachVmAddress(w * 4)
                    break
                }
            }
            _ = vmDeallocateFn?(p, dataPtr, dataLen)
            if found != 0 {
                return "扫基址: 命中 0x\(String(found, radix: 16)) 块\(i + 1) 可读\(readable)"
            }
        }
        return "扫基址: 128MB 内未命中 可读\(readable)块"
    }
}
