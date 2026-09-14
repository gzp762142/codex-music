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

    /// 按绝对地址读 8 字节，并按指针解读。
    private static func readPointer(port: MachPort, address: MachVmAddress)
        -> (KernReturn, UInt64, Bool, String) {
        guard let vmRead = vmReadFn else { return (KERN_FAILURE, 0, false, "n/a") }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 8
        let kr = vmRead(port, address, 8, &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen >= 8 else { return (kr, 0, false, "n/a") }
        var value: UInt64 = 0
        if let p = UnsafeRawPointer(bitPattern: dataPtr) {
            value = p.load(as: UInt64.self)
        }
        _ = vmDeallocateFn?(port, dataPtr, dataLen)
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
            let (rk, value, real, _) = readPointer(port: p, address: MachVmAddress(addr))
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
    static func stepFindBase(pid: Int32) -> String {
        let off = Offsets.load()
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "找村口: 取端口失败 \(describe(kr))" }

        let page: UInt64 = 0x4000
        let dumpBase = off.moduleBase
        let expectedDelta: UInt64 = 0x117597F90 - 0x115A21B00
        let objectsOff = off.gObjects - dumpBase
        let namesOff = off.gNames - dumpBase
        let lo: UInt64 = 0x1000000000
        let hi: UInt64 = 0x1400000000

        // 先诊断：在 dump 基址上读一次，看两个全局量分别是什么
        // （这比直接扫有用 —— 如果这里就能看出是哪个不对，就不用扫）
        var diag = ""
        do {
            let (r1, g) = readPointer(port: p, address: MachVmAddress(dumpBase + objectsOff))
            let (r2, n) = readPointer(port: p, address: MachVmAddress(dumpBase + namesOff))
            let gOk = (r1 == KERN_SUCCESS) && g >= lo && g < hi
            let nOk = (r2 == KERN_SUCCESS) && n >= lo && n < hi
            diag = " [dump基址: GObj\(gOk ? "内" : "外") GName\(nOk ? "内" : "外")]"
        }

        // 逐轮向外扩：每轮扫窗口 [dump ± span*(round+1)]，只扫新增的环带，不重复
        let span = page * 256                 // 每轮外扩 4MB
        var scanned = 0
        for round in 0..<4 {                  // 最多到 ±16MB
            let w = span * UInt64(round + 1)
            // 低侧环带
            var a = dumpBase
            while a >= dumpBase - w, a > page {
                if let hit = probeBase(port: p, base: a, objectsOff: objectsOff,
                                       namesOff: namesOff, expectedDelta: expectedDelta) {
                    return "找村口: 命中 0x\(String(hit, radix: 16)) 扫\(scanned)页" + diag
                }
                a -= page
                scanned += 1
            }
            // 高侧环带
            var b = dumpBase
            while b <= dumpBase + w {
                if let hit = probeBase(port: p, base: b, objectsOff: objectsOff,
                                       namesOff: namesOff, expectedDelta: expectedDelta) {
                    return "找村口: 命中 0x\(String(hit, radix: 16)) 扫\(scanned)页" + diag
                }
                b += page
                scanned += 1
            }
        }
        return "找村口: ±16MB 内未命中 扫\(scanned)页" + diag
    }

    /// 试探一个候选基址：读 GObjects/GNames 两个全局量，看差值对不对。
    private static func probeBase(port: MachPort, base: UInt64, objectsOff: UInt64,
                                  namesOff: UInt64, expectedDelta: UInt64) -> UInt64? {
        let (rk1, g) = readPointer(port: port, address: MachVmAddress(base + objectsOff))
        guard rk1 == KERN_SUCCESS, g != 0 else { return nil }
        let (rk2, n) = readPointer(port: port, address: MachVmAddress(base + namesOff))
        guard rk2 == KERN_SUCCESS, n != 0 else { return nil }

        let delta = (n > g) ? (n - g) : (g - n)
        guard delta == expectedDelta else { return nil }
        // 两个值都要落在 dump 的地址空间（0x1000000000 ~ 0x1400000000）
        let inSpace = { (v: UInt64) -> Bool in v >= 0x1000000000 && v < 0x1400000000 }
        guard inSpace(g), inSpace(n) else { return nil }
        return base
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
