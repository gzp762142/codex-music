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
    static func stepSymbols() -> String { symbolSummary }

    /// 第 2 步：只调 libSystem 的 task_for_pid。
    func stepDlsym(pid: Int32) -> String {
        guard let fn = Self.taskForPidFn else { return "dlsym: 符号缺失" }
        var port: MachPort = 0
        let kr = fn(mach_task_self_, pid, &port)
        if kr == KERN_SUCCESS, port != 0 {
            return "dlsym: 成功 port=0x\(String(port, radix: 16))"
        }
        return "dlsym: \(Self.describe(kr))"
    }

    // MARK: - 读证

    /// 按已知地址读一段内存。**只有 3 个参数**：task / addr / size。
    ///
    /// 这是刻意的：`mach_vm_region` 有两个出参（info / count），我已经在它上面
    /// 连错两次（count 填 0、info 不匹配），而读内存本身根本不需要枚举内存区。
    /// 读已知地址这条路参数最少，出错面最小。
    /// 返回 (kern_return, 读到的前 4 字节)
    private func readAt(port: MachPort, address: MachVmAddress) -> (KernReturn, UInt32) {
        guard let vmRead = Self.vmReadFn else { return (KERN_FAILURE, 0) }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 4
        let kr = vmRead(port, address, 4, &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen >= 4 else { return (kr, 0) }
        var magic: UInt32 = 0
        if let p = UnsafeRawPointer(bitPattern: dataPtr) {
            magic = p.assumingMemoryBound(to: UInt32.self).pointee
        }
        // 内核给的内存必须还回去
        _ = Self.vmDeallocateFn?(port, dataPtr, dataLen)
        return (KERN_SUCCESS, magic)
    }

    // MARK: - 定点读（用 dump 偏移，不做任何扫描）

    /// 按绝对地址读 8 字节，并按指针解读。
    /// 返回 (kern_return, 原始值, 是否像有效指针, 值的高 4 位十六进制)
    private func readPointer(port: MachPort, address: MachVmAddress) -> (KernReturn, UInt64, Bool, String) {
        guard let vmRead = Self.vmReadFn else { return (KERN_FAILURE, 0, false, "n/a") }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 8
        let kr = vmRead(port, address, 8, &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen >= 8 else { return (kr, 0, false, "n/a") }
        var value: UInt64 = 0
        if let p = UnsafeRawPointer(bitPattern: dataPtr) {
            value = p.load(as: UInt64.self)
        }
        _ = Self.vmDeallocateFn?(port, dataPtr, dataLen)
        // iOS arm64 用户态地址是 36 位宽（0x1_0000_0000 ~ 0x100_0000_0000）。
        // 上一版用「高 16 位非零」判断 —— 太窄：0x0001xxxxxxxx 这种正常堆地址
        // 高 16 位是 0x0001，非零没错，但 0x0000_1xxx_xxxx 就会被误判成异常。
        let looksReal = value >= 0x100000000 && value < 0x10000000000
        let hi = String(format: "%04llx", (value >> 32) & 0xFFFF)
        return (KERN_SUCCESS, value, looksReal, hi)
    }

    /// 读模块头：dump 基址处读 Mach-O 头（magic + cputype）。
    static func stepModuleHead(pid: Int32) -> String {
        let probe = MemoryProbe()
        let off = Offsets.load()
        guard let tfp = taskForPidFn else { return "模块头: tfp 符号缺失" }
        var port: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else { return "模块头: 取端口失败 \(describe(kr))" }

        guard let vmRead = vmReadFn else { return "模块头: vm_read 符号缺失" }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 16
        let rk = vmRead(port, MachVmAddress(off.moduleBase), 16, &dataPtr, &dataLen)
        guard rk == KERN_SUCCESS, dataPtr != 0, dataLen >= 8 else {
            return "模块头: 读 0x\(String(off.moduleBase, radix: 16)) 失败 \(describe(rk))"
        }
        var magic: UInt32 = 0
        var cputype: UInt32 = 0
        if let p = UnsafeRawPointer(bitPattern: dataPtr) {
            magic = p.assumingMemoryBound(to: UInt32.self).pointee
            cputype = p.advanced(by: 4).assumingMemoryBound(to: UInt32.self).pointee
        }
        _ = vmDeallocateFn?(port, dataPtr, dataLen)
        let isMachO = (magic == 0xFEEDFACF)
        return "模块头: 0x\(String(off.moduleBase, radix: 16)) magic=0x\(String(magic, radix: 16))"
            + " cpu=\(cputype) " + (isMachO ? "是Mach-O(基址正确)" : "不是Mach-O(基址被ASLR搬了)")
    }

    /// 定点读：用 dump 偏移算绝对地址，读 8 字节。
    /// **一次只读一个地址** —— 这是刻意的：扫大范围是上几次出问题的来源。
    static func stepFixedRead(pid: Int32) -> String {
        let probe = MemoryProbe()
        let off = Offsets.load()
        guard let tfp = taskForPidFn else { return "定点读: tfp 符号缺失" }
        var port: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else { return "定点读: 取端口失败 \(describe(kr))" }

        // 三个全局静态量，都应该是有效指针
        let items: [(String, UInt64)] = [
            ("GObjects", off.gObjects),
            ("GNames", off.gNames),
            ("GWorld", off.gWorld)
        ]
        var ok = 0
        var parts: [String] = []
        for (name, addr) in items {
            let (rk, value, real, hi) = probe.readPointer(port: port, address: MachVmAddress(addr))
            if rk != KERN_SUCCESS {
                parts.append("\(name)=\(describe(rk))")
            } else if real {
                ok += 1
                parts.append("\(name)=OK(hi\(hi))")
            } else {
                parts.append("\(name)=值异常(v=0x\(String(value, radix: 16)))")
            }
        }
        let verdict: String
        if ok == items.count { verdict = "三个都在 → 读通" }
        else if ok > 0 { verdict = "部分通" }
        else { verdict = "全不通" }
        return "定点读[\(verdict)] " + parts.joined(separator: " ")
    }

    /// 扫基址：找 Mach-O magic。范围按块推进，比上一版小（只 128MB）。
    static func stepBaseScan(pid: Int32) -> String {
        let probe = MemoryProbe()
        guard let tfp = taskForPidFn else { return "扫基址: tfp 符号缺失" }
        var port: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else { return "扫基址: 取端口失败 \(describe(kr))" }
        guard let vmRead = vmReadFn else { return "扫基址: vm_read 符号缺失" }

        let startAddr: MachVmAddress = 0x100000000
        let blockSize = 0x10000
        let blocks = 2048                      // 128MB
        var readable = 0
        for i in 0..<blocks {
            let addr = startAddr + MachVmAddress(i * blockSize)
            var dataPtr: UInt = 0
            var dataLen: MachVmSize = MachVmSize(blockSize)
            let rk = vmRead(port, addr, MachVmSize(blockSize), &dataPtr, &dataLen)
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
            _ = vmDeallocateFn?(port, dataPtr, dataLen)
            if found != 0 {
                return "扫基址: 命中 0x\(String(found, radix: 16)) 块\(i + 1) 可读\(readable)"
            }
        }
        return "扫基址: 128MB 内未命中 可读\(readable)块"
    }
}
