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

    /// **对照实验**：对自己进程读一段**保证可读**的内存 —— 用 dlsym 拿到的
    /// 函数地址。自己的权限必然够，所以这里失败只可能是代码问题，不是权限。
    static func stepSelfTest() -> String {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "task_for_pid"),
              let vmRead = vmReadFn else {
            return "自测: 符号缺失"
        }
        let addr = MachVmAddress(UInt(bitPattern: sym))
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 8
        let kr = vmRead(mach_task_self_, addr, 8, &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0 else {
            return "自测: 读自己的代码失败 \(describe(kr))"
        }
        var bytes = "0x"
        if let base = UnsafeRawPointer(bitPattern: dataPtr) {
            let p = base.assumingMemoryBound(to: UInt8.self)
            for i in 0..<4 { bytes += String(format: "%02x", p[i]) }
        }
        _ = vmDeallocateFn?(mach_task_self_, dataPtr, dataLen)
        return "自测: 读自己OK addr=0x\(String(addr, radix: 16)) 首4字节=\(bytes)"
    }

    /// 读证：拿到端口后，按候选地址直接读 4 字节。
    ///
    /// 候选地址顺序：
    ///   1. 0x100000000 —— arm64 上主可执行文件在**未启用 PIE 随机化**时的经典基址
    ///   2. 0x102000000 —— 部分系统上 dyld 的基址
    ///   3. 0x100000000 的前一页（0x0ffff0000）
    /// 三个都失败不代表读不了，只代表这几个地址不对；那时再想办法从别的渠道
    /// 拿真实基址（后续做内存扫描时本来也要找基址）。
    func stepReadProof(pid: Int32) -> String {
        guard let tfp = Self.taskForPidFn else { return "读证: tfp 符号缺失" }
        var port: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else {
            return "读证: 取端口失败 \(Self.describe(kr))"
        }

        let candidates: [MachVmAddress] = [0x100000000, 0x102000000, 0x0ffff0000]
        var out: [String] = []
        for addr in candidates {
            let (rk, magic) = readAt(port: port, address: addr)
            if rk == KERN_SUCCESS {
                out.append("0x\(String(addr, radix: 16))→OK head=0x\(String(magic, radix: 16))")
                return "读证: " + out.joined(separator: " ")
            }
            out.append("0x\(String(addr, radix: 16))→\(rk)")
        }
        return "读证: 端口OK但候选地址均不可读 [" + out.joined(separator: " ") + "]"
    }
}
