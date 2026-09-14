import Foundation
import Darwin

/// 读内存探针：**只读**，不写、不 hook、不注入。
///
/// **每一步都拆成独立可调用的动作**，不做"一次跑完"的流水线：
/// 上一版把 dlsym / task_for_pid / syscall / 读证 串成一个 probe()，一点设置
/// 就闪退，却分不清崩在哪一步。现在每个动作单独触发，点哪步崩就是哪步的错。
///
/// 已知的坑，写在这里免得再犯：
/// - 不要扫 mach trap 编号。编号含义不明时调用会直接杀掉进程（已踩过）。
/// - mach_vm_read 读出来的内存要 vm_deallocate，否则每读一次漏一次。
/// - proc_pidpath 的返回长度要按 -1 算终止符。
final class MemoryProbe {

    private typealias MachPort = UInt32
    private typealias KernReturn = Int32
    private typealias MachVmAddress = UInt64
    private typealias MachVmSize = UInt64

    private typealias TaskForPidFn = @convention(c) (MachPort, Int32, UnsafeMutablePointer<MachPort>) -> KernReturn
    private typealias SyscallFn = @convention(c) (Int32, Int32, UInt32, UnsafeMutablePointer<UInt32>) -> Int32
    private typealias VmRegionFn = @convention(c) (MachPort, UnsafeMutablePointer<MachVmAddress>,
                                                   UnsafeMutablePointer<MachVmSize>, Int32,
                                                   UnsafeMutablePointer<Int32>,
                                                   UnsafeMutablePointer<UInt32>) -> KernReturn
    private typealias VmReadFn = @convention(c) (MachPort, MachVmAddress, MachVmSize,
                                                 UnsafeMutablePointer<UInt>,
                                                 UnsafeMutablePointer<MachVmSize>) -> KernReturn
    private typealias VmDeallocateFn = @convention(c) (MachPort, UInt, MachVmSize) -> KernReturn

    /// 45 = task_for_pid 的 mach trap 号（已确认）。26 是 ptrace，绝不调用。
    static let taskForPidTrap: Int32 = 45

    private static func symbol<T>(_ name: String, as: T.Type) -> T? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static let taskForPidFn = symbol("task_for_pid", as: TaskForPidFn.self)
    private static let syscallFn = symbol("syscall", as: SyscallFn.self)
    private static let vmRegionFn = symbol("mach_vm_region", as: VmRegionFn.self)
    private static let vmReadFn = symbol("mach_vm_read", as: VmReadFn.self)
    private static let vmDeallocateFn = symbol("mach_vm_deallocate", as: VmDeallocateFn.self)

    static var symbolSummary: String {
        let a = taskForPidFn != nil ? "tfp=OK" : "tfp=nil"
        let b = syscallFn != nil ? "syscall=OK" : "syscall=nil"
        let c = vmReadFn != nil ? "vm_read=OK" : "vm_read=nil"
        let d = vmDeallocateFn != nil ? "vm_dealloc=OK" : "vm_dealloc=nil"
        return "\(a) \(b) \(c) \(d)"
    }

    // MARK: - 单步动作

    /// 第 1 步：只解析符号，不调用任何东西。
    static func stepSymbols() -> String {
        symbolSummary
    }

    /// 第 2 步：只调 libSystem 的 task_for_pid。
    func stepDlsym(pid: Int32) -> String {
        guard let fn = Self.taskForPidFn else { return "dlsym: 符号缺失" }
        var port: MachPort = 0
        let kr = fn(mach_task_self_, pid, &port)
        if kr == KERN_SUCCESS, port != 0 {
            return "dlsym: 成功 port=0x\(String(port, radix: 16))"
        }
        return "dlsym: ret=\(kr)"
    }

    /// 第 3 步：只走 syscall(45, ...)。崩不崩在这步立刻见分晓。
    func stepSyscall(pid: Int32) -> String {
        guard let sc = Self.syscallFn else { return "syscall: 符号缺失" }
        var port: MachPort = 0
        let kr = sc(Self.taskForPidTrap, Int32(bitPattern: mach_task_self_),
                    UInt32(bitPattern: pid), &port)
        if kr == KERN_SUCCESS, port != 0 {
            return "syscall45: 成功 port=0x\(String(port, radix: 16))"
        }
        return "syscall45: ret=\(kr)"
    }

    /// 第 4 步：拿端口 → 枚举一块区 → 读 4 字节 → 释放。
    /// 用 dlsym 方式取端口，避免把上一步的问题混进来。
    func stepReadProof(pid: Int32) -> String {
        guard let tfp = Self.taskForPidFn else { return "读证: tfp 符号缺失" }
        var port: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else { return "读证: 取端口失败 ret=\(kr)" }

        guard let vmRegion = Self.vmRegionFn else { return "读证: vm_region 符号缺失" }
        var address: MachVmAddress = 0
        var size: MachVmSize = 0
        var info: Int32 = 0
        var count: UInt32 = 0
        let rk = vmRegion(port, &address, &size, 9 /* VM_REGION_BASIC_INFO_64 */, &info, &count)
        guard rk == KERN_SUCCESS, size > 0 else { return "读证: vm_region ret=\(rk)" }

        guard let vmRead = Self.vmReadFn else { return "读证: vm_read 符号缺失" }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 4
        let wk = vmRead(port, address, 4, &dataPtr, &dataLen)
        guard wk == KERN_SUCCESS, dataPtr != 0 else { return "读证: vm_read ret=\(wk)" }

        var magic: UInt32 = 0
        if dataLen >= 4, let p = UnsafeRawPointer(bitPattern: dataPtr) {
            magic = p.assumingMemoryBound(to: UInt32.self).pointee
        }
        // 读出来的这块内存是内核给的，必须还回去
        _ = Self.vmDeallocateFn?(port, dataPtr, dataLen)

        return "读证: 区=\(count) head=0x\(String(magic, radix: 16))"
    }
}
