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
    private typealias VmRegionFn = @convention(c) (MachPort, UnsafeMutablePointer<MachVmAddress>,
                                                   UnsafeMutablePointer<MachVmSize>, Int32,
                                                   UnsafeMutablePointer<Int32>,
                                                   UnsafeMutablePointer<UInt32>) -> KernReturn
    private typealias VmReadFn = @convention(c) (MachPort, MachVmAddress, MachVmSize,
                                                 UnsafeMutablePointer<UInt>,
                                                 UnsafeMutablePointer<MachVmSize>) -> KernReturn
    private typealias VmDeallocateFn = @convention(c) (MachPort, UInt, MachVmSize) -> KernReturn

    private static func symbol<T>(_ name: String, as: T.Type) -> T? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static let taskForPidFn = symbol("task_for_pid", as: TaskForPidFn.self)
    private static let vmRegionFn = symbol("mach_vm_region", as: VmRegionFn.self)
    private static let vmReadFn = symbol("mach_vm_read", as: VmReadFn.self)
    private static let vmDeallocateFn = symbol("mach_vm_deallocate", as: VmDeallocateFn.self)

    static var symbolSummary: String {
        let a = taskForPidFn != nil ? "tfp=OK" : "tfp=nil"
        let b = vmRegionFn != nil ? "vm_region=OK" : "vm_region=nil"
        let c = vmReadFn != nil ? "vm_read=OK" : "vm_read=nil"
        let d = vmDeallocateFn != nil ? "vm_dealloc=OK" : "vm_dealloc=nil"
        return "\(a) \(b) \(c) \(d)"
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

    /// 第 3 步：拿端口 → 枚举一块区 → 读 4 字节 → 归还内存。
    func stepReadProof(pid: Int32) -> String {
        guard let tfp = Self.taskForPidFn else { return "读证: tfp 符号缺失" }
        var port: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else {
            return "读证: 取端口失败 \(Self.describe(kr))"
        }

        guard let vmRegion = Self.vmRegionFn else { return "读证: vm_region 符号缺失" }
        var address: MachVmAddress = 0
        var size: MachVmSize = 0
        var info: Int32 = 0
        var count: UInt32 = 0
        let rk = vmRegion(port, &address, &size, 9 /* VM_REGION_BASIC_INFO_64 */, &info, &count)
        guard rk == KERN_SUCCESS, size > 0 else { return "读证: vm_region \(Self.describe(rk))" }

        guard let vmRead = Self.vmReadFn else { return "读证: vm_read 符号缺失" }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 4
        let wk = vmRead(port, address, 4, &dataPtr, &dataLen)
        guard wk == KERN_SUCCESS, dataPtr != 0 else { return "读证: vm_read \(Self.describe(wk))" }

        var magic: UInt32 = 0
        if dataLen >= 4, let p = UnsafeRawPointer(bitPattern: dataPtr) {
            magic = p.assumingMemoryBound(to: UInt32.self).pointee
        }
        // 读出来的这块内存是内核给的，必须还回去，否则每读一次漏一次
        _ = Self.vmDeallocateFn?(port, dataPtr, dataLen)

        return "读证: 区=\(count) head=0x\(String(magic, radix: 16))"
    }
}
