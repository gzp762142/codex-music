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
    /// mach_vm_region 的出参 info 是 vm_region_info_64_t（11 个字的结构体），
    /// 用 raw 指针传递，count 必须显式给出结构体字数 —— 之前把 count 写成 0，
    /// 内核直接以 KERN_INVALID_ARGUMENT 拒掉。
    private typealias VmRegionFn = @convention(c) (MachPort, UnsafeMutablePointer<MachVmAddress>,
                                                   UnsafeMutablePointer<MachVmSize>, Int32,
                                                   UnsafeMutableRawPointer,
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

    /// VM_REGION_BASIC_INFO_64 = 9，对应结构体 vm_region_info_64_t 共 11 个 Int32。
    /// count 是这个结构体的**字数**，不填或填 0 都会 KERN_INVALID_ARGUMENT。
    private static let basicInfo64Flavor: Int32 = 9
    private static let basicInfo64Count: UInt32 = 11
    /// 备选 flavor：VM_REGION_EXTENDED_INFO = 13，结构体 19 个字。
    private static let extendedInfoFlavor: Int32 = 13
    private static let extendedInfoCount: UInt32 = 19

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

    // MARK: - 读证

    /// 枚举第一块区。flavor/count 可切换，用来在对照实验里找出能用的组合。
    /// 返回 (kern_return, address, size)
    private func firstRegion(port: MachPort, flavor: Int32, count: UInt32)
        -> (KernReturn, MachVmAddress, MachVmSize) {
        guard let vmRegion = Self.vmRegionFn else { return (KERN_FAILURE, 0, 0) }
        var address: MachVmAddress = 0
        var size: MachVmSize = 0
        // info 要放下 flavor 对应的结构体：按最大 19 个字备着
        var info = [Int32](repeating: 0, count: 32)
        var words = count
        let kr = info.withUnsafeMutableBytes { buf -> KernReturn in
            vmRegion(port, &address, &size, flavor, buf.baseAddress, &words)
        }
        return (kr, address, size)
    }

    /// **对照实验**：对自己进程跑同一套调用（权限必然足够），
    /// 就能把「参数错」和「权限错」彻底分开。
    /// 对自己失败 → 参数写错了；对自己成功、对游戏失败 → 那才是权限问题。
    static func stepSelfTest() -> String {
        var selfPort: MachPort = 0
        if let tfp = taskForPidFn {
            _ = tfp(mach_task_self_, Int32(ProcessInfo.processInfo.processIdentifier), &selfPort)
        }
        // 拿不到自己的端口就直接用自己的 task 名，够验证参数了
        let port = (selfPort != 0) ? selfPort : mach_task_self_

        var lines: [String] = []
        for (name, flavor, cnt) in [("basic64/11", basicInfo64Flavor, basicInfo64Count),
                                    ("basic64/0", basicInfo64Flavor, 0),
                                    ("extended/19", extendedInfoFlavor, extendedInfoCount)] {
            guard let vmRegion = vmRegionFn else {
                lines.append("\(name): 符号缺失")
                continue
            }
            var address: MachVmAddress = 0
            var size: MachVmSize = 0
            var info = [Int32](repeating: 0, count: 32)
            var words = cnt
            let kr = info.withUnsafeMutableBytes { buf -> KernReturn in
                vmRegion(port, &address, &size, flavor, buf.baseAddress, &words)
            }
            lines.append("\(name)=\(kr)")
        }
        return "自测(本进程) " + lines.joined(separator: " ")
    }

    /// 第 3 步：拿端口 → 枚举一块区 → 读 4 字节 → 归还内存。
    func stepReadProof(pid: Int32) -> String {
        guard let tfp = Self.taskForPidFn else { return "读证: tfp 符号缺失" }
        var port: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else {
            return "读证: 取端口失败 \(Self.describe(kr))"
        }

        // 先用 basic64 + 正确 count；不行再退到 extended
        var (rk, address, size) = firstRegion(port: port, flavor: Self.basicInfo64Flavor,
                                              count: Self.basicInfo64Count)
        var used = "basic64"
        if rk != KERN_SUCCESS {
            (rk, address, size) = firstRegion(port: port, flavor: Self.extendedInfoFlavor,
                                              count: Self.extendedInfoCount)
            used = "extended"
        }
        guard rk == KERN_SUCCESS, size > 0 else {
            return "读证: vm_region[\(used)] \(Self.describe(rk))"
        }

        guard let vmRead = Self.vmReadFn else { return "读证: vm_read 符号缺失" }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 4
        let wk = vmRead(port, address, 4, &dataPtr, &dataLen)
        guard wk == KERN_SUCCESS, dataPtr != 0 else {
            return "读证: vm_read \(Self.describe(wk))"
        }

        var magic: UInt32 = 0
        if dataLen >= 4, let p = UnsafeRawPointer(bitPattern: dataPtr) {
            magic = p.assumingMemoryBound(to: UInt32.self).pointee
        }
        // 读出来的这块内存是内核给的，必须还回去，否则每读一次漏一次
        _ = Self.vmDeallocateFn?(port, dataPtr, dataLen)

        return "读证: [\(used)] 首址=0x\(String(address, radix: 16)) head=0x\(String(magic, radix: 16))"
    }
}
