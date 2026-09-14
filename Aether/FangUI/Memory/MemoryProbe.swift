import Foundation
import Darwin

/// 读内存探针：**只读**，不写、不 hook、不注入。
///
/// 两条通道，都只碰「明确知道用途」的调用：
///   A. dlsym 取 libSystem 的 `task_for_pid`
///   B. syscall 直调同一个调用（绕过可能的用户态 hook）
/// 拿到端口后确实读一次内存（`mach_vm_region` + `mach_vm_read`），
/// 用读回的 Mach-O magic 作为「真的读到了它的内存」的证据。
///
/// **不要在这个文件里扫 mach trap 编号。** 上一版做过：在 20…43 区间逐个
/// `syscall(N, ...)` 试探，其中有些编号不是安全的只读调用（thread_switch /
/// mach_msg_trap 那一类），实机上点一下设置就直接闪退。
/// 编号只能一次试一个明确的候选，试之前先想清楚它是什么调用。
final class MemoryProbe {

    struct Result {
        let symbolFound: Bool
        /// A：libSystem 调用返回码
        let symbolReturn: Int32
        /// B：syscall 直调返回码；Int32.min = 未执行
        let syscallReturn: Int32
        /// B 用的 syscall 号
        let syscallNumber: Int32
        let taskPort: UInt32
        let regionCount: Int
        let headMagic: UInt32
        let summary: String
        /// 编号判定说明（面板第二栏）
        let numberNote: String
        let ok: Bool
    }

    private typealias MachPort = UInt32
    private typealias KernReturn = Int32
    private typealias MachVmAddress = UInt64
    private typealias MachVmSize = UInt64

    private typealias TaskForPidFn = @convention(c) (MachPort, Int32, UnsafeMutablePointer<MachPort>) -> KernReturn
    /// syscall 的变参在 arm64 上同样走 x0..x7，所以固定 4 参签名可以调用。
    private typealias SyscallFn = @convention(c) (Int32, Int32, UInt32, UnsafeMutablePointer<UInt32>) -> Int32
    private typealias VmRegionFn = @convention(c) (MachPort, UnsafeMutablePointer<MachVmAddress>,
                                                   UnsafeMutablePointer<MachVmSize>, Int32,
                                                   UnsafeMutablePointer<Int32>,
                                                   UnsafeMutablePointer<UInt32>) -> KernReturn
    /// out 参数用 UInt：Swift 里 vm_offset_t 是 UInt 的别名。
    private typealias VmReadFn = @convention(c) (MachPort, MachVmAddress, MachVmSize,
                                                 UnsafeMutablePointer<UInt>,
                                                 UnsafeMutablePointer<MachVmSize>) -> KernReturn

    /// syscall 号候选。**只放确认过含义的号，绝不做区间遍历。**
    ///
    /// 45 = task_for_pid 的 mach trap 号（已确认）。
    /// 26 已移除：那是 ptrace —— 有副作用、会改目标进程状态的调用，
    /// 为了"试一下"去调它是错的。
    static let syscallCandidates: [Int32] = [45]

    private static func symbol<T>(_ name: String, as: T.Type) -> T? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static let taskForPidFn = symbol("task_for_pid", as: TaskForPidFn.self)
    private static let syscallFn = symbol("syscall", as: SyscallFn.self)
    private static let vmRegionFn = symbol("mach_vm_region", as: VmRegionFn.self)
    private static let vmReadFn = symbol("mach_vm_read", as: VmReadFn.self)

    private static let ENOSYS: Int32 = -78

    static var symbolSummary: String {
        let a = taskForPidFn != nil ? "task_for_pid=OK" : "task_for_pid=nil"
        let b = syscallFn != nil ? "syscall=OK" : "syscall=nil"
        let c = vmReadFn != nil ? "mach_vm_read=OK" : "mach_vm_read=nil"
        return "\(a) · \(b) · \(c)"
    }

    // MARK: - 主流程

    func probe(pid: Int32) -> Result {
        var port: MachPort = 0
        var symbolReturn: Int32 = Int32.min

        // 通道 A：libSystem 符号
        if let taskForPid = Self.taskForPidFn {
            symbolReturn = taskForPid(mach_task_self_, pid, &port)
        }

        // 通道 B：仅在 A 未成功时，逐个试明确的候选号（不做区间遍历）。
        // 每个候选都记录返回码：ENOSYS 说明号不对，其它值说明号存在。
        var syscallReturn: Int32 = Int32.min
        var candidate: Int32 = 0
        var numberNote = "B 未执行（A 已成功或 syscall 符号缺失）"
        if port == 0, let sc = Self.syscallFn {
            var notes: [String] = []
            for n in Self.syscallCandidates {
                var p: MachPort = 0
                let kr = sc(n, Int32(bitPattern: mach_task_self_),
                            UInt32(bitPattern: pid), &p)
                if candidate == 0 { candidate = n }
                syscallReturn = kr
                if kr == KERN_SUCCESS, p != 0 {
                    port = p
                    candidate = n
                    notes.append("\(n)=成功")
                    break
                } else if kr == Self.ENOSYS {
                    notes.append("\(n)=ENOSYS")
                } else {
                    notes.append("\(n)=ret\(kr)")
                }
            }
            numberNote = "B " + notes.joined(separator: " ")
        }

        if port == 0 {
            let a = symbolReturn == Int32.min ? "符号缺失" : "ret=\(symbolReturn)"
            let b = syscallReturn == Int32.min ? "未执行" : "ret=\(syscallReturn)"
            return Result(symbolFound: symbolReturn != Int32.min, symbolReturn: symbolReturn,
                          syscallReturn: syscallReturn, syscallNumber: candidate,
                          taskPort: 0, regionCount: 0, headMagic: 0,
                          summary: "取端口失败：A[\(a)] B[\(b)]", numberNote: numberNote,
                          ok: false)
        }

        let (regionCount, magic) = inspect(port: port)
        let via = (symbolReturn == KERN_SUCCESS) ? "A:dlsym" : "B:syscall"
        let summary = "读通 \(via) · port=0x\(String(port, radix: 16)) · 区=\(regionCount) · head=0x\(String(magic, radix: 16))"
        return Result(symbolFound: true, symbolReturn: symbolReturn,
                      syscallReturn: syscallReturn, syscallNumber: candidate,
                      taskPort: port, regionCount: regionCount, headMagic: magic,
                      summary: summary, numberNote: numberNote, ok: true)
    }

    /// 枚举第一块区并读前 4 字节。
    private func inspect(port: MachPort) -> (Int, UInt32) {
        guard let vmRegion = Self.vmRegionFn else { return (0, 0) }
        var address: MachVmAddress = 0
        var size: MachVmSize = 0
        var info: Int32 = 0
        var count: UInt32 = 0
        let kr = vmRegion(port, &address, &size, 9 /* VM_REGION_BASIC_INFO_64 */, &info, &count)
        guard kr == KERN_SUCCESS, size > 0 else { return (0, 0) }

        guard let vmRead = Self.vmReadFn else { return (1, 0) }
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 4
        let readKr = vmRead(port, address, 4, &dataPtr, &dataLen)
        guard readKr == KERN_SUCCESS, dataPtr != 0, dataLen >= 4 else { return (1, 0) }

        let p = UnsafeRawPointer(bitPattern: dataPtr)?.assumingMemoryBound(to: UInt32.self)
        return (1, p?.pointee ?? 0)
    }
}
