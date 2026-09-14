import Foundation
import Darwin

/// 读内存探针：**只读**，不写、不 hook、不注入。
///
/// 目标是把「能不能读到游戏内存」变成面板上的可见结果，分三条通道试：
///   A. dlsym 取 libSystem 的 `task_for_pid`，直接调用
///   B. syscall 直调内核（绕过用户态 hook；若挡人的是内核，结果会一致）
///   C. 拿到端口后确实读一次内存（`mach_vm_region` + `mach_vm_read`），
///      用读回的 Mach-O magic 作为证据 —— 端口号本身证明不了任何事
///
/// mach trap 编号不靠记忆：`syscall` 在编号不存在时返回 ENOSYS(-78)，
/// 所以扫描一段编号，返回码不是 ENOSYS 的那个才是真号。
/// 另有原生命令可对照：`sudo dtrace -n 'syscall::-1:entry'`（需 dtrace 权限）。
final class MemoryProbe {

    struct Result {
        /// A：dlsym 是否解析到 task_for_pid
        let symbolFound: Bool
        /// A：调用返回码
        let symbolReturn: Int32
        /// B：syscall 直调返回码；-78 = ENOSYS 表示 trap 号不存在
        let syscallReturn: Int32
        /// B：实际使用的 trap 号
        let syscallNumber: Int32
        /// 端口（两条通道合起来看，谁成功算谁的）
        let taskPort: UInt32
        let regionCount: Int
        let headMagic: UInt32
        /// 面板上直接显示的结论行
        let summary: String
        /// mach trap 编号扫描结果（面板显示的诊断行）
        let trapScan: String
        let ok: Bool
    }

    private typealias MachPort = UInt32
    private typealias KernReturn = Int32
    private typealias MachVmAddress = UInt64
    private typealias MachVmSize = UInt64

    private typealias TaskForPidFn = @convention(c) (MachPort, Int32, UnsafeMutablePointer<MachPort>) -> KernReturn
    /// syscall 的变参在 arm64 上同样走 x0..x7，所以固定 4 参签名可以调用；
    /// mach trap 第 4 个参数用不上，但为了对齐寄存器仍要传。
    private typealias SyscallFn = @convention(c) (Int32, Int32, UInt32, UnsafeMutablePointer<UInt32>) -> Int32
    private typealias VmRegionFn = @convention(c) (MachPort, UnsafeMutablePointer<MachVmAddress>,
                                                   UnsafeMutablePointer<MachVmSize>, Int32,
                                                   UnsafeMutablePointer<Int32>,
                                                   UnsafeMutablePointer<UInt32>) -> KernReturn
    /// out 参数用 UInt 而不是 UInt64：Swift 里 vm_offset_t 是 UInt 的别名。
    private typealias VmReadFn = @convention(c) (MachPort, MachVmAddress, MachVmSize,
                                                 UnsafeMutablePointer<UInt>,
                                                 UnsafeMutablePointer<MachVmSize>) -> KernReturn

    private static func symbol<T>(_ name: String, as: T.Type) -> T? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static let taskForPidFn = symbol("task_for_pid", as: TaskForPidFn.self)
    private static let syscallFn = symbol("syscall", as: SyscallFn.self)
    private static let vmRegionFn = symbol("mach_vm_region", as: VmRegionFn.self)
    private static let vmReadFn = symbol("mach_vm_read", as: VmReadFn.self)

    /// mach trap 编号比 BSD syscall 表更早，但不同 XNU 版本有出入，
    /// 所以默认从这个号起扫，扫到不是 ENOSYS 的为止。
    private static let trapScanStart: Int32 = 20
    private static let trapScanCount = 24
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
        } else {
            symbolReturn = Int32.min   // 用 Int32.min 表示「符号都没有」
        }

        // 通道 B：只有 A 没成功才试
        var syscallReturn: Int32 = Int32.min
        var usedNumber: Int32 = Self.trapScanStart
        let scanLine = scanMachTrapNumbers()
        if port == 0, let sc = Self.syscallFn {
            let numbers = scanLine.numbers
            for n in numbers {
                var p: MachPort = 0
                let kr = sc(n, Int32(bitPattern: mach_task_self_), UInt32(bitPattern: pid), &p)
                syscallReturn = kr
                usedNumber = n
                if kr == KERN_SUCCESS, p != 0 {
                    port = p
                    break
                }
            }
        }

        let scanText = scanLine.text
        if port == 0 {
            let a = symbolReturn == Int32.min ? "符号缺失" : "ret=\(symbolReturn)"
            let b = syscallReturn == Int32.min ? "未执行" : "trap\(usedNumber) ret=\(syscallReturn)"
            return Result(symbolFound: symbolReturn != Int32.min, symbolReturn: symbolReturn,
                          syscallReturn: syscallReturn, syscallNumber: usedNumber,
                          taskPort: 0, regionCount: 0, headMagic: 0,
                          summary: "取端口失败：A[\(a)] B[\(b)]", trapScan: scanText,
                          ok: false)
        }

        let (regionCount, magic) = inspect(port: port)
        let via = (symbolReturn == KERN_SUCCESS) ? "A:dlsym" : "B:syscall"
        let summary = "读通 \(via) · port=0x\(String(port, radix: 16)) · 区=\(regionCount) · head=0x\(String(magic, radix: 16))"
        return Result(symbolFound: true, symbolReturn: symbolReturn,
                      syscallReturn: syscallReturn, syscallNumber: usedNumber,
                      taskPort: port, regionCount: regionCount, headMagic: magic,
                      summary: summary, trapScan: scanText, ok: true)
    }

    /// 扫一段 mach trap 编号：ENOSYS 之外的返回码说明这个号存在。
    /// 用 pid 0（不可能存在的进程）探号，避免对真实进程反复试。
    private func scanMachTrapNumbers() -> (text: String, numbers: [Int32]) {
        guard let sc = Self.syscallFn else { return ("syscall 符号缺失，无法扫号", []) }
        var hits: [Int32] = []
        var detail: [String] = []
        for i in 0..<Self.trapScanCount {
            let n = Self.trapScanStart + Int32(i)
            var dummy: MachPort = 0
            let kr = sc(n, Int32(bitPattern: mach_task_self_), 0, &dummy)
            if kr != Self.ENOSYS {
                hits.append(n)
                detail.append("\(n)=\(kr)")
            }
        }
        if hits.isEmpty {
            return ("trap 扫描 \(Self.trapScanStart)…\(Self.trapScanStart + Int32(Self.trapScanCount) - 1)：全部 ENOSYS", [])
        }
        return ("trap 命中 " + detail.joined(separator: " "), hits)
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
