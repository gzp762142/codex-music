import Foundation
import Darwin

/// 读内存探针：**只读**，不写、不 hook、不注入。
///
/// 目标是把「能不能读到游戏内存」这件事变成面板上的可见结果：
/// 1. dlsym 取 `task_for_pid` —— 拿不到就直接报告符号缺失
/// 2. 调用它拿游戏进程的 task port —— 返回码原样报告，不猜
///    （KERN_SUCCESS=0 / KERN_FAILURE=5=权限被挡 / KERN_INVALID_ARGUMENT=4=参数错）
/// 3. 拿到 port 后 `mach_vm_region` 枚举内存区 + `mach_vm_read` 读可执行区头部，
///    用来证明「确实读到了它的内存」而不是只拿到一个没人认的端口号
///
/// 所有 mach 调用都走 dlsym：iOS SDK 不导出 mach_vm_* 的声明，
/// 编译期直接引用会失败（跟 proc_listpids 同一个原因）。
final class MemoryProbe {

    struct Result {
        /// dlsym 是否拿到 task_for_pid
        let symbolFound: Bool
        /// task_for_pid 的返回值（kern_return_t）
        let kernReturn: Int32
        /// 端口号；拿不到时为 0
        let taskPort: UInt32
        /// 枚举到的内存区数量
        let regionCount: Int
        /// 第一个可读区的前 4 字节（Mach-O magic 应为 0xFEEDFACF / 0xFEEDFACE）
        let headMagic: UInt32
        /// 人类可读的状态串，直接贴到面板上
        let summary: String
        let ok: Bool
    }

    // mach 类型（Swift 侧就是 UInt32）
    private typealias MachPort = UInt32
    private typealias KernReturn = Int32
    private typealias MachVmAddress = UInt64
    private typealias MachVmSize = UInt64

    private typealias TaskForPidFn = @convention(c) (MachPort, Int32, UnsafeMutablePointer<MachPort>) -> KernReturn
    private typealias VmRegionFn = @convention(c) (MachPort, UnsafeMutablePointer<MachVmAddress>,
                                                   UnsafeMutablePointer<MachVmSize>, Int32,
                                                   UnsafeMutablePointer<Int32>,
                                                   UnsafeMutablePointer<UInt32>) -> KernReturn
    /// 注意 out 参数用 UInt 而不是 UInt64：Swift 里 vm_offset_t 是 UInt 的别名，
    /// 写成 UInt64 会让 &dataPtr 的类型对不上而编译失败。
    private typealias VmReadFn = @convention(c) (MachPort, MachVmAddress, MachVmSize,
                                                 UnsafeMutablePointer<UInt>,
                                                 UnsafeMutablePointer<MachVmSize>) -> KernReturn

    private static func symbol<T>(_ name: String, as: T.Type) -> T? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static let taskForPidFn = symbol("task_for_pid", as: TaskForPidFn.self)
    private static let vmRegionFn = symbol("mach_vm_region", as: VmRegionFn.self)
    private static let vmReadFn = symbol("mach_vm_read", as: VmReadFn.self)

    /// 面板上显示用：三个符号各自是否解析成功。
    static var symbolSummary: String {
        let a = taskForPidFn != nil ? "task_for_pid=OK" : "task_for_pid=nil"
        let b = vmRegionFn != nil ? "mach_vm_region=OK" : "mach_vm_region=nil"
        let c = vmReadFn != nil ? "mach_vm_read=OK" : "mach_vm_read=nil"
        return "\(a) · \(b) · \(c)"
    }

    /// 对指定 pid 做一次完整探测。
    func probe(pid: Int32) -> Result {
        guard let taskForPid = Self.taskForPidFn else {
            return Result(symbolFound: false, kernReturn: -1, taskPort: 0, regionCount: 0,
                          headMagic: 0,
                          summary: "task_for_pid 符号未找到（dlsym 返回 nil）", ok: false)
        }

        var port: MachPort = 0
        let kr = taskForPid(mach_task_self_, pid, &port)
        if kr != KERN_SUCCESS || port == 0 {
            let why: String
            switch kr {
            case KERN_FAILURE: why = "权限被挡（KERN_FAILURE）"
            case 4: why = "参数错（KERN_INVALID_ARGUMENT）"
            case 5: why = "权限被挡（值=5）"
            default: why = "kern_return=\(kr)"
            }
            return Result(symbolFound: true, kernReturn: kr, taskPort: 0, regionCount: 0,
                          headMagic: 0,
                          summary: "task_for_pid 失败：\(why)", ok: false)
        }

        // 拿到 port 了：枚举一块区并读它的头部，证明端口真能用
        let (regionCount, magic) = inspect(port: port)
        let summary = "task port = 0x\(String(port, radix: 16)) · 区=\(regionCount) · head=0x\(String(magic, radix: 16))"
        return Result(symbolFound: true, kernReturn: kr, taskPort: port,
                      regionCount: regionCount, headMagic: magic, summary: summary, ok: true)
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
        let magic = p?.pointee ?? 0
        return (1, magic)
    }
}
