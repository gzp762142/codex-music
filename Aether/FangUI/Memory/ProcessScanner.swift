import Foundation
import Darwin

/// 进程枚举 + 目标匹配。
///
/// 只读：不写内存、不 hook、不注入。这一版只负责**找到游戏进程的 pid**。
///
/// 两条枚举路径：
/// 1. `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)` —— 拿 pid + p_comm。
///    `<sys/sysctl.h>` 在 iOS SDK 里存在，可以直接链接。
/// 2. `proc_listpids(PROC_ALL_PIDS)` + `proc_pidpath` —— 兜底，并补可执行路径。
///    iOS SDK **没有** `<libproc.h>`（macOS 手册），无法编译期声明；
///    但 libSystem 里有实现，所以用 dlsym 运行时取函数指针。
///    dlsym 返回 nil 时这条路直接跳过，退化成 sysctl 单路，不会崩。
///
/// 权限：`Music.entitlements` 已有 `proc_info-allow`。`task_for_pid-allow`
/// 是下一步（真正读内存）才需要的东西，这一阶段不碰。
final class ProcessScanner {

    struct ProcEntry {
        let pid: Int32
        /// kinfo_proc 的 p_comm（内核只保留前 16 字符，MAXCOMLEN = 16）
        let comm: String
        /// proc_pidpath 拿到的可执行路径；拿不到就是空串
        let path: String
        let matched: Bool
    }

    /// 匹配词：先精确比对（不区分大小写），再退到小写子串包含。
    /// 注意 p_comm 只有 16 字符，"ShadowTrackerExtra" 会被内核截成
    /// "ShadowTrackerExt" —— 所以精确词里两个都留着。
    static let exactNames: [String] = ["pubgmhd", "ShadowTrackerExt", "ShadowTracker"]
    static let substrings: [String] = ["pubgmhd", "shadowtracker"]

    /// libproc.h 里的 PROC_ALL_PIDS。iOS 上没有该头文件，只能自己写死。
    private static let PROC_ALL_PIDS: Int32 = 1
    /// libproc.h 里的 PROC_PIDPATHINFO_MAXSIZE。
    private static let PIDPATH_MAXSIZE = 4096

    private var cachedPID: Int32?
    private var cachedAt: Date = .distantPast
    /// 缓存有效期：界面会反复调这个函数，全量枚举太贵；但游戏重启会换 pid，
    /// 所以必须有 TTL。
    private let cacheTTL: TimeInterval = 2.0

    // MARK: - dlsym

    private typealias ProcListPidsFn = @convention(c) (UInt32, UInt32, UnsafeMutableRawPointer?, Int32) -> Int32
    private typealias ProcPidPathFn = @convention(c) (Int32, UnsafeMutableRawPointer?, UInt32) -> Int32

    /// 运行时解析；libSystem 提供实现但没有公开声明。
    private static let procListPidsPtr: ProcListPidsFn? = {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "proc_listpids") else { return nil }
        return unsafeBitCast(sym, to: ProcListPidsFn.self)
    }()

    private static let procPidPathPtr: ProcPidPathFn? = {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "proc_pidpath") else { return nil }
        return unsafeBitCast(sym, to: ProcPidPathFn.self)
    }()

    /// 供调试页显示：两条路各自是否可用。
    static var channelSummary: String {
        let a = procListPidsPtr != nil ? "proc_listpids=OK" : "proc_listpids=nil"
        let b = procPidPathPtr != nil ? "proc_pidpath=OK" : "proc_pidpath=nil"
        return "\(a) · \(b)"
    }

    // MARK: - 对外

    /// 找游戏进程 pid。找不到返回 nil。
    func findGamePID(forceRefresh: Bool = false) -> Int32? {
        if !forceRefresh, let pid = cachedPID, Date().timeIntervalSince(cachedAt) < cacheTTL {
            return pid
        }
        let hit = scan().first(where: { $0.matched })
        cachedPID = hit?.pid
        cachedAt = Date()
        return cachedPID
    }

    /// 主动失效缓存（调试页的刷新按钮用）。
    func invalidate() {
        cachedPID = nil
        cachedAt = .distantPast
    }

    /// 完整扫描（调试页用）：全部进程 + 匹配结果。
    @discardableResult
    func scan() -> [ProcEntry] {
        var byPID: [Int32: (comm: String, path: String)] = [:]

        for raw in rawSysctlList() {
            byPID[raw.pid] = (raw.comm, "")
        }
        for pid in rawProcLists() where byPID[pid] == nil {
            byPID[pid] = ("", "")
        }
        // 给缺路径的条目补路径（proc_pidpath 可用时才有意义）
        for pid in Array(byPID.keys) where byPID[pid]?.path.isEmpty == true {
            if let path = pathFor(pid: pid) {
                byPID[pid] = (byPID[pid]?.comm ?? "", path)
            }
        }

        return byPID
            .map { pid, v in
                ProcEntry(pid: pid, comm: v.comm, path: v.path,
                          matched: Self.matches(comm: v.comm, path: v.path))
            }
            .sorted { $0.pid < $1.pid }
    }

    // MARK: - 匹配

    static func matches(comm: String, path: String) -> Bool {
        let c = comm.lowercased()
        let p = path.lowercased()
        for name in exactNames where c == name.lowercased() { return true }
        for needle in substrings where c.contains(needle) || p.contains(needle) { return true }
        return false
    }

    // MARK: - 枚举实现

    private struct RawProc {
        let pid: Int32
        let comm: String
    }

    /// sysctl(KERN_PROC_ALL)：两段式调用，先问长度再取数据。
    private func rawSysctlList() -> [RawProc] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0

        guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0, size > 0 else {
            return []
        }
        // 两次调用之间内核可能又起了新进程，留 20% 余量。
        size = Int(Double(size) * 1.2)

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, u_int(mib.count), &buffer, &size, nil, 0) == 0 else {
            return []
        }

        // 元素大小现算，不用编译期常量，避免对齐/padding 算错。
        let elemStride = MemoryLayout<kinfo_proc>.stride
        guard elemStride > 0 else { return [] }
        let count = size / elemStride
        guard count > 0 else { return [] }

        var result: [RawProc] = []
        result.reserveCapacity(count)

        buffer.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            for i in 0..<count {
                let p = base.advanced(by: i * elemStride).assumingMemoryBound(to: kinfo_proc.self)
                let kp = p.pointee
                let pid = kp.kp_proc.p_pid
                if pid <= 0 { continue }
                // p_comm 是定长 char[17]，不是 char*。就地读，只在闭包内构造
                // String —— 取局部副本的指针会悬垂。
                var name = ""
                withUnsafeBytes(of: kp.kp_proc.p_comm) { commBytes in
                    let chars = commBytes.bindMemory(to: CChar.self)
                    if let start = chars.baseAddress {
                        name = String(cString: start)
                    }
                }
                result.append(RawProc(pid: pid, comm: name))
            }
        }
        return result
    }

    /// proc_listpids 兜底：只给 pid，不给名字。符号取不到就返回空。
    private func rawProcLists() -> [Int32] {
        guard let fn = Self.procListPidsPtr else { return [] }
        let maxCount = 4096
        var pids = [Int32](repeating: 0, count: maxCount)
        let byteCount = pids.withUnsafeMutableBytes { buf -> Int32 in
            fn(UInt32(Self.PROC_ALL_PIDS), 0, buf.baseAddress,
               Int32(maxCount * MemoryLayout<Int32>.size))
        }
        guard byteCount > 0 else { return [] }
        let n = Int(byteCount) / MemoryLayout<Int32>.size
        return pids.prefix(n).filter { $0 > 0 }
    }

    /// 可执行路径。符号取不到就返回 nil。
    private func pathFor(pid: Int32) -> String? {
        guard let fn = Self.procPidPathPtr else { return nil }
        var buffer = [CChar](repeating: 0, count: Self.PIDPATH_MAXSIZE)
        let n = buffer.withUnsafeMutableBytes { buf -> Int32 in
            fn(pid, buf.baseAddress, UInt32(Self.PIDPATH_MAXSIZE))
        }
        guard n > 0 else { return nil }
        let path = String(cString: buffer)
        return path.isEmpty ? nil : path
    }
}
