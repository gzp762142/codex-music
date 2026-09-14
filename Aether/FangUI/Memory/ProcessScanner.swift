import Foundation

/// 进程枚举 + 目标匹配。
///
/// 只读：不写内存、不 hook、不注入。这一版只负责**找到游戏进程的 pid**。
///
/// 枚举走两条路（互相兜底）：
/// 1. `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)` —— 能拿到 `p_comm`
/// 2. `proc_listpids(PROC_ALL_PIDS)` + `proc_pidpath` —— 拿到 pid 与可执行路径
///
/// 权限：`Music.entitlements` 里已有 `proc_info-allow`，枚举本身不需要额外的
/// `task_for_pid-allow`。后者只在真正去取 task port 读内存时才需要。
final class ProcessScanner {

    struct ProcEntry {
        let pid: Int32
        /// kinfo_proc 的 p_comm（内核只保留前 16 个字符，MAXCOMLEN = 16）
        let comm: String
        /// proc_pidpath 拿到的可执行路径，拿不到就是空串
        let path: String
        /// 是否命中目标匹配词
        let matched: Bool
    }

    /// 匹配词：先精确比对（不区分大小写），再退到小写子串包含。
    /// 注意 p_comm 只有 16 字符，"ShadowTrackerExtra" 会被截成
    /// "ShadowTrackerExt" —— 所以精确词里两个都要留。
    static let exactNames: [String] = ["pubgmhd", "ShadowTrackerExt", "ShadowTracker"]
    static let substrings: [String] = ["pubgmhd", "shadowtracker"]

    private var cachedPID: Int32?
    private var cachedAt: Date = .distantPast
    /// 缓存有效期：这函数会被界面反复调用，全量枚举太贵；但游戏重启会换 pid，
    /// 所以必须有过期时间。
    private let cacheTTL: TimeInterval = 2.0

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

    /// 完整扫描（调试页用）：返回全部进程与匹配结果。
    @discardableResult
    func scan() -> [ProcEntry] {
        var byPID: [Int32: (comm: String, path: String)] = [:]

        for raw in rawSysctlList() {
            byPID[raw.pid] = (raw.comm, "")
        }
        // proc_listpids 兜底 + 补路径
        for pid in rawProcLists() where byPID[pid] == nil {
            byPID[pid] = ("", "")
        }
        for pid in Array(byPID.keys) {
            if byPID[pid]?.path.isEmpty == true, let path = pathFor(pid: pid) {
                byPID[pid] = (byPID[pid]?.comm ?? "", path)
            }
        }

        return byPID
            .map { pid, v in
                ProcEntry(pid: pid, comm: v.comm, path: v.path, matched: Self.matches(comm: v.comm, path: v.path))
            }
            .sorted { $0.pid < $1.pid }
    }

    // MARK: - 匹配

    static func matches(comm: String, path: String) -> Bool {
        let c = comm.lowercased()
        let p = path.lowercased()
        for name in exactNames where c == name.lowercased() {
            return true
        }
        for needle in substrings where c.contains(needle) || p.contains(needle) {
            return true
        }
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

        // 第一段：拿需要的字节数
        guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0, size > 0 else {
            return []
        }
        // 内核在两次调用之间可能又起了新进程，留 20% 余量，避免白跑一次。
        size = Int(Double(size) * 1.2)

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, u_int(mib.count), &buffer, &size, nil, 0) == 0 else {
            return []
        }

        // 用 sizeof 现算元素大小，别用编译期常量，避免对齐/padding 算错。
        let stride = MemoryLayout<kinfo_proc>.stride
        guard stride > 0 else { return [] }
        let count = size / stride
        guard count > 0 else { return [] }

        var result: [RawProc] = []
        result.reserveCapacity(count)

        buffer.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            for i in 0..<count {
                let p = base.advanced(by: i * stride)
                    .assumingMemoryBound(to: kinfo_proc.self)
                let kp = p.pointee
                let pid = kp.kp_proc.p_pid
                if pid <= 0 { continue }
                // p_comm 是定长 char[17]，不是 char*。用 withUnsafeBytes 就地读，
                // 只在闭包内构造 String —— 取局部副本的指针会悬垂。
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

    /// proc_listpids 兜底：只给 pid，不给名字。
    private func rawProcLists() -> [Int32] {
        let maxCount = 4096
        var pids = [Int32](repeating: 0, count: maxCount)
        let byteCount = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids, Int32(maxCount * MemoryLayout<Int32>.size))
        guard byteCount > 0 else { return [] }
        let n = Int(byteCount) / MemoryLayout<Int32>.size
        return pids.prefix(n).filter { $0 > 0 }
    }

    /// 可执行路径。需要 proc_info-allow / no-sandbox，拿不到就返回 nil。
    private func pathFor(pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PROC_PIDPATHINFO_MAXSIZE))
        let n = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard n > 0 else { return nil }
        let path = String(cString: buffer)
        return path.isEmpty ? nil : path
    }
}
