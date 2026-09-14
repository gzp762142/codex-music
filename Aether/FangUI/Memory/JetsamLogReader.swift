import Foundation

/// 读 JetsamEvent 日志。
///
/// **关键点一**：JetsamEvent 的文件名不带进程名（只有时间戳），
/// 而标准崩溃日志是 `<进程名>-<时间>.ips`。按进程名去找永远搜不到 ——
/// 这正是"被内存杀了却看不到报告"的来源。
///
/// **关键点二**：日志里 / 内核给的进程名可能是**截断**的（MAXCOMLEN=16），
/// 所以搜目标必须用共同前缀 `ShadowTracker`，不能用完整名 ——
/// 上一版用完整名搜索，导致"目标不在日志中"这个结论不可信。
///
/// 三种 reason：
///   per-process-limit  → 某进程超过自己的 highwater
///   highwater          → 内存压力下选中超水位进程
///   vm-pageshortage    → 系统整体不足
final class JetsamLogReader {

    private static let dirs: [String] = [
        "/var/mobile/Library/Logs/CrashReporter",
        "/var/mobile/Library/Logs",
        "/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs"
    ]

    /// 目标匹配前缀（内核名可能被截断成 ShadowTrackerExt）
    static let targetPrefix = "ShadowTracker"

    static func findLogs() -> [(path: String, date: Date)] {
        let fm = FileManager.default
        var out: [(String, Date)] = []
        for dir in dirs {
            guard let items = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for name in items where name.lowercased().hasPrefix("jetsamevent") {
                let path = dir + "/" + name
                let d = (try? URL(fileURLWithPath: path)
                    .resourceValues(forKeys: [.contentModificationDateKey]))?
                    .contentModificationDate ?? .distantPast
                out.append((path, d))
            }
        }
        return out.sorted { $0.1 > $1.1 }
    }

    /// 生成多行报告（面板表格里逐行显示）。
    static func report() -> [String] {
        let logs = findLogs()
        guard !logs.isEmpty else {
            return ["未找到 JetsamEvent 日志", "已扫目录："]
                + dirs.map { "  " + $0 }
        }

        var rows: [String] = ["JetsamEvent 共 \(logs.count) 份"]
        // 先列时间线，便于跟"哪次崩"对齐
        for (i, l) in logs.prefix(6).enumerated() {
            let name = (l.path as NSString).lastPathComponent
            rows.append("  [\(i)] " + name.replacingOccurrences(of: "JetsamEvent-", with: "")
                        .replacingOccurrences(of: ".ips", with: ""))
        }

        // 最新一份详情
        let path = logs[0].path
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            rows.append("读取失败: " + path)
            return rows
        }
        rows.append("— 最新一份详情 —")
        rows.append("file: " + (path as NSString).lastPathComponent)
        if let r = extract(text, key: "\"reason\"") { rows.append("reason = " + r) }
        if let lp = extract(text, key: "\"largestProcess\"") { rows.append("largest = " + lp) }
        if let bt = extract(text, key: "\"bug_type\"") { rows.append("bug_type = " + bt) }

        // 目标：用前缀搜（不能要求完整名）
        let hasTarget = text.contains(targetPrefix)
        if hasTarget {
            rows.append("目标[\\(targetPrefix)] 在日志中 ✓ rpages=" + String(targetPages(text)))
        } else {
            rows.append("目标[\\(targetPrefix)] 不在日志中 ✗")
        }

        // 把日志里出现过的、带 rpages 的进程名列出来（前 12 个）
        rows.append("— 日志中的进程（名称 + rpages）—")
        rows.append(contentsOf: listProcesses(text, limit: 12))
        return rows
    }

    /// 抠目标进程的 rpages
    private static func targetPages(_ text: String) -> Int {
        guard let r = text.range(of: targetPrefix) else { return 0 }
        let tail = text[r.upperBound...].prefix(1200)
        guard let m = tail.range(of: "\"rpages\"") else { return 0 }
        let after = tail[m.upperBound...]
        let digits = after.drop(while: { !$0.isNumber }).prefix(while: { $0.isNumber })
        return Int(digits) ?? 0
    }

    /// 列出 "<名字>": {... "rpages": N ...} 形式的条目
    private static func listProcesses(_ text: String, limit: Int) -> [String] {
        var out: [String] = []
        for m in text.ranges(of: "\"rpages\"") {
            let after = text[m.upperBound...]
            let digits = after.drop(while: { !$0.isNumber }).prefix(while: { $0.isNumber })
            guard let pages = Int(digits) else { continue }
            // 往回找这个条目所属的进程名：最近的一个 "xxx": { 形式
            let head = text[text.startIndex..<m.lowerBound]
            let back = head.suffix(400)
            var name = "?"
            if let colon = back.lastIndex(of: ":") {
                let before = back[back.startIndex..<colon]
                if let q2 = before.lastIndex(of: "\"") {
                    let quoted = before[before.startIndex..<q2]
                    if let q1 = quoted.lastIndex(of: "\"") {
                        name = String(quoted[quoted.index(after: q1)...])
                    }
                }
            }
            out.append("  " + name + "  rpages=" + String(pages))
            if out.count >= limit { break }
        }
        return out
    }

    private static func extract(_ text: String, key: String) -> String? {
        guard let r = text.range(of: key) else { return nil }
        let tail = text[r.upperBound...].drop(while: { $0 == ":" || $0 == " " })
        guard tail.first == "\"" else { return nil }
        let body = tail.dropFirst()
        guard let end = body.firstIndex(of: "\"") else { return nil }
        return String(body[body.startIndex..<end])
    }
}

private extension String {
    /// 所有匹配位置（避免依赖 NSRegularExpression）
    func ranges(of needle: String) -> [Range<String.Index>] {
        var out: [Range<String.Index>] = []
        var start = startIndex
        while let r = range(of: needle, range: start..<endIndex) {
            out.append(r)
            start = r.upperBound
            if out.count > 400 { break }
        }
        return out
    }
}
