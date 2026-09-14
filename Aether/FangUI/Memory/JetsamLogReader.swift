import Foundation

/// 读 JetsamEvent 日志。
///
/// 关键点：**JetsamEvent 的文件名不带进程名**（只有时间戳），
/// 而标准崩溃日志是 `<进程名>-<时间>.ips`。按进程名去找会永远搜不到，
/// 这正是"被内存杀了却看不到报告"的来源。
///
/// 三个 reason 的含义：
///   per-process-limit  → 目标超过自己的 highwater（读取顶爆目标的证据）
///   highwater          → 内存压力下选中超水位进程
///   vm-pageshortage    → 系统整体不足
final class JetsamLogReader {

    /// 候选目录。iOS 17 前后路径不同，都扫。
    private static let dirs: [String] = [
        "/var/mobile/Library/Logs/CrashReporter",
        "/var/mobile/Library/Logs",
        "/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs"
    ]

    /// 找所有 JetsamEvent 日志，返回 (路径, 修改时间) 按时间倒序
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

    /// 解析最新一份，挑出最有价值的字段。
    /// 返回 (摘要, 该日志是否提到目标进程, 目标的 rpages)
    static func latestSummary(target: String) -> (String, Bool, Int)? {
        let logs = findLogs()
        guard !logs.isEmpty else { return nil }
        let path = logs[0].path
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }

        let name = (path as NSString).lastPathComponent
        var out: [String] = ["file: \(name)"]

        // reason（三种之一）
        if let r = extract(text, key: "\"reason\"") { out.append("reason=\(r)") }
        // 被杀的最大进程
        if let lp = extract(text, key: "\"largestProcess\"") { out.append("largest=\(lp)") }

        // 目标进程是否出现在日志里，以及它的 rpages
        let hasTarget = text.contains(target)
        var targetPages = 0
        if hasTarget {
            // 形如 "ShadowTrackerExtra": { ..., "rpages": 123456, ... }
            if let range = text.range(of: target) {
                let tail = text[range.upperBound...].prefix(600)
                if let m = tail.range(of: "\"rpages\"") {
                    let after = tail[m.upperBound...]
                    let digits = after.drop(while: { !$0.isNumber }).prefix(while: { $0.isNumber })
                    targetPages = Int(digits) ?? 0
                }
            }
            out.append("目标在日志中 ✓ rpages=\(targetPages)")
        } else {
            out.append("目标不在日志中")
        }
        return (out.joined(separator: " · "), hasTarget, targetPages)
    }

    /// 从 JSON 文本里抠一个字符串字段的原始值（不引 JSONSerialization，日志是流式大文件）
    private static func extract(_ text: String, key: String) -> String? {
        guard let r = text.range(of: key) else { return nil }
        let tail = text[r.upperBound...].drop(while: { $0 == ":" || $0 == " " })
        guard tail.first == "\"" else { return nil }
        let body = tail.dropFirst()
        guard let end = body.firstIndex(of: "\"") else { return nil }
        return String(body[body.startIndex..<end])
    }
}
