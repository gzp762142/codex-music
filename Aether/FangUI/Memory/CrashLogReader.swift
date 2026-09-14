import Foundation

/// 读系统的崩溃报告（.ips），把最后的崩溃原因和栈顶几帧抠出来显示。
///
/// 为什么需要它：进程内的 signal 处理器抓不到**被系统直接杀掉**的情况
/// （SIGKILL / watchdog / jetsam），那种闪退只有系统写的 .ips 里才有记录。
/// 本 App 带 no-sandbox / kTCCServiceSystemPolicyAllFiles，可以直接读。
final class CrashLogReader {

    /// 候选目录，按可能性排序。iOS 17 前后路径不同，都试一遍。
    private static let dirs: [String] = [
        "/var/mobile/Library/Logs/CrashReporter",
        "/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs",
        "/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs/Retired",
        "/var/mobile/Library/Logs/CrashReporter/Retired"
    ]

    /// 列出崩溃报告目录里的全部 .ips（按时间倒序），并标出是谁的。
    ///
    /// 为什么需要它：JetsamEvent 里**没有**游戏 → 游戏不是被内存杀的 →
    /// 那它要么死于某个信号（会留下 ShadowTracker*.ips），要么被 SIGKILL
    /// （不留下任何报告）。这两种情况的下一步完全不同，所以要先看目录里有什么。
    static func listReports(limit: Int = 24) -> [String] {
        let fm = FileManager.default
        let scanDirs = dirs + ["/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs"]
        var all: [(name: String, date: Date)] = []

        for dir in scanDirs {
            guard let items = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for name in items where name.hasSuffix(".ips") {
                let path = dir + "/" + name
                let d = (try? URL(fileURLWithPath: path)
                    .resourceValues(forKeys: [.contentModificationDateKey]))?
                    .contentModificationDate ?? .distantPast
                all.append((name, d))
            }
        }
        guard !all.isEmpty else {
            return ["崩溃报告目录为空或不可读", "已扫:"] + scanDirs.map { "  " + $0 }
        }
        all.sort { $0.date > $1.date }

        var rows: [String] = ["崩溃报告共 \(all.count) 份（按时间倒序）"]
        for item in all.prefix(limit) {
            var mark = ""
            if item.name.hasPrefix("ShadowTracker") { mark = "  ◀ 游戏" }
            else if item.name.hasPrefix("Music") { mark = "  ◀ 我们" }
            else if item.name.lowercased().hasPrefix("jetsam") { mark = "  (jetsam)" }
            rows.append("  " + item.name.replacingOccurrences(of: ".ips", with: "") + mark)
        }
        if all.count > limit { rows.append("  …还有 \(all.count - limit) 份") }
        return rows
    }

    /// 找最新的 Music 崩溃报告并返回摘要；找不到返回 nil。
    static func latestSummary() -> String? {
        let fm = FileManager.default
        var newest: URL?
        var newestDate = Date.distantPast

        for dir in dirs {
            guard let items = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for name in items {
                guard name.hasPrefix("Music"), name.hasSuffix(".ips") else { continue }
                let url = URL(fileURLWithPath: dir).appendingPathComponent(name)
                let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
                    .contentModificationDate ?? .distantPast
                if date > newestDate {
                    newestDate = date
                    newest = url
                }
            }
        }

        guard let url = newest,
              let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        return summarize(text, name: url.lastPathComponent)
    }

    /// .ips 是「一行 JSON + 一段 JSON 正文」，只挑关键字段，整篇太长了。
    private static func summarize(_ text: String, name: String) -> String {
        var out: [String] = ["file: \(name)"]

        // 头部那行 JSON 里有 bug_type / 时间
        if let firstLine = text.split(separator: "\n").first,
           let data = firstLine.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let bt = obj["bug_type"] { out.append("bug_type=\(bt)") }
            if let ts = obj["timestamp"] { out.append("at \(ts)") }
        }

        // reason / exception / termination 三选一
        for key in ["\"termination\"", "\"exception\"", "\"reason\""] {
            if let range = text.range(of: key) {
                let tail = text[range.lowerBound...].prefix(240)
                let oneLine = tail.split(separator: "\n").joined(separator: " ")
                out.append(oneLine)
                break
            }
        }

        // 栈顶几帧
        if let fr = text.range(of: "\"frames\"") {
            let tail = text[fr.upperBound...].prefix(400)
            let cleaned = tail.replacingOccurrences(of: "\n", with: " ")
                .replacingOccurrences(of: "  ", with: " ")
            out.append(String(cleaned))
        }
        return out.joined(separator: "\n")
    }
}
