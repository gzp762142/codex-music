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
