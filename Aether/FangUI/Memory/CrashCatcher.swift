import Foundation

/// 崩溃 / 异常捕获，把最后一次崩溃原因写到文件，重启后在面板上显示。
///
/// 目的：没有 Mac、没有日志环境时，闪退原因必须能在面板上读到，而不是靠猜。
///
/// 只做两件事：
/// 1. 装 NSSetUncaughtExceptionHandler 抓 Objective-C/Swift 未捕获异常
/// 2. 用 signal() 给常见致命信号装处理函数，把信号号写盘
///
/// 信号处理函数里只调用异步信号安全的函数（open/write/close），不做任何
/// 分配、不加锁 —— 否则是在崩溃路径上再崩溃。
final class CrashCatcher {

    private static let logFileName = "last_crash.log"

    static var logURL: URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
            .appendingPathComponent(logFileName)
    }

    /// 在 didFinishLaunching 最早期调用。
    static func install() {
        NSSetUncaughtExceptionHandler { ex in
            let text = """
            [uncaught exception] \(ex.name.rawValue)
            reason: \(ex.reason ?? "-")
            \(ex.callStackSymbols.joined(separator: "\n"))
            """
            write(text)
        }

        // 常见致命信号：只记信号号，信息量不大但足以定位是哪一类崩溃
        for sig in [SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGSYS, SIGTRAP, SIGFPE] {
            signal(sig, { signo in
                let msg = "[signal] \(signo)\n"
                if let url = CrashCatcher.logURL {
                    let fd = open(url.path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
                    if fd >= 0 {
                        msg.withCString { ptr in
                            _ = write(fd, ptr, strlen(ptr))
                        }
                        close(fd)
                    }
                }
                // 恢复默认处理并重新抛给系统，保持正常的崩溃行为
                signal(signo, SIG_DFL)
                raise(signo)
            })
        }
    }

    /// 读最后一次崩溃记录；没有就返回 nil。
    static func lastCrash() -> String? {
        guard let url = logURL, let text = try? String(contentsOf: url, encoding: .utf8),
              !text.isEmpty else { return nil }
        return text
    }

    static func clear() {
        guard let url = logURL else { return }
        try? FileManager.default.removeItem(at: url)
    }

    private static func write(_ text: String) {
        guard let url = logURL else { return }
        try? text.write(to: url, atomically: true, encoding: .utf8)
    }
}
