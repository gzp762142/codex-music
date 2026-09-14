import Foundation
import Darwin

/// 崩溃记录文件名（顶层常量，信号处理函数里也要用）。
private let kCrashLogName = "last_crash.log"

/// 把文本追加写进崩溃日志。**必须写成顶层函数**：
/// - 信号处理函数要求异步信号安全，只能用 open/write/close
/// - NSSetUncaughtExceptionHandler / signal 的参数是 C 函数指针，
///   会捕获上下文的闭包（比如引用 self 或静态方法）编译器直接拒绝
private func appendCrashLog(_ text: String) {
    let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
    guard let url = dir?.appendingPathComponent(kCrashLogName) else { return }
    // APPEND + CREATE，避免第二次崩溃把第一次的记录冲掉
    let fd = open(url.path, O_WRONLY | O_CREAT | O_APPEND, 0o644)
    guard fd >= 0 else { return }
    text.withCString { ptr in
        _ = Darwin.write(fd, ptr, strlen(ptr))
    }
    close(fd)
}

/// 未捕获异常处理器：必须是 C 函数，不能是捕获上下文的闭包。
private func uncaughtHandler(_ ex: NSException) {
    let text = "[uncaught] \(ex.name.rawValue)\nreason: \(ex.reason ?? "-")\n"
        + ex.callStackSymbols.joined(separator: "\n") + "\n"
    appendCrashLog(text)
}

/// 致命信号处理器：只写信号号，只调异步信号安全的函数。
private func signalHandler(_ signo: Int32) {
    let msg = "[signal] \(signo)\n"
    let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
    if let url = dir?.appendingPathComponent(kCrashLogName) {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_APPEND, 0o644)
        if fd >= 0 {
            msg.withCString { ptr in
                _ = Darwin.write(fd, ptr, strlen(ptr))
            }
            close(fd)
        }
    }
    // 恢复默认处理并重新抛给系统，保持正常的崩溃行为
    signal(signo, SIG_DFL)
    raise(signo)
}

/// 崩溃 / 异常捕获，把最后一次崩溃原因写到文件，重启后在面板上显示。
///
/// 目的：没有 Mac、没有日志环境时，闪退原因必须能在面板上读到，而不是靠猜。
final class CrashCatcher {

    /// 在 didFinishLaunching 最早期调用。
    static func install() {
        NSSetUncaughtExceptionHandler(uncaughtHandler)
        for sig in [SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGSYS, SIGTRAP, SIGFPE] {
            signal(sig, signalHandler)
        }
    }

    /// 读最后一次崩溃记录；没有就返回 nil。
    static func lastCrash() -> String? {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        guard let url = dir?.appendingPathComponent(kCrashLogName),
              let text = try? String(contentsOf: url, encoding: .utf8),
              !text.isEmpty else { return nil }
        return text
    }

    static func clear() {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        guard let url = dir?.appendingPathComponent(kCrashLogName) else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
