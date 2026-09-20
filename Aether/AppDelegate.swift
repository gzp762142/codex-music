import UIKit

@UIApplicationMain
final class AppDelegate: UIResponder, UIApplicationDelegate {
    let state = AppState()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // 装崩溃捕获：闪退原因写盘，下次进面板能直接读到
        CrashCatcher.install()

        // 后台保活：我们是悬浮窗形态、跑在后台的，系统默认几秒内就挂起线程。
        // Info.plist 里声明了 audio 后台模式还不够 —— 必须真的在播音频才作数。
        BackgroundKeepAlive.shared.start()

        // FangUI 关闭按钮 → 控制台「关闭」→ 自动收起菜单
        FangUIBridge.setPowerCallback { [weak self] on in
            self?.state.setPower(on)
        }

        // 内核内存层自检。kopen 是重操作（PUAFF 要跑几十秒），
        // 放后台队列，绝不出现在启动路径上。
        //
        // 输出必须走 NSLog 而不是 print：我们跑在游戏之上、自己不是前台 app，
        // Swift 的 print 只写 stdout，不进 unified log —— Console.app 和设备
        // 日志都看不到，等于自检结果没有出口。NSLog 会进 unified log，
        // 按子系统/进程过滤就能读到。
        DispatchQueue.global(qos: .userInitiated).async {
            var error: UnsafePointer<CChar>?
            let ok = km_init(&error)
            if ok {
                var buffer = [CChar](repeating: 0, count: 512)
                km_self_test(&buffer, buffer.count)
                // 逐行打，日志面板按行显示更清楚
                let report = String(cString: buffer)
                for line in report.split(separator: "\n", omittingEmptySubsequences: false) {
                    NSLog("[KernelMemory] %@", String(line))
                }
                AppDelegate.kernelNote = "[内核] 就绪 · kbase=0x"
                    + String(km_kernel_base(), radix: 16) + "\n" + report
            } else {
                let reason = error.map { String(cString: $0) } ?? "unknown"
                NSLog("[KernelMemory] not available: %@", reason)
                AppDelegate.kernelNote = "[内核] 不可用：" + reason
            }
            // 置位放最后：状态机和调试页都靠它区分「内核没好」和「真的失败了」
            kernelReady = true
        }
        return true
    }

    // MARK: - 内核层状态（跨线程只读）

    /// `km_init` 是否已经跑完（无论成功还是失败）。
    ///
    /// 为什么需要它：`km_init` 异步、且 PUAFF 要几十秒。在那之前
    /// `km_proc_for_pid` 一律返回 0，而调用方会把它误报成「找不到该进程的 proc」——
    /// 一个假错误。有了这个标志，上层才能说「内核还在初始化」而不是「进程有问题」。
    ///
    /// 写只在 AppDelegate 那个后台闭包里发生一次，读是跨线程的（状态机队列、
    /// 主线程 UI）。是个 bool，用不着加锁。
    static var kernelReady = false

    /// 最近一次内核自检的文本（成功是整份报告，失败是一行原因）。
    static var kernelNote = "[内核] 初始化中…"

    // MARK: UISceneSession

    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let config = UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
        config.delegateClass = SceneDelegate.self
        return config
    }
}
