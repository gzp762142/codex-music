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
        DispatchQueue.global(qos: .userInitiated).async {
            var error: UnsafePointer<CChar>?
            let ok = km_init(&error)
            if ok {
                var buffer = [CChar](repeating: 0, count: 512)
                km_self_test(&buffer, buffer.count)
                print("[KernelMemory] ready\n" + String(cString: buffer))
            } else {
                let reason = error.map { String(cString: $0) } ?? "unknown"
                print("[KernelMemory] not available: " + reason)
            }
        }
        return true
    }

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
