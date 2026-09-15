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
