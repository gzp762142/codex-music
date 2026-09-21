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
            /*
             * 置位放最后，但置的是「跑完了」而不是「成功了」。
             *
             * 原先是 `Self.kernelReady = true` 写在 if/else **之外**，也就是
             * km_init 失败时照样把"可用"置成 true —— 而 MemoryProbe 拿这个
             * 标志当自映射快路径的开关（那条路的注释自己写着"暂时关闭"），
             * 于是一个失败的内核层反而把那条没验通的快路径打开了。
             * 现在失败只会让 kernelInitDone 置位，kernelReady 仍然是 false。
             *
             * 静态属性在实例方法里必须带类型前缀，不能裸写 kernelInitDone。
             */
            Self.kernelInitDone = true
        }
        return true
    }

    // MARK: - 内核层状态（跨线程只读）

    /// `km_init` 是否已经**返回过**（无论成功还是失败）。
    ///
    /// 为什么需要它：`km_init` 异步、且 PUAFF 要几十秒。在那之前
    /// `km_proc_for_pid` 一律返回 0，而调用方会把它误报成「找不到该进程的 proc」——
    /// 一个假错误。有了这个标志，上层才能说「内核还在初始化」而不是「进程有问题」。
    ///
    /// 写只在 AppDelegate 那个后台闭包里发生一次，读是跨线程的（状态机队列、
    /// 主线程 UI）。是个 bool，用不着加锁。
    static var kernelInitDone = false

    /// 内核层是否**真的可用**（`km_init` 成功且句柄有效）。
    ///
    /// 为什么必须与 `kernelInitDone` 分开：这两者回答的是不同的问题，
    /// 「还在初始化」和「已经失败」对用户要做的事完全不同 —— 前者等着就行，
    /// 后者得看诊断。合在一个 bool 里就会出现"失败被当成没跑完"这种误报。
    ///
    /// 用 `km_ready()` 而不是再添一个静态标志：那个函数已经带了"句柄有效 &&
    /// 内部步骤全跑完"的判断（`g_kernel_ready && g_handle != 0`），
    /// 是内核层唯一的真相来源。多存一份状态就多一份能不一致的东西。
    /// 它是 C 函数、无副作用，读的开销可以忽略。
    ///
    /// 待办（刻意不改）：这两个标志都是普通 `static var`，跨线程读写没有
    /// volatile / 原子化。真要说风险，是后台线程写、主线程读，理论上可能读到
    /// 旧值 —— 但这只影响提示文案出现的早晚，不会让任何数据路径走错。
    /// 要动就得先定"用原子还是用串行队列发布"，不在本次改动范围。
    static var kernelReady: Bool { km_ready() }

    /// 是否处于「还在初始化」这个中间态（跑起来了、但还没跑完）。
    ///
    /// 调用方拿它给提示语，避免每处都自己拼 `!kernelInitDone && !kernelReady`
    /// 这种双重否定的表达式 —— 那种表达式在几处复制之后总会有一处写反。
    static var kernelInitializing: Bool { !kernelInitDone && !kernelReady }

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
