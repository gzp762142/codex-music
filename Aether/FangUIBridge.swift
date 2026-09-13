import UIKit

// MARK: - Overlay window
/// System-level window (ObjC FangUISystemWindow: _isSystemWindow / _isSecure).
/// FangUI 自绘不透明面板：窗口自带底色，任何区域都不透出桌面 / 下层 app。
final class FangUIOverlayWindow: FangUISystemWindow {
    override func hitTest(_ point: CGPoint, with event: UIEvent?) -> UIView? {
        let v = super.hitTest(point, with: event)
        return v === self ? nil : v
    }

    override var canBecomeKey: Bool { true }
}

// MARK: - Bridge
enum FangUIBridge {
    private static var window: FangUIOverlayWindow?
    private static var keepAlive: Timer?
    private static var onPowerOff: ((Bool) -> Void)?
    private static var observers: [NSObjectProtocol] = []

    /// 面板不透明底色，由 RootViewController 随明暗主题回传。
    private static var surface: UIColor = Palette.light.bg
    /// 面板控制器强引用（视图挂在窗口上，控制器不能被释放）。
    private static var panel: RootViewController?
    /// 用户拖动后的面板中心：心跳重设几何时沿用它，不再回到默认位。
    /// 存 center 而不是 frame —— 窗口带方向变换时 frame 是包围盒，不可靠。
    private static var customCenter: CGPoint?

    /// 已向 SpringBoard 注册过的窗口：同一个窗口只注册一次。
    private static weak var registeredContextWindow: UIWindow?

    /// 菜单是否处于「已开启」。窗口现在是长期存在的，
    /// 所以必须另有一个逻辑开关，否则生命周期通知会把它重新亮出来。
    private static var isOpen = false

    /// SpringBoard 托管开关（排查重影用）。**启动时读取**：
    /// `registerWindowWithContextID:` 没有对应的注销接口，运行期改这个值
    /// 不会撤掉已经注册的托管层，所以只能靠重启生效。
    // Use a versioned key so an old diagnostic toggle cannot silently disable
    // the cross-app menu after upgrading to the single-window implementation.
    private static let hostingKey = "FangUI.SpringBoardHostingEnabled.v2"

    static var hostingEnabled: Bool {
        get {
            if UserDefaults.standard.object(forKey: hostingKey) == nil { return true }
            return UserDefaults.standard.bool(forKey: hostingKey)
        }
        set { UserDefaults.standard.set(newValue, forKey: hostingKey) }
    }

    /// 翻转托管开关，返回新状态；需要重启 App 才生效。
    @discardableResult
    static func toggleHosting() -> Bool {
        hostingEnabled.toggle()
        return hostingEnabled
    }

    /// 拖动把手回调：把面板搬到新位置并记住。
    static func setPanelCenter(_ center: CGPoint) {
        customCenter = center
        guard let w = window else { return }
        applySceneGeometry(w)
    }

    /// 注册给 SpringBoard 的层级：系统级，浮在所有 App 之上。
    /// TrollEngine SHMainWnd: UIWindowLevelStatusBar + 2000
    private static let levelSystem = UIWindow.Level(rawValue: UIWindow.Level.statusBar.rawValue + 2000)

    /// 本地窗口层级档位（可在设备上循环切换，运行期即可生效）。
    ///
    /// 背景：窗口交给 SpringBoard 托管后系统会**再合成一份**，于是
    /// 「App 内两份 / 退出后一份」。两份来自同一份 layer，我们施加的任何变换
    /// 对两份的影响相同，而 SpringBoard 还会叠加屏幕旋转 —— 所以两份的朝向
    /// 必然相差 90°，**只改变换永远只能对一份**。要单份，只能让本地那份不参与合成，
    /// 而「本地层放到哪一档才不被自己场景合成」这件事只能在真机上试出来，
    /// 因此给出这几档而不是写死一个猜测值。
    private static let localLevels: [(name: String, level: UIWindow.Level)] = [
        ("-100", UIWindow.Level(rawValue: -100)),
        ("-1",   UIWindow.Level(rawValue: -1)),
        ("0",    .normal),
        ("sb1",  UIWindow.Level(rawValue: UIWindow.Level.statusBar.rawValue + 1)),
        ("sys",  UIWindow.Level(rawValue: UIWindow.Level.statusBar.rawValue + 2000))
    ]

    // Bump the key so devices that previously persisted the diagnostic `sys`
    // level start with the single-copy production setting.
    private static let levelKey = "FangUI.LocalWindowLevelIndex.v2"

    static var localLevelIndex: Int {
        get {
            let v = UserDefaults.standard.integer(forKey: levelKey)
            return (v >= 0 && v < localLevels.count) ? v : 0
        }
        set {
            let clamped = min(max(newValue, 0), localLevels.count - 1)
            UserDefaults.standard.set(clamped, forKey: levelKey)
        }
    }

    static var localLevel: UIWindow.Level { localLevels[localLevelIndex].level }

    static var localLevelName: String { localLevels[localLevelIndex].name }

    /// 循环本地层级档位；立即生效（无需重启）。
    @discardableResult
    static func cycleLocalLevel() -> String {
        localLevelIndex = localLevelIndex + 1
        if let w = window {
            w.windowLevel = localLevel
            applySceneGeometry(w)
        }
        return localLevelName
    }

    static var isVisible: Bool {
        guard isOpen, let w = window else { return false }
        return !w.isHidden && w.alpha > 0.01
    }

    static func setPowerCallback(_ cb: @escaping (Bool) -> Void) {
        onPowerOff = cb
    }

    static func setVisible(_ visible: Bool) {
        DispatchQueue.main.async {
            if visible { show() } else { hide() }
        }
    }

    // MARK: Show / hide

    private static func show() {
        installLifecycleObserversIfNeeded()
        startOrientationObserver()

        // The registration guard intentionally checks this flag. Set it before
        // creating the first window so makeWindow() can register its context.
        isOpen = true

        // 窗口是**长期单例**：创建一次、注册一次、永不销毁。
        // 每次开关都新建窗口的话，旧窗口的 SpringBoard 托管层不会被注销，
        // 屏幕上就会叠加出好几份面板（实测重影的来源）。
        let w: FangUIOverlayWindow
        if let existing = window {
            w = existing
        } else {
            w = makeWindow()
            window = w
        }

        if panel == nil || panel?.view.superview !== w {
            attachPanel(to: w)
        }
        applySceneGeometry(w)
        // 只让 SpringBoard 托管那份可见：本地窗口保持低位、不抢 key。
        w.windowLevel = localLevel
        w.isHidden = false
        w.alpha = 1
        applySceneGeometry(w)
        CATransaction.flush()
        // Register only after the panel and its final geometry are attached.
        // The operation is idempotent for this context and retries if CA has
        // not assigned a context id yet.
        registerWithSpringBoard(w)
        startKeepAlive()
    }

    private static func makeWindow() -> FangUIOverlayWindow {
        let w = FangUIOverlayWindow(frame: .zero)
        w.windowLevel = localLevel
        // 窗口只覆盖卡片本身（含阴影边距）：卡片不透明，
        // 卡片之外透出桌面或下层 app —— 这才是外挂悬浮菜单的形态。
        w.backgroundColor = .clear
        w.isOpaque = false
        // 宿主 VC 只管窗口状态；面板视图直接挂在窗口上，
        // 绕开 UIKit 对 rootViewController.view 的方向旋转。
        w.rootViewController = FangUIContentHost()
        // Keep this window detached from the application's UIWindowScene.
        // Attaching it to the scene makes UIKit composite a second local copy;
        // SpringBoard hosting is the only compositor for this window.
        // The window still gets a WindowServer context when made visible.
        w.isHidden = false
        CATransaction.flush()
        return w
    }

    /// 保证窗口里只有一份面板视图。
    private static func attachPanel(to w: UIWindow) {
        if let existing = panel, existing.view.superview === w { return }
        panel?.view.removeFromSuperview()

        let content = RootViewController()
        content.onSurfaceColorChange = { color in surface = color }
        content.onRequestClose = { onPowerOff?(false) }
        content.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        w.addSubview(content.view)
        content.setActive(true)
        panel = content
    }

    private static func hide() {
        isOpen = false
        keepAlive?.invalidate()
        keepAlive = nil
        FangUIOrientationBridge.stopObserving()
        // 收起时只摘掉面板视图并隐藏窗口；窗口与它的托管上下文留着复用。
        panel?.setActive(false)
        panel?.view.removeFromSuperview()
        panel = nil
        customCenter = nil
        guard let w = window else { return }
        w.isHidden = true
        w.alpha = 0
        // 关闭多发生在 App 已退到后台时；不 flush 的话隐藏标志可能赶不上挂起。
        CATransaction.flush()
        if w.isKeyWindow {
            if let appWin = UIApplication.shared.windows.first(where: { $0 !== w && !$0.isHidden }) {
                appWin.makeKey()
            }
        }
    }

    /// Cross-app key: SBSAccessibilityWindowHostingController
    /// registerWindowWithContextID:atLevel:
    ///
    /// 只对一个窗口的 contextID 注册一次：同一个窗口重复调用没有意义，
    /// 反而给 SpringBoard 制造重复托管的机会。
    private static func registerWithSpringBoard(_ w: UIWindow) {
        guard isOpen, hostingEnabled else { return }
        if registeredContextWindow === w { return }
        // 关键：注册用的是**系统级**层级，与窗口自身的本地层级无关。
        let ok = FangUISBSHosting.shared().register(w, atLevel: Double(levelSystem.rawValue))
        if ok {
            registeredContextWindow = w
            return
        }
        // Retry once after the window is fully in the hierarchy.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            // 期间可能已收起：不要再给一个关掉的窗口注册。
            guard isOpen, registeredContextWindow !== w else { return }
            if FangUISBSHosting.shared().register(w, atLevel: Double(levelSystem.rawValue)) {
                registeredContextWindow = w
            }
        }
    }

    private static func reassert(_ w: UIWindow) {
        // 菜单处于收起状态时，生命周期通知不该把它重新亮出来（也不该抢 key）。
        guard isOpen else { return }
        applySceneGeometry(w)
        // 本地层级始终压在 App 之下；可见性交给 SpringBoard 那份。
        w.windowLevel = localLevel
        w.isHidden = false
        w.alpha = 1
        // 注册已在窗口创建时完成；这里只在丢失后补一次。
        registerWithSpringBoard(w)
    }

    /// 面板 ＝ 一块悬浮卡片：窗口只覆盖卡片（加上阴影边距）。
    ///
    /// 三处修正：
    /// 1. 布局空间按**界面方向归一化**（长边做宽），不再依赖某一个 API 是否跟手旋转。
    /// 2. 夹取位置用 **旋转后的包围盒**，否则一转就顶出屏幕。
    /// 3. 方向变换可切换（`PanelOrientation`），不再写死 identity。
    private static func applySceneGeometry(_ w: UIWindow) {
        let space = layoutSpace()
        let inset = RootViewController.shadowInset

        // 空间已归一化（横屏时长边 = 宽），这里再夹一次保证卡片宽 > 高。
        let longSide = max(space.width, space.height)
        let shortSide = min(space.width, space.height)
        // Match the original ImGui root window: centered card with 60pt
        // total margin and a 900x620 maximum. The previous proportional
        // 0.58/0.72 sizing compressed the wide layout into a narrow card,
        // stretching Exit and overlapping the title bar.
        let panelW = min(max(longSide - 120, 560), 900)
        let panelH = min(max(shortSide - 120, 420), 620)
        let winSize = CGSize(width: panelW + inset * 2, height: panelH + inset * 2)

        let comp = PanelOrientation.transform()
        // 旋转以中心为轴：先定中心，再用旋转后的半宽半高夹取。
        let rotated = CGRect(origin: .zero, size: winSize).applying(comp)
        let halfW = abs(rotated.width) / 2
        let halfH = abs(rotated.height) / 2

        var center: CGPoint
        if let saved = customCenter {
            center = saved
        } else {
            // 默认正居中。
            center = CGPoint(x: space.midX, y: space.midY)
        }
        // Clamp in the scene's actual coordinate space. Some iPad scenes have
        // a non-zero bounds origin; clamping against zero shifts the panel.
        let minX = space.minX + halfW
        let maxX = max(minX, space.maxX - halfW)
        let minY = space.minY + halfH
        let maxY = max(minY, space.maxY - halfH)
        center.x = min(max(center.x, minX), maxX)
        center.y = min(max(center.y, minY), maxY)

        let changed = w.bounds.size != winSize || w.center != center || w.transform != comp
        if changed {
            w.transform = .identity
            w.bounds = CGRect(origin: .zero, size: winSize)
            w.center = center
            w.transform = comp
            w.setNeedsLayout()
            w.layoutIfNeeded()
        }
        // 宿主视图始终归零；面板视图也不带变换（变换在窗口上）。
        w.rootViewController?.view.transform = .identity
        panel?.view.transform = .identity
        panel?.view.frame = w.bounds
    }

    /// 布局空间：使用 Scene 的实际坐标空间，不再依据方向缓存交换宽高。
    ///
    /// 某些 iPad/SpringBoard 托管场景会短暂返回错误的
    /// `interfaceOrientation`（例如横屏画面返回 portrait）。如果再按这个值
    /// 交换尺寸，面板会按竖屏计算并被放到左上角。coordinateSpace.bounds
    /// 已经是当前显示空间，直接使用它才能保证居中。
    private static func layoutSpace() -> CGRect {
        var size = UIScreen.main.bounds.size
        var origin = CGPoint.zero

        if #available(iOS 13.0, *) {
            if let scene = (window?.windowScene ?? preferredWindowScene()) {
                let b = scene.coordinateSpace.bounds
                if b.width > 0 && b.height > 0 {
                    size = b.size
                    origin = b.origin
                }
            }
        }

        return CGRect(origin: origin, size: size)
    }

    /// 面板几何快照，供诊断行显示。
    ///
    /// 这一行是实机排查的唯一抓手，所以同时给出「进程内有几个我们的窗口」
    /// 和「SpringBoard 托管是否注册成功」——两者组合能区分两种重影来源：
    ///   `#w1 sbsY` + 仍看到两份 → 第二份来自 SpringBoard 的托管层；
    ///   `#w2` 以上            → 进程内真的建了多个窗口。
    static func geometryDescription() -> String {
        let screen = UIScreen.main.bounds.size
        var sceneSize = CGSize.zero
        if #available(iOS 13.0, *) {
            if let scene = (window?.windowScene ?? preferredWindowScene()) {
                sceneSize = scene.coordinateSpace.bounds.size
            }
        }
        let size = window?.bounds.size ?? .zero
        let space = layoutSpace()
        let count = overlayWindowCount()
        let sbs = registeredContextWindow != nil ? "Y" : "N"
        let lv = Int(window?.windowLevel.rawValue ?? 0)
        let ori: String
        switch currentOrientation() {
        case .landscapeLeft: ori = "L"
        case .landscapeRight: ori = "R"
        case .portraitUpsideDown: ori = "U"
        default: ori = "P"
        }
        return String(format: "#w%d sbs%@ lv%d ori%@ %@ · sp %.0f×%.0f · sc %.0f×%.0f · win %.0f×%.0f",
                      count, sbs, lv, ori,
                      PanelOrientation.describe(),
                      space.width, space.height,
                      sceneSize.width, sceneSize.height,
                      size.width, size.height)
    }

    /// 进程内属于我们自己的悬浮窗口数量（正常应为 1）。
    static func overlayWindowCount() -> Int {
        let all = UIApplication.shared.windows
        return all.filter { $0 is FangUIOverlayWindow }.count
    }

    /// 长按品牌区循环切换方向修正。
    @discardableResult
    static func cycleOrientationFix() -> String {
        let fix = PanelOrientation.cycle()
        if let w = window {
            applySceneGeometry(w)
            registerWithSpringBoard(w)
        }
        return fix.label
    }

    /// 当前界面方向。
    ///
    /// **实时 scene 优先**：桥里的缓存可能由兜底探测写入且不会随旋转刷新，
    /// 让它排在活的 scene 之前会把方向冻住。
    static func currentOrientation() -> UIInterfaceOrientation {
        if #available(iOS 13.0, *) {
            if let scene = (window?.windowScene ?? preferredWindowScene()) {
                let o = scene.interfaceOrientation
                let b = scene.coordinateSpace.bounds
                // SpringBoard-hosted windows can report a stale portrait value
                // while the physical scene is landscape. Trust the scene only
                // when its orientation agrees with the actual coordinate-space
                // aspect ratio.
                let physicalLandscape = b.width > b.height
                if o != .unknown && o.isLandscape == physicalLandscape { return o }
            }
        }
        let raw = FangUIOrientationBridge.activeOrientation()
        if let o = UIInterfaceOrientation(rawValue: raw), o != .unknown {
            let b = UIScreen.main.bounds
            if o.isLandscape == (b.width > b.height) { return o }
        }
        switch UIDevice.current.orientation {
        case .landscapeLeft:       return .landscapeRight
        case .landscapeRight:      return .landscapeLeft
        case .portraitUpsideDown:  return .portraitUpsideDown
        default:                   return .portrait
        }
    }

    private static func startOrientationObserver() {
        FangUIOrientationBridge.startObserving { _, _ in
            guard let w = window else { return }
            applySceneGeometry(w)
            registerWithSpringBoard(w)
        }
    }

    // MARK: Keep-alive

    private static func startKeepAlive() {
        keepAlive?.invalidate()
        keepAlive = Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { _ in
            guard let w = window else {
                keepAlive?.invalidate()
                keepAlive = nil
                return
            }
            guard isOpen else { return }
            if w.isHidden {
                reassert(w)
            } else {
                // 方向/层级档位可能变化；保持与当前档位一致。
                if w.windowLevel != localLevel { w.windowLevel = localLevel }
                applySceneGeometry(w)
                // Context IDs can be assigned after the first CA commit. Keep
                // retrying until SpringBoard accepts the one registration;
                // the guard in registerWithSpringBoard prevents duplicates.
                registerWithSpringBoard(w)
            }
        }
        RunLoop.main.add(keepAlive!, forMode: .common)
    }

    private static func installLifecycleObserversIfNeeded() {
        guard observers.isEmpty else { return }
        let nc = NotificationCenter.default
        let names: [Notification.Name] = [
            UIApplication.didEnterBackgroundNotification,
            UIApplication.willEnterForegroundNotification,
            UIApplication.didBecomeActiveNotification,
            UIApplication.willResignActiveNotification
        ]
        for name in names {
            observers.append(nc.addObserver(forName: name, object: nil, queue: .main) { _ in
                guard let w = window else { return }
                reassert(w)
            })
        }
    }

    private static func preferredWindowScene() -> UIWindowScene? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        if let fg = scenes.first(where: { $0.activationState == .foregroundActive }) {
            return fg
        }
        return scenes.first
    }
}

// MARK: - Window state host
/// 空宿主：只提供 key window 需要的 rootViewController 与方向掩码。
/// 面板视图由 FangUIBridge 直接挂在窗口上，绕开 UIKit 按界面方向
/// 对 rootViewController.view 施加的旋转（那正是面板横躺 90° 的来源）。
private final class FangUIContentHost: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        view.isOpaque = false
        view.isUserInteractionEnabled = false
        view.transform = .identity
    }

    override var supportedInterfaceOrientations: UIInterfaceOrientationMask { .all }

    override var prefersHomeIndicatorAutoHidden: Bool { true }
}
