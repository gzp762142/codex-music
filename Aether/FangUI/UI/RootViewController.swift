import UIKit

/// 根控制器：Metal 特效层 + 卡片 + 标题栏 + 分页内容 + 底部玻璃导航
/// 架构对齐 Music 外挂：UIKit 做菜单，Metal 做背景/特效绘制
final class RootViewController: UIViewController {
    /// 面板底色回传：窗口层跟着换底，保证整块画面不透明。
    var onSurfaceColorChange: ((UIColor) -> Void)?
    /// 关闭（收起面板）回传。
    var onRequestClose: (() -> Void)?

    private let state = FangUIState()
    private var palette = Palette.light
    private var lastSurface: UIColor?

    /// 窗口比卡片四周各留这么多，用于渲染卡片阴影。
    static let shadowInset: CGFloat = 14

    private let fxView = MetalFXView(frame: .zero, device: MetalContext.shared.device)
    private let cardShadow = UIView()
    private let cardView = UIView()
    private let dragHandle = UIView()
    private let closeBtn = UIButton(type: .system)
    private let titleLabel = UILabel()
    private let subtitleLabel = UILabel()
    private let brandLabel = UILabel()
    private let brandSub = UILabel()
    private let themeSwitch = UISwitch()
    private let badgeLabel = UILabel()
    /// 诊断行：实时显示窗口/面板/内容尺寸 + 构建标记，用来确认跑的是哪一版。
    private let diagLabel = UILabel()
    private var diagTick = 0
    private let scrollView = UIScrollView()
    private let contentContainer = UIView()
    private let navBar = UIView()
    private var navButtons: [UIButton] = []
    private let navIndicator = UIView()
    private var pages: [UIView & PageSizing] = []
    private var displayLink: CADisplayLink?
    private var linkTarget: WeakDisplayLinkTarget?
    private var lastTs: CFTimeInterval = 0

    private let tabTitles = ["Overview", "Controls", "Colors", "Effects"]
    private let tabSubs = [
        "Buttons, sliders & inputs",
        "Toggles, checks & radios",
        "Palette & color controls",
        "Background FX & motion"
    ]
    /// 底栏图标（SF Symbols，iOS 13 起可用）。
    private let navIcons = ["square.grid.2x2", "slider.horizontal.3",
                            "paintpalette.fill", "sparkles"]

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        view.isOpaque = false

        // 阴影层：窗口比卡片大一圈，阴影落在这里，不会被窗口裁掉。
        cardShadow.layer.shadowColor = UIColor.black.cgColor
        cardShadow.layer.shadowOpacity = 0.22
        cardShadow.layer.shadowRadius = 14
        cardShadow.layer.shadowOffset = CGSize(width: 0, height: 6)
        view.addSubview(cardShadow)

        // 卡片本体：圆角 + 裁剪 + 不透明底色，是画面上唯一的不透明面。
        cardView.clipsToBounds = true
        cardView.layer.cornerRadius = 22
        cardShadow.addSubview(cardView)

        // Metal 点阵 + 光束画在面板内部，作为 FangUI 自己的背景。
        fxView.translatesAutoresizingMaskIntoConstraints = false
        cardView.addSubview(fxView)
        NSLayoutConstraint.activate([
            fxView.topAnchor.constraint(equalTo: cardView.topAnchor),
            fxView.bottomAnchor.constraint(equalTo: cardView.bottomAnchor),
            fxView.leadingAnchor.constraint(equalTo: cardView.leadingAnchor),
            fxView.trailingAnchor.constraint(equalTo: cardView.trailingAnchor)
        ])

        closeBtn.setTitle("✕", for: .normal)
        closeBtn.titleLabel?.font = .systemFont(ofSize: 15, weight: .semibold)
        closeBtn.addTarget(self, action: #selector(onCloseTap), for: .touchUpInside)
        cardView.addSubview(closeBtn)

        brandLabel.font = .systemFont(ofSize: 20, weight: .bold)
        brandLabel.text = "DsTool"
        brandSub.font = .systemFont(ofSize: 11, weight: .medium)
        brandSub.text = "UI THEME KIT · v5"
        titleLabel.font = .systemFont(ofSize: 24, weight: .bold)
        titleLabel.text = tabTitles[0]
        titleLabel.adjustsFontSizeToFitWidth = true
        titleLabel.minimumScaleFactor = 0.7
        subtitleLabel.font = .systemFont(ofSize: 13)
        subtitleLabel.text = tabSubs[0]
        // 顶栏文本一律单行：宽度异常时截断，不要逐字竖排
        [brandLabel, brandSub, titleLabel, subtitleLabel, badgeLabel].forEach {
            $0.numberOfLines = 1
            $0.lineBreakMode = .byTruncatingTail
        }

        diagLabel.font = .monospacedSystemFont(ofSize: 9, weight: .regular)
        diagLabel.numberOfLines = 1
        diagLabel.textAlignment = .center
        diagLabel.alpha = 0.65
        cardView.addSubview(diagLabel)
        badgeLabel.font = .systemFont(ofSize: 13, weight: .medium)
        badgeLabel.text = "  ● Ready  "
        badgeLabel.textAlignment = .center
        badgeLabel.layer.cornerRadius = 15
        badgeLabel.clipsToBounds = true

        themeSwitch.addTarget(self, action: #selector(onTheme), for: .valueChanged)

        [brandLabel, brandSub, titleLabel, subtitleLabel, themeSwitch, badgeLabel].forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
            cardView.addSubview($0)
        }

        scrollView.contentInsetAdjustmentBehavior = .never
        scrollView.alwaysBounceVertical = true
        scrollView.showsVerticalScrollIndicator = true
        scrollView.clipsToBounds = true
        cardView.addSubview(scrollView)

        // 内容容器：宽度锁在滚动视口上，高度由最"高"的页面内容决定。
        contentContainer.translatesAutoresizingMaskIntoConstraints = false
        scrollView.addSubview(contentContainer)
        NSLayoutConstraint.activate([
            contentContainer.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor),
            contentContainer.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor),
            contentContainer.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor),
            contentContainer.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor),
            contentContainer.widthAnchor.constraint(equalTo: scrollView.frameLayoutGuide.widthAnchor)
        ])

        pages = [
            OverviewPage(state: state),
            ControlsPage(state: state),
            ColorsPage(state: state),
            EffectsPage(state: state)
        ]
        (pages[3] as? EffectsPage)?.onBurst = { [weak self] p in
            self?.fxView.emitBurst(at: p, count: 60)
        }
        pages.forEach { p in
            p.translatesAutoresizingMaskIntoConstraints = false
            p.isHidden = true
            contentContainer.addSubview(p)
            p.installContentStackConstraints()
            NSLayoutConstraint.activate([
                p.leadingAnchor.constraint(equalTo: contentContainer.leadingAnchor),
                p.trailingAnchor.constraint(equalTo: contentContainer.trailingAnchor),
                p.topAnchor.constraint(equalTo: contentContainer.topAnchor),
                p.bottomAnchor.constraint(equalTo: contentContainer.bottomAnchor)
            ])
        }
        pages[0].isHidden = false

        navBar.translatesAutoresizingMaskIntoConstraints = false
        navBar.layer.cornerRadius = 29
        navBar.clipsToBounds = false
        cardView.addSubview(navBar)

        navIndicator.backgroundColor = palette.accent
        navIndicator.layer.cornerRadius = 2.5
        navBar.addSubview(navIndicator)

        for (i, title) in tabTitles.enumerated() {
            let b = UIButton(type: .system)
            b.setTitle(title, for: .normal)
            b.titleLabel?.font = .systemFont(ofSize: 11, weight: .regular)
            b.titleEdgeInsets = UIEdgeInsets(top: 26, left: 0, bottom: 0, right: 0)
            b.tag = i
            b.addTarget(self, action: #selector(onTab(_:)), for: .touchUpInside)
            b.translatesAutoresizingMaskIntoConstraints = false

            let icon = UIImageView(image: UIImage(systemName: navIcons[i]))
            icon.contentMode = .scaleAspectFit
            icon.isUserInteractionEnabled = false
            icon.tag = 900 + i
            b.addSubview(icon)

            navBar.addSubview(b)
            navButtons.append(b)
        }

        // 顶栏左侧拖拽把手：按住可把卡片拖到屏幕任意位置。
        dragHandle.backgroundColor = .clear
        dragHandle.addGestureRecognizer(
            UIPanGestureRecognizer(target: self, action: #selector(onDrag(_:)))
        )
        // 长按同一区域：循环方向修正档位。
        let cycle = UILongPressGestureRecognizer(
            target: self, action: #selector(onCycleOrientation(_:))
        )
        cycle.minimumPressDuration = 0.7
        // 放宽位移容差：手指微动不该让长按失败（否则会被 pan 抢走）。
        cycle.allowableMovement = 24
        dragHandle.addGestureRecognizer(cycle)

        // 双指长按整卡：翻转 SpringBoard 托管开关（排查重影用，需重启生效）。
        let hostToggle = UILongPressGestureRecognizer(
            target: self, action: #selector(onToggleHosting(_:))
        )
        hostToggle.numberOfTouchesRequired = 2
        hostToggle.minimumPressDuration = 0.8
        cardView.addGestureRecognizer(hostToggle)
        cardView.addSubview(dragHandle)

        applyPalette(animated: false)
        startDisplayLink()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()

        // 每轮布局都归位：任何方向旋转都在这里被抹掉。
        if view.transform != .identity { view.transform = .identity }

        // 卡片浮在窗口里，四周留出阴影边距。
        cardShadow.frame = view.bounds.insetBy(dx: RootViewController.shadowInset,
                                                dy: RootViewController.shadowInset)
        cardView.frame = cardShadow.bounds

        let W = cardView.bounds.width
        let H = cardView.bounds.height
        let top = view.safeAreaInsets.top
        let bottom = view.safeAreaInsets.bottom
        let pad: CGFloat = 20
        let wide = W >= 620
        let headerH: CGFloat = wide ? 72 : 104

        // 右上角自右向左：关闭 → Ready 徽章 → 主题开关
        let closeSide: CGFloat = 30
        closeBtn.frame = CGRect(x: W - pad - closeSide,
                                y: top + (wide ? 18 : 14),
                                width: closeSide, height: closeSide)
        closeBtn.layer.cornerRadius = closeSide / 2
        themeSwitch.frame = CGRect(x: closeBtn.frame.minX - 12 - 51,
                                   y: closeBtn.frame.midY - 15.5,
                                   width: 51, height: 31)

        badgeLabel.text = (badgeLabel.text ?? "").trimmingCharacters(in: .whitespaces)
        badgeLabel.sizeToFit()
        let badgeW = min(max(badgeLabel.bounds.width + 22, 86), W * 0.45)
        let badgeH: CGFloat = 28
        badgeLabel.layer.cornerRadius = badgeH / 2

        titleLabel.sizeToFit()

        if wide {
            // 单行 header：品牌 | 标题 + 副标题 … 开关 · 徽章 · 关闭
            brandLabel.frame = CGRect(x: pad + 8, y: top + 18, width: 160, height: 24)
            brandSub.frame = CGRect(x: pad + 8, y: top + 42, width: 160, height: 14)
            brandSub.isHidden = false
            subtitleLabel.isHidden = false

            titleLabel.frame = CGRect(x: 176, y: top + 20,
                                      width: titleLabel.bounds.width, height: 30)
            let subX = titleLabel.frame.maxX + 12
            subtitleLabel.frame = CGRect(
                x: subX, y: top + 27,
                width: max(0, themeSwitch.frame.minX - 16 - subX), height: 18
            )
            badgeLabel.frame = CGRect(x: themeSwitch.frame.minX - 12 - badgeW,
                                      y: top + 21, width: badgeW, height: badgeH)
        } else {
            // 窄屏两行 header：上行品牌 + 开关/关闭，下行标题 + 徽章
            brandLabel.frame = CGRect(x: pad + 8, y: top + 14, width: 160, height: 26)
            brandSub.isHidden = true
            subtitleLabel.isHidden = true

            titleLabel.frame = CGRect(x: pad + 8, y: top + 48,
                                      width: min(titleLabel.bounds.width,
                                                 W - pad * 2 - badgeW - 12),
                                      height: 30)
            badgeLabel.frame = CGRect(x: W - pad - badgeW, y: top + 50,
                                      width: badgeW, height: badgeH)
        }

        // 底部玻璃导航
        let navH: CGFloat = 58
        let navW = min(W - 40, 560)
        navBar.frame = CGRect(x: (W - navW) / 2,
                              y: H - navH - 16 - bottom,
                              width: navW, height: navH)
        layoutNav()

        // 内容区：宽度由约束链锁定，高度由页面内容撑开，滚动交给 UIScrollView。
        let contentTop = top + headerH
        let contentBottom = navBar.frame.minY - 34
        scrollView.frame = CGRect(x: pad, y: contentTop,
                                  width: W - pad * 2,
                                  height: max(40, contentBottom - contentTop))

        // 诊断行贴在导航条上方：窗口 / 面板 / 内容尺寸，用来确认版本与几何。
        diagLabel.frame = CGRect(x: pad, y: navBar.frame.minY - 20,
                                 width: W - pad * 2, height: 14)
        // The scroll view must stop below the diagnostic line; keep the
        // navigation capsule above both layers like ImGui's BottomNav.
        navBar.superview?.bringSubviewToFront(navBar)
        navBar.superview?.bringSubviewToFront(diagLabel)

        // 拖拽把手覆盖顶栏左侧品牌区，右侧的开关 / 徽章 / 关闭不受影响。
        dragHandle.frame = CGRect(x: 0, y: 0,
                                  width: min(W * 0.45, 220),
                                  height: top + headerH)
    }

    private func layoutNav() {
        let n = CGFloat(navButtons.count)
        let cellW = navBar.bounds.width / n
        for (i, b) in navButtons.enumerated() {
            b.frame = CGRect(x: CGFloat(i) * cellW, y: 0, width: cellW, height: navBar.bounds.height)
            b.setTitleColor(i == state.page ? palette.accent : palette.textDim, for: .normal)
            b.titleLabel?.font = .systemFont(ofSize: 11, weight: i == state.page ? .semibold : .regular)
            b.titleEdgeInsets = UIEdgeInsets(top: 26, left: 0, bottom: 0, right: 0)
            if let icon = b.viewWithTag(900 + i) {
                let side: CGFloat = 20
                icon.frame = CGRect(x: (b.bounds.width - side) / 2, y: 8,
                                    width: side, height: side)
                (icon as? UIImageView)?.tintColor =
                    i == state.page ? palette.accent : palette.textDim
            }
        }
        updateIndicator(animated: false)
    }

    private func updateIndicator(animated: Bool) {
        let n = CGFloat(navButtons.count)
        let cellW = navBar.bounds.width / n
        let target = cellW * (state.navIndic + 0.5)
        let updates = {
            self.navIndicator.frame = CGRect(x: target - 12, y: 0, width: 24, height: 5)
        }
        if animated {
            UIView.animate(withDuration: 0.35, delay: 0,
                           usingSpringWithDamping: 0.85, initialSpringVelocity: 0.6,
                           options: [], animations: updates)
        } else {
            updates()
        }
    }

    private func startDisplayLink() {
        guard displayLink == nil else { return }
        lastTs = CACurrentMediaTime()
        let proxy = linkTarget ?? WeakDisplayLinkTarget(self)
        linkTarget = proxy
        let link = CADisplayLink(target: proxy, selector: #selector(WeakDisplayLinkTarget.tick(_:)))
        link.add(to: .main, forMode: .common)
        displayLink = link
    }

    /// 由宿主（FangUIBridge）在面板被摘出窗口 / 重新挂上时调用。
    /// 收起后必须停表，否则离屏仍在 60fps 空转。
    func setActive(_ active: Bool) {
        if active {
            startDisplayLink()
        } else {
            displayLink?.invalidate()
            displayLink = nil
        }
    }

    @objc fileprivate func tick() {
        let now = CACurrentMediaTime()
        var dt = CGFloat(now - lastTs)
        lastTs = now
        if dt > 0.1 { dt = 0.1 }

        // 主题过渡（对应 Approach）
        let target: CGFloat = state.dark ? 1 : 0
        state.themeT = FangUIState.approach(state.themeT, target, dt: dt, speed: 8)

        // 导航弹簧（对应 Spring）
        var vel = state.navVel
        state.navIndic = FangUIState.spring(state.navIndic, CGFloat(state.page), vel: &vel, dt: dt)
        state.navVel = vel
        updateIndicator(animated: false)

        // 标题淡入淡出
        if state.titlePage != state.page {
            state.titleFade -= dt / 0.12
            if state.titleFade <= 0 {
                state.titleFade = 0
                state.titlePage = state.page
                titleLabel.text = tabTitles[state.titlePage]
                subtitleLabel.text = tabSubs[state.titlePage]
            }
        } else if state.titleFade < 1 {
            state.titleFade = min(1, state.titleFade + dt / 0.16)
        }
        titleLabel.alpha = state.titleFade
        subtitleLabel.alpha = state.titleFade

        // 主题色连续刷
        let p = Palette.lerp(state.themeT)
        palette = p
        view.backgroundColor = .clear
        cardView.backgroundColor = p.bg
        navBar.backgroundColor = p.navBar
        navIndicator.backgroundColor = p.accent
        closeBtn.backgroundColor = p.accentSoft
        closeBtn.setTitleColor(p.text, for: .normal)
        if lastSurface?.isEqual(p.bg) != true {
            lastSurface = p.bg
            onSurfaceColorChange?(p.bg)
        }
        fxView.accent = p.accent
        fxView.dotColor = p.dotGrid
        fxView.showBeams = state.showBeams
        fxView.showDots = state.showDots
        brandLabel.textColor = p.text
        brandSub.textColor = p.textDim
        titleLabel.textColor = p.text
        subtitleLabel.textColor = p.textDim
        badgeLabel.backgroundColor = p.accentSoft
        badgeLabel.textColor = p.text
        navButtons.enumerated().forEach { i, b in
            b.setTitleColor(i == state.page ? p.accent : p.textDim, for: .normal)
            (b.viewWithTag(900 + i) as? UIImageView)?.tintColor =
                i == state.page ? p.accent : p.textDim
        }
        (pages[state.page] as? PageBuildable)?.rebuild(palette: p)

        // 每半秒刷一次诊断行，避免每帧都做字符串格式化。
        diagTick += 1
        if diagTick % 30 == 1 {
            diagLabel.textColor = p.textDim
            diagLabel.text = FangUIBridge.geometryDescription()
        }
    }

    private func applyPalette(animated: Bool) {
        let p = Palette.lerp(state.themeT)
        palette = p
        view.backgroundColor = .clear
        cardView.backgroundColor = p.bg
        navBar.backgroundColor = p.navBar
        closeBtn.backgroundColor = p.accentSoft
        closeBtn.setTitleColor(p.text, for: .normal)
        if lastSurface?.isEqual(p.bg) != true {
            lastSurface = p.bg
            onSurfaceColorChange?(p.bg)
        }
        navBar.layer.shadowColor = UIColor.black.cgColor
        navBar.layer.shadowOpacity = 0.12
        navBar.layer.shadowRadius = 12
        navBar.layer.shadowOffset = CGSize(width: 0, height: 4)
        brandLabel.textColor = p.text
        brandSub.textColor = p.textDim
        titleLabel.textColor = p.text
        subtitleLabel.textColor = p.textDim
        badgeLabel.backgroundColor = p.accentSoft
        badgeLabel.textColor = p.text
        pages.forEach { $0.rebuild(palette: p) }
        _ = animated
    }

    @objc private func onTheme() {
        state.dark.toggle()
    }

    @objc private func onTab(_ sender: UIButton) {
        guard sender.tag != state.page else { return }
        state.page = sender.tag
        pages.forEach { $0.isHidden = ($0 !== pages[sender.tag]) }
        pages[sender.tag].rebuild(palette: palette)
        scrollView.setContentOffset(.zero, animated: false)
        view.setNeedsLayout()
        UIView.transition(with: contentContainer, duration: 0.2,
                          options: .transitionCrossDissolve, animations: nil)
    }

    @objc private func onCloseTap() {
        onRequestClose?()
    }

    /// 拖拽把手：把悬浮窗口搬到新位置。
    /// 窗口带方向变换时 `frame` 是旋转后的包围盒，平移必须用 center 才准。
    @objc private func onDrag(_ g: UIPanGestureRecognizer) {
        guard let win = view.window else { return }
        let space = win.superview ?? win
        let t = g.translation(in: space)
        g.setTranslation(.zero, in: space)
        FangUIBridge.setPanelCenter(CGPoint(x: win.center.x + t.x,
                                            y: win.center.y + t.y))
    }

    /// 长按品牌区：循环切换方向修正（在设备上找回正确的变换，不用重编）。
    @objc private func onCycleOrientation(_ g: UILongPressGestureRecognizer) {
        guard g.state == .began else { return }
        let label = FangUIBridge.cycleOrientationFix()
        badgeLabel.text = "  ● \(label)  "
        view.setNeedsLayout()
    }

    /// 双指长按整卡：循环本地窗口层级档位（运行期生效），用来找到
    /// 「只剩一份面板」的那一档。
    @objc private func onToggleHosting(_ g: UILongPressGestureRecognizer) {
        guard g.state == .began else { return }
        let name = FangUIBridge.cycleLocalLevel()
        badgeLabel.text = "  ● lv \(name)  "
        view.setNeedsLayout()
    }

    deinit {
        displayLink?.invalidate()
    }
}

/// `CADisplayLink(target:)` 会强引用 target，`deinit { invalidate() }` 因此永远跑不到。
/// 用弱代理打破这个环，收起面板后控制器才能正常释放。
private final class WeakDisplayLinkTarget {
    weak var target: RootViewController?

    init(_ target: RootViewController) {
        self.target = target
    }

    @objc func tick(_ link: CADisplayLink) {
        target?.tick()
    }
}
