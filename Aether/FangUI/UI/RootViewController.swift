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
    /// 自绘主题开关，对应 ImGui TitleBar 右侧药丸（ui.cpp:625-675）。
    private let themeSwitch = ThemeSwitch()
    private let badgeLabel = UILabel()
    /// 顶栏 logo：对应原 ImGui TitleBar 左侧的「圆底 + DS 纹理」
    /// （ui.cpp:547-565，圆心 min.x+28、半径 18）。原工程用
    /// assets/ds_light.bin / ds_dark.bin 位图，iOS 端没有该资源，
    /// 这里用同尺寸圆底 + 文本做等效还原。
    private let logoDisc = UIView()
    private let logoLabel = UILabel()
    /// 徽章纯文字（不含圆点符号）；配色由 refreshBadge() 按当前主题拼。
    private var badgeRaw = "Ready"
    /// 诊断行：实时显示窗口/面板/内容尺寸 + 构建标记，用来确认跑的是哪一版。
    private let diagLabel = UILabel()
    private var diagTick = 0
    private let scrollView = UIScrollView()
    private let contentContainer = UIView()
    /// 承载四个 page 的垂直 stack：只有可见页参与布局，
    /// 容器高度自动等于当前页内容高度（切页由 isHidden 驱动）。
    private let pageStack = UIStackView()
    private let navBar = UIView()
    private var navButtons: [UIButton] = []
    /// GlassPill 的顶边高光：1pt 白线，透明度按底色亮度算（ui.cpp:558-563）。
    private let navHighlight = UIView()
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
        brandSub.text = "UI THEME KIT"
        titleLabel.font = .systemFont(ofSize: 24, weight: .bold)
        titleLabel.text = tabTitles[0]
        titleLabel.adjustsFontSizeToFitWidth = true
        titleLabel.minimumScaleFactor = 0.7
        subtitleLabel.font = .systemFont(ofSize: 18)
        subtitleLabel.text = tabSubs[0]
        // 顶栏文本一律单行：宽度异常时截断，不要逐字竖排
        [brandLabel, brandSub, titleLabel, subtitleLabel, badgeLabel].forEach {
            $0.numberOfLines = 1
            $0.lineBreakMode = .byTruncatingTail
        }

        diagLabel.font = .monospacedSystemFont(ofSize: 9, weight: .regular)
        diagLabel.numberOfLines = 1
        diagLabel.textAlignment = .center
        // Diagnostics are useful during development but overlap the original
        // ImGui content when the hosted card is scaled. Keep them disabled in
        // the production layout; geometry remains available in the bridge.
        diagLabel.alpha = 0
        cardView.addSubview(diagLabel)
        badgeLabel.font = .systemFont(ofSize: 18, weight: .medium)
        refreshBadge()
        badgeLabel.textAlignment = .center
        badgeLabel.layer.cornerRadius = 14
        badgeLabel.clipsToBounds = true

        themeSwitch.addTarget(self, action: #selector(onTheme), for: .valueChanged)

        // 顶栏这一段（以及下面的 navBar / 导航按钮）全部由
        // viewDidLayoutSubviews 里的 frame 驱动，必须保留默认的
        // translatesAutoresizingMaskIntoConstraints(true)。关掉它却不加约束，
        // Auto Layout 会把这批控件甩到 (0,0)、只留 intrinsic 尺寸 ——
        // 顶栏叠成一团、底部导航整个消失。只有配了约束的
        // fxView / contentContainer / page 才保持 false。
        logoDisc.layer.cornerRadius = 18
        logoDisc.clipsToBounds = true
        logoLabel.font = .systemFont(ofSize: 15, weight: .heavy)
        logoLabel.text = "DS"
        logoLabel.textAlignment = .center
        logoLabel.adjustsFontSizeToFitWidth = true
        logoDisc.addSubview(logoLabel)

        [logoDisc, brandLabel, brandSub, titleLabel, subtitleLabel, themeSwitch, badgeLabel].forEach {
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
        // page 放进垂直 stack：只有可见页参与布局，容器高度就等于当前页的
        // 内容高度。原来四个 page 各自把 top/bottom 都钉死在容器上，于是每个
        // 都被拉成容器等高，contentStack 多出来的垂直空间被 UIStackView 全摊
        // 进 spacing —— 整页控件越拉越开，Dropdown / Text input 被顶出视口。
        pageStack.axis = .vertical
        pageStack.spacing = 0
        pageStack.alignment = .fill
        pageStack.distribution = .fill
        pageStack.translatesAutoresizingMaskIntoConstraints = false
        contentContainer.addSubview(pageStack)
        NSLayoutConstraint.activate([
            pageStack.topAnchor.constraint(equalTo: contentContainer.topAnchor),
            pageStack.leadingAnchor.constraint(equalTo: contentContainer.leadingAnchor),
            pageStack.trailingAnchor.constraint(equalTo: contentContainer.trailingAnchor),
            pageStack.bottomAnchor.constraint(equalTo: contentContainer.bottomAnchor)
        ])

        pages.forEach { p in
            p.isHidden = true
            pageStack.addArrangedSubview(p)
            p.installContentStackConstraints()
        }
        pages[0].isHidden = false

        // navBar / 导航按钮同样只走 frame（见 viewDidLoad 顶栏段说明）。
        navBar.layer.cornerRadius = 29
        navBar.clipsToBounds = false
        cardView.addSubview(navBar)

        navIndicator.backgroundColor = palette.accent
        navIndicator.layer.cornerRadius = 2.5
        navBar.addSubview(navIndicator)

        navHighlight.isUserInteractionEnabled = false
        navBar.addSubview(navHighlight)

        for (i, title) in tabTitles.enumerated() {
            let b = UIButton(type: .system)
            b.tag = i
            b.addTarget(self, action: #selector(onTab(_:)), for: .touchUpInside)
            // 导航按钮只走 frame（layoutNav），保留 autoresizing 转换。
            //
            // 图标和文字都手摆：iOS 15+ 的 UIButton 会被 UIButtonConfiguration
            // 接管，setImage 配 imageEdgeInsets / titleEdgeInsets 会被忽略，
            // 图标整个不显示。原 ImGui 是「图标在左 + 文字在右」水平居中于
            // 格子（ui.cpp:524-534）。
            let icon = UIImageView()
            icon.contentMode = .scaleAspectFit
            icon.isUserInteractionEnabled = false
            icon.tag = 900 + i
            b.addSubview(icon)

            let lab = UILabel()
            lab.text = title
            lab.numberOfLines = 1
            lab.isUserInteractionEnabled = false
            lab.tag = 800 + i
            b.addSubview(lab)

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
        let top: CGFloat = 0
        let pad: CGFloat = 20
        /// 内容左右内边距：原 ImGui 用 cmin.x + 28 / cardW - 56（ui.cpp:725-726）。
        let contentPad: CGFloat = 28
        let wide = W >= 620
        /// 顶栏高度：原 ImGui TitleBar 恒为 64（ui.cpp:720），窄屏另走两行布局。
        let headerH: CGFloat = wide ? 64 : 104
        /// 顶栏垂直中线：原 ImGui 的 cy = (min.y + max.y) * 0.5 = 卡片顶 + 32（ui.cpp:567）。
        let cy = top + headerH * 0.5

        // 右上角自右向左：关闭 → Ready 徽章 → 主题开关。
        // 相对次序对齐原 ImGui：开关在左、徽章在右
        // （ui.cpp:627 的 max.x-224 与 ui.cpp:682 的 max.x-24）；
        // 关闭按钮是本工程新增，挂在最右。
        let closeSide: CGFloat = 30
        closeBtn.frame = CGRect(x: W - pad - closeSide,
                                y: cy - closeSide / 2,
                                width: closeSide, height: closeSide)
        closeBtn.layer.cornerRadius = closeSide / 2

        refreshBadge()
        let badgeW = min(max(badgeLabel.bounds.width + 22, 86), W * 0.45)
        let badgeH: CGFloat = 28
        badgeLabel.layer.cornerRadius = badgeH / 2
        let badgeX = closeBtn.frame.minX - 12 - badgeW
        badgeLabel.frame = CGRect(x: badgeX, y: cy - badgeH / 2,
                                  width: badgeW, height: badgeH)
        themeSwitch.frame = CGRect(x: badgeX - 12 - 56, y: cy - 14,
                                   width: 56, height: 28)

        titleLabel.sizeToFit()

        // logo：原 ImGui 的圆底 + DS 纹理，圆心 min.x+28、半径 18
        // （ui.cpp:548-556）。iOS 端没有 assets/ds_*.bin，用同尺寸圆底 + 文本等效。
        logoDisc.frame = CGRect(x: 10, y: cy - 18, width: 36, height: 36)
        logoDisc.layer.cornerRadius = logoDisc.bounds.width * 0.5
        logoLabel.frame = logoDisc.bounds

        if wide {
            // 单行 header：logo | 品牌 | 标题 + 副标题 … 开关 · 徽章 · 关闭
            // 品牌 x = min.x + 64（ui.cpp:596），两行块竖直居中于 cy。
            brandLabel.frame = CGRect(x: 64, y: cy - 18, width: 160, height: 24)
            brandSub.frame = CGRect(x: 64, y: cy + 5, width: 160, height: 14)
            brandSub.isHidden = false
            subtitleLabel.isHidden = false

            // 标题 x = min.x + 168（ui.cpp:614），字号 24，竖直居中于 cy。
            titleLabel.frame = CGRect(x: 168, y: cy - 15,
                                      width: titleLabel.bounds.width, height: 30)
            let subX = titleLabel.frame.maxX + 16      // ui.cpp:622 scX + scW + 16
            subtitleLabel.frame = CGRect(
                x: subX, y: cy - 9,
                width: max(0, themeSwitch.frame.minX - 16 - subX), height: 18
            )
        } else {
            // 窄屏两行 header：上行 logo + 品牌 + 开关/关闭，下行标题
            brandLabel.frame = CGRect(x: 64, y: top + 14, width: 160, height: 26)
            brandSub.isHidden = true
            subtitleLabel.isHidden = true

            titleLabel.frame = CGRect(x: pad + 8, y: top + 48,
                                      width: min(titleLabel.bounds.width,
                                                 W - pad * 2 - badgeW - 12),
                                      height: 30)
        }

        // 底部玻璃胶囊导航：原 ImGui 固定 navW=560 / navH=58，底边距卡片 16
        // （ui.cpp:467-470）。原版没有安全区概念，这里同样不加 bottom 偏移。
        let navH: CGFloat = 58
        let navW = min(W - 40, 560)
        navBar.frame = CGRect(x: (W - navW) / 2,
                              y: H - navH - 16,
                              width: navW, height: navH)
        layoutNav()
        // GlassPill 顶边高光：从圆角内缩处画到另一端（ui.cpp:560-561）。
        let hairline = 1.0 / max(traitCollection.displayScale, 1)
        navHighlight.frame = CGRect(x: navH * 0.5, y: hairline,
                                    width: max(0, navW - navH), height: hairline)

        // 内容区：宽度由约束链锁定，高度由页面内容撑开，滚动交给 UIScrollView。
        // 对齐 ImGui：内容从标题栏下方 16pt 开始、左右各留 contentPad
        // （ui.cpp:725 的 SetCursorScreenPos(cmin.x + 28, tbMax.y + 16)）。
        let contentTop = top + headerH + 16
        let contentBottom = navBar.frame.minY - 22
        scrollView.frame = CGRect(x: contentPad, y: contentTop,
                                  width: W - contentPad * 2,
                                  height: max(40, contentBottom - contentTop))

        // 诊断行贴在导航条上方：窗口 / 面板 / 内容尺寸，用来确认版本与几何。
        diagLabel.frame = CGRect(x: contentPad, y: navBar.frame.minY - 20,
                                 width: W - contentPad * 2, height: 14)
        // The scroll view must stop below the diagnostic line; keep the
        // navigation capsule above both layers like ImGui's BottomNav.
        navBar.superview?.bringSubviewToFront(navBar)
        navBar.superview?.bringSubviewToFront(diagLabel)

        // 拖拽把手覆盖顶栏左侧品牌区，右侧的开关 / 徽章 / 关闭不受影响。
        dragHandle.frame = CGRect(x: 0, y: 0,
                                  width: min(W * 0.45, 220),
                                  height: top + headerH)
    }

    /// Ready 徽章：原 ImGui 用绿色实心点 + 主色文字（ui.cpp:686-687）。
    /// 这里用同一套配色拼 attributed string，圆点颜色跟随主题的 success。
    /// 主题稳定时 palette 颜色不再变化，用 key 挡掉每帧重建。
    private var badgeCacheKey: String?

    private func refreshBadge() {
        // tick() 每帧都调；主题稳定时 palette 颜色不再变化，用 key 挡掉重建。
        let key = badgeRaw + "|" + palette.text.description + "|" + palette.success.description
        guard key != badgeCacheKey else { return }
        badgeCacheKey = key
        let font = UIFont.systemFont(ofSize: 18, weight: .medium)
        let s = NSMutableAttributedString(
            string: "● ",
            attributes: [.font: font, .foregroundColor: palette.success]
        )
        s.append(NSAttributedString(
            string: badgeRaw,
            attributes: [.font: font, .foregroundColor: palette.text]
        ))
        badgeLabel.attributedText = s
        badgeLabel.sizeToFit()
    }

    /// 底部胶囊的玻璃质感：原 ImGui GlassPill 的细描边 + 顶边高光
    /// （ui.cpp:558-563）。外阴影已在 applyPalette 里设置。
    private func applyNavChrome(_ p: Palette) {
        // 1 物理像素的细描边；写 1.0 在 Retina 上是 2~3 像素，看着像硬边框。
        navBar.layer.borderWidth = 1.0 / max(traitCollection.displayScale, 1)
        navBar.layer.borderColor = p.cardBorder.cgColor
        var cr: CGFloat = 0, cg: CGFloat = 0, cb: CGFloat = 0, ca: CGFloat = 0
        p.card.getRed(&cr, green: &cg, blue: &cb, alpha: &ca)
        // hlA = 0.10 + 0.25 * 底色亮度（浅底更亮，深底收敛）
        let lum = cr * 0.299 + cg * 0.587 + cb * 0.114
        navHighlight.backgroundColor = UIColor(white: 1, alpha: 0.10 + 0.25 * lum)
    }

    private func layoutNav() {
        let n = CGFloat(navButtons.count)
        let cellW = navBar.bounds.width / n
        let h = navBar.bounds.height
        // 原 ImGui: iconSz = 15, gap = 8（ui.cpp:529-530）
        let iconSz: CGFloat = 15
        let gap: CGFloat = 8

        for (i, b) in navButtons.enumerated() {
            let sel = (i == state.page)
            b.frame = CGRect(x: CGFloat(i) * cellW, y: 0, width: cellW, height: h)

            guard let icon = b.viewWithTag(900 + i) as? UIImageView,
                  let lab = b.viewWithTag(800 + i) as? UILabel else { continue }

            // 字号对齐 ImGui 的 io.FontSize（main.cpp 载入的是 18.0f）。
            lab.font = .systemFont(ofSize: 18, weight: sel ? .medium : .regular)
            lab.sizeToFit()
            icon.image = UIImage(systemName: navIcons[i],
                                 withConfiguration: UIImage.SymbolConfiguration(pointSize: 15,
                                                                                weight: .medium))

            let tint = sel ? palette.accent : palette.textDim
            icon.tintColor = tint
            lab.textColor = tint

            // 图标在左 + 文字在右，整组水平居中于格子（ui.cpp:531-534）
            let groupW = iconSz + gap + lab.bounds.width
            let gx = max(4, (cellW - groupW) * 0.5)
            let cy = h * 0.5
            icon.frame = CGRect(x: gx, y: cy - iconSz * 0.5, width: iconSz, height: iconSz)
            lab.frame = CGRect(x: gx + iconSz + gap,
                               y: cy - lab.bounds.height * 0.5,
                               width: lab.bounds.width,
                               height: lab.bounds.height)
        }
        updateIndicator(animated: false)
    }

    private func updateIndicator(animated: Bool) {
        let n = CGFloat(navButtons.count)
        let cellW = navBar.bounds.width / n
        let target = cellW * (state.navIndic + 0.5)
        let updates = {
            // 原 ImGui 的灯条悬在胶囊顶边上方：lampCY = min.y - 2、lampH = 5
            // （ui.cpp:489-490），即 y 从 -4.5 到 +0.5。
            self.navIndicator.frame = CGRect(x: target - 12, y: -4.5, width: 24, height: 5)
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
        applyNavChrome(p)
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
        logoDisc.backgroundColor = p.accentSoft
        logoLabel.textColor = p.text
        themeSwitch.palette = p
        themeSwitch.knobT = state.themeT
        themeSwitch.isDark = state.dark
        badgeLabel.backgroundColor = p.accentSoft
        refreshBadge()
        navButtons.enumerated().forEach { i, b in
            let tint = (i == state.page) ? p.accent : p.textDim
            (b.viewWithTag(900 + i) as? UIImageView)?.tintColor = tint
            (b.viewWithTag(800 + i) as? UILabel)?.textColor = tint
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
        applyNavChrome(p)
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
        logoDisc.backgroundColor = p.accentSoft
        logoLabel.textColor = p.text
        themeSwitch.palette = p
        themeSwitch.knobT = state.themeT
        themeSwitch.isDark = state.dark
        badgeLabel.backgroundColor = p.accentSoft
        refreshBadge()
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
        badgeRaw = label
        view.setNeedsLayout()
    }

    /// 双指长按整卡：循环本地窗口层级档位（运行期生效），用来找到
    /// 「只剩一份面板」的那一档。
    @objc private func onToggleHosting(_ g: UILongPressGestureRecognizer) {
        guard g.state == .began else { return }
        let name = FangUIBridge.cycleLocalLevel()
        badgeRaw = "lv \(name)"
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