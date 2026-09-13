import UIKit

/// 菜单面板 —— **只有背景，固定居中，不可拖动**。
///
/// 面板内不含任何控件：没有标题栏、品牌、标题、副标题、主题开关、状态徽章、
/// 关闭按钮、页签导航，也没有四页内容（按钮 / 滑块 / 下拉 / 输入框）。
/// 面板整体就是一张背景图。
///
/// 面板本体不接收触摸（没有任何手势），位置由 FangUIBridge 钉在屏幕正中；
/// 唯一可交互的元素是底部居中的分段控件。
///
/// 几何全部走 frame（viewDidLayoutSubviews），不引入 Auto Layout 约束：
/// 历史提交里两次布局错乱都来自「手写 frame 与 Auto Layout 混用」。
final class RootViewController: UIViewController {

    /// 窗口比卡片四周各大这么多，用来容纳阴影。
    static let shadowInset: CGFloat = 14

    /// 面板不透明底色，回传给 FangUIBridge（窗口层跟着换底）。
    var onSurfaceColorChange: ((UIColor) -> Void)?
    /// 收起回调。面板上没有关闭按钮，保留接口以免桥接处断链。
    var onRequestClose: (() -> Void)?

    /// 承载阴影的容器：比卡片大 shadowInset，阴影不会被裁掉。
    private let cardShadow = UIView()
    /// 菜单本体：圆角 + 背景图，上面不放任何子视图，也不接任何手势。
    private let cardView = UIView()
    /// 背景层：柔和的径向渐变，作为菜单的背景图。
    private let backdrop = CAGradientLayer()
    /// 底部分段控件（切换页面用），贴面板底边居中。
    private let tabs = SegmentedTabs(titles: ["概览", "机制", "数据"])
    /// 控件距面板底边的距离。
    private let tabsBottomInset: CGFloat = 20

    /// 背景底色：取自设计稿的米白。
    private var surface: UIColor { Palette.light.card }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
        view.isOpaque = false

        cardShadow.layer.shadowColor = Palette.light.shadow.cgColor
        cardShadow.layer.shadowOpacity = 1
        cardShadow.layer.shadowRadius = 18
        cardShadow.layer.shadowOffset = CGSize(width: 0, height: 8)
        view.addSubview(cardShadow)

        cardView.layer.cornerRadius = 28
        cardView.layer.cornerCurve = .continuous
        cardView.clipsToBounds = true
        cardView.backgroundColor = surface
        cardShadow.addSubview(cardView)

        // 背景图：中上方偏亮、四周略沉，做出柔光纸面的感觉。
        backdrop.type = .radial
        backdrop.colors = [
            UIColor.white.withAlphaComponent(0.75).cgColor,
            UIColor.white.withAlphaComponent(0.0).cgColor
        ]
        backdrop.locations = [0, 1]
        backdrop.startPoint = CGPoint(x: 0.5, y: 0.34)
        backdrop.endPoint = CGPoint(x: 1.15, y: 1.25)
        cardView.layer.addSublayer(backdrop)

        tabs.onSelect = { [weak self] index in
            self?.showPage(index)
        }
        cardView.addSubview(tabs)

        onSurfaceColorChange?(surface)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()

        // 每轮布局都归位：任何方向旋转都在这里被抹掉。
        if view.transform != .identity { view.transform = .identity }

        cardShadow.frame = view.bounds.insetBy(dx: Self.shadowInset, dy: Self.shadowInset)
        cardView.frame = cardShadow.bounds
        // 渐变层不走自动布局，尺寸跟着卡片走。
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        backdrop.frame = cardView.bounds
        CATransaction.commit()

        // 分段控件：水平居中、贴底边；宽度按面板宽度夹一下，
        // 窄面板上不会被挤出圆角。
        let tabsSize = tabs.intrinsicSize
        let tabsW = min(tabsSize.width, cardView.bounds.width - 32)
        tabs.frame = CGRect(x: (cardView.bounds.width - tabsW) / 2,
                            y: cardView.bounds.height - tabsSize.height - tabsBottomInset,
                            width: tabsW,
                            height: tabsSize.height)
    }

    /// 分段控件的落点：先记录下标，页面内容随后再挂。
    private func showPage(_ index: Int) {
        _ = index
    }

    /// 由宿主在面板被摘出窗口 / 重新挂上时调用。面板没有动画，只保留接口。
    func setActive(_ active: Bool) {
        _ = active
    }
}
