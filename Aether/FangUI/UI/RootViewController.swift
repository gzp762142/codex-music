import UIKit

/// 极简面板：**只有一个菜单，菜单上只有背景**。
///
/// 刻意不包含：顶部标题栏、品牌、标题、副标题、主题开关、状态徽章、
/// 页签导航、四页内容、关闭按钮、诊断行。
/// 唯一保留的交互是拖动 —— 它属于窗口本身，不是控件。
///
/// 几何全部走 frame（viewDidLayoutSubviews），不引入任何 Auto Layout 约束：
/// 历史提交里两次布局错乱都来自「手写 frame 与 Auto Layout 混用」。
final class RootViewController: UIViewController {

    /// 窗口比卡片四周各大这么多，用来容纳阴影。
    static let shadowInset: CGFloat = 14

    /// 面板不透明底色，回传给 FangUIBridge（窗口层跟着换底）。
    var onSurfaceColorChange: ((UIColor) -> Void)?
    /// 收起回调。极简版没有关闭按钮，保留接口以免桥接处断链。
    var onRequestClose: (() -> Void)?

    /// 承载阴影的容器：它比卡片大 shadowInset，所以阴影不会被裁掉。
    private let cardShadow = UIView()
    /// 菜单本体：圆角 + 背景，上面不放任何控件。
    private let cardView = UIView()
    /// 拖动把手：只有顶栏那一条响应 pan，卡片其余部分不拦手势。
    private let dragHandle = UIView()
    private var dragStartCenter: CGPoint = .zero

    /// 面板底色：取自设计稿的米白背景。
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
        cardView.backgroundColor = surface
        cardShadow.addSubview(cardView)

        dragHandle.backgroundColor = .clear
        dragHandle.addGestureRecognizer(
            UIPanGestureRecognizer(target: self, action: #selector(onDrag(_:)))
        )
        cardView.addSubview(dragHandle)

        onSurfaceColorChange?(surface)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()

        // 每轮布局都归位：任何方向旋转都在这里被抹掉。
        if view.transform != .identity { view.transform = .identity }

        cardShadow.frame = view.bounds.insetBy(dx: Self.shadowInset, dy: Self.shadowInset)
        cardView.frame = cardShadow.bounds
        // 顶部 56pt 作为拖动条；其余区域完全留白。
        dragHandle.frame = CGRect(x: 0, y: 0,
                                  width: cardView.bounds.width, height: 56)
    }

    /// 由宿主在面板被摘出窗口 / 重新挂上时调用。极简版没有动画，只保留接口。
    func setActive(_ active: Bool) {
        _ = active
    }

    // MARK: - 拖动

    @objc private func onDrag(_ g: UIPanGestureRecognizer) {
        guard let superview = cardView.superview else { return }
        let p = g.translation(in: superview)

        switch g.state {
        case .began:
            dragStartCenter = cardView.center
        case .changed, .ended:
            cardView.center = CGPoint(x: dragStartCenter.x + p.x,
                                      y: dragStartCenter.y + p.y)
            // 用 center 而不是 frame：窗口带方向变换时 frame 是包围盒，不可靠。
            FangUIBridge.setPanelCenter(cardView.center)
        default:
            break
        }
    }
}
