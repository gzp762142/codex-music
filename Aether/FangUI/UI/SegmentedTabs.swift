import UIKit

/// 分段控件（对应你给的 HTML：`.tabs` + `.tab` + `.glider`）。
///
/// 行为一致：
/// - 一条胶囊轨道，内部一个滑块（glider）在选中的格子上滑动
/// - 点击某一格 → 滑块平移到该格，选中文字变色
/// - 圆角 99px 等价于高度的一半（胶囊）
///
/// 配色按面板的米白底推导，不使用原示例里的蓝色，以免和背景打架。
final class SegmentedTabs: UIView {

    /// 选中项下标变化时回调。
    var onSelect: ((Int) -> Void)?

    private let titles: [String]
    private let track = UIView()
    private let glider = UIView()
    private var labels: [UILabel] = []

    private let trackPadding: CGFloat = 4
    private let cellWidth: CGFloat
    private let cellHeight: CGFloat

    private(set) var selectedIndex = 0

    // 配色：照参考 HTML 的蓝色系 —— 白色轨道 + 浅蓝滑块 + 蓝字。
    // 数值直接取自原示例（#fff / #e6eef9 / #185ee0 / #5a6a82）。
    private let trackColor = UIColor.hex(0xFFFFFF)            // 轨道：#fff 实心白
    private let gliderColor = UIColor.hex(0xE6EEF9)           // 滑块：#e6eef9 浅蓝
    private let gliderShadow = UIColor.hex(0x185EE0, 0.15)    // 滑块投影：蓝调
    private let selectedText = UIColor.hex(0x185EE0)          // 选中文字：#185ee0
    private let normalText = UIColor.hex(0x5A6A82)            // 未选中：#5a6a82
    /// 轨道描边：原示例用蓝色淡影 0 0 1px rgba(24,94,224,.15)
    private let trackBorder = UIColor.hex(0x185EE0, 0.15)

    init(titles: [String], cellWidth: CGFloat = 84, cellHeight: CGFloat = 30) {
        self.titles = titles
        self.cellWidth = cellWidth
        self.cellHeight = cellHeight
        let w = cellWidth * CGFloat(titles.count) + 4 * 2
        let h = cellHeight + 4 * 2
        super.init(frame: CGRect(x: 0, y: 0, width: w, height: h))
        backgroundColor = .clear
        build()
    }

    required init?(coder: NSCoder) { fatalError() }

    /// 轨道自然尺寸（外层布局用）。
    var intrinsicSize: CGSize {
        CGSize(width: cellWidth * CGFloat(titles.count) + 4 * 2, height: cellHeight + 4 * 2)
    }

    private func build() {
        // 轨道
        track.frame = bounds
        track.backgroundColor = trackColor
        track.layer.cornerRadius = bounds.height / 2
        track.layer.cornerCurve = .continuous
        track.layer.borderWidth = 1
        track.layer.borderColor = trackBorder.cgColor
        addSubview(track)

        // 滑块（glider）
        glider.frame = cellFrame(at: 0)
        glider.backgroundColor = gliderColor
        glider.layer.cornerRadius = cellHeight / 2
        glider.layer.cornerCurve = .continuous
        glider.layer.shadowColor = gliderShadow.cgColor
        glider.layer.shadowOpacity = 1
        glider.layer.shadowRadius = 6
        glider.layer.shadowOffset = CGSize(width: 0, height: 2)
        addSubview(glider)

        // 文字格（对应 .tab）
        for (i, title) in titles.enumerated() {
            let l = UILabel(frame: cellFrame(at: i))
            l.text = title
            l.textAlignment = .center
            l.font = .systemFont(ofSize: 14, weight: .medium)
            l.adjustsFontSizeToFitWidth = true
            l.minimumScaleFactor = 0.7
            l.textColor = (i == 0) ? selectedText : normalText
            l.isUserInteractionEnabled = false
            addSubview(l)
            labels.append(l)
        }

        addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(onTap(_:))))
    }

    private func cellFrame(at index: Int) -> CGRect {
        CGRect(x: trackPadding + CGFloat(index) * cellWidth,
               y: trackPadding,
               width: cellWidth, height: cellHeight)
    }

    @objc private func onTap(_ g: UITapGestureRecognizer) {
        let x = g.location(in: self).x
        let idx = Int((x - trackPadding) / cellWidth)
        select(index: idx, animated: true)
    }

    /// 选中某一格：滑块平移过去，文字颜色跟着切。
    func select(index: Int, animated: Bool) {
        let idx = min(max(index, 0), titles.count - 1)
        guard idx != selectedIndex || !animated else { return }
        selectedIndex = idx
        let target = cellFrame(at: idx)
        let updates = {
            self.glider.frame = target
            for (i, l) in self.labels.enumerated() {
                l.textColor = (i == idx) ? self.selectedText : self.normalText
            }
        }
        if animated {
            UIView.animate(withDuration: 0.28, delay: 0,
                           options: [.curveEaseInOut, .beginFromCurrentState],
                           animations: updates)
        } else {
            updates()
        }
        onSelect?(idx)
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        track.frame = bounds
        track.layer.cornerRadius = bounds.height / 2
        glider.layer.cornerRadius = cellHeight / 2
        glider.frame = cellFrame(at: selectedIndex)
        for (i, l) in labels.enumerated() { l.frame = cellFrame(at: i) }
    }
}
