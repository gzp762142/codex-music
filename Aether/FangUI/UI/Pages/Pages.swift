import UIKit

protocol PageBuildable: AnyObject {
    func rebuild(palette: Palette)
}

/// 页面统一约定：内容栈宽度跟随页面、高度只由内容决定
/// （不会被容器摊开成巨大间距），超出可视高度时交给外层 UIScrollView。
protocol PageSizing: PageBuildable {
    var contentStack: UIStackView { get }
}

extension PageSizing where Self: UIView {
    /// 用约束把内容栈钉在页面四边：宽度继承页面宽度，高度由内容撑开。
    /// 约束链一路连到窗口，杜绝手工 frame 在异常尺寸下算成 1 字符宽。
    func installContentStackConstraints() {
        contentStack.translatesAutoresizingMaskIntoConstraints = false
        if contentStack.superview == nil {
            addSubview(contentStack)
        }
        NSLayoutConstraint.activate([
            contentStack.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            contentStack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            contentStack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            contentStack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4)
        ])
    }
}

/// 页 0：Overview —— 按钮 / 滑条 / 下拉 / 输入
final class OverviewPage: UIView, PageSizing {
    private let stack = UIStackView()
    var contentStack: UIStackView { stack }
    private let primaryBtn = UIButton(type: .system)
    private let ghostBtn = UIButton(type: .system)
    private let dangerBtn = UIButton(type: .system)
    private var slider: FancySlider!
    private let langButton = UIButton(type: .system)
    private let textField = UITextField()
    private let state: FangUIState

    init(state: FangUIState) {
        self.state = state
        super.init(frame: .zero)
        stack.axis = .vertical
        stack.spacing = 12
        stack.alignment = .fill
        stack.distribution = .fill
        addSubview(stack)

        primaryBtn.setTitle("Primary", for: .normal)
        ghostBtn.setTitle("Ghost", for: .normal)
        dangerBtn.setTitle("Exit", for: .normal)
        let btnRow = UIStackView(arrangedSubviews: [primaryBtn, ghostBtn, dangerBtn])
        btnRow.axis = .horizontal
        btnRow.spacing = 12
        // ImGui uses compact intrinsic button widths. Give each control an
        // explicit width so UIKit cannot stretch the last button to fill the
        // whole row on wide cards.
        btnRow.distribution = .fill
        NSLayoutConstraint.activate([
            primaryBtn.widthAnchor.constraint(equalToConstant: 94),
            ghostBtn.widthAnchor.constraint(equalToConstant: 82),
            dangerBtn.widthAnchor.constraint(equalToConstant: 58)
        ])

        slider = FancySlider(value: state.fpsLimit, min: 30, max: 240, format: "%.0f FPS")
        slider.addTarget(self, action: #selector(onFps), for: .valueChanged)

        langButton.setTitle("Language: English", for: .normal)
        langButton.contentHorizontalAlignment = .left
        langButton.addTarget(self, action: #selector(onLang), for: .touchUpInside)

        textField.borderStyle = .roundedRect
        textField.text = state.textBuf
        textField.addTarget(self, action: #selector(onText), for: .editingChanged)

        for (title, view) in [
            ("BUTTONS", btnRow),
            ("SLIDER", slider as UIView),
            ("DROPDOWN", langButton),
            ("TEXT INPUT", textField)
        ] {
            let sec = SectionLabel()
            sec.text = title
            stack.addArrangedSubview(sec)
            stack.addArrangedSubview(view)
        }
        // Keep the ImGui section rhythm fixed instead of allowing the page
        // height to distribute extra space through the controls.
        for arranged in stack.arrangedSubviews {
            if arranged is SectionLabel {
                arranged.heightAnchor.constraint(equalToConstant: 18).isActive = true
            }
        }
        btnRow.heightAnchor.constraint(equalToConstant: 40).isActive = true
        slider.heightAnchor.constraint(equalToConstant: 44).isActive = true
        langButton.heightAnchor.constraint(equalToConstant: 40).isActive = true
        textField.heightAnchor.constraint(equalToConstant: 40).isActive = true
    }

    required init?(coder: NSCoder) { fatalError() }

    @objc private func onFps() { state.fpsLimit = slider.value }
    @objc private func onText() { state.textBuf = textField.text ?? "" }

    @objc private func onLang() {
        let langs = ["English", "中文", "日本語", "Español"]
        let sheet = UIAlertController(title: "Language", message: nil, preferredStyle: .actionSheet)
        langs.enumerated().forEach { i, name in
            sheet.addAction(UIAlertAction(title: name, style: .default) { _ in
                self.state.langIdx = i
                self.langButton.setTitle("Language: \(name)", for: .normal)
            })
        }
        sheet.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        // UIWindowScene.keyWindow is iOS 15+; walk windows for iOS 13.
        let key = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
        if let root = key?.rootViewController {
            root.present(sheet, animated: true)
        }
    }

    func rebuild(palette: Palette) {
        backgroundColor = .clear
        primaryBtn.backgroundColor = palette.accent
        primaryBtn.setTitleColor(.white, for: .normal)
        primaryBtn.layer.cornerRadius = 12
        primaryBtn.contentEdgeInsets = UIEdgeInsets(top: 10, left: 18, bottom: 10, right: 18)

        ghostBtn.backgroundColor = .clear
        ghostBtn.setTitleColor(palette.accent, for: .normal)
        ghostBtn.layer.cornerRadius = 12
        ghostBtn.layer.borderWidth = 1
        ghostBtn.layer.borderColor = palette.accentSoft.cgColor
        ghostBtn.contentEdgeInsets = primaryBtn.contentEdgeInsets

        dangerBtn.backgroundColor = palette.dangerSoft
        dangerBtn.setTitleColor(palette.danger, for: .normal)
        dangerBtn.layer.cornerRadius = 12
        dangerBtn.contentEdgeInsets = primaryBtn.contentEdgeInsets

        slider.apply(palette: palette)
        langButton.setTitleColor(palette.textDim, for: .normal)
        textField.textColor = palette.text
        textField.backgroundColor = palette.track.withAlphaComponent(0.35)
        textField.attributedPlaceholder = NSAttributedString(
            string: "Type here",
            attributes: [.foregroundColor: palette.textDim]
        )
        stack.arrangedSubviews.forEach {
            if let s = $0 as? SectionLabel { s.textColor = palette.textDim }
            if let r = $0 as? UIStackView {
                r.arrangedSubviews.forEach { ($0 as? UIButton)?.titleLabel?.font = .systemFont(ofSize: 15, weight: .medium) }
            }
        }
    }

}

/// 页 1：Controls —— 勾选 / 开关 / 单选 / 音量 / 质量
final class ControlsPage: UIView, PageSizing {
    private let stack = UIStackView()
    var contentStack: UIStackView { stack }
    private let state: FangUIState
    private var chips: [CheckChip] = []
    private var toggles: [ToggleSwitch] = []
    private var volumeSlider: FancySlider!
    private let qualitySeg = UISegmentedControl(items: ["Low", "Medium", "High", "Ultra"])
    private let radioStack = UIStackView()
    private var radioButtons: [UIButton] = []

    init(state: FangUIState) {
        self.state = state
        super.init(frame: .zero)
        stack.axis = .vertical
        stack.spacing = 10
        addSubview(stack)

        let names = ["Skeleton", "Name", "Distance", "Health", "Map grid", "Warning"]
        let sec1 = SectionLabel(); sec1.text = "TOGGLES"
        stack.addArrangedSubview(sec1)
        for (i, name) in names.enumerated() {
            let chip = CheckChip(title: name, on: state.toggles[i])
            chip.tag = i
            chip.addTarget(self, action: #selector(onChip(_:)), for: .valueChanged)
            chips.append(chip)
            let row = RowView(title: name, control: chip)
            row.tag = 100 + i
            stack.addArrangedSubview(row)
        }

        let sec2 = SectionLabel(); sec2.text = "RADIO"
        stack.addArrangedSubview(sec2)
        radioStack.axis = .horizontal
        radioStack.spacing = 8
        for (i, title) in ["Dynamic", "Fixed", "Auto"].enumerated() {
            let b = UIButton(type: .system)
            b.setTitle(title, for: .normal)
            b.tag = i
            b.addTarget(self, action: #selector(onRadio(_:)), for: .touchUpInside)
            radioButtons.append(b)
            radioStack.addArrangedSubview(b)
        }
        stack.addArrangedSubview(radioStack)

        let sec3 = SectionLabel(); sec3.text = "VOLUME"
        stack.addArrangedSubview(sec3)
        volumeSlider = FancySlider(value: state.volume, min: 0, max: 1, format: "%.0f%%", scale: 100)
        volumeSlider.addTarget(self, action: #selector(onVol), for: .valueChanged)
        stack.addArrangedSubview(volumeSlider)

        let sec4 = SectionLabel(); sec4.text = "QUALITY"
        stack.addArrangedSubview(sec4)
        qualitySeg.selectedSegmentIndex = state.quality
        qualitySeg.addTarget(self, action: #selector(onQuality), for: .valueChanged)
        stack.addArrangedSubview(qualitySeg)
    }

    required init?(coder: NSCoder) { fatalError() }

    @objc private func onChip(_ sender: CheckChip) {
        state.toggles[sender.tag] = sender.isOn
    }

    @objc private func onVol() { state.volume = volumeSlider.value }
    @objc private func onQuality() { state.quality = qualitySeg.selectedSegmentIndex }

    @objc private func onRadio(_ sender: UIButton) {
        state.radio = sender.tag
        radioButtons.forEach {
            $0.backgroundColor = $0.tag == sender.tag ? FangTheme.palette().accentSoft : .clear
        }
    }

    func rebuild(palette: Palette) {
        stack.arrangedSubviews.forEach {
            if let s = $0 as? SectionLabel { s.textColor = palette.textDim }
            if let r = $0 as? RowView {
                r.apply(palette: palette)
                (r.control as? CheckChip)?.apply(palette: palette)
            }
        }
        volumeSlider.apply(palette: palette)
        qualitySeg.selectedSegmentTintColor = palette.accent
        qualitySeg.setTitleTextAttributes([.foregroundColor: palette.text], for: .normal)
        radioButtons.forEach {
            $0.setTitleColor(palette.accent, for: .normal)
            $0.layer.cornerRadius = 10
            $0.contentEdgeInsets = UIEdgeInsets(top: 8, left: 12, bottom: 8, right: 12)
            $0.backgroundColor = $0.tag == state.radio ? palette.accentSoft : .clear
        }
    }

}

/// 页 2：Colors —— 色板 / 取色 / 进度条
final class ColorsPage: UIView, PageSizing {
    private let stack = UIStackView()
    var contentStack: UIStackView { stack }
    private let swatchRow = UIStackView()
    private let progress = UIProgressView(progressViewStyle: .default)
    private let rgbSlider = UISlider()
    private let state: FangUIState
    private var swatchViews: [UIView] = []
    private let swatchNames = ["Accent", "Hover", "Success", "Danger", "Text", "Dim"]

    init(state: FangUIState) {
        self.state = state
        super.init(frame: .zero)
        stack.axis = .vertical
        stack.spacing = 14
        addSubview(stack)

        let sec1 = SectionLabel(); sec1.text = "ACCENT PALETTE"
        stack.addArrangedSubview(sec1)
        swatchRow.axis = .horizontal
        swatchRow.spacing = 10
        swatchRow.distribution = .fillEqually
        for _ in 0..<6 {
            let v = UIView()
            v.layer.cornerRadius = 12
            v.heightAnchor.constraint(equalToConstant: 56).isActive = true
            swatchViews.append(v)
            swatchRow.addArrangedSubview(v)
        }
        stack.addArrangedSubview(swatchRow)

        let sec2 = SectionLabel(); sec2.text = "COLOR / PROGRESS"
        stack.addArrangedSubview(sec2)
        rgbSlider.minimumValue = 0
        rgbSlider.maximumValue = 1
        rgbSlider.value = state.rgb.0
        stack.addArrangedSubview(rgbSlider)
        progress.progress = state.volume
        stack.addArrangedSubview(progress)
    }

    required init?(coder: NSCoder) { fatalError() }

    func rebuild(palette: Palette) {
        let cols = [palette.accent, palette.accentHover, palette.success,
                    palette.danger, palette.text, palette.textDim]
        zip(swatchViews, cols).forEach { v, c in
            v.backgroundColor = c
            v.layer.borderWidth = 1
            v.layer.borderColor = palette.cardBorder.cgColor
        }
        progress.progressTintColor = palette.accent
        progress.trackTintColor = palette.track
        progress.progress = state.volume
        rgbSlider.minimumTrackTintColor = palette.accent
        rgbSlider.maximumTrackTintColor = palette.track
        stack.arrangedSubviews.forEach {
            if let s = $0 as? SectionLabel { s.textColor = palette.textDim }
        }
    }

}

/// 页 3：Effects —— 背景特效开关 / 粒子
final class EffectsPage: UIView, PageSizing {
    private let stack = UIStackView()
    var contentStack: UIStackView { stack }
    private let state: FangUIState
    private let beamsSwitch = UISwitch()
    private let dotsSwitch = UISwitch()
    private let burstBtn = UIButton(type: .system)
    var onBurst: ((CGPoint) -> Void)?

    init(state: FangUIState) {
        self.state = state
        super.init(frame: .zero)
        stack.axis = .vertical
        stack.spacing = 12
        addSubview(stack)

        let sec1 = SectionLabel(); sec1.text = "BACKGROUND FX"
        stack.addArrangedSubview(sec1)

        beamsSwitch.isOn = state.showBeams
        beamsSwitch.addTarget(self, action: #selector(onBeams), for: .valueChanged)
        dotsSwitch.isOn = state.showDots
        dotsSwitch.addTarget(self, action: #selector(onDots), for: .valueChanged)
        stack.addArrangedSubview(RowView(title: "Beam rain (雨丝光束)", control: beamsSwitch))
        stack.addArrangedSubview(RowView(title: "Dot grid (点阵纹理)", control: dotsSwitch))

        let sec2 = SectionLabel(); sec2.text = "PARTICLE BURST"
        stack.addArrangedSubview(sec2)
        burstBtn.setTitle("Burst here!", for: .normal)
        burstBtn.addTarget(self, action: #selector(onBurstTap), for: .touchUpInside)
        stack.addArrangedSubview(burstBtn)

        let sec3 = SectionLabel(); sec3.text = "ABOUT"
        stack.addArrangedSubview(sec3)
        let about = UILabel()
        about.numberOfLines = 0
        about.font = .systemFont(ofSize: 13)
        about.text = "UIKit 菜单 + Metal 特效。对应原 ImGui FangUI：明/暗主题过渡、点阵背景、雨丝光束、粒子爆裂、弹性药丸导航。"
        about.tag = 999
        stack.addArrangedSubview(about)
    }

    required init?(coder: NSCoder) { fatalError() }

    @objc private func onBeams() { state.showBeams = beamsSwitch.isOn }
    @objc private func onDots() { state.showDots = dotsSwitch.isOn }

    @objc private func onBurstTap() {
        let p = burstBtn.center
        onBurst?(p)
    }

    func rebuild(palette: Palette) {
        beamsSwitch.onTintColor = palette.accent
        dotsSwitch.onTintColor = palette.accent
        burstBtn.backgroundColor = palette.accent
        burstBtn.setTitleColor(.white, for: .normal)
        burstBtn.layer.cornerRadius = 12
        burstBtn.contentEdgeInsets = UIEdgeInsets(top: 10, left: 18, bottom: 10, right: 18)
        stack.arrangedSubviews.forEach {
            if let s = $0 as? SectionLabel { s.textColor = palette.textDim }
            if let r = $0 as? RowView { r.apply(palette: palette) }
            if $0.tag == 999, let l = $0 as? UILabel { l.textColor = palette.textDim }
        }
    }
}
