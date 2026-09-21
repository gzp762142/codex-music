import UIKit

/// 进程扫描 + 内存探针调试页（挂在「设置」页签下面）。
///
/// 三行状态 + 一排单步按钮 + 可滚动的 p_comm 列表。
/// **探针是单步的**：点哪一步崩，就说明崩在那一步 —— 上一版把整条链路串成
/// 一个动作，一点就闪退却分不清位置。
final class DebugProcView: UIView, UITableViewDataSource, UITableViewDelegate {

    static let rowHeight: CGFloat = 22

    private let scanner = ProcessScanner()
    private let probe = MemoryProbe()
    /// 静默测试：只持端口、零读取，看目标是否自己死
    private let silent = SilentProbe()
    private var entries: [ProcessScanner.ProcEntry] = []
    /// 非空时表格显示这些文本行（Jetsam 报告等），否则显示进程列表
    private var extraRows: [String] = []
    private var gpid: Int32 = 0
    /// 顶部信息区的高度：三行读数 + 一行 XPF 常驻状态 + 一行 Slide 常驻状态。
    private let headerH: CGFloat = 79
    private let btnRowH: CGFloat = 26

    private let countLabel = UILabel()
    private let hitLabel = UILabel()
    private let probeLabel = UILabel()
    private let crashLabel = UILabel()
    /// XPF 常驻状态行（「［XPF］未初始化 / 已就绪…」）。
    ///
    /// 为什么不复用 probeLabel：那一行会被每次手动操作覆盖（「读取中…」）、
    /// 面板每次收放还会整个重建。而 XPF 一旦初始化成功就一直是就绪的，
    /// 它的结论最该像「［窗口］」那样常驻 —— 重建后靠 xpfNote 恢复。
    private let xpfLabel = UILabel()
    /// Slide 常驻状态行（「［Slide］未计算 / 就绪 · slide=0x…」）。
    ///
    /// 与 xpfLabel 同理：面板收放会整个重建，而 slide 一旦算出来就一直有效
    /// （它只能通过 kernel_base 处的 Mach-O 头自检才会被发布），所以结论要常驻，
    /// 重建后靠 slideNote 恢复。
    private let slideLabel = UILabel()
    private let table = UITableView(frame: .zero, style: .plain)

    /// 跑一次：刷新 → 找村口 → 世界 → 名字池，一条链自动走完
    private let btnAuto = UIButton(type: .system)
    private let btnRefresh = UIButton(type: .system)
    private let btnSym = UIButton(type: .system)
    private let btnDlsym = UIButton(type: .system)
    private let btnProof = UIButton(type: .system)
    private let btnCrashFile = UIButton(type: .system)
    /// 定点读：用「找村口」存下的 base/slide 换算后点读 GObjects 链
    private let btnFixed = UIButton(type: .system)
    /// GNames：把 FName 索引解成字符串（验收：0/1/2 → None/ByteProperty/IntProperty）
    private let btnNames = UIButton(type: .system)
    /// 对象：从对象表取前 16 个，解出「类名 + 对象名」
    private let btnObjects = UIButton(type: .system)
    /// 世界：GWorld → PersistentLevel → Actors（三次小读，走热页）
    private let btnWorld = UIButton(type: .system)
    /// 自己：LocalPlayer → PlayerController → Pawn → 坐标
    private let btnSelf = UIButton(type: .system)
    /// 玩家：GameState → PlayerArray → 每个玩家的 Pawn → 坐标（全场，绕开加密）
    private let btnPlayers = UIButton(type: .system)
    /// 内存：读游戏的内存账本（footprint / compressed），不碰游戏内存
    private let btnMemory = UIButton(type: .system)
    /// 自动总开关：启动/停止后台状态机。手动按钮**全部保留**，用来和自动模式对照排查。
    private let btnTracker = UIButton(type: .system)
    /// 映射：把游戏内存 remap 进我们自己进程，之后本地读（样本的读取方式）
    private let btnMap = UIButton(type: .system)
    /// 窗口：样本的建窗体（本地虚拟地址窗口）—— 第一步就是把它建起来并当场自验证
    private let btnWindow = UIButton(type: .system)
    /// 枚举：只枚举几个 region 打原始字段，验证 vm_region_64 这个调用本身
    private let btnEnum = UIButton(type: .system)
    /// 读模块头：dump 基址处读 Mach-O，判断 ASLR 是否搬过基址
    /// 扫基址：128MB 内找 Mach-O magic（比上一版范围小）
    private let btnScan = UIButton(type: .system)
    /// 区域归属：问「这个地址属于哪个文件」（零风险探测）
    private let btnRegion = UIButton(type: .system)
    /// 静默测试：只持端口零读取（切掉"端口本身是否致命"这一类假设）
    private let btnSilent = UIButton(type: .system)
    /// Jetsam 日志：文件名不带进程名，必须按 JetsamEvent 前缀扫
    private let btnJetsam = UIButton(type: .system)
    /// XPF：读设备的 kernelcache 并解析 physrw 要用的那批内核符号。
    /// 与「窗口」同类 —— 不要求 pid、不依赖内核读写层，可单独跑。
    private let btnXpf = UIButton(type: .system)
    /// Slide：算出 kernel slide / kernel base，并读回 ptov_table 做 PA→KVA 换算。
    /// 与「XPF」的差别是它**要 kread**（读 fileproc / fileops / ptov_table），
    /// 所以前置条件是内核层就绪，且必须与读取链串行（见 runSlideProbe）。
    private let btnSlide = UIButton(type: .system)

    /// 面板上的按钮与其 action。**唯一数据源**：init 按它接线，layoutSubviews 按它排版。
    /// 原先这两处各写一份列表，加一个按钮就得改两个地方、还必须顺序一致 —— 迟早会错位。
    /// 顺序即排列顺序（从左到右、从上到下）。按钮数不再是 12 的倍数时，
    /// 排版会自动多出一行，表格起点跟着往下让（见 layoutSubviews）。
    ///
    /// 为什么是 `lazy var` 而不是 `static let`：表里装的是**实例按钮**，而静态存储属性的
    /// 初始化器跑在 `self` 构造出来之前 —— 引用实例成员会被编译器直接拒掉
    /// （instance member cannot be used on type）。`lazy` 首次被访问时才初始化，
    /// 那时 self 已完全构造，所以能引用任何实例属性，也与声明先后顺序无关。
    private lazy var actionButtons: [(button: UIButton, title: String, action: Selector)] = [
        (btnWorld, "世界", #selector(onWorld)),
        (btnSelf, "自己", #selector(onSelf)),
        (btnPlayers, "玩家", #selector(onPlayers)),
        (btnAuto, "跑一次", #selector(onAutoRun)),
        (btnMap, "映射", #selector(onMapProbe)),
        (btnWindow, "窗口", #selector(onWindowProbe)),
        (btnEnum, "枚举", #selector(onEnumProbe)),
        (btnRefresh, "刷新", #selector(onRefresh)),
        (btnObjects, "对象", #selector(onObjects)),
        (btnCrashFile, "崩溃文件", #selector(onCrashFile)),
        (btnMemory, "内存", #selector(onMemory)),
        (btnTracker, "自动", #selector(onTracker)),
        (btnXpf, "XPF", #selector(onXpfProbe)),
        (btnSlide, "Slide", #selector(onSlideProbe))
    ]

    private let accent = UIColor.hex(0x185EE0)
    private let idleText = UIColor.hex(0x5A6A82)
    private let warnText = UIColor.hex(0xB04141)

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear

        for l in [countLabel, hitLabel, probeLabel, crashLabel, xpfLabel, slideLabel] {
            l.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            l.textColor = idleText
            l.adjustsFontSizeToFitWidth = true
            l.minimumScaleFactor = 0.6
            l.lineBreakMode = .byTruncatingTail
            addSubview(l)
        }
        hitLabel.font = .monospacedSystemFont(ofSize: 11, weight: .medium)

        // 全部单步按钮都接线。主链已经验证过了，不必再一步步点，但每一个都留着 ——
        // 出了岔子时要靠它单独复现某一段（例如「窗口」「XPF」是内核层挂掉时仅有的判据）。
        for (b, title, sel) in actionButtons {
            b.setTitle(title, for: .normal)
            b.titleLabel?.font = .systemFont(ofSize: 11, weight: .semibold)
            // 6 列比 5 列窄，长标题（崩溃文件）允许自动缩一点，避免被截断
            b.titleLabel?.adjustsFontSizeToFitWidth = true
            b.titleLabel?.minimumScaleFactor = 0.7
            b.setTitleColor(accent, for: .normal)
            b.layer.cornerRadius = 6
            b.layer.borderWidth = 1
            b.layer.borderColor = accent.withAlphaComponent(0.35).cgColor
            b.addTarget(self, action: sel, for: .touchUpInside)
            addSubview(b)
        }

        // XPF 状态跨面板重建保留（面板收放会新建整个视图）：XPF 只初始化一次，
        // 那几十秒不该因为收起再弹出就白等第二遍。
        xpfLabel.text = DebugProcView.xpfNote
        // Slide 同理：它只有在通过 kernel_base 的 Mach-O 头自检之后才有结论。
        slideLabel.text = DebugProcView.slideNote

        table.dataSource = self
        table.delegate = self
        table.rowHeight = Self.rowHeight
        table.backgroundColor = .clear
        table.separatorStyle = .none
        table.register(UITableViewCell.self, forCellReuseIdentifier: "proc")
        addSubview(table)

        // 冷启动自动开启。**不能只靠 didMoveToWindow** —— 面板窗口是 FangUIBridge
        // 用私有 entitlement 挂上去的，走的不是标准 addSubview 路径，那个回调
        // 不保证触发（实测就没触发，状态机一直没起来）。
        // 这里排进主队列：等 self 完全初始化、当前 runloop 结束后直接启动。
        DispatchQueue.main.async { [weak self] in
            self?.autoStartOnce(from: "冷启动")
        }

        // 内核自检是异步的（PUAFF 几十秒），面板可能先于它建好 —— 起个轻量定时器
        // 等它就绪后自动刷一次。跟状态机开不开无关：这是现在唯一要盯的东西。
        startKernelStatusWatch()
    }

    required init?(coder: NSCoder) { fatalError() }

    override func layoutSubviews() {
        super.layoutSubviews()
        let w = bounds.width
        countLabel.frame = CGRect(x: 0, y: 0, width: w, height: 14)
        hitLabel.frame = CGRect(x: 0, y: 15, width: w * 0.6, height: 14)
        crashLabel.frame = CGRect(x: w * 0.6, y: 15, width: w * 0.4, height: 14)
        probeLabel.frame = CGRect(x: 0, y: 30, width: w, height: 14)
        xpfLabel.frame = CGRect(x: 0, y: 45, width: w, height: 14)
        slideLabel.frame = CGRect(x: 0, y: 60, width: w, height: 14)

        // 6 列一行。按钮数由 actionButtons 决定，不再假定正好 12 个（6×2）——
        // 多出来的按钮会自动排到下一行，表格起点跟着让，不会被压住。
        let all = actionButtons.map { $0.button }
        let gap: CGFloat = 4
        let perRow = 6
        let bw = (w - gap * CGFloat(perRow - 1)) / CGFloat(perRow)
        let bh = btnRowH - 6
        for (i, b) in all.enumerated() {
            let col = CGFloat(i % perRow)
            let row = CGFloat(i / perRow)
            b.frame = CGRect(x: col * (bw + gap), y: headerH + row * btnRowH,
                             width: bw, height: bh)
        }

        // 用实际上用掉的行数算表格起点：写死行数会和按钮排版悄悄错开
        let usedRows = CGFloat((all.count + perRow - 1) / perRow)
        let tableTop = headerH + btnRowH * usedRows
        table.frame = CGRect(x: 0, y: tableTop, width: w,
                             height: max(0, bounds.height - tableTop))
    }

    func reload() { onRefresh() }

    /// 上一次读取还没回来：挡住重复点击，避免后台堆积多个操作。
    private var probeBusy = false
    /// 上一次读取的发起时刻 —— 用来判断它是不是已经被内核永久堵住了。
    private var probeStarted = Date.distantPast
    /// 轮询后台进度的定时器：面板上实时显示走到哪一步。
    private var stageTimer: Timer?
    /// 状态机每拍都会回调，但列表没必要跟着 20Hz 重刷 —— 节流到 4Hz。
    private var lastTrackerUI = Date.distantPast
    /// 冷启动只自动开启一次。
    private var autoStarted = false

    /// 所有内存操作都从这里走：**切到后台线程执行，回来后刷 UI**。
    ///
    /// 绝不能在主线程直接调 `mach_vm_read`。它进内核后要等目标进程 vm_map 的锁，
    /// 游戏主线程每帧都在分配内存（持写锁），我们可能排很久；如果那一页还要从
    /// 磁盘换入（__DATA 是文件映射），还得等 I/O。而且这个等待**不可中断、没有超时**。
    /// 实测点「世界」把整个面板卡死过一次 —— 游戏毫发无伤，卡住的是我们自己。
    ///
    /// 顺带把耗时打出来：那是判断"一次读取到底多贵"最直接的数。
    private func runProbe(_ pending: String, _ work: @escaping (Int32) -> String) {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        if probeBusy {
            // 被内核堵死的话不会自己回来，30 秒后放行新的请求，免得面板只能用一次
            if Date().timeIntervalSince(probeStarted) > 30 {
                probeBusy = false
            } else {
                probeLabel.text = "上一个读取还没回来（被内核堵住了），等它"
                return
            }
        }
        probeBusy = true
        probeStarted = Date()
        probeLabel.text = pending
        probeLabel.textColor = idleText
        // 屏幕尺寸在主线程取一次交给探测层 —— 投影跑在后台线程，不该去碰 UIScreen。
        MemoryProbe.screenSize = UIScreen.main.bounds.size
        let pid = gpid

        // 每个动作前统一绑定目标进程 —— 没有这一步，按需映射那条路根本不会启动
        MemoryProbe.bind(pid: pid)

        // Music 是悬浮窗形态（窗口浮在游戏之上），它很可能**根本不在前台**。
        // 而后台 app 的线程会被 iOS 挂起 —— 挂起之后读取链就停在原地，
        // 面板表现正好是"卡在第一步不动"，几秒后整个进程被系统终止。
        // 这里把 app 状态记下来，并且申请一段后台执行时间（没有它的话，
        // 任务可能在第一秒就被挂起）。
        var appState = "未知"
        switch UIApplication.shared.applicationState {
        case .active: appState = "前台"
        case .inactive: appState = "非活跃"
        case .background: appState = "后台"
        @unknown default: appState = "未知"
        }

        var bgTask = UIBackgroundTaskIdentifier.invalid
        bgTask = UIApplication.shared.beginBackgroundTask(withName: "aether.read") {
            if bgTask != .invalid {
                UIApplication.shared.endBackgroundTask(bgTask)
                bgTask = .invalid
            }
        }

        // 后台每一步都直接推进面板 —— 不走 Timer 轮询。
        // Timer 跑在主线程，主线程一旦被任何内核调用堵住就再也不触发，
        // 面板会停在最后一个值上，跟"真的卡住了"长得一样。
        MemoryProbe.onStage = { [weak self] stage in
            self?.probeLabel.text = "\(pending) · \(stage)"
        }

        DispatchQueue.global(qos: .userInitiated).async {
            MemoryProbe.stageMark(pending + " · 后台已启动[app \(appState)]")
            let t0 = Date()
            // 手动操作走状态机**同一条串行队列** —— 两边都会碰 MemoryProbe 的静态状态
            // （mappedRanges / activePid / imageBase），并发跑会互相踩；尤其 bind()
            // 会清空映射，正好撞上状态机在读的时候。
            let result = AutoTracker.shared.syncExternal { work(pid) }
            let ms = Int(Date().timeIntervalSince(t0) * 1000)
            DispatchQueue.main.async { [weak self] in
                guard let s = self else { return }
                MemoryProbe.onStage = nil
                s.probeBusy = false
                s.stageTimer?.invalidate()
                s.stageTimer = nil
                if bgTask != .invalid {
                    UIApplication.shared.endBackgroundTask(bgTask)
                    bgTask = .invalid
                }
                s.showReport("[\(ms) ms][app \(appState)] " + result)
            }
        }
    }

    /// 把多行报告同时放进状态行（第一行）和可滚动列表（全部行）。
    /// 「找村口」「定点读」的结论是多行的（base/slide/三个落点/链上的值），
    /// 单行状态栏放不下，必须给列表看。
    ///
    /// 注意：这里会丢掉空行（split 的默认行为）。所以报告里的分区只能靠标题行
    /// （「== xxx ==」）划开，别指望空行 —— 见 xpfReport。
    private func showReport(_ text: String) {
        let lines = text.split(separator: "\n").map(String.init)
        probeLabel.text = lines.first ?? text
        probeLabel.textColor = text.contains("✓") ? accent : warnText
        extraRows = lines
        table.reloadData()
    }

    // MARK: - 内核层状态（面板常驻显示）

    /*
     * 内核自检的结果必须常驻可见。
     *
     * 为什么不能塞进 extraRows：那个数组在每次手动操作、Jetsam 报告、状态机回调时
     * 都会被整个覆盖 —— 塞进去的那一次会在下一次点击时消失，而内核结果恰恰是
     * 最该一直挂着看的。
     *
     * 所以放在数据源里动态拼：每次都算一遍，永远在列表最前。
     */
    private func kernelStatusRows() -> [String] {
        /*
         * 守卫用 kernelInitDone，不是 kernelReady。
         *
         * 这个函数要显示的是"内核层现在什么状态"。只看 kernelReady 的话，
         * 初始化**失败**时这里会永远显示"初始化中…（PUAFF 需要几十秒）"，
         * 而真正的失败原因（kernelNote 里那行"不可用：…"）永远没机会显示出来
         * —— 用户会一直等一个不会来的结果。只要 km_init 返回过，就该把
         * kernelNote 摊开给他看；那一行本身已经区分了成功（报告）和失败（原因）。
         */
        guard AppDelegate.kernelInitDone else {
            return ["［内核层］ 初始化中…（PUAFF 需要几十秒）",
                    "［窗口］ " + MemoryProbe.windowLine]
        }
        var out = AppDelegate.kernelNote
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
        // 空的话给个占位，否则表格里那一段会整块消失
        if out.allSatisfy({ $0.isEmpty }) { out = ["［内核层］ （无报告）"] }
        /*
         * 窗口状态**常驻最后一行**（自带前缀，不跟着上面那批走）。
         *
         * 为什么不塞进 extraRows：那个数组在每次手动操作、Jetsam 报告、状态机回调时
         * 都会被整个覆盖 —— 窗口建过一次之后一直有效，它最该挂在那儿被人看见。
         * 而且窗口是第一步唯一"内核层挂掉也能跑"的东西（纯用户态 Mach 调用），
         * 内核那一段报错时它照样有话说 —— 两者放在一起对比才有意义。
         */
        var rows = out.map { "［内核］ " + $0 }
        rows.append("［窗口］ " + MemoryProbe.windowLine)
        return rows
    }

    // MARK: - XPF 状态（面板常驻显示）

    /// XPF 常驻状态行。**静态**，因为面板每次收放都会新建本视图：
    /// XPF 只初始化一次、不会因为面板重建而失效，状态就不该随之丢掉。
    ///
    /// 与 `AppDelegate.kernelNote` 同理 —— 只在主线程读写，一个字符串，用不着加锁。
    private static var xpfNote = "［XPF］ 未初始化（点「XPF」按钮）"

    /// Slide 常驻状态行。理由与 xpfNote 完全相同（面板每次收放都会新建本视图）。
    private static var slideNote = "［Slide］ 未计算（点「Slide」按钮）"

    /// 内核就绪后自动刷一次面板 —— 自检是异步的，面板可能先于它建好。
    private var kernelWasReady = false
    private var kernelUITimer: Timer?

    private func startKernelStatusWatch() {
        guard kernelUITimer == nil else { return }
        kernelUITimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] t in
            guard let s = self else { t.invalidate(); return }
            let ready = AppDelegate.kernelReady
            guard ready != s.kernelWasReady else { return }
            s.kernelWasReady = ready
            // 内核刚就绪：清掉手动操作留下的旧结果，让内核报告独占列表开头
            s.extraRows = []
            s.table.reloadData()
            s.probeLabel.text = ready
                ? "[内核] 就绪 —— 报告见列表首行，或看设备日志 [KernelMemory]"
                : "[内核] 初始化中…"
        }
    }

    // MARK: - 自动追踪总开关

    override func didMoveToWindow() {
        super.didMoveToWindow()
        guard window != nil else { return }
        autoStartOnce(from: "窗口挂载")     // 兜底：init 那条路已经先跑过了
    }

    /// 冷启动自动开启，只跑一次。`init` 与 `didMoveToWindow` 都会调它。
    ///
    /// **要的是「确保在跑」，不是「切换」。** `setTracker` 是个 toggle，
    /// 而 `autoStarted` 只是**本实例**的守卫 —— 面板每次收放都会重建：
    /// 音量- 走 `FangUIBridge.hide()`，那里把 `panel = nil`；下次弹出来时
    /// `attachPanel` 会新建整个 `RootViewController`（连带本视图）。新实例的守卫是
    /// false，于是又调一次 `setTracker`；而 `AutoTracker.shared` 是单例、`isRunning`
    /// 早已是 true —— toggle 直接把跑着的状态机关掉。表现就是「开一下、关一下」，
    /// 收放两次菜单等于白开。而 `RootView` 里音量- 的注释写的是「服务可继续跑」。
    private func autoStartOnce(from source: String) {
        guard !autoStarted else { return }
        autoStarted = true
        let t = AutoTracker.shared
        if t.isRunning {
            // 服务本来就该继续跑。这里只把回调重新接到**当前**这个实例上 ——
            // 旧视图已经释放，它那些闭包是弱引用，等于空转，新面板会一片空白。
            claimTrackerCallbacks()
            btnTracker.setTitleColor(accent, for: .normal)
            probeLabel.text = "自动[\(t.state.rawValue)] \(t.detail)"
            return
        }
        setTracker(source)
    }

    /// 把状态机的两个回调接到**当前**这个面板实例上。
    /// 面板重建后旧实例已经释放（闭包都是弱引用），必须重新认领，否则新面板收不到任何东西。
    private func claimTrackerCallbacks() {
        let t = AutoTracker.shared
        MemoryProbe.screenSize = UIScreen.main.bounds.size
        t.onStatus = { [weak self] text in
            self?.probeLabel.text = text
        }
        t.onTargets = { [weak self] list, snap in
            guard let s = self else { return }
            let now = Date()
            if now.timeIntervalSince(s.lastTrackerUI) < 0.25 { return }   // 列表 4Hz 就够
            s.lastTrackerUI = now
            s.renderTracker(list, snap)
        }
    }

    /// 自动总开关。开启后不必再点任何按钮 —— 状态机自己 attach、找基址、持续出坐标；
    /// 游戏退出会自动释放映射与端口，重开自动重挂。手动按钮**全部保留**，
    /// 两者走同一条串行队列，可以随时对照排查。
    ///
    /// **带参数的那个不能也叫 onTracker**：重载会让 `#selector(onTracker)` 变成
    /// 含糊引用（编译器直接报 "onTracker 用法含糊"），所以它另起名 setTracker。
    @objc private func onTracker() { setTracker("手动") }

    private func setTracker(_ source: String) {
        let t = AutoTracker.shared
        if t.isRunning {
            t.onStatus = nil
            t.onTargets = nil
            t.stop()
            btnTracker.setTitleColor(warnText, for: .normal)
            probeLabel.text = "自动: 已停止（\(source)）"
            return
        }
        claimTrackerCallbacks()
        t.start()
        btnTracker.setTitleColor(accent, for: .normal)
        probeLabel.text = "自动: 启动中…（\(source)）"
    }

    /// 把状态机每拍的目标摊到可滚动区。这一步只做**显示**，不做绘制 ——
    /// 屏幕坐标已经算好了（`RenderTarget.screen`），画框接上去就能用。
    private func renderTracker(_ list: [AutoTracker.RenderTarget],
                               _ snap: MemoryProbe.SelfSnapshot) {
        var rows: [String] = []
        let me = snap.loc
        rows.append(String(format: "自身 (%.1f, %.1f, %.1f)  相机%@ FOV %.0f  映射 %d 块",
                           me.0, me.1, me.2,
                           snap.camera.valid ? "✓" : "✗",
                           snap.camera.fov,
                           MemoryProbe.mappedBlockCount))
        // 保护位单独一行、放在「目标」之上：并进「自身」那行会溢出（那行已贴到右缘），
        // 挂在状态行尾部同样放不下，截断之后就等于没显示
        rows.append(AutoTracker.shared.protectionNote)
        // 有失败才多占一行：把地址和返回码摆出来 —— 光有次数定不了位
        if !MemoryProbe.lastProtectFailure.isEmpty {
            // 拆行渲染：面板一行装不下七十多个字符，后半段（源 prot）会被截掉 ——
            // 而它正是诊断的判据，截掉就等于白跑一轮
            let parts = MemoryProbe.lastProtectFailure.split(separator: "\n")
            for (i, part) in parts.enumerated() {
                rows.append(i == 0 ? "降权失败详情: \(part)" : "　\(part)")
            }
        }
        rows.append("目标 \(list.count) 个 · \(AutoTracker.shared.lastScanNote)")
        for t in list.sorted(by: { $0.dist < $1.dist }).prefix(30) {
            let tag = t.isSelf ? "★你 " : "    "
            let scr: String
            if let s = t.screen {
                scr = String(format: "屏幕(%4.0f,%4.0f)%@", s.0, s.1, t.onScreen ? " " : "屏外")
            } else {
                scr = "屏幕(身后)  "
            }
            rows.append(String(format: "  %@%5.0fm  %@  %@", tag, t.dist, scr, t.cls))
        }
        extraRows = rows
        table.reloadData()
    }

    // MARK: - 单步动作

    /// 重扫进程、刷新顶部三行状态。返回后 gpid 就是最新的。
    private func refreshProcess() {
        scanner.invalidate()
        entries = scanner.scan()
        gpid = scanner.findGamePID(forceRefresh: true) ?? 0

        let exact = entries.filter { $0.exact }.count
        let loose = entries.filter { $0.matched && !$0.exact }.count
        // app 自己在前台还是后台必须一眼能看到：后台意味着线程随时会被挂起，
        // 那之后的任何"卡住"都不能算在读取头上。
        var stateText = "?"
        switch UIApplication.shared.applicationState {
        case .active: stateText = "前台"
        case .inactive: stateText = "非活跃"
        case .background: stateText = "★后台"
        @unknown default: stateText = "?"
        }
        countLabel.text = "共 \(entries.count) · 精确\(exact) · 疑似\(loose) · app:\(stateText) · 保活:\(BackgroundKeepAlive.shared.lastNote)"
        if gpid != 0 {
            hitLabel.text = "pid=\(gpid)"
            hitLabel.textColor = accent
        } else {
            hitLabel.text = "pid=未找到"
            hitLabel.textColor = warnText
        }
        if let crash = CrashCatcher.lastCrash() {
            crashLabel.text = "自记:" + crash.split(separator: "\n").prefix(1).joined()
            crashLabel.textColor = warnText
        } else {
            crashLabel.text = "自记:无"
        }
    }

    /// 一键跑完整条链：刷新 → 找村口 → 世界 → 名字池。
    ///
    /// 约 15 次 mach_vm_read，远低于会把游戏推崩的量级（实测 128 次才出事），
    /// 所以串起来跑是安全的。哪一步断了就停在哪一步，报告里会写清楚。
    /// 之所以能这么干，是因为这条链的每一段都已经单独验证过了 ——
    /// 之前必须一步步点，是因为当时不知道哪一步会崩。
    @objc private func onAutoRun() {
        refreshProcess()
        guard gpid != 0 else {
            probeLabel.text = "自动: 没找到游戏进程"
            probeLabel.textColor = warnText
            return
        }
        runProbe("自动: 找村口 → 世界 → 名字池…") { pid -> String in
            var out: [String] = []
            let base = MemoryProbe.stepFindBase(pid: pid)
            out.append(base)
            guard base.contains("✓ base=") else {
                out.append("→ 停在这里：基址没拿到，后面的步骤没有意义")
                return out.joined(separator: "\n")
            }
            // 每步之间先确认目标还在。游戏要是先崩了，继续读它会跟它销毁 vm_map
            // 的过程抢锁 —— 那是长时间内核自旋、CPU 被烧穿的典型场景。
            guard MemoryProbe.targetAlive(pid) else {
                out.append("→ 目标进程已经消失，后面的步骤全部停掉（继续读只会烧 CPU）")
                return out.joined(separator: "\n")
            }
            out.append("")
            out.append(MemoryProbe.stepWorld(pid: pid))
            guard MemoryProbe.targetAlive(pid) else {
                out.append("→ 目标进程已经消失，停掉")
                return out.joined(separator: "\n")
            }
            out.append("")
            out.append(MemoryProbe.stepGNames(pid: pid))
            return out.joined(separator: "\n")
        }
    }

    @objc private func onRefresh() {
        refreshProcess()
        // 刷新 = 回进程列表（报告是上一次动作的产物，不该一直占着列表）
        extraRows = []
        table.reloadData()
        probeLabel.text = gpid != 0 ? "已刷新 pid=\(gpid)" : "没找到游戏进程"
        probeLabel.textColor = gpid != 0 ? accent : warnText
    }

    @objc private func onSym() {
        probeLabel.text = "符号 " + MemoryProbe.stepSymbols()
        probeLabel.textColor = idleText
    }

    @objc private func onDlsym() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("dlsym: 读取中…") { MemoryProbe.stepDlsym(pid: $0) }
    }

    @objc private func onProof() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("读证: 读取中…") { MemoryProbe.stepReadProof(pid: $0) }
    }

    /// 定点读：用「找村口」存下的 base/slide 换算后点读 GObjects 链（约 20 字节）。
    @objc private func onFixedRead() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("定点读: 读取中…") { MemoryProbe.stepFixedRead(pid: $0) }
    }

    /// 静默测试：拿到端口后什么都不读，看目标会不会自己死。
    /// 再点一次 = 手动停止。
    @objc private func onSilent() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        if silent.isRunning { silent.stop(); probeLabel.text = "静默测试: 手动停止"; return }

        silent.onTick = { [weak self] sec, alive in
            guard let s = self else { return }
            s.probeLabel.text = "静默 \(sec)s · \(alive ? "存活" : "已消失")"
            s.probeLabel.textColor = alive ? s.idleText : s.warnText
        }
        silent.onFinish = { [weak self] sec, aliveAtEnd, gotPort in
            guard let s = self else { return }
            let note = gotPort ? "端口已持有" : "端口未拿到"
            s.probeLabel.text = aliveAtEnd
                ? "静默\(sec)s 全程存活 → 端口本身不致命[\(note)]"
                : "静默\(sec)s 时游戏消失 → 病根在端口/进程状态，不在读取[\(note)]"
            s.probeLabel.textColor = aliveAtEnd ? s.accent : s.warnText
        }
        probeLabel.text = "静默测试启动：只持端口，零读取，120s"
        probeLabel.textColor = idleText
        silent.start(pid: gpid, seconds: 120)
    }

    /// Jetsam 日志：完整报告填进表格（可滚动）；再点一次返回进程列表
    @objc private func onJetsam() {
        if !extraRows.isEmpty {
            extraRows = []
            table.reloadData()
            probeLabel.text = "已返回进程列表"
            probeLabel.textColor = idleText
            return
        }
        extraRows = JetsamLogReader.report()
        table.reloadData()
        probeLabel.text = "Jetsam 报告 \(extraRows.count) 行已填入列表（可滚动）"
        probeLabel.textColor = accent
    }

    /// 区域归属：一次调用问「dump 基址属于哪个文件」。
    @objc private func onRegionName() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("区域归属: 读取中…") { MemoryProbe.stepRegionName(pid: $0) }
    }

    /// 找村口：枚举 region（三条件）+ Mach-O 头校验；命中后记下 base/slide。
    /// 报告多行：第一行进状态行，全部行进可滚动列表。
    @objc private func onFindBase() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("找村口: 读取中…") { MemoryProbe.stepFindBase(pid: $0) }
    }

    /// 名字：解 FName 索引（验收点：0/1/2 → None / ByteProperty / IntProperty）。
    @objc private func onNames() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("名字: 读取中…") { MemoryProbe.stepGNames(pid: $0) }
    }

    /// 对象：对象表前 16 个的「类名 + 对象名」（验证 Class/Name 这条链）。
    @objc private func onObjects() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("对象: 读取中…") { MemoryProbe.stepObjects(pid: $0) }
    }

    /// 玩家：GameState → PlayerArray → 每个玩家的 Pawn → 坐标。
    /// 这条路绕开 LocalPlayers 那层加密，而且直接给全场玩家。
    @objc private func onPlayers() {
        refreshProcess()
        guard gpid != 0 else {
            probeLabel.text = "玩家: 没找到游戏进程"
            probeLabel.textColor = warnText
            return
        }
        runProbe("玩家: 读取中…") { pid -> String in
            var out: [String] = []
            if !MemoryProbe.baseReady(for: pid) {
                let base = MemoryProbe.stepFindBase(pid: pid)
                out.append(base)
                guard base.contains("✓ base=") else {
                    out.append("→ 没拿到基址，读不了玩家")
                    return out.joined(separator: "\n")
                }
                out.append("")
            }
            out.append(MemoryProbe.stepPlayers(pid: pid))
            return out.joined(separator: "\n")
        }
    }

    /// 自己：LocalPlayer → PlayerController → Pawn → 坐标。
    /// 同样自包含 —— 缺基址自己找，缺映射按需建。
    @objc private func onSelf() {
        refreshProcess()
        guard gpid != 0 else {
            probeLabel.text = "自己: 没找到游戏进程"
            probeLabel.textColor = warnText
            return
        }
        runProbe("自己: 读取中…") { pid -> String in
            var out: [String] = []
            if !MemoryProbe.baseReady(for: pid) {
                let base = MemoryProbe.stepFindBase(pid: pid)
                out.append(base)
                guard base.contains("✓ base=") else {
                    out.append("→ 没拿到基址，定位不了自己")
                    return out.joined(separator: "\n")
                }
                out.append("")
            }
            out.append(MemoryProbe.stepSelf(pid: pid))
            return out.joined(separator: "\n")
        }
    }

    /// 世界：GWorld → PersistentLevel → Actors → 认类名。
    ///
    /// **自包含**：缺基址就自己找一次（跟「映射」一样）。所以正常只用点这一个按钮，
    /// 不必先「枚举」「映射」「对象」走一圈 —— 那些是排查阶段的产物，现在留着手动用。
    @objc private func onWorld() {
        refreshProcess()
        guard gpid != 0 else {
            probeLabel.text = "世界: 没找到游戏进程"
            probeLabel.textColor = warnText
            return
        }
        runProbe("世界: 读取中…") { pid -> String in
            var out: [String] = []
            if !MemoryProbe.baseReady(for: pid) {
                let base = MemoryProbe.stepFindBase(pid: pid)
                out.append(base)
                guard base.contains("✓ base=") else {
                    out.append("→ 没拿到基址，世界链没得走")
                    return out.joined(separator: "\n")
                }
                out.append("")
            }
            out.append(MemoryProbe.stepWorld(pid: pid))
            return out.joined(separator: "\n")
        }
    }

    /// 枚举：只枚举几个 region 打原始字段，验证 vm_region_64 这个调用本身。
    @objc private func onEnumProbe() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("枚举: 读取中…") { MemoryProbe.stepRegionProbe(pid: $0) }
    }

    /// 内存：游戏的内存账本（不碰游戏内存），用来看操作前后 footprint/compressed 的差值。
    @objc private func onMemory() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("内存: 读取中…") { MemoryProbe.stepMemory(pid: $0) }
    }

    /// 映射：样本的读取方式（窗口 + 本地读）—— 第一步验证的是**窗口本身**。
    ///
    /// 这个按钮原来要求"先刷新拿 pid、缺基址就自己找一次"，因为它当时做的是把游戏的
    /// 映像头 / `__DATA` 段 remap 进本进程。那条路现在停了（需要目标 task port），
    /// 而窗口与目标进程无关 —— 所以这里不再要求 pid，也不再「找村口」：
    /// 那是白碰一次游戏内存，换不来任何东西。
    ///
    /// 与「窗口」按钮走**同一条路**，差别只有一行说明文字（跨进程那半边为什么没开）。
    @objc private func onMapProbe() {
        let pid = gpid
        runWindowProbe("映射: 建窗中…") { MemoryProbe.stepRemapProbe(pid: pid) }
    }

    /// 窗口：样本的建窗体跑一遍，并**当场自验证**（写 pattern → 读回 → alias 交叉读）。
    @objc private func onWindowProbe() {
        runWindowProbe("窗口: 建窗中…") { MemoryProbe.stepWindowProbe() }
    }

    /// 「窗口」与「映射」共用的执行体。
    ///
    /// **不要求 pid**：窗口这一段全是本进程的 Mach 调用，跟游戏进程、跟内核层都没关系。
    /// 它是第一步唯一一个"内核挂掉也能跑"的判据，所以不能被"先刷新拿到 pid"那道门挡住
    /// —— 别的按钮的前置条件对它不成立。
    ///
    /// 仍然走 `AutoTracker` 那条**串行队列**：窗口会碰 `MemoryProbe` 的静态状态
    /// （localWindow / mlockFailures / 计数器），跟状态机的读取并发跑会互相踩。
    ///
    /// 不复用 `runProbe` 的唯一原因：那个函数第一行就是 `guard gpid != 0`
    /// —— 对窗口来说这是一道不该存在的门。
    private func runWindowProbe(_ pending: String, _ work: @escaping () -> String) {
        if probeBusy {
            // 与 runProbe 同一套防重入：被堵死的那次不会自己回来，30 秒后放行。
            if Date().timeIntervalSince(probeStarted) <= 30 {
                probeLabel.text = "上一个读取还没回来，等它"
                return
            }
        }
        probeBusy = true
        probeStarted = Date()
        probeLabel.text = pending
        probeLabel.textColor = idleText
        DispatchQueue.global(qos: .userInitiated).async {
            let text = AutoTracker.shared.syncExternal { work() }
            DispatchQueue.main.async { [weak self] in
                guard let s = self else { return }
                s.probeBusy = false
                s.showReport(text)
            }
        }
    }

    // MARK: - XPF：kernelcache 与内核符号

    /*
     * 这一步要回答三个问题，且都要能**一眼看到**：
     *   ① 设备上的 kernelcache 到底读到没有（三条候选路径各自什么下场）；
     *   ② XPF 初始化成功没有（耗时多久）；
     *   ③ physrw 要用的那批内核符号解析出来没有（每个键的名字与值）。
     *
     * 为什么值得单独一个按钮：XPF 走的是「读文件 → mmap 内核 Mach-O → 按内核源码字符串
     * 定位符号」，全程只有 POSIX 文件与内存映射，跟 km_init 那条内核读写通路**毫无关系**。
     * 所以它和「窗口」一样，属于内核层挂掉时还能给出判据的那类探针 ——
     * 因此它不设前置条件：不要求 pid，也不要求内核层就绪。
     */

    /// XPF 探测在跑。
    ///
    /// 为什么不复用 `probeBusy`：`km_xpf_init` 要 mmap 并解析几十 MB 的内核映像，
    /// 实测可能几十秒；共用那个标志的话，每次点内存按钮都会看到「上一个读取还没回来」，
    /// 把等待错记到读取头上。两者本来也不冲突 —— XPF 只碰自己的 C 侧全局状态与一把
    /// 内部互斥锁，和 MemoryProbe / AutoTracker 的串行队列没有交集，可以并行。
    private var xpfBusy = false
    private var xpfStarted = Date.distantPast

    /// XPF 探测要解析的键，顺序即显示顺序。
    ///
    /// 键名一字不改：它们必须与 libxpf 里 `xpf_item_register()` 注册的名字逐字相同，
    /// 写错一个字母就会得到「key is not registered」，而那是**诊断结论本身**，
    /// 不该由这里的排版去猜。备注写的是这个值在 physrw 里干什么用。
    private static let xpfSymbolKeys: [(key: String, purpose: String)] = [
        ("kernelSymbol.ptov_table", "物理转虚拟页表（physrw 的换算基准）"),
        ("kernelSymbol.gVirtBase", "内核虚拟基址"),
        ("kernelSymbol.gPhysBase", "内核物理基址"),
        ("kernelSymbol.gPhysSize", "内核物理内存大小"),
        ("kernelSymbol.phystokv", "物理→虚拟偏移换算函数"),
        ("kernelSymbol.cpu_ttep", "CPU 转换表基址（TTBR1）"),
        ("kernelSymbol.allproc", "进程链表头"),
        ("kernelConstant.T1SZ_BOOT", "启动期地址空间尺寸（位数，不是指针）")
    ]

    /// 「XPF」按钮。**不要求 pid，也不要求内核层就绪**：它只读设备上的 kernelcache。
    @objc private func onXpfProbe() {
        runXpfProbe()
    }

    /// XPF 探测：初始化 → 诊断快照 → 逐键取符号。
    ///
    /// 全程在后台线程跑，理由与 `runProbe` 里那段完全一样，但更硬：
    /// `km_xpf_init` 要解压并解析几十 MB 的内核映像，同步放在主线程上，
    /// 面板会冻住几十秒（看起来就像死机）。用 `Date()` 量的是**墙钟**耗时 ——
    /// 用户等的是这个数，不是 C 侧单调时钟给出的"内部净耗时"。
    private func runXpfProbe() {
        if xpfBusy {
            // 与 runProbe 同一套防重入：被卡住的那次不会自己回来，90 秒后放行。
            // 这个门槛比读取那边（30s）宽，因为 XPF 初始化本来就慢，不能拿它当卡死。
            if Date().timeIntervalSince(xpfStarted) <= 90 {
                showReport("XPF: 初始化还在跑（要解析内核映像），完成后自动出结果")
                return
            }
        }
        xpfBusy = true
        xpfStarted = Date()
        xpfLabel.text = "［XPF］ 初始化中…（要解析内核映像，可能几十秒）"
        xpfLabel.textColor = idleText
        probeLabel.text = "XPF: 读 kernelcache 中…"
        probeLabel.textColor = idleText

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let began = Date()
            let report = DebugProcView.xpfReport(elapsedSeconds: Date().timeIntervalSince(began))

            DispatchQueue.main.async {
                guard let s = self else { return }
                s.xpfBusy = false
                s.showReport(report.text)
                s.xpfLabel.text = report.statusLine
                s.xpfLabel.textColor = report.ready ? s.accent : s.warnText
                DebugProcView.xpfNote = report.statusLine
            }
        }
    }

    /// 真正碰 C 接口的那些调用。**必须在主线程之外执行**（见 runXpfProbe）。
    private static func xpfReport(elapsedSeconds: Double) -> (text: String, statusLine: String, ready: Bool) {
        var lines: [String] = []

        /*
         * 每个键解析之前先抓一份错误快照。
         *
         * 为什么必须这样：`km_xpf_resolve_symbol` 成功时**不会**清掉上一次失败留下的
         * 错误（XpfBridge 刻意保留，好让人事后追失败原因），而 `km_xpf_last_error()`
         * 会把"上游 xpf 错误缓冲 + 最近一次失败"拼起来。于是一次失败之后，
         * 后面每个取值成功的键都会看到同一段旧文本 —— 直接拿它当"这个键的失败原因"
         * 就会张冠李戴。判据用「返回值 + 错误文本是否较上一个键发生变化」两条一起看：
         * 只有文本变了才说明是**这个键**新报的错。唯一的例外是本批第一个键 ——
         * 它前面没有任何键可以比，那就照实报，并在文末把残留错误另列一段供对照。
         */
        var errorCarriedOver = km_xpf_last_error()
        let alreadyReady = km_xpf_ready()
        let ok = alreadyReady ? true : km_xpf_init()

        lines.append("== XPF 诊断 ==")
        if let diagnostic = km_xpf_diagnostic() {
            lines.append(contentsOf: diagnostic.split(separator: "\n").map(String.init))
        }
        // 耗时用墙钟再报一次：诊断里那个是 C 侧自己量的，面板正在等的是墙钟
        lines.append(String(format: "init wall time: %.2f s", elapsedSeconds))
        if alreadyReady { lines.append("(本次点击前就已就绪，上面是之前那次的结果)") }

        if !ok {
            /*
             * 失败时**两条来源都要摊开**：`km_xpf_last_error()` 把二者拼成多行 ——
             * 一条是 C 侧记录的"哪条候选路径 + 什么原因"，另一条是上游 xpf 自己的
             * 错误缓冲。只显示其中一条时，最常见的那种失败（三条路径全不可读）
             * 会只剩一句笼统的话，看不出到底卡在文件、解压还是 Mach-O 解析。
             */
            lines.append("== 失败原因 ==")
            lines.append(contentsOf: errorLines(km_xpf_last_error()))
            return (lines.joined(separator: "\n"),
                    "［XPF］ 不可用（耗时 " + String(format: "%.1f", elapsedSeconds) + " s）—— 失败原因见列表",
                    false)
        }

        if let loadedPath = km_xpf_kernelcache_path() {
            lines.append("loaded: " + loadedPath)
        }
        if errorCarriedOver != nil {
            lines.append("(注意：本次解析之前就存在一段残留错误，见文末「残留错误」)")
        }

        // 分区只靠标题行：showReport 会丢掉空行（见那个函数的注释）
        lines.append("== 符号解析 ==")
        var lastError = errorCarriedOver
        var isFirstKey = true
        var failedKeys = 0
        for symbol in DebugProcView.xpfSymbolKeys {
            let value = km_xpf_resolve_symbol(symbol.key)
            let errorNow = km_xpf_last_error()
            let isNewFailure = isFirstKey || errorNow != lastError
            isFirstKey = false
            lastError = errorNow

            if value != 0 {
                lines.append("✓ \(symbol.key) = 0x" + String(value, radix: 16) + "  — " + symbol.purpose)
                continue
            }
            failedKeys += 1
            lines.append("✗ \(symbol.key) = 取不到值（" + symbol.purpose + "）")
            /* 错误文本没变 ⟹ 这段错误在这一个键解析之前就已经存在，不是它报的。
             * 那种情况下真正的原因只能是「键名没在 XPF 里注册」或「finder 静默失败」，
             * 照实说；把快照里的旧文本挂到它头上就是伪造证据。 */
            if isNewFailure {
                errorLines(errorNow).forEach { lines.append("    " + $0) }
            } else {
                lines.append("    该键没有新报错：键名可能没在 XPF 里注册，或 finder 静默失败")
            }
        }

        if let leftover = lastError {
            lines.append("== 残留错误（不是本批键新报的，供对照） ==")
            errorLines(leftover).forEach { lines.append("  " + $0) }
        }

        let symbolStatus = failedKeys == 0
            ? "8/8 符号就绪"
            : "\(xpfSymbolKeys.count - failedKeys)/\(xpfSymbolKeys.count) 符号就绪，\(failedKeys) 个失败"
        return (lines.joined(separator: "\n"),
                "［XPF］ 已就绪（耗时 " + String(format: "%.1f", elapsedSeconds) + " s）· " + symbolStatus,
                true)
    }

    private static func errorLines(_ error: String?) -> [String] {
        guard let error else { return ["（没有错误文本）"] }
        return error.split(separator: "\n").map(String.init)
    }

    // MARK: - Slide：kernel slide 与 PA→KVA 换算

    /*
     * 这个按钮要回答两件事：内核被搬到哪去了（slide / kernel base），以及一个物理
     * 地址对应哪个内核虚拟地址（PA→KVA）。它是按 PA 改写 PTE 那条路的前置 ——
     * 「证明某个地址确实已映射」这件事的技术前提，正是一套不依赖页表遍历的换算基准。
     *
     * 与「XPF」按钮的关键差别：**它会 kread**
     * （proc → fd_ofiles → fileproc → fileglob → fileops → fo_kqfilter，再读
     *  ptov_table 与三个全局）。libkfd 的后端不是线程安全的 —— kread_sem_open 每次读
     * 都要改写自己 psemnode 的 pinfo，并发的两次 kread 会互相踩。所以这里走
     * `AutoTracker.shared.syncExternal`，与 runProbe 同一条串行队列。
     * XPF 不走它：那条路只碰文件与 mmap，和内核读写无关。
     *
     * 前置条件只有「内核层已就绪」；XPF 还没初始化时，本按钮会自己初始化它
     * （要解压解析几十 MB 的 kernelcache，可能几十秒 —— 面板会显示"计算中"）。
     */

    private var slideBusy = false
    private var slideStarted = Date.distantPast

    @objc private func onSlideProbe() {
        runSlideProbe()
    }

    private func runSlideProbe() {
        if slideBusy {
            // 与 XPF 同一套防重入。门槛比 XPF 宽：它可能先花几十秒去初始化 XPF。
            if Date().timeIntervalSince(slideStarted) <= 120 {
                showReport("Slide: 还在算（首次要初始化 XPF，可能几十秒）")
                return
            }
        }
        slideBusy = true
        slideStarted = Date()
        slideLabel.text = "［Slide］ 计算中…（可能要先解析 kernelcache）"
        slideLabel.textColor = idleText
        probeLabel.text = "Slide: 计算中…"
        probeLabel.textColor = idleText

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // 与读取链共用同一条串行队列 —— 本按钮会 kread（理由见上面那段注释）
            let text = AutoTracker.shared.syncExternal { DebugProcView.slideReport() }
            DispatchQueue.main.async {
                guard let s = self else { return }
                s.slideBusy = false
                s.showReport(text)

                let ready = km_phystokv_ready()
                let slide = km_slide_value()
                let line: String
                if ready {
                    line = "［Slide］ 就绪 · slide=0x" + String(slide, radix: 16)
                        + " · base=0x" + String(km_slide_kernel_base(), radix: 16)
                } else if slide != 0 {
                    line = "［Slide］ slide 已通过自检，换算表未就绪（诊断见列表）"
                } else {
                    line = "［Slide］ 未完成（诊断见列表）"
                }
                s.slideLabel.text = line
                s.slideLabel.textColor = ready ? s.accent : s.warnText
                DebugProcView.slideNote = line
            }
        }
    }

    /// 真正碰 C 接口的那些调用。**必须在主线程之外执行**（见 runSlideProbe）。
    ///
    /// 报告的正文（每一步的判据与读到的值）由 C 侧拼好放在第一行摘要之后 ——
    /// 分步逻辑在 KernelSlide.m 里，这里只负责显示：面板不复算任何判据，
    /// 免得两边各判断一次、结论还不一致。
    private static func slideReport() -> String {
        var lines: [String] = []

        let ok = km_slide_resolve()
        lines.append(ok ? "✓ Slide 就绪" : "✗ Slide 未完成（失败在哪一步见下面第一行摘要）")

        if let diagnostic = km_slide_diagnostic() {
            lines.append(contentsOf: diagnostic.split(separator: "\n").map(String.init))
        }

        lines.append("== 对外接口 ==")
        lines.append("km_slide_value() = 0x" + String(km_slide_value(), radix: 16))
        lines.append("km_slide_kernel_base() = 0x" + String(km_slide_kernel_base(), radix: 16))
        lines.append("km_phystokv_ready() = " + (km_phystokv_ready() ? "true" : "false"))
        return lines.joined(separator: "\n")
    }

    @objc private func onCrashFile() {
        if !extraRows.isEmpty {
            extraRows = []
            table.reloadData()
            probeLabel.text = "已返回进程列表"
            probeLabel.textColor = idleText
            return
        }
        // 顺序：上次走到哪 → 游戏最新崩溃详情 → 我们自己的 → 全部报告列表
        var rows = ["══ 上次走到 ══"]
        rows.append("最新一步: " + MemoryProbe.latestStage())
        let stages = MemoryProbe.lastStages(8)
        rows.append(contentsOf: stages.isEmpty ? ["(无记录)"] : stages)
        rows.append("")
        rows.append("══ 游戏最新崩溃 ══")
        rows.append(contentsOf: CrashLogReader.crashDetail(for: "ShadowTrackerExtra"))
        rows.append("")
        rows.append("══ Music 最新崩溃 ══")
        if let s = CrashLogReader.latestSummary() {
            rows.append(contentsOf: s.split(separator: "\n").prefix(4).map(String.init))
        } else {
            rows.append("(无)")
        }
        rows.append("")
        rows.append("══ 全部报告 ══")
        rows.append(contentsOf: CrashLogReader.listReports(limit: 16))
        extraRows = rows
        table.reloadData()
        probeLabel.text = "崩溃报告 \(rows.count) 行已填入列表（可滚动）"
        probeLabel.textColor = accent
    }

    // MARK: - Table

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        kernelStatusRows().count + (extraRows.isEmpty ? entries.count : extraRows.count)
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "proc", for: indexPath)
        cell.backgroundColor = .clear
        cell.selectionStyle = .none

        // 内核层状态常驻在最前，不被任何操作覆盖
        let krows = kernelStatusRows()
        if indexPath.row < krows.count {
            let line = krows[indexPath.row]
            cell.textLabel?.text = line
            cell.textLabel?.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
            cell.textLabel?.lineBreakMode = .byTruncatingTail
            if line.contains("不可用") {
                cell.textLabel?.textColor = warnText
            } else if line.contains("✗") {
                // 失败标记优先于下面那些"成功"关键词：XPF 的失败行里会带上候选路径全文，
                // 而内核路径本身就含 "OK" 之类的片段，按顺序判会把它染成成功色。
                cell.textLabel?.textColor = warnText
            } else if line.contains("就绪") || line.contains("✓") || line.contains("OK") || line.contains("MATCH") {
                cell.textLabel?.textColor = accent
            } else {
                cell.textLabel?.textColor = idleText
            }
            return cell
        }
        let row = indexPath.row - krows.count

        // 文本行模式（Jetsam 报告等）：逐行显示，可滚动
        if !extraRows.isEmpty {
            guard row < extraRows.count else { return cell }
            let line = extraRows[row]
            cell.textLabel?.text = line
            cell.textLabel?.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
            cell.textLabel?.lineBreakMode = .byTruncatingTail
            if line.contains("✓") {
                cell.textLabel?.textColor = accent
            } else if line.contains("✗") {
                cell.textLabel?.textColor = warnText
            } else {
                cell.textLabel?.textColor = idleText
            }
            return cell
        }

        if row >= entries.count { return cell }

        let e = entries[row]
        let comm = e.comm.isEmpty ? "(no comm)" : e.comm
        var mark = ""
        if e.exact { mark = "  ●" } else if e.matched { mark = "  ○" }
        cell.textLabel?.text = String(format: "%6d  %@%@", e.pid, comm, mark)
        let weight: UIFont.Weight = e.exact ? .bold : (e.matched ? .semibold : .regular)
        cell.textLabel?.font = .monospacedSystemFont(ofSize: 11, weight: weight)
        if e.exact {
            cell.textLabel?.textColor = accent
        } else if e.matched {
            cell.textLabel?.textColor = UIColor.hex(0x7A93B8)
        } else {
            cell.textLabel?.textColor = idleText
        }
        cell.textLabel?.lineBreakMode = .byTruncatingMiddle
        return cell
    }
}
