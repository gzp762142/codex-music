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
    private let headerH: CGFloat = 50
    private let btnRowH: CGFloat = 26

    private let countLabel = UILabel()
    private let hitLabel = UILabel()
    private let probeLabel = UILabel()
    private let crashLabel = UILabel()
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
    /// 内存：读游戏的内存账本（footprint / compressed），不碰游戏内存
    private let btnMemory = UIButton(type: .system)
    /// 映射：把游戏内存 remap 进我们自己进程，之后本地读（样本的读取方式）
    private let btnMap = UIButton(type: .system)
    /// 读模块头：dump 基址处读 Mach-O，判断 ASLR 是否搬过基址
    /// 扫基址：128MB 内找 Mach-O magic（比上一版范围小）
    private let btnScan = UIButton(type: .system)
    /// 区域归属：问「这个地址属于哪个文件」（零风险探测）
    private let btnRegion = UIButton(type: .system)
    /// 静默测试：只持端口零读取（切掉"端口本身是否致命"这一类假设）
    private let btnSilent = UIButton(type: .system)
    /// Jetsam 日志：文件名不带进程名，必须按 JetsamEvent 前缀扫
    private let btnJetsam = UIButton(type: .system)

    private let accent = UIColor.hex(0x185EE0)
    private let idleText = UIColor.hex(0x5A6A82)
    private let warnText = UIColor.hex(0xB04141)

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear

        for l in [countLabel, hitLabel, probeLabel, crashLabel] {
            l.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            l.textColor = idleText
            l.adjustsFontSizeToFitWidth = true
            l.minimumScaleFactor = 0.6
            l.lineBreakMode = .byTruncatingTail
            addSubview(l)
        }
        hitLabel.font = .monospacedSystemFont(ofSize: 11, weight: .medium)

        // 面板只留 5 个。主链已经验证过了，不需要再一步步点 ——
        // 其余按钮的声明和 action 都还留在文件里（只是不接线），要单独排查时接回来即可。
        let buttons: [(UIButton, String, Selector)] = [
            (btnAuto, "跑一次", #selector(onAutoRun)),
            (btnMap, "映射", #selector(onMapProbe)),
            (btnRefresh, "刷新", #selector(onRefresh)),
            (btnObjects, "对象", #selector(onObjects)),
            (btnCrashFile, "崩溃文件", #selector(onCrashFile)),
            (btnMemory, "内存", #selector(onMemory))
        ]
        for (b, title, sel) in buttons {
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

        table.dataSource = self
        table.delegate = self
        table.rowHeight = Self.rowHeight
        table.backgroundColor = .clear
        table.separatorStyle = .none
        table.register(UITableViewCell.self, forCellReuseIdentifier: "proc")
        addSubview(table)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func layoutSubviews() {
        super.layoutSubviews()
        let w = bounds.width
        countLabel.frame = CGRect(x: 0, y: 0, width: w, height: 14)
        hitLabel.frame = CGRect(x: 0, y: 15, width: w * 0.6, height: 14)
        crashLabel.frame = CGRect(x: w * 0.6, y: 15, width: w * 0.4, height: 14)
        probeLabel.frame = CGRect(x: 0, y: 30, width: w, height: 14)

        // 6 个按钮排成 3 列 × 2 行
        let all = [btnAuto, btnMap, btnRefresh, btnObjects, btnCrashFile, btnMemory]
        let gap: CGFloat = 4
        let perRow = 3
        let bw = (w - gap * CGFloat(perRow - 1)) / CGFloat(perRow)
        let bh = btnRowH - 6
        for (i, b) in all.enumerated() {
            let col = CGFloat(i % perRow)
            let row = CGFloat(i / perRow)
            b.frame = CGRect(x: col * (bw + gap), y: headerH + row * btnRowH,
                             width: bw, height: bh)
        }

        table.frame = CGRect(x: 0, y: headerH + btnRowH * 2, width: w,
                             height: max(0, bounds.height - headerH - btnRowH * 2))
    }

    func reload() { onRefresh() }

    /// 上一次读取还没回来：挡住重复点击，避免后台堆积多个操作。
    private var probeBusy = false
    /// 上一次读取的发起时刻 —— 用来判断它是不是已经被内核永久堵住了。
    private var probeStarted = Date.distantPast
    /// 轮询后台进度的定时器：面板上实时显示走到哪一步。
    private var stageTimer: Timer?

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
        let pid = gpid

        // 面板上实时显示后台走到哪一步。崩之前那一瞬间屏幕上的字是唯一的现场 ——
        // 落盘和崩溃日志都可能来不及（被系统直接杀掉时信号处理器根本没机会跑）。
        stageTimer?.invalidate()
        stageTimer = Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { [weak self] _ in
            guard let s = self, s.probeBusy else { return }
            let stage = MemoryProbe.currentStage
            s.probeLabel.text = stage.isEmpty ? pending : "\(pending) · \(stage)"
        }

        DispatchQueue.global(qos: .userInitiated).async {
            MemoryProbe.stageMark(pending)
            let t0 = Date()
            let result = work(pid)
            let ms = Int(Date().timeIntervalSince(t0) * 1000)
            MemoryProbe.stageMark("完成 · \(ms) ms")
            DispatchQueue.main.async { [weak self] in
                guard let s = self else { return }
                s.probeBusy = false
                s.stageTimer?.invalidate()
                s.stageTimer = nil
                s.showReport("[\(ms) ms] " + result)
            }
        }
    }

    /// 把多行报告同时放进状态行（第一行）和可滚动列表（全部行）。
    /// 「找村口」「定点读」的结论是多行的（base/slide/三个落点/链上的值），
    /// 单行状态栏放不下，必须给列表看。
    private func showReport(_ text: String) {
        let lines = text.split(separator: "\n").map(String.init)
        probeLabel.text = lines.first ?? text
        probeLabel.textColor = text.contains("✓") ? accent : warnText
        extraRows = lines
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
        countLabel.text = "共 \(entries.count) · 精确\(exact) · 疑似\(loose) · \(ProcessScanner.channelSummary)"
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

    /// 世界：GWorld → PersistentLevel → Actors（三次小读，走热页）。
    @objc private func onWorld() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("世界: 读取中…") { MemoryProbe.stepWorld(pid: $0) }
    }

    /// 内存：游戏的内存账本（不碰游戏内存），用来看操作前后 footprint/compressed 的差值。
    @objc private func onMemory() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        runProbe("内存: 读取中…") { MemoryProbe.stepMemory(pid: $0) }
    }

    /// 映射：把游戏内存 remap 进我们自己进程，之后从本地内存读（样本的读取方式）。
    ///
    /// **自包含**：先自己刷新拿 pid，缺基址就自己找一次（找基址本身几乎不读游戏内存，
    /// 只有 Mach-O 头校验那两次调用）。所以这一步不需要你先点别的按钮 ——
    /// 前面手动串联的步骤，凡是能自动的都自动掉。
    @objc private func onMapProbe() {
        refreshProcess()
        guard gpid != 0 else {
            probeLabel.text = "映射: 没找到游戏进程"
            probeLabel.textColor = warnText
            return
        }
        runProbe("映射: 建立中…") { pid -> String in
            var out: [String] = []
            if !MemoryProbe.baseReady(for: pid) {
                let base = MemoryProbe.stepFindBase(pid: pid)
                out.append(base)
                guard base.contains("✓ base=") else {
                    out.append("→ 没拿到基址，映射没得做")
                    return out.joined(separator: "\n")
                }
                out.append("")
            }
            out.append(MemoryProbe.stepRemapProbe(pid: pid))
            return out.joined(separator: "\n")
        }
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
        extraRows.isEmpty ? entries.count : extraRows.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "proc", for: indexPath)
        cell.backgroundColor = .clear
        cell.selectionStyle = .none

        // 文本行模式（Jetsam 报告等）：逐行显示，可滚动
        if !extraRows.isEmpty {
            guard indexPath.row < extraRows.count else { return cell }
            let line = extraRows[indexPath.row]
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

        if indexPath.row >= entries.count { return cell }

        let e = entries[indexPath.row]
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
