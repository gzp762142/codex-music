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

    private let btnRefresh = UIButton(type: .system)
    private let btnSym = UIButton(type: .system)
    private let btnDlsym = UIButton(type: .system)
    private let btnProof = UIButton(type: .system)
    private let btnCrashFile = UIButton(type: .system)
    /// 定点读：用 dump 偏移读 GObjects/GNames/GWorld —— 只读 3 个地址，不扫描
    private let btnFixed = UIButton(type: .system)
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

        let buttons: [(UIButton, String, Selector)] = [
            (btnSym, "符号", #selector(onSym)),
            (btnDlsym, "dlsym", #selector(onDlsym)),
            (btnProof, "读证", #selector(onProof)),
            (btnFixed, "定点读", #selector(onFixedRead)),
            (btnRegion, "区域归属", #selector(onRegionName)),
            (btnScan, "找村口", #selector(onFindBase)),
            (btnRefresh, "刷新", #selector(onRefresh)),
            (btnCrashFile, "崩溃文件", #selector(onCrashFile)),
            (btnSilent, "静默", #selector(onSilent)),
            (btnJetsam, "Jetsam", #selector(onJetsam))
        ]
        for (b, title, sel) in buttons {
            b.setTitle(title, for: .normal)
            b.titleLabel?.font = .systemFont(ofSize: 11, weight: .semibold)
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

        // 八个按钮排成 4×2
        let all = [btnSym, btnDlsym, btnProof, btnFixed, btnRegion,
                   btnScan, btnRefresh, btnCrashFile, btnSilent, btnJetsam]
        let gap: CGFloat = 4
        let perRow = 5
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

    // MARK: - 单步动作

    @objc private func onRefresh() {
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
        table.reloadData()
    }

    @objc private func onSym() {
        probeLabel.text = "符号 " + MemoryProbe.stepSymbols()
        probeLabel.textColor = idleText
    }

    @objc private func onDlsym() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        probeLabel.text = MemoryProbe.stepDlsym(pid: gpid)
        probeLabel.textColor = accent
    }

    @objc private func onProof() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        probeLabel.text = MemoryProbe.stepReadProof(pid: gpid)
        probeLabel.textColor = accent
    }

    /// 定点读：只用 dump 偏移读 3 个全局量，一次调用读完，不扫描。
    /// 读到有效指针 → 权限和读链路都没问题，"找不到"是范围/基址问题。
    @objc private func onFixedRead() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        probeLabel.text = MemoryProbe.stepFixedRead(pid: gpid)
        probeLabel.textColor = accent
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
        probeLabel.text = MemoryProbe.stepRegionName(pid: gpid)
        probeLabel.textColor = accent
    }

    /// 找村口：小范围页步进 + Δ 判据，每页只读 8 字节。
    @objc private func onFindBase() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        probeLabel.text = MemoryProbe.stepFindBase(pid: gpid)
        probeLabel.textColor = accent
    }

    @objc private func onCrashFile() {
        if !extraRows.isEmpty {
            extraRows = []
            table.reloadData()
            probeLabel.text = "已返回进程列表"
            probeLabel.textColor = idleText
            return
        }
        // 顺序：先列全部 .ips → 再游戏最新崩溃详情（最关键）→ 最后我们自己的
        var rows = CrashLogReader.listReports(limit: 16)
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
