import UIKit

/// 进程扫描 + 读内存探针的调试页（挂在「设置」页签下面）。
///
/// 上半部分显示三行状态：
///   1. 进程数 / 命中数 / libproc 两条路是否可用
///   2. 游戏 pid（精确命中才有）
///   3. task_for_pid 探针结果 —— 端口号、内存区数、读到的 Mach-O magic
/// 下面是可滚动的 p_comm 列表，● 精确命中、○ 疑似。
final class DebugProcView: UIView, UITableViewDataSource, UITableViewDelegate {

    static let rowHeight: CGFloat = 22

    private let scanner = ProcessScanner()
    private let probe = MemoryProbe()
    private var entries: [ProcessScanner.ProcEntry] = []
    private let headerH: CGFloat = 50

    private let refreshBtn = UIButton(type: .system)
    private let countLabel = UILabel()
    private let hitLabel = UILabel()
    private let probeLabel = UILabel()
    /// 崩溃记录（贴在 hit 行右侧，不额外占高度）
    private let crashLabel = UILabel()
    private let table = UITableView(frame: .zero, style: .plain)

    private let accent = UIColor.hex(0x185EE0)
    private let idleText = UIColor.hex(0x5A6A82)
    private let warnText = UIColor.hex(0xB04141)

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear

        refreshBtn.setTitle("刷新", for: .normal)
        refreshBtn.titleLabel?.font = .systemFont(ofSize: 13, weight: .semibold)
        refreshBtn.setTitleColor(accent, for: .normal)
        refreshBtn.addTarget(self, action: #selector(onRefresh), for: .touchUpInside)
        addSubview(refreshBtn)

        for l in [countLabel, hitLabel, probeLabel, crashLabel] {
            l.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            l.textColor = idleText
            l.adjustsFontSizeToFitWidth = true
            l.minimumScaleFactor = 0.65
            l.lineBreakMode = .byTruncatingTail
            addSubview(l)
        }
        hitLabel.font = .monospacedSystemFont(ofSize: 11, weight: .medium)

        table.dataSource = self
        table.delegate = self
        table.rowHeight = Self.rowHeight
        table.backgroundColor = .clear
        table.separatorStyle = .none
        table.showsVerticalScrollIndicator = true
        table.register(UITableViewCell.self, forCellReuseIdentifier: "proc")
        addSubview(table)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func layoutSubviews() {
        super.layoutSubviews()
        let w = bounds.width
        refreshBtn.frame = CGRect(x: w - 62, y: 0, width: 56, height: 28)
        countLabel.frame = CGRect(x: 0, y: 0, width: w - 66, height: 14)
        hitLabel.frame = CGRect(x: 0, y: 15, width: w - 66, height: 14)
        // 第三行：左半结论，右半 syscall 候选号返回码
        probeLabel.frame = CGRect(x: 0, y: 30, width: w * 0.62, height: 14)
        crashLabel.frame = CGRect(x: w * 0.64, y: 30, width: w * 0.36, height: 14)
        table.frame = CGRect(x: 0, y: headerH, width: w,
                             height: max(0, bounds.height - headerH))
    }

    /// 进入这一页时调用：重扫一遍。
    func reload() {
        onRefresh()
    }

    @objc private func onRefresh() {
        scanner.invalidate()            // 手动刷新必须绕过 2 秒 TTL
        entries = scanner.scan()
        let hit: Int32? = scanner.findGamePID(forceRefresh: true)

        let total = entries.count
        let exactCount = entries.filter { $0.exact }.count
        let looseCount = entries.filter { $0.matched && !$0.exact }.count
        countLabel.text = "共 \(total) · 精确\(exactCount) · 疑似\(looseCount) · \(ProcessScanner.channelSummary)"

        if let pid = hit {
            hitLabel.text = "game pid = \(pid)  确认"
            hitLabel.textColor = accent
            runProbe(pid: pid)
        } else {
            hitLabel.text = "game pid = 未找到"
            hitLabel.textColor = warnText
            probeLabel.text = "task_for_pid: 等待命中进程"
            probeLabel.textColor = idleText
            crashLabel.text = ""
        }
        table.reloadData()
    }

    /// 清掉崩溃记录（调试页右上角长按用；也可由外部调用）。
    func clearCrashLog() {
        CrashCatcher.clear()
        crashLabel.text = ""
    }

    /// 探针：dlsym task_for_pid → 取端口 → 枚举区 + 读头部。
    private func runProbe(pid: Int32) {
        let r = probe.probe(pid: pid)
        probeLabel.text = r.summary
        probeLabel.textColor = r.ok ? accent : warnText
        // 崩过就先显示崩溃原因，否则显示 syscall 候选号的返回码
        if let crash = CrashCatcher.lastCrash() {
            let firstLine = crash.split(separator: "\n").prefix(2).joined(separator: " ")
            crashLabel.text = "崩溃: " + firstLine
            crashLabel.textColor = warnText
        } else {
            crashLabel.text = r.numberNote
            crashLabel.textColor = idleText
        }
    }

    // MARK: - Table

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        entries.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "proc", for: indexPath)
        cell.backgroundColor = .clear
        cell.selectionStyle = .none
        if indexPath.row >= entries.count { return cell }

        let e = entries[indexPath.row]
        let comm = e.comm.isEmpty ? "(no comm)" : e.comm
        // ● = 精确命中（判据）／○ = 疑似（仅子串命中，可能是误报）
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
