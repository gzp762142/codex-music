import UIKit

/// 进程扫描调试页（挂在「设置」页签下面）。
///
/// 目的很单纯：**把 p_comm 直接摆在面板上看**。没有 Mac 日志，肉眼扫列表最快。
/// 命中目标进程的行整行标蓝，一眼能看见。
final class DebugProcView: UIView, UITableViewDataSource, UITableViewDelegate {

    static let rowHeight: CGFloat = 22

    private let scanner = ProcessScanner()
    private var entries: [ProcessScanner.ProcEntry] = []
    private let headerH: CGFloat = 34

    private let refreshBtn = UIButton(type: .system)
    private let countLabel = UILabel()
    private let hitLabel = UILabel()
    private let table = UITableView(frame: .zero, style: .plain)

    private let accent = UIColor.hex(0x185EE0)
    private let idleText = UIColor.hex(0x5A6A82)
    private let mainText = UIColor.hex(0x2A2A32)

    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear

        refreshBtn.setTitle("刷新", for: .normal)
        refreshBtn.titleLabel?.font = .systemFont(ofSize: 13, weight: .semibold)
        refreshBtn.setTitleColor(accent, for: .normal)
        refreshBtn.addTarget(self, action: #selector(onRefresh), for: .touchUpInside)
        addSubview(refreshBtn)

        countLabel.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        countLabel.textColor = idleText
        addSubview(countLabel)

        hitLabel.font = .monospacedSystemFont(ofSize: 11, weight: .medium)
        hitLabel.textColor = mainText
        addSubview(hitLabel)

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
        refreshBtn.frame = CGRect(x: w - 62, y: 0, width: 56, height: headerH)
        countLabel.frame = CGRect(x: 0, y: 2, width: w - 66, height: 14)
        hitLabel.frame = CGRect(x: 0, y: 17, width: w - 66, height: 14)
        table.frame = CGRect(x: 0, y: headerH, width: w, height: max(0, bounds.height - headerH))
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
        let matched = entries.filter { $0.matched }.count
        countLabel.text = "共 \(total) 个进程 · 命中 \(matched)"
        if let pid = hit {
            hitLabel.text = "game pid = \(pid)"
            hitLabel.textColor = accent
        } else {
            hitLabel.text = "game pid = 未找到"
            hitLabel.textColor = UIColor.hex(0xB04141)
        }
        table.reloadData()
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
        var text = String(format: "%6d  %@", e.pid, comm)
        if e.matched {
            text = String(format: "%6d  %@  ●", e.pid, comm)
        }
        cell.textLabel?.text = text
        cell.textLabel?.font = .monospacedSystemFont(ofSize: 11, weight: e.matched ? .semibold : .regular)
        cell.textLabel?.textColor = e.matched ? accent : idleText
        cell.textLabel?.lineBreakMode = .byTruncatingMiddle
        return cell
    }
}
