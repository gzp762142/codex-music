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
    private var entries: [ProcessScanner.ProcEntry] = []
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
    private let btnHead = UIButton(type: .system)
    /// 扫基址：128MB 内找 Mach-O magic（比上一版范围小）
    private let btnScan = UIButton(type: .system)

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
            (btnHead, "模块头", #selector(onModuleHead)),
            (btnScan, "扫基址", #selector(onBaseScan)),
            (btnRefresh, "刷新", #selector(onRefresh)),
            (btnCrashFile, "崩溃文件", #selector(onCrashFile))
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
        let all = [btnSym, btnDlsym, btnProof, btnFixed, btnHead, btnScan, btnRefresh, btnCrashFile]
        let gap: CGFloat = 4
        let perRow = 4
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

    /// 读模块头：dump 基址处读 Mach-O 头，能判断 ASLR 是否搬过基址。
    @objc private func onModuleHead() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        probeLabel.text = MemoryProbe.stepModuleHead(pid: gpid)
        probeLabel.textColor = accent
    }

    /// 扫基址：最后手段，128MB 内找 Mach-O magic。
    @objc private func onBaseScan() {
        guard gpid != 0 else { probeLabel.text = "先刷新拿到 pid"; return }
        probeLabel.text = MemoryProbe.stepBaseScan(pid: gpid)
        probeLabel.textColor = accent
    }

    @objc private func onCrashFile() {
        if let s = CrashLogReader.latestSummary() {
            probeLabel.text = "ips: " + s.replacingOccurrences(of: "\n", with: " | ")
        } else {
            probeLabel.text = "ips: 没找到 Music 的崩溃报告"
        }
        probeLabel.textColor = warnText
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
