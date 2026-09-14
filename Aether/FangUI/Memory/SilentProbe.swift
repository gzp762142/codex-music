import Foundation

/// 静默测试：**只持有 task port，一个字节都不读**，观察目标是否自己死掉。
///
/// 这是切掉一整类假设的实验：
///   崩 → 病根是"拿到端口"这件事本身（CS_DEBUGGED / 进程状态被改），
///        与读不读内存无关，整个读取模型要重写
///   不崩 → 排除这一整类，问题回到"读取动作"上
///
/// 存活检测用**重新枚举进程列表**，不用 mach_vm_read ——
/// 全程零内存读取。
final class SilentProbe {

    /// 检查间隔（秒）。枚举进程本身有开销，不宜过密。
    private let interval = 5

    private var timer: Timer?
    private var elapsed = 0
    private var duration = 120
    private var pid: Int32 = 0
    private var heldPort: UInt32 = 0
    private let scanner = ProcessScanner()

    /// 每次检查回调：(已过秒数, 是否仍存活)
    var onTick: ((Int, Bool) -> Void)?
    /// 结束回调：(坚持了秒数, 是否活到最后, 端口是否拿到)
    var onFinish: ((Int, Bool, Bool) -> Void)?

    var isRunning: Bool { timer != nil }

    func start(pid: Int32, seconds: Int = 120) {
        stop()
        self.pid = pid
        self.duration = seconds
        self.elapsed = 0

        // 只取端口并持有它 —— 这是本次实验唯一的动作
        if let got = MemoryProbe.acquirePort(pid: pid) {
            heldPort = got.port
        } else {
            heldPort = 0
        }

        timer = Timer.scheduledTimer(withTimeInterval: Double(interval), repeats: true) {
            [weak self] _ in
            self?.tick()
        }
    }

    private func tick() {
        elapsed += interval
        let alive = scanner.scan().contains { $0.pid == pid }
        onTick?(elapsed, alive)

        if !alive {
            finish(aliveAtEnd: false)
            return
        }
        if elapsed >= duration {
            finish(aliveAtEnd: true)
        }
    }

    private func finish(aliveAtEnd: Bool) {
        stop()
        onFinish?(elapsed, aliveAtEnd, heldPort != 0)
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }
}
