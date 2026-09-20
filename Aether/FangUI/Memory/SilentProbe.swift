//
//  SilentProbe.swift
//  静默测试：**只解析目标 proc，一个字节都不读**，观察目标是否自己死掉。
//
//  读取路径切到内核之后，这里的探测手段也跟着换了：
//  旧版靠持有一个 task port（副作用是给目标挂一个 send right），
//  端口机制已经整体移除，所以现在改为用 km_proc_for_pid 做纯查询 ——
//  它只在 p_list 环上比 p_pid，不读目标任何数据，比原版更"静默"。
//
//  结论仍然分两类：
//    崩 → 病根在"在内核里定位这个进程"这件事本身，与读不读内存无关；
//    不崩 → 排除这一整类，问题回到"读取动作"上。
//
//  存活检测用**重新枚举进程列表**，不用内核读 —— 全程零内存读取。
//
final class SilentProbe {

    /// 检查间隔（秒）。枚举进程本身有开销，不宜过密。
    private let interval = 5

    private var timer: Timer?
    private var elapsed = 0
    private var duration = 120
    private var pid: Int32 = 0
    /// 目标 proc 是否解析成功（等价于旧版的"端口是否拿到"）。
    private var resolved = false
    private let scanner = ProcessScanner()

    /// 每次检查回调：(已过秒数, 是否仍存活)
    var onTick: ((Int, Bool) -> Void)?
    /// 结束回调：(坚持了秒数, 是否活到最后, proc 是否解析成功)
    var onFinish: ((Int, Bool, Bool) -> Void)?

    var isRunning: Bool { timer != nil }

    func start(pid: Int32, seconds: Int = 120) {
        stop()
        self.pid = pid
        self.duration = seconds
        self.elapsed = 0

        // 本次实验唯一的动作：在内核里解析这个 pid 的 proc。
        resolved = (km_proc_for_pid(pid) != 0)

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
        onFinish?(elapsed, aliveAtEnd, resolved)
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        // 内核路径不持有 port right，也就没有需要释放的东西；
        // 目标 proc 的地址只是记录，不增加目标引用计数。
        resolved = false
    }
}
