import Foundation
import UIKit

/// 后台自动化状态机 —— 把「人工按顺序点按钮」这个前提去掉。
///
/// 两层，**不合并**：
///
///   **心跳层 1Hz** —— 只做生命周期：探 pid、attach、判断游戏是否还在。
///   没挂上且游戏在 → `bind` + `attachPort` + 找基址 + 铺一次映射；
///   挂上了但游戏没了 → `detachPort` + `releaseAllMappings`，回到等待。
///   **这一层绝不做全量扫描。**
///
///   **快照层 20Hz** —— 只走「自己 + 相机」这条短链（约 15–20 次小读）；
///   Actors 全量遍历挂在同一条队列的 1Hz 慢分频上（那条链有 650 个 actor）。
///
/// 手动按钮和它**共用同一条串行队列**：`MemoryProbe` 的 `mappedRanges` /
/// `activePid` / `imageBase` 全是静态状态，两条路并发跑会互相踩 ——
/// 尤其 `bind()` 会清空映射，正好撞上快照层正在读的时候。
final class AutoTracker {

    static let shared = AutoTracker()

    // MARK: - 状态

    enum State: String {
        case idle      = "空闲"
        case waiting   = "等游戏"
        case attaching = "挂载中"
        case running   = "运行中"
        case degraded  = "降频"
        case failed    = "失败"
    }

    /// 画框要用的东西：屏幕坐标 + 距离，全部已算好。
    struct RenderTarget {
        var actor: UInt64 = 0
        var cls = ""
        var loc: (Float, Float, Float) = (0, 0, 0)
        var dist: Double = 0
        /// 屏幕逻辑坐标；nil = 在相机身后
        var screen: (Double, Double)?
        var onScreen = false
        var isSelf = false
    }

    /*
     * 状态的跨线程可见性 —— 用计算属性把**写**收在队列里，**读**也走队列。
     *
     * 为什么不能裸读：这些值全部只在 `queue` 上写，但 `DebugProcView` 在主线程
     * 直接读（`t.state.rawValue`、`AutoTracker.shared.protectionNote`、
     * `lastScanNote`）。`String` 不是原子类型，主线程读、后台写同一个 String
     * 可能读到半更新的内部缓冲；`[RenderTarget]` 更是有崩溃面。
     *
     * `syncExternal` 自己会先查 `DispatchSpecificKey`，已在队列上就直接调、
     * 不重入 `queue.sync` —— 所以这些访问器在队列内部读也安全。
     * 代价是 UI 每读一个字段一次 `queue.sync`，读发生在 4Hz 的列表刷新上，
     * 不在热路径。
     */
    private func withState<T>(_ body: () -> T) -> T {
        syncExternal(body)
    }

    private var _state: State = .idle
    private var _detail = ""
    private var _targets: [RenderTarget] = []
    private var _selfSnap = MemoryProbe.SelfSnapshot()

    var state: State { withState { _state } }
    var detail: String { withState { _detail } }
    var targets: [RenderTarget] { withState { _targets } }
    var selfSnap: MemoryProbe.SelfSnapshot { withState { _selfSnap } }

    private var _fastHz: Double = 20
    private var _tickCount = 0
    private var _lastScanNote = ""
    private var _lastScanKernelReads = 0
    private var _lastScanMappedHits = 0
    private var _lastScanOnDemand = 0
    private var _fastTickKernelReads = 0
    private var _mappingBlocks = 0
    private var _protectionNote = "保护位: 等待首次抽查"
    private var _running = false

    /// 自检数字（验收要看的就是这几个）
    var fastHz: Double { withState { _fastHz } }
    var tickCount: Int { withState { _tickCount } }
    var lastScanNote: String { withState { _lastScanNote } }
    var lastScanKernelReads: Int { withState { _lastScanKernelReads } }
    /// 本轮扫描走映射本地读的次数（累计值在 MemoryProbe 里）
    var lastScanMappedHits: Int { withState { _lastScanMappedHits } }
    /// 本轮扫描现场补建的映射块数
    var lastScanOnDemand: Int { withState { _lastScanOnDemand } }
    var fastTickKernelReads: Int { withState { _fastTickKernelReads } }
    var mappingBlocks: Int { withState { _mappingBlocks } }
    /// 保护位抽查结果（每轮一块，轮换覆盖）。在后台队列里算好，UI 只负责读 ——
    /// `vm_region_64` 是内核调用，不该落在主线程上。
    var protectionNote: String { withState { _protectionNote } }

    /// 状态行（主线程回调）
    var onStatus: ((String) -> Void)?
    /// 目标列表（主线程回调）—— 以后 ESP 绘制从这儿取
    var onTargets: (([RenderTarget], MemoryProbe.SelfSnapshot) -> Void)?

    // MARK: - 内部

    private static let queueKey = DispatchSpecificKey<Int>()
    /// **唯一**的读取队列。手动按钮通过 `syncExternal` 走同一条。
    private let queue = DispatchQueue(label: "aether.autotracker", qos: .userInitiated)
    private let scanner = ProcessScanner()

    private var heartbeatTimer: DispatchSourceTimer?
    private var fastTimer: DispatchSourceTimer?
    private var slowTimer: DispatchSourceTimer?

    private var running = false
    private var targetPid: Int32 = 0
    private var hintPC: UInt64 = 0
    private var world: UInt64 = 0
    private var baseReady = false
    private var fastFailStreak = 0
    private var slowFailStreak = 0
    private var lastStatusPush = Date.distantPast
    private var observing = false
    /// 正常目标的频率（前后台切换只改它）。
    private var normalHz: Double = 20
    /// 自检不通过后置位 —— 一旦置位就**不再恢复**，只能重启状态机复位。
    /// 否则切一次前后台就会把降级结果冲掉。
    private var degraded = false

    private init() {
        queue.setSpecific(key: Self.queueKey, value: 1)
    }

    // MARK: - 生命周期

    func start() {
        queue.async { [weak self] in
            guard let self = self, !self._running else { return }
            self._running = true
            self.degraded = false          // 重新启动时复位降级状态
            self.normalHz = 20
            self.pushStatus("自动: 启动")
            self.observeAppState()
            self.startTimers()
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self = self else { return }
            self._running = false
            self.stopTimers()
            self.teardownLocked(reason: "手动停止")
            self.pushStatus("自动: 已停止")
        }
    }

    /// `_running` 只在队列上写；这里同步取，避免主线程裸读。
    var isRunning: Bool { withState { _running } }

    /// 手动按钮专用：在读取队列上**同步**执行。
    /// 这样按钮和状态机天然互斥，不会同时碰 `MemoryProbe` 的静态状态。
    func syncExternal<T>(_ work: () -> T) -> T {
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil {
            return work()                      // 已在队列上，直接跑（防死锁）
        }
        return queue.sync(execute: work)
    }

    private func startTimers() {
        let hb = DispatchSource.makeTimerSource(queue: queue)
        hb.schedule(deadline: .now(), repeating: 1.0, leeway: .milliseconds(200))
        hb.setEventHandler { [weak self] in self?.heartbeat() }
        hb.resume()
        heartbeatTimer = hb

        applyFrequency()

        let slow = DispatchSource.makeTimerSource(queue: queue)
        slow.schedule(deadline: .now() + 0.30, repeating: 1.0, leeway: .milliseconds(150))
        slow.setEventHandler { [weak self] in self?.slowTick() }
        slow.resume()
        slowTimer = slow
    }

    private func makeFastTimer() {
        fastTimer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        let iv = 1.0 / max(1.0, _fastHz)
        t.schedule(deadline: .now() + 0.05, repeating: iv, leeway: .milliseconds(5))
        t.setEventHandler { [weak self] in self?.fastTick() }
        t.resume()
        fastTimer = t
    }

    /// 频率的**唯一**出口：正常频率折半（若已降级），再套到定时器上。
    /// 前后台切换和自检降级都走这里，两边不会互相冲掉。
    private func applyFrequency() {
        let base = degraded ? max(5, normalHz / 2) : normalHz
        _fastHz = max(1, min(base, 30))
        makeFastTimer()
    }

    private func stopTimers() {
        heartbeatTimer?.cancel(); heartbeatTimer = nil
        fastTimer?.cancel(); fastTimer = nil
        slowTimer?.cancel(); slowTimer = nil
    }

    /// 释放一切：端口 + 映射 + 缓存地址。
    /// **必须成对**：attachPort ↔ detachPort，映射 ↔ releaseAllMappings。
    private func teardownLocked(reason: String) {
        MemoryProbe.detachPort()
        MemoryProbe.releaseAllMappings()
        targetPid = 0
        hintPC = 0
        world = 0
        baseReady = false
        _targets = []
        _selfSnap = MemoryProbe.SelfSnapshot()
        _mappingBlocks = 0
        setState(.waiting, "已释放（\(reason)）")
    }

    /// 前后台切换时**降频，不释放**。
    ///
    /// 悬浮窗形态下 `applicationState` 长期就是 `.background`（窗口浮在游戏之上，
    /// 自己不是前台 app）—— 所以"切后台就释放映射"这条不能照字面执行，否则状态机
    /// 在启动瞬间就会把自己拆掉、永远停在未挂载。这里改成：后台 2Hz、回前台 20Hz。
    /// 既避开 CPU 配额（这个项目被 cpu_resource_fatal 杀过一次），又保住功能。
    private func observeAppState() {
        guard !observing else { return }
        observing = true
        let c = NotificationCenter.default
        c.addObserver(forName: UIApplication.didEnterBackgroundNotification,
                      object: nil, queue: nil) { [weak self] _ in
            self?.queue.async { self?.setBackground(true) }
        }
        c.addObserver(forName: UIApplication.willEnterForegroundNotification,
                      object: nil, queue: nil) { [weak self] _ in
            self?.queue.async { self?.setBackground(false) }
        }
    }

    private func setBackground(_ bg: Bool) {
        guard _running else { return }
        normalHz = bg ? 2 : 20
        applyFrequency()
        pushStatus(bg ? "自动: 进入后台，降到 \(Int(_fastHz))Hz" : "自动: 回到前台，恢复 \(Int(_fastHz))Hz")
    }

    // MARK: - 心跳层（1Hz，只做生命周期）

    private func heartbeat() {
        guard _running else { return }
        scanner.invalidate()
        let list = scanner.scan()
        // 把 comm 一起带出来：`exact` 只说明 comm/路径匹配了白名单，
        // 显示出来才能确认挂的到底是哪个进程。
        guard let hit = list.first(where: { $0.exact }) else {
            if MemoryProbe.isAttached { teardownLocked(reason: "游戏已退出") }
            else { setState(.waiting, "等待游戏进程（扫到 \(list.count) 个）") }
            return
        }
        let pid = hit.pid

        // 已挂载但 pid 变了（游戏重启）→ 先释放再重挂
        if MemoryProbe.isAttached, targetPid != pid {
            teardownLocked(reason: "pid 变化 \(targetPid)→\(pid)")
        }

        // 未挂载 → 挂载
        if !MemoryProbe.isAttached {
            setState(.attaching, "发现 pid=\(pid)，正在挂载")
            MemoryProbe.bind(pid: pid)
            let (ok, note) = MemoryProbe.attachPort(pid)
            guard ok else {
                setState(.failed, note)
                return
            }
            targetPid = pid
            baseReady = false
        }

        // 基址只找一次；找不到就下一拍再试（不在这里死循环）
        if !baseReady {
            let r = MemoryProbe.stepFindBase(pid: pid)
            guard r.contains("✓ base=") else {
                setState(.attaching, "找基址未命中：" + (r.split(separator: "\n").first.map(String.init) ?? ""))
                return
            }
            baseReady = true
            // 首次挂载主动铺一次映射，之后靠按需兜底
            let mapNote = MemoryProbe.mapAllRegions(pid: pid)
            _mappingBlocks = MemoryProbe.mappedBlockCount
            setState(.running, "已挂载 \(hit.comm) pid=\(pid) · \(mapNote)")
            return
        }

        if _state != .running {
            setState(.running, "已挂载 \(hit.comm) pid=\(pid)")
        }
    }

    // MARK: - 慢分频（1Hz，Actors 全量）

    private func slowTick() {
        guard _running, MemoryProbe.isAttached, baseReady else { return }
        // 计数器一律取「本轮差值」：累计值看不出当下走的是映射还是内核
        let mappedBefore = MemoryProbe.mappedHitCalls
        let onDemandBefore = MemoryProbe.onDemandMapBlocks
        let scan = MemoryProbe.scanTargets(pid: targetPid)
        _lastScanNote = scan.note
        _lastScanKernelReads = scan.vmReads
        _lastScanMappedHits = MemoryProbe.mappedHitCalls - mappedBefore
        _lastScanOnDemand = MemoryProbe.onDemandMapBlocks - onDemandBefore
        _mappingBlocks = scan.usedMappings

        // 世界指针和本机 PlayerController **每拍更新** —— 换图/重生都会换对象，
        // 抱着旧指针去读只会得到一串 0。
        if scan.world > 0x100000000 { world = scan.world }
        if scan.localPC > 0x100000000 { hintPC = scan.localPC }
        let selfPawn = scan.localPawn

        if scan.targets.isEmpty {
            slowFailStreak += 1
            if slowFailStreak >= 3 {
                setState(.degraded, "全量扫描连续 \(slowFailStreak) 次为空：\(scan.note)")
            }
            return
        }
        slowFailStreak = 0

        var tmp: [RenderTarget] = []
        for t in scan.targets {
            var rt = RenderTarget()
            rt.actor = t.actor
            rt.cls = t.cls
            rt.loc = t.loc
            rt.isSelf = (selfPawn != 0 && t.actor == selfPawn)
            tmp.append(rt)
        }
        _targets = tmp
        // 先算好距离与屏幕坐标再推。否则这一拍交给 UI 的是 dist=0、screen=nil 的原始
        // 对象，列表会显示成一片「0m / 屏幕(身后)」，要等下一次 fastTick 才被填上 ——
        // 慢分频 1Hz 而快照 2Hz，肉眼就是距离在 0 和真实值之间来回跳。
        projectAll()
        pushTargets()
    }

    // MARK: - 快照层（20Hz，自己 + 相机）

    private func fastTick() {
        guard _running, MemoryProbe.isAttached, baseReady else { return }
        _tickCount += 1

        let vmBefore = MemoryProbe.hardReadCalls
        let snap = MemoryProbe.readSelfAndCamera(pid: targetPid, hintPC: hintPC, world: world)
        let vmDelta = MemoryProbe.hardReadCalls - vmBefore
        _fastTickKernelReads = vmDelta

        // ── 自检：降级了要**明确降频**，不静默继续 ──
        if vmDelta > 50 {
            fastFailStreak += 1
            if fastFailStreak >= 3 { degrade("单轮内核读 \(vmDelta) 次 > 50，映射没铺好") }
            return
        }
        if MemoryProbe.mappedBlockCount >= 2048 {
            fastFailStreak += 1
            if fastFailStreak >= 3 { degrade("映射块数撞到 2048 天花板") }
            return
        }
        fastFailStreak = 0

        guard snap.valid else {
            // 短链读不到（在加载画面/观战/重生中），不算失败，只是这拍没数据
            _selfSnap = snap
            return
        }

        _selfSnap = snap
        hintPC = snap.pc
        projectAll()
        pushTargets()

        // 状态行每秒刷一次就够，别把主线程打爆
        if Date().timeIntervalSince(lastStatusPush) >= 1.0 {
            lastStatusPush = Date()
            let cam = snap.camera.valid
                ? "cam(\(Int(snap.camera.fov))°)"
                : "cam无"
            // 双口径：括号里是本轮增量（看当下走哪条路），前面是累计（看趋势 ——
            // 内核读的累计值涨得太快，说明映射覆盖率不够，那是个独立信号）
            let counters = "映射命中 \(MemoryProbe.mappedHitCalls)(+\(_lastScanMappedHits))"
                + " 按需映射 \(MemoryProbe.onDemandMapBlocks)(+\(_lastScanOnDemand))"
                + " 内核读 \(MemoryProbe.hardReadCalls)(+\(_lastScanKernelReads))"
            // 抽查放后台队列算，结果留给列表单独一行 —— 状态行已经塞不下它了。
            // 降权失败数挂在这行上：它必须是 0，而且要在状态机跑着的时候也看得见 ——
            // 手动按钮的报告会被状态行/列表覆写，靠点按钮读不到它。
            _protectionNote = MemoryProbe.spotCheckProtection()
                + " · 降权失败 \(MemoryProbe.protectFailures)"
            setState(_state == .degraded ? .degraded : .running,
                     "pid=\(targetPid) \(Int(_fastHz))Hz tick=\(_tickCount) 目标\(_targets.count) 映射\(MemoryProbe.mappedBlockCount)块 \(cam) vm=\(_fastTickKernelReads)"
                     + " | \(counters)")
        }
    }

    /// 用高频层的相机给慢分频拿到的坐标做投影 —— 坐标 1Hz、相机 20Hz，
    /// 两者分开采样，画出来才不会因为列表刷新而卡顿。
    private func projectAll() {
        let cam = _selfSnap.camera
        let sw = Double(MemoryProbe.screenSize.width)
        let sh = Double(MemoryProbe.screenSize.height)
        let me = _selfSnap.loc
        for i in _targets.indices {
            let p = _targets[i].loc
            let dx = Double(p.0 - me.0), dy = Double(p.1 - me.1), dz = Double(p.2 - me.2)
            _targets[i].dist = (dx * dx + dy * dy + dz * dz).squareRoot() / 100.0
            let s = MemoryProbe.projectPoint(p.0, p.1, p.2, camera: cam, screenW: sw, screenH: sh)
            _targets[i].screen = s
            if let s = s {
                _targets[i].onScreen = (s.0 >= 0 && s.0 <= sw && s.1 >= 0 && s.1 <= sh)
            } else {
                _targets[i].onScreen = false
            }
        }
    }

    private func degrade(_ why: String) {
        if degraded {
            setState(.degraded, "自检持续不通过（\(why)），已是最低频 \(Int(_fastHz))Hz")
            return
        }
        degraded = true
        applyFrequency()
        setState(.degraded, "自检不通过（\(why)）→ 频率降到 \(Int(_fastHz))Hz")
    }

    // MARK: - 状态推送（一律回主线程）

    private func setState(_ s: State, _ d: String) {
        _state = s
        _detail = d
        let text = "自动[\(s.rawValue)] \(d)"
        pushStatus(text)
    }

    private func pushStatus(_ text: String) {
        let cb = onStatus
        DispatchQueue.main.async { cb?(text) }
    }

    private func pushTargets() {
        let t = _targets
        let s = _selfSnap
        let cb = onTargets
        DispatchQueue.main.async { cb?(t, s) }
    }
}
