import Foundation
import AVFoundation

/// 后台保活。
///
/// **为什么必须有这个**：Music 是以悬浮窗形态跑在**后台**的（窗口浮在游戏之上，
/// 自己并不是前台 app）。iOS 对后台 app 的处理是几秒内挂起它的线程、并且把它的
/// CPU 配额压到极低 —— 表现就是面板上的进度停住不动、随后整个进程被系统终止。
///
/// `Info.plist` 里虽然已经声明了 `UIBackgroundModes: audio`，但**声明不等于生效**：
/// 系统只在「真的在播放音频」时才让 app 保持后台运行。所以我们得真的播点什么 ——
/// 一段自己生成的循环静音，音量本来就是 0，对用户完全无声。
final class BackgroundKeepAlive {

    static let shared = BackgroundKeepAlive()

    private var player: AVAudioPlayer?
    private var started = false

    /// 上层是否希望保活跑着（**意图**，不是事实）。
    ///
    /// 必须和 `started` 分开：`started` 说的是"我们成功启动过"，
    /// 而下面那些通报入口要判断的是"**该不该**把会话抢回来"。
    /// 少了这道闸，`VolumeButtonMonitor.stop()` 会在保活从未被请求过的时候
    /// 凭空拉起一段静音循环；`BackgroundKeepAlive.stop()` 之后也会被它复活。
    private var wanted = false

    /// 共享会话是否已被**确凿地**停用、等着我们重新激活（**事实**）。
    ///
    /// 为什么只能靠自记：iOS 13 的公开 API 里没有任何东西能查"我们自己的共享会话
    /// 还活不活着"—— `isOtherAudioPlaying` / `secondaryAudioShouldBeSilencedHint`
    /// 描述的都是**别的 app**；而 `AVAudioSession.isActive` 这个属性**根本不存在**
    /// （三条独立证据见 `activate()` 里的长注释）。所以只能由确切知道这件事的地方立旗：
    ///   * 本类 `stop()` —— 自己调了 `setActive(false)`；
    ///   * `VolumeButtonMonitor.stop()` —— 它调 `setActive(false, .notifyOthersOnDeactivation)`
    ///     停的是**同一个**进程级共享会话，然后通过 `resumeAfterSessionDeactivated()` 报进来。
    /// 只有 `setActive(true)` 真正成功之后才降旗。
    private var sessionLost = false

    /// 最近一次"会话曾经不可用"的原因（空串 = 从没发生过）。
    ///
    /// 为什么不直接写进 `lastNote`：`lastNote` 在恢复成功时会被覆盖成"运行中"，
    /// 那样面板上就看不出刚刚丢过一次会话 —— 而"丢过又恢复了"恰恰是最该被看见的信号
    /// （它意味着有人动过共享会话）。所以单独存一份，恢复成功时拼进 `lastNote` 里。
    private var lastLoss = ""

    /// 音频会话被打断（以及打断结束）的系统通知观察者。
    ///
    /// **它只是辅路径**，主路径是 `VolumeButtonMonitor.stop()` 的显式通报。
    /// 主次划分与理由见 `registerSessionObserverIfNeeded()`。
    private var interruptionObserver: NSObjectProtocol?

    /// 上次启动失败的原因（面板上能直接看到，不用靠猜）。
    ///
    /// 诊断职责：只被本类写、被面板（`DebugProcView`）读。
    /// 线程约定：本类所有会话/播放器操作都发生在**主线程**（调用点只有 AppDelegate、
    /// VolumeButtonMonitor，以及下面显式跳主线程的通知回调），所以不需要加锁。
    private(set) var lastNote = "未启动"

    /// 启动保活。幂等：真在跑的时候不会重建播放器。
    func start() {
        // 记下意图：只要有人调过 start，就说明上层要保活跑着。
        // 下面所有"会话被动了"的通报都拿它当准入条件。
        wanted = true
        activate()
    }

    /// **保活的实时重新激活入口**：由确切知道共享会话被停用的人调用。
    ///
    /// 目前唯一的调用点是 `VolumeButtonMonitor.stop()` —— 它调
    /// `setActive(false, options: .notifyOthersOnDeactivation)` 停掉的是**进程级共享**
    /// 的那个会话，而我们的静音循环正靠那个会话维持后台执行权。会话一停，系统几秒内
    /// 就会挂起整个进程，而挂起可能落在外挂内核操作的中途 —— 那是最不该被打断的地方
    /// （写坏的 vm_map 只能靠重启设备恢复）。
    ///
    /// 【为什么必须由它来喊，而不是等通知】
    /// `notifyOthersOnDeactivation` 的文档原话是 "indicates that the system should
    /// notify **other apps** that you've deactivated your app's audio session" ——
    /// 通知对象写的是 **other apps**，全文没有一个字承诺会回送给本进程的观察者。
    /// 这条通知到底送不送，我在真机之外没有办法验证，所以不押注在它身上
    /// （主次说明见 `registerSessionObserverIfNeeded()`）。
    /// 而 `VolumeButtonMonitor.stop()` 是**代码事实**：它确实调了 `setActive(false)`，
    /// 会话确实会死（依据见 VolumeButtonMonitor.stop() 里的注释）。这是唯一确定的信号。
    ///
    /// 【完整恢复链路】
    ///   VolumeButtonMonitor.stop()
    ///     → try? session.setActive(false, .notifyOthersOnDeactivation)
    ///     → resumeAfterSessionDeactivated(reason:)            ← 本方法
    ///     → sessionLost = true、lastLoss = reason
    ///     → activate()
    ///     → 幂等守卫因 sessionLost 为 true 而不成立 → 拆掉旧播放器
    ///     → session.setActive(true) → sessionLost = false
    ///     → 重新 AVAudioPlayer.play() → started = true
    ///     → lastNote = "运行中（静音循环；… → 已恢复）"
    ///
    /// - Parameter reason: 诊断文字，面板上看得到是谁让会话没了的。
    func resumeAfterSessionDeactivated(reason: String) {
        lastLoss = reason
        sessionLost = true

        // 保活没被上层请求过（wanted 为 false）就什么都不做：
        // 不能因为音量键监听停了一次，就凭空拉起一段从未被请求的静音循环；
        // BackgroundKeepAlive.stop() 之后也不该被它复活。
        guard wanted else { return }
        activate()
    }

    /// 保守的重新核对入口：调用方**动过**共享会话，但不确定是否把它停掉了。
    ///
    /// 目前唯一的调用点是 `VolumeButtonMonitor.start()`：它会
    /// `setCategory(.playback, options: [.mixWithOthers])`，而这个调用在**已激活**的
    /// 会话上会触发一次隐式的 deactivate / reactivate —— 我们的 AVAudioPlayer
    /// 有可能被那一下打断（是否真的会，我离线验证不了）。这里不做任何断言，
    /// 只是让 `activate()` 用守卫里的 `player?.isPlaying` 实测一次：
    /// 真在跑就是零代价的 no-op，被停掉了就重建。
    ///
    /// 与 `resumeAfterSessionDeactivated()` 的分工：那个是**确凿失效**（立旗），
    /// 这个是**状态存疑**（只核对，不立旗）。
    func revalidateSession() {
        guard wanted else { return }
        activate()
    }

    /// 保活的实际启动/恢复实现。**所有入口共用这一条**（`start()`、
    /// `resumeAfterSessionDeactivated()`、`revalidateSession()`、通知回调）——
    /// 各写一份的话，两条路迟早会不一致。
    private func activate() {
        let session = AVAudioSession.sharedInstance()

        /*
         * ── 幂等守卫：三个条件同时成立才认为"真的还在保活" ──
         *
         *   1. started            —— 我们自己成功启动过（纯自身状态，单独用不够）；
         *   2. player?.isPlaying  —— 播放器自称还在播，兜的是**没人报备**的会话失效
         *                            （会话被来源不明地 deactivate 时，播放器会不会被
         *                             通知、isPlaying 会不会变 false，我离线验证不了，
         *                             所以它只算"尽力而为"的第二道网，不是唯一依据）；
         *   3. !sessionLost       —— 没有任何人报告过"共享会话被停用了"。
         *                            这是**确定性**的那一道，由确切知道会话被停用的
         *                            调用点立旗（见字段说明与 resumeAfterSessionDeactivated）。
         *                            2 与 3 互补：2 覆盖来源不明的失效，3 覆盖已知的两处。
         *
         * 【为什么不能只用 started】
         * 原来的写法是 `guard !started else { return }`。`started` 只反映自身状态，
         * 对"共享会话被 VolumeButtonMonitor.stop() 停掉"一无所知，于是保活
         * **永久**起不来 —— 面板上还写着"运行中"，实际进程已经可以被系统挂起，
         * 而挂起可能正好落在一次内核操作中途（写坏的 vm_map 只能靠重启设备恢复）。
         *
         * 【为什么不能用 isOtherAudioPlaying / secondaryAudioShouldBeSilencedHint】
         * 这两条的语义都是"**别人**"。Apple 头文件（AVFAudio.framework 的
         * AVAudioSession.h）原文：
         *   otherAudioPlaying:
         *     "True when another application is playing audio."
         *   secondaryAudioShouldBeSilencedHint:
         *     "True when another application with a non-mixable audio session
         *      is playing audio."
         * 都只说"别的 app 在不在播音"。会话被停 + 没有别的 app 在播音时，它们恒为
         * false；而播放器对象在这时**可能**仍自称在播（它到底会不会被告知会话已死，
         * 我离线无法验证）。两个条件一旦同时成立，守卫照样直接 return，
         * 保活依然起不来 —— 这条路堵死。
         * （另一条近亲 AVAudioSessionSilenceSecondaryAudioHintNotification 同样不可用：
         *   头文件说它是在"they are in the foreground with an active audio session"
         *   时报告 other applications 的 primary audio 起停 —— 本 app 恰恰长期在后台。）
         *
         * 【为什么不能用 AVAudioSession.isActive】
         * 因为**没有这个属性**。三条独立证据：
         *   a. iOS 16.5 SDK 的 AVFAudio.framework/Headers/AVAudioSession.h 里，
         *      AVAudioSession 的全部 @property 中没有 active / isActive；
         *      Activation 分类下只有 setActive:error: 与 setActive:withOptions:error:；
         *   b. Apple 当前文档 AVAudioSession 的成员索引里，
         *      "Activating and deactivating the session" 一组同样只有方法、没有属性；
         *   c. iOS 26 新增的是 didBecomeActiveNotification /
         *      didBecomeInactiveNotification 那一族，包里依然没有 isActive 属性，
         *      而且本工程 IPHONEOS_DEPLOYMENT_TARGET = 13.0，也用不上。
         * 结论：**查不到会话状态**。这一点必须如实承认，不能拿一条不存在的 API 当依据。
         *
         * 【那还剩什么】
         * 只剩"谁确切知道，谁就报一声"这条路：本工程里能确定性知道共享会话被停用的
         * 地方只有 `BackgroundKeepAlive.stop()` 和 `VolumeButtonMonitor.stop()` 两处。
         * 前者自己处理，后者通过 `resumeAfterSessionDeactivated()` 显式通报。
         * 落在 `sessionLost` 上 —— 它不依赖任何 API 语义猜测，是本文件的核心判据。
         *
         * 幂等性不受影响：真在跑时三个条件都成立，直接 return，不会反复重建播放器
         * （反复重建会留下两个循环播放的实例，也会让会话被无谓地重新激活）。
         */
        if started, player?.isPlaying == true, !sessionLost { return }

        // 走到这里说明要么没启动过，要么会话已经被人停掉。
        // 先把可能还挂着的播放器收干净，否则下面重建会留下两个循环播放的实例。
        if player != nil {
            NSLog("[BackgroundKeepAlive] 会话已失效，重建保活（lastNote=%@）", lastNote)
            player?.stop()
            player = nil
        }
        started = false

        registerSessionObserverIfNeeded()

        do {
            /*
             * 分类只在**家族**不对的时候才重设。
             *
             * 为什么不是每次都设：在**已激活**的会话上调 setCategory，系统会先把会话
             * deactivate 再按新分类 reactivate 一次；这条路径会打断正在播的音频，
             * 也会把 VolumeButtonMonitor 特意加上的 .mixWithOthers 顶掉 ——
             * 那会让我们的静音循环独占音频焦点，把用户正在听的游戏背景音乐按下去。
             *
             * 为什么家族对了就够：保活的资格来自 Info.plist 的 UIBackgroundModes: audio
             * 加上"会话属于 .playback 家族且真的在播"，混不混音不参与这个判定 ——
             * AVAudioSessionTypes.h 对 MixWithOthers 的原话是
             *     "allowing other applications to play in the background.
             *      Your app will still be able to play regardless of the setting
             *      of the ringer switch."
             * 也就是说 .mixWithOthers 让出的是**别人**的播放权，**我们自己**照常能播，
             * 静音循环不受影响，所以保留别人设好的 options 是安全的。
             * （未能核实的一点：这段原文没有直接写"后台保活资格也不变"，
             *   上真机时优先复验这一条。）
             * 首次进入时分类是系统默认的 .soloAmbient（Apple 文档原话：
             * "The default audio session category."），不等于 .playback，
             * 这里照样会把 .playback 配上，第一次启动那条路径不受影响。
             */
            if session.category != AVAudioSession.Category.playback {
                try session.setCategory(.playback, mode: .default, options: [])
            }
            try session.setActive(true)
            // 降旗必须放在 setActive(true) **成功之后**：失败时保持 sessionLost = true，
            // 下一次任何入口进来都会重试，不会留下"以为恢复了、其实没有"的假象。
            sessionLost = false
        } catch {
            lastNote = "音频会话失败: \(error.localizedDescription)"
            return
        }

        do {
            let url = try silentWavURL()
            let p = try AVAudioPlayer(contentsOf: url)
            p.numberOfLoops = -1          // 无限循环
            p.prepareToPlay()
            guard p.play() else {
                lastNote = "play() 返回 false"
                return
            }
            player = p
            started = true
            // 恢复成功时把"丢过一次会话"这条历史留在面板上（lastLoss 不清）：
            // 这正是诊断要求 —— 会话被别人停掉又恢复，必须看得出来发生过什么。
            lastNote = lastLoss.isEmpty
                ? "运行中（静音循环）"
                : "运行中（静音循环；\(lastLoss) → 已恢复）"
        } catch {
            lastNote = "播放失败: \(error.localizedDescription)"
        }
    }

    /// 注册**辅路径**：系统音频会话打断通知。只注册一次
    /// （重复注册会让一次打断触发多次 `activate()`）。
    ///
    /// ── 主次关系（这一版最关键的一件事）──
    /// 主路径 = `VolumeButtonMonitor.stop()` → `resumeAfterSessionDeactivated()`。
    ///          它是唯一确切知道共享会话被停用的地方，不依赖任何通知语义。
    /// 辅路径 = 下面这个观察者，只兜住"**外部**打断"这一类：来电、其他 app 抢走
    ///          音频焦点，以及它们结束后该恢复播放的时机。就算它一次都不来，
    ///          主路径也已经把会话恢复了 —— 这是刻意设计成"辅路径可以整个失效"的。
    ///
    /// ── 为什么辅路径不能升格成主路径（旧注释在这点上押错了）──
    /// 旧写法声称 `.ended` 会在"同一进程里有人
    /// setActive(false, .notifyOthersOnDeactivation)"时送达。核实结果：
    ///   * AVAudioSession.h 对 interruptionNotification 的原话是
    ///     "Notification sent to registered listeners when the **system** has
    ///      interrupted the audio session and when the interruption has ended."
    ///     —— 描述的是**系统**打断；
    ///   * notifyOthersOnDeactivation 的文档原话是
    ///     "indicates that the system should notify **other apps** that you've
    ///      deactivated your app's audio session."
    ///     —— 通知对象写的是 **other apps**，还特别说明受益者是
    ///     "other audio sessions that had been interrupted by your session"。
    /// 两处措辞都指向"外部 / 其他 app"，**没有任何文字**承诺本进程的观察者会收到
    /// 主动停用的回送。我无法在真机之外确认它到底送不送，所以：保留它，
    /// 但绝不把保活的恢复押在它身上。
    ///
    /// ── object 为什么传 nil ──
    /// 传 nil 表示不按发送者过滤：宁可多收，不可漏收。本进程只有一个会话，
    /// 多收没有任何代价；而如果系统投递时 object 不是 AVAudioSession.sharedInstance()
    /// 那个实例，传实例反而会把通知滤掉 —— 那又是一个赌注。
    private func registerSessionObserverIfNeeded() {
        guard interruptionObserver == nil else { return }

        interruptionObserver = NotificationCenter.default.addObserver(
            forName: AVAudioSession.interruptionNotification,
            object: nil,
            queue: nil
        ) { [weak self] note in
            guard let self else { return }
            guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
                  let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }

            /*
             * 一律回主线程再动播放器/会话：通知不保证投递线程（外部打断来自系统线程），
             * 而本类所有会话操作都约定在主线程（见 lastNote 上的线程约定）。
             * 用显式异步跳转而不是 queue: .main，是为了**避免重入** —— 如果通知恰好在
             * 主线程同步发出，queue: .main 会让 block 在当前栈里直接跑起来，
             * 和正在执行的会话操作嵌套在一起。
             */
            DispatchQueue.main.async {
                switch type {
                case .began:
                    /*
                     * 系统把会话从我们手里拿走了。这里**不能**去抢激活（会话还被别人
                     * 占着，setActive(true) 只会失败），但必须把失效标记立起来：
                     * 打断期间 player.isPlaying 究竟会不会变成 false，我离线验证不了，
                     * 不能赌；而 sessionLost 是确定的，它保证 .ended 之后的重新激活
                     * 不会被幂等守卫挡在门外。
                     */
                    self.sessionLost = true
                    self.lastLoss = "外部打断"
                    // 只有保活确实在跑时才改写面板文字 —— 没在跑却显示"被打断（等待恢复）"
                    // 会让人以为保活是活的，那正好是这次要修掉的那种谎报。
                    if self.started { self.lastNote = "会话被打断（等待恢复）" }

                case .ended:
                    // 走和 VolumeButtonMonitor 一样的核对入口：.began 已经立过旗，
                    // 所以这里 activate() 会真的重建；如果没立过旗（例如只收到 .ended），
                    // 守卫会按实测状态决定要不要动，不会无谓重建。
                    self.revalidateSession()

                @unknown default:
                    break
                }
            }
        }
    }

    func stop() {
        // 降下意图闸：之后再有人通报"会话被动了"，也不该把保活复活。
        wanted = false
        // 我们自己把共享会话 deactivate 了，会话从此不活跃 —— 立旗，
        // 这样下一次 start() 一定走重建，而不是被幂等守卫挡在门外。
        sessionLost = true

        player?.stop()
        player = nil
        started = false
        lastNote = "已停止"
        try? AVAudioSession.sharedInstance().setActive(false)
    }

    /// 生成一段 2 秒的静音 WAV（44.1kHz / 单声道 / 16bit）。
    /// 采样值全是 0，所以用户听不到任何东西。
    private func silentWavURL() throws -> URL {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let url = dir.appendingPathComponent("aether_silence.wav")
        if FileManager.default.fileExists(atPath: url.path) { return url }

        let sampleRate: UInt32 = 44100
        let seconds = 2
        let dataSize = Int(sampleRate) * seconds * 2      // 16bit 单声道

        func le32(_ v: UInt32) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
        func le16(_ v: UInt16) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
        func ascii(_ s: String) -> Data { s.data(using: .ascii) ?? Data() }

        var wav = Data()
        wav.append(ascii("RIFF"))
        wav.append(le32(UInt32(36 + dataSize)))
        wav.append(ascii("WAVE"))
        wav.append(ascii("fmt "))
        wav.append(le32(16))                              // PCM 头长度
        wav.append(le16(1))                               // PCM
        wav.append(le16(1))                               // 单声道
        wav.append(le32(sampleRate))
        wav.append(le32(sampleRate * 2))                  // 字节率
        wav.append(le16(2))                               // 块对齐
        wav.append(le16(16))                              // 位深
        wav.append(ascii("data"))
        wav.append(le32(UInt32(dataSize)))
        wav.append(Data(count: dataSize))                 // 全 0 = 静音
        try wav.write(to: url)
        return url
    }
}
