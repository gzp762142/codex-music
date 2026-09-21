import UIKit
import AVFoundation
import MediaPlayer

/// Hardware volume-button bridge.
/// Volume UP → show overlay; Volume DOWN → hide overlay.
/// Silent audio + MPVolumeView restore keep events firing at 0% / 100%.
final class VolumeButtonMonitor {
    var onVolumeUp: (() -> Void)?
    var onVolumeDown: (() -> Void)?

    private var session: AVAudioSession { .sharedInstance() }
    private var observation: NSKeyValueObservation?
    private var silentPlayer: AVAudioPlayer?
    private var volumeView: MPVolumeView?
    private var lastVolume: Float = 0.5
    private var running = false
    private var swallow = false

    func start() {
        guard !running else { return }
        running = true

        // Keep session active so outputVolume KVO fires.
        try? session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
        try? session.setActive(true, options: .notifyOthersOnDeactivation)

        // 上面两句动的是**进程级共享**的音频会话，也就是 BackgroundKeepAlive
        // 那段静音循环赖以存活的同一个会话：在已激活的会话上调 setCategory，系统会先
        // deactivate 再按新分类 reactivate 一次，保活的 AVAudioPlayer 有可能被那一下
        // 打断 —— 这一点我离线验证不了，所以这里不做任何断言，只叫保活来实测核对一次：
        // 它真在跑就是零代价的 no-op，被停掉了就重建。
        // 注意方向 —— 这里**不**调 resumeAfterSessionDeactivated()：本方法结束时会话
        // 是 active 的，不存在"确凿失效"，立旗只会让保活被无谓地重建一遍。
        BackgroundKeepAlive.shared.revalidateSession()

        playSilentLoopIfNeeded()
        attachHiddenVolumeView()

        lastVolume = session.outputVolume
        observation = session.observe(\.outputVolume, options: [.old, .new]) { [weak self] _, change in
            self?.handle(change: change)
        }
    }

    func stop() {
        guard running else { return }
        running = false
        observation?.invalidate()
        observation = nil
        silentPlayer?.stop()
        silentPlayer = nil
        volumeView?.removeFromSuperview()
        volumeView = nil

        // 这一句停的是**进程级共享**的音频会话，不是本类私有的：BackgroundKeepAlive
        // 那段静音循环正靠它维持后台执行权。会话一停，系统几秒内就会挂起整个进程，
        // 而挂起可能落在外挂内核操作的中途 —— 那是最不该被打断的地方。
        //
        // 而且它**一定**会把会话停掉，跟返回值无关。AVAudioSession.h 的原话是：
        //     "Starting in iOS 8, if the session has running I/Os at the time that
        //      deactivation is requested, the session will be deactivated, but the
        //      method will return NO and populate the NSError with the code property
        //      set to AVAudioSessionErrorCodeIsBusy to indicate the misuse of the API."
        // 保活的 AVAudioPlayer 还在播，正好就是"有 running I/O"的情形；那个 NO 会被
        // 上面的 try? 吞掉，所以**不能**靠返回值判断有没有出事。
        try? session.setActive(false, options: .notifyOthersOnDeactivation)

        // 本类是**唯一确切知道**共享会话刚刚被停用的地方（会话状态在 iOS 13 的公开 API
        // 里查不到，interruptionNotification 也不保证回送本进程，理由详见
        // BackgroundKeepAlive 里的说明），所以由这里显式把保活拉回来，不依赖任何
        // 通知语义猜测。恢复链路：
        //   resumeAfterSessionDeactivated(reason:)
        //     → activate() → setActive(true)
        //     → 重建并 play() 静音循环 → lastNote 记下"曾恢复"
        // 保活从未被请求过时（wanted == false）这一步是空操作，不会凭空拉起静音循环。
        BackgroundKeepAlive.shared.resumeAfterSessionDeactivated(
            reason: "VolumeButtonMonitor.stop() 停用了共享会话")
    }

    private func handle(change: NSKeyValueObservedChange<Float>) {
        guard running, !swallow else { return }
        guard let neu = change.newValue, let old = change.oldValue else { return }
        let delta = neu - old
        if abs(delta) < 0.01 { return }

        if neu > old {
            onVolumeUp?()
        } else if neu < old {
            onVolumeDown?()
        }

        lastVolume = neu
        // Restore so the next press is always a real change.
        DispatchQueue.main.async { [weak self] in
            self?.restoreVolume()
        }
    }

    private func restoreVolume() {
        guard let slider = systemVolumeSlider() else { return }
        swallow = true
        // Park volume mid-range so both + and − always produce events.
        slider.value = 0.5
        lastVolume = 0.5
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { [weak self] in
            self?.swallow = false
        }
    }

    private func attachHiddenVolumeView() {
        guard volumeView == nil else { return }
        let v = MPVolumeView(frame: CGRect(x: -100, y: -100, width: 1, height: 1))
        v.isHidden = true
        v.alpha = 0.01
        if let w = keyWindow() {
            w.addSubview(v)
        }
        volumeView = v
    }

    private func systemVolumeSlider() -> UISlider? {
        if volumeView == nil { attachHiddenVolumeView() }
        return volumeView?.subviews.compactMap { $0 as? UISlider }.first
    }

    private func playSilentLoopIfNeeded() {
        guard silentPlayer == nil else { return }
        // 1-frame-ish silent wav generated at runtime (44-byte header + zeros).
        let url = writeSilentWav()
        silentPlayer = try? AVAudioPlayer(contentsOf: url)
        silentPlayer?.volume = 0.01
        silentPlayer?.numberOfLoops = -1
        silentPlayer?.play()
    }

    private func writeSilentWav() -> URL {
        let sampleRate = 8000
        let samples = 800
        var data = Data()
        func u32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
        func u16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
        data.append(contentsOf: Array("RIFF".utf8))
        u32(UInt32(36 + samples * 2))
        data.append(contentsOf: Array("WAVE".utf8))
        data.append(contentsOf: Array("fmt ".utf8))
        u32(16)
        u16(1)          // PCM
        u16(1)          // mono
        u32(UInt32(sampleRate))
        u32(UInt32(sampleRate * 2))
        u16(2)
        u16(16)
        data.append(contentsOf: Array("data".utf8))
        u32(UInt32(samples * 2))
        data.append(Data(count: samples * 2))
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("silent_vol.wav")
        try? data.write(to: url)
        return url
    }

    private func keyWindow() -> UIWindow? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        for s in scenes {
            if let w = s.windows.first(where: { $0.isKeyWindow }) { return w }
            if let w = s.windows.first { return w }
        }
        return UIApplication.shared.windows.first
    }
}
