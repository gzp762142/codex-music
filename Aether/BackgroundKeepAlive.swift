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

    /// 上次启动失败的原因（面板上能直接看到，不用靠猜）。
    private(set) var lastNote = "未启动"

    func start() {
        guard !started else { return }

        let session = AVAudioSession.sharedInstance()
        do {
            // playback + audio 后台模式：这两样配对，系统才认。
            try session.setCategory(.playback, mode: .default, options: [])
            try session.setActive(true)
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
            lastNote = "运行中（静音循环）"
        } catch {
            lastNote = "播放失败: \(error.localizedDescription)"
        }
    }

    func stop() {
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
