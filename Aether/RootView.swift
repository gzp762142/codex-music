import SwiftUI

enum AppPhase {
    case loading
    case unlock
    case control
}

final class AppState: ObservableObject {
    @Published var phase: AppPhase = .loading
    /// Default OFF — overlay UI must not appear until user explicitly turns it on.
    @Published var isPoweredOn = false
    @Published var sessionStart: Date?
    @Published var cardMessage: String?

    private let volumeMonitor = VolumeButtonMonitor()

    init() {
        volumeMonitor.onVolumeUp = { [weak self] in
            // 音量+：只弹出菜单，不强制改电源状态
            guard let self, self.phase == .control else { return }
            FangUIBridge.setVisible(true)
        }
        volumeMonitor.onVolumeDown = { [weak self] in
            // 音量-：只收起菜单，服务可继续跑
            guard let self, self.phase == .control else { return }
            FangUIBridge.setVisible(false)
        }
    }

    func completeLoading() {
        withAnimation(.easeInOut(duration: 0.45)) {
            phase = .unlock
        }
    }

    func enterControl() {
        sessionStart = Date()
        // Fresh session after card-key: stay OFF. User must tap 开启.
        isPoweredOn = false
        withAnimation(.spring(response: 0.45, dampingFraction: 0.85)) {
            phase = .control
        }
        FangUIBridge.setVisible(false)
        volumeMonitor.start()
    }

    func setPower(_ on: Bool) {
        if on {
            if !isPoweredOn {
                withAnimation(.spring(response: 0.4, dampingFraction: 0.8)) {
                    isPoweredOn = true
                }
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
            }
            // Re-tap 开启 while already on: re-present if overlay was lost
            // (crash of Metal layer, window recreate, etc.).
            FangUIBridge.setVisible(true)
        } else {
            if isPoweredOn {
                withAnimation(.spring(response: 0.4, dampingFraction: 0.8)) {
                    isPoweredOn = false
                }
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
            }
            FangUIBridge.setVisible(false)
        }
    }

    func powerOffFromOverlay() {
        setPower(false)
    }

    /// Call when returning to foreground so UI/state stay consistent.
    func resyncOverlay() {
        switch phase {
        case .control:
            // Do not force overlay to match power — volume keys may have hidden UI
            // while service stays on. Only ensure monitor is running.
            volumeMonitor.start()
        case .loading, .unlock:
            volumeMonitor.stop()
            FangUIBridge.setVisible(false)
        }
    }
}

struct RootView: View {
    @ObservedObject var state: AppState

    var body: some View {
        ZStack {
            Color(.systemGroupedBackground)
                .edgesIgnoringSafeArea(.all)

            if state.phase == .loading {
                LoadingView {
                    state.completeLoading()
                }
                .transition(.opacity)
            } else if state.phase == .unlock {
                UnlockHostView {
                    state.enterControl()
                }
                .transition(.opacity.combined(with: .scale(scale: 1.02)))
            } else {
                ControlView()
                    .environmentObject(state)
                    .transition(.opacity.combined(with: .scale(scale: 0.98)))
            }
        }
        .preferredColorScheme(.light)
        .onAppear {
            NotificationCenter.default.addObserver(
                forName: UIApplication.willEnterForegroundNotification,
                object: nil,
                queue: .main
            ) { _ in
                state.resyncOverlay()
            }
        }
    }
}

struct RootView_Previews: PreviewProvider {
    static var previews: some View {
        RootView(state: AppState())
    }
}
