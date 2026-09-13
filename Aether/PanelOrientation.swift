import UIKit

/// Counter-rotation applied to the floating panel window.
///
/// SpringBoard hosts our window as an accessibility window and UIKit adds its own
/// orientation rotation on top of whatever we set, so the composition is not
/// something we can reproduce off-device. `auto` derives the cancel from the
/// interface orientation; the other cases are the remaining elements of the
/// rotation/reflection group so the correct one can be found on-device with a
/// long-press on the panel brand area, then persisted.
enum PanelOrientation {

    enum Fix: Int, CaseIterable {
        case auto = 0
        case none = 1
        case ccw90 = 2
        case cw90 = 3
        case half = 4
        case mirror = 5
        case mirrorCcw90 = 6
        case mirrorCw90 = 7
        case mirrorHalf = 8

        var label: String {
            switch self {
            case .auto:        return "auto"
            case .none:        return "0°"
            case .ccw90:       return "-90°"
            case .cw90:        return "+90°"
            case .half:        return "180°"
            case .mirror:      return "mirror"
            case .mirrorCcw90: return "mirror-90°"
            case .mirrorCw90:  return "mirror+90°"
            case .mirrorHalf:  return "mirror180°"
            }
        }

        var transform: CGAffineTransform {
            let half = CGFloat.pi / 2
            switch self {
            case .auto:        return PanelOrientation.autoTransform()
            case .none:        return .identity
            case .ccw90:       return CGAffineTransform(rotationAngle: -half)
            case .cw90:        return CGAffineTransform(rotationAngle: half)
            case .half:        return CGAffineTransform(rotationAngle: .pi)
            case .mirror:      return CGAffineTransform(scaleX: -1, y: 1)
            case .mirrorCcw90: return CGAffineTransform(rotationAngle: -half)
                                    .concatenating(CGAffineTransform(scaleX: -1, y: 1))
            case .mirrorCw90:  return CGAffineTransform(rotationAngle: half)
                                    .concatenating(CGAffineTransform(scaleX: -1, y: 1))
            case .mirrorHalf:  return CGAffineTransform(scaleX: 1, y: -1)
            }
        }
    }

    // Do not reuse a stale value from the old diagnostic implementation. A
    // persisted 90-degree override would make the repaired menu look rotated
    // immediately after upgrade, before the user has interacted with it.
    private static let defaultsKey = "FangUI.PanelOrientationOverride.v2"

    static var override: Fix {
        get {
            let raw = UserDefaults.standard.integer(forKey: defaultsKey)
            return Fix(rawValue: raw) ?? .auto
        }
        set {
            UserDefaults.standard.set(newValue.rawValue, forKey: defaultsKey)
        }
    }

    static var active: Fix { override }

    static func transform() -> CGAffineTransform { active.transform }

    /// Best guess: cancel the interface rotation. Observed on iPad landscape the
    /// system contributes the required orientation for a detached
    /// SpringBoard-hosted window. Since this window is no longer attached to an
    /// App UIWindowScene, adding a local rotation would rotate it a second time.
    static func autoTransform() -> CGAffineTransform {
        return .identity
    }

    @discardableResult
    static func cycle() -> Fix {
        let all = Fix.allCases
        let idx = all.firstIndex(of: active) ?? 0
        let next = all[(idx + 1) % all.count]
        override = next
        return next
    }

    static func describe() -> String {
        let resolved = active == .auto ? "auto(\(active.transform.rotationDegreesText))" : active.label
        return "tf \(resolved)"
    }
}

private extension CGAffineTransform {
    var rotationDegreesText: String {
        let deg = Int((atan2(b, a) * 180 / .pi).rounded())
        return "\(deg)°"
    }
}
