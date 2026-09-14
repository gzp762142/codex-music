import Foundation

/// 从游戏模块读偏移所需的常量。
///
/// 默认值取自 `和平精英_1.38.12_Offsets.hpp`（MobileDumper-7 全量 dump，
/// 模块 ShadowTrackerExtra，dump 时模块基址 0x1047D0000，全部数值为 RVA）。
///
/// 可以在 App 的 Documents 目录放一个 `offsets.txt` 覆盖，格式：
///
///     模块基址=0x1047D0000
///     GObjects=0x111251B00
///     GNames=0x1176ED520
///     GWorld=0x11148B608
///
/// 换游戏版本时只改这个文件，不用重新编译 —— 偏移每次更新都会变。
struct Offsets {

    /// dump 时模块基址（会被 ASLR 改变，只作为读取起点参考）
    var moduleBase: UInt64
    /// FUObjectArray 结构体地址
    var gObjects: UInt64
    /// TNameArray (FNamePool) 地址
    var gNames: UInt64
    /// UWorld**
    var gWorld: UInt64
    /// 模块名（用来在进程内定位真实基址）
    var moduleName: String

    static let defaultModuleBase: UInt64 = 0x1047D0000
    static let defaultGObjects: UInt64   = 0x111251B00
    static let defaultGNames: UInt64     = 0x1176ED520
    static let defaultGWorld: UInt64     = 0x11148B608
    static let defaultModuleName         = "ShadowTrackerExtra"

    static func load() -> Offsets {
        var o = Offsets(moduleBase: defaultModuleBase,
                        gObjects: defaultGObjects,
                        gNames: defaultGNames,
                        gWorld: defaultGWorld,
                        moduleName: defaultModuleName)

        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        guard let url = dir?.appendingPathComponent("offsets.txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return o
        }
        for rawLine in text.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#"), let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[line.startIndex..<eq]).trimmingCharacters(in: .whitespaces)
            let val = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            switch key {
            case "模块基址", "moduleBase": if let v = parseHex(val) { o.moduleBase = v }
            case "GObjects": if let v = parseHex(val) { o.gObjects = v }
            case "GNames": if let v = parseHex(val) { o.gNames = v }
            case "GWorld": if let v = parseHex(val) { o.gWorld = v }
            case "模块名", "moduleName": o.moduleName = val
            default: break
            }
        }
        return o
    }

    private static func parseHex(_ s: String) -> UInt64? {
        var t = s.lowercased()
        if t.hasPrefix("0x") { t.removeFirst(2) }
        return UInt64(t, radix: 16)
    }
}
