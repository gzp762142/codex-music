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
///     GNames=0x111FBA198
///     GWorld=0x11148B608
///
/// **下面这三个 OFFSET 都是「静态 vmaddr 域地址」，不是 RVA**：
/// dump 时 __TEXT.vmaddr 恒为 0x100000000，所以
///     运行时地址 = slide + 静态地址,   slide = imageBase − 0x100000000
/// 换算只允许走 MemoryProbe.runtime()，别处不要自己加减。
///
/// GNames 必须给**槽的静态域地址** 0x111FBA198
/// （= dump 日志里 "GNames ptr addr 0x11678A198" − slide 0x47D0000）；
/// 日志里那个 0x1176ED520 是 FNamePool 的**堆地址**，跨进程无效。
///
/// 换游戏版本时只改这个文件，不用重新编译 —— 偏移每次更新都会变。
struct Offsets {

    /// dump 时模块基址（会被 ASLR 改变，只作为读取起点参考）
    var moduleBase: UInt64
    /// FUObjectArray 结构体地址
    var gObjects: UInt64
    /// GNames 槽的静态域地址（不是 dump 日志里的 FNamePool 堆地址）
    var gNames: UInt64
    /// UWorld**
    var gWorld: UInt64

    static let defaultModuleBase: UInt64 = 0x1047D0000
    static let defaultGObjects: UInt64   = 0x111251B00
    static let defaultGNames: UInt64     = 0x111FBA198
    static let defaultGWorld: UInt64     = 0x11148B608

    static func load() -> Offsets {
        var o = Offsets(moduleBase: defaultModuleBase,
                        gObjects: defaultGObjects,
                        gNames: defaultGNames,
                        gWorld: defaultGWorld)

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
