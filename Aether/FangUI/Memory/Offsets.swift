import Foundation

/// 从目标模块读偏移所需的常量。
///
/// 默认值是**占位值**，需按自己的 dump 结果替换（见下面 `default*` 的说明）。
/// 全部数值为 RVA，模块基址取自 dump 时的记录。
///
/// 可以在 App 的 Documents 目录放一个 `offsets.txt` 覆盖，格式：
///
///     模块基址=0x100000000
///     GObjects=0x10000
///     GNames=0x20000
///     GWorld=0x30000
///
/// **下面这三个 OFFSET 都是「静态 vmaddr 域地址」，不是 RVA**：
/// dump 时 __TEXT.vmaddr 恒为一个固定常量（本机 dump 记录的是 0x100000000），所以
///     运行时地址 = slide + 静态地址,   slide = imageBase − <dump 期 __TEXT.vmaddr>
/// 换算只允许走 MemoryProbe.runtime()，别处不要自己加减。
///
/// GNames 必须给**槽的静态域地址**（= dump 日志里的 "GNames ptr addr" − slide）；
/// 日志里另有一个 FNamePool 的**堆地址**，跨进程无效，不要拿它当槽地址。
///
/// 换目标版本时只改这个文件，不用重新编译 —— 偏移每次更新都会变。
struct Offsets {

    /// dump 时模块基址（会被 ASLR 改变，只作为读取起点参考）
    var moduleBase: UInt64
    /// FUObjectArray 结构体地址
    var gObjects: UInt64
    /// GNames 槽的静态域地址（不是 dump 日志里的 FNamePool 堆地址）
    var gNames: UInt64
    /// UWorld**
    var gWorld: UInt64

    /// 以下四个是**占位默认值**，必须按自己的 dump 结果替换。
    /// 保留具体数值的结构（便于理解换算关系），但数值本身不带任何版本信息。
    /// 运行时优先读 Documents/offsets.txt，那里的值覆盖这几个。
    static let defaultModuleBase: UInt64 = 0x100000000
    static let defaultGObjects: UInt64   = 0x10000
    static let defaultGNames: UInt64     = 0x20000
    static let defaultGWorld: UInt64     = 0x30000

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
