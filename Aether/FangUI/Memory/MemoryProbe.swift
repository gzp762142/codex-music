import Foundation
import Darwin

/// 读内存探针：**只读**，不写、不 hook、不注入。**只有一条路**。
///
/// ```
/// let fn  = dlsym(RTLD_DEFAULT, "task_for_pid")
/// let tfp = unsafeBitCast(fn, to: TaskForPidFn.self)
/// let kr  = tfp(mach_task_self_, pid, &port)
/// ```
///
/// **绝不使用 syscall()。** `syscall()` 只走 BSD syscall 表，而 task_for_pid 是
/// Mach trap，两套编号互不相通。把 mach trap 号（45）交给 syscall() 会让它按
/// BSD 表跳到第 45 号那个完全不同的调用上 —— 实测直接闪退。
/// 26 同理（BSD 表第 26 号是 ptrace，还有副作用）。
///
/// 这条路如果返回 KERN_FAILURE(5)，那是**权限**问题不是号错：
/// `Music.entitlements` 需要 `task_for_pid-allow`，重签重装后再试。
final class MemoryProbe {

    private typealias MachPort = UInt32
    private typealias KernReturn = Int32
    private typealias MachVmAddress = UInt64
    private typealias MachVmSize = UInt64

    private typealias TaskForPidFn = @convention(c) (MachPort, Int32,
                                                     UnsafeMutablePointer<MachPort>) -> KernReturn
    private typealias VmReadFn = @convention(c) (MachPort, MachVmAddress, MachVmSize,
                                                 UnsafeMutablePointer<UInt>,
                                                 UnsafeMutablePointer<MachVmSize>) -> KernReturn
    private typealias VmDeallocateFn = @convention(c) (MachPort, UInt, MachVmSize) -> KernReturn

    private static func symbol<T>(_ name: String, as: T.Type) -> T? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static let taskForPidFn = symbol("task_for_pid", as: TaskForPidFn.self)

    /// mach_port_deallocate：释放我们自己持有的 port right。
    private typealias PortDeallocateFn = @convention(c) (MachPort, MachPort) -> KernReturn
    private static let portDeallocateFn = symbol("mach_port_deallocate", as: PortDeallocateFn.self)
    /// vm_region_recurse_64：枚举目标地址空间里的 region（**不读内存内容**）。
    ///
    /// 比 mach_vm_region 少一个 flavor 参数、多一个 nesting_depth，
    /// info 是 vm_region_submap_info_64（19 个字）。
    /// 注意：mach_vm_region 因为在它上面配错过参数（count=0 / info 指针类型），
    /// 连崩两次，所以这里在真正枚举目标之前**先对自己进程枚举一次**做参数自检。
    private typealias VmRegionRecurseFn = @convention(c) (
        UInt32,                              // task
        UnsafeMutablePointer<UInt64>,        // &address (in/out)
        UnsafeMutablePointer<UInt64>,        // &size
        UnsafeMutablePointer<UInt32>,        // &nesting_depth
        UnsafeMutableRawPointer,             // info
        UnsafeMutablePointer<UInt32>         // &infoCnt（字数）
    ) -> Int32

    private static let vmRegionRecurseFn = symbol("vm_region_recurse_64", as: VmRegionRecurseFn.self)

    /// proc_regionfilename：问「这个地址属于哪个文件」。
    /// 只要 pid + 地址，不需要 mach_vm_region —— 正好绕开那个我连错两次的调用。
    /// iOS 无 <libproc.h>，符号同样只能 dlsym 取。
    private typealias ProcRegionFileNameFn = @convention(c) (Int32, UInt64, UnsafeMutableRawPointer?, UInt32) -> Int32
    private static let procRegionFileNameFn = symbol("proc_regionfilename", as: ProcRegionFileNameFn.self)
    private static let vmReadFn = symbol("mach_vm_read", as: VmReadFn.self)
    private static let vmDeallocateFn = symbol("mach_vm_deallocate", as: VmDeallocateFn.self)


    static var symbolSummary: String {
        let a = taskForPidFn != nil ? "tfp=OK" : "tfp=nil"
        let b = vmReadFn != nil ? "vm_read=OK" : "vm_read=nil"
        let c = vmDeallocateFn != nil ? "vm_dealloc=OK" : "vm_dealloc=nil"
        return "\(a) \(b) \(c)"
    }

    /// 把 kern_return_t 翻成人和自己能读懂的话。
    private static func describe(_ kr: KernReturn) -> String {
        switch kr {
        case KERN_SUCCESS: return "成功"
        case KERN_FAILURE: return "权限被挡 (KERN_FAILURE)"
        case 4: return "参数错 (KERN_INVALID_ARGUMENT)"
        case 2: return "KERN_INVALID_TASK"
        case 3: return "KERN_INVALID_ADDRESS"
        default: return "ret=\(kr)"
        }
    }

    // MARK: - 单步动作

    /// 第 1 步：只解析符号，不调用任何东西。
    /// 只取端口并返回它（**不读任何内存**），供静默测试用。
    /// 返回 nil 表示符号缺失或取端口失败。
    ///
    /// 注意返回值写 UInt32 而不是私有别名 MachPort：
    /// internal 函数的签名不能暴露 private typealias，否则编译报
    /// "method must be declared private because its parameter uses a private type"。
    static func acquirePort(pid: Int32) -> (port: UInt32, note: String)? {
        guard let fn = taskForPidFn else { return nil }
        var port: MachPort = 0
        let kr = fn(mach_task_self_, pid, &port)
        guard kr == KERN_SUCCESS, port != 0 else { return nil }
        return (port, "port=0x\(String(port, radix: 16))")
    }

    /// 第 1 步：只报告符号解析情况，不调用任何东西。
    static func stepSymbols() -> String { symbolSummary }

    /// 第 2 步：只调 libSystem 的 task_for_pid —— 唯一被允许的取端口方式。
    /// 不用 syscall：syscall() 只走 BSD 表，Mach trap 号交给它会跳到别的调用上。
    static func stepDlsym(pid: Int32) -> String {
        guard let fn = taskForPidFn else { return "dlsym: 符号缺失" }
        var port: MachPort = 0
        let kr = fn(mach_task_self_, pid, &port)
        defer { dropPort(port) }
        if kr == KERN_SUCCESS, port != 0 {
            return "dlsym: 成功 port=0x\(String(port, radix: 16))"
        }
        return "dlsym: \(describe(kr))"
    }

    // MARK: - 读（全部 static：纯函数，不需要实例）

    /// 本次动作触及的内存页（4KB 对齐去重）+ 发起的 mach_vm_read 次数。
    ///
    /// **真正的成本指标是调用次数，不是页数。**
    /// 读 384 字节一次读完，和读 8 字节读 48 次，占的页数完全一样，
    /// 但后者要抢 48 次目标进程 vm_map 的锁 —— 游戏主线程每帧都在做内存分配，
    /// 我们每多抢一次读锁，就多打断它一次。
    ///
    /// 实测对照：找村口 2 次调用不崩；对象表 16 个全解约 128 次调用后游戏闪退。
    private static var touchedPages = Set<UInt64>()
    private static var probeCalls = 0

    /// 记一次读取：调用次数 + 触及的页。
    private static func noteRead(_ addr: UInt64, _ bytes: Int) {
        probeCalls += 1
        let first = addr >> 12
        let last = (addr &+ UInt64(bytes > 0 ? bytes - 1 : 0)) >> 12
        var p = first
        while p <= last {
            touchedPages.insert(p)
            if p == UInt64.max { return }
            p += 1
        }
    }

    /// 每次动作开头清零。
    private static func resetCounters() {
        probeCalls = 0
        resetCounters()
    }

    /// 本次动作的成本：调用次数是主指标，页数作参考。
    private static func costLine() -> String {
        "本次读取: \(probeCalls) 次 mach_vm_read · 触及 \(touchedPages.count) 页（4KB 去重）"
    }

    /// 从字节数组里读一个小端 UInt64（越界返回 0）。
    private static func u64le(_ b: [UInt8], _ offset: Int) -> UInt64 {
        guard offset >= 0, offset + 8 <= b.count else { return 0 }
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(b[offset + i]) << (8 * i) }
        return v
    }

    /// 按绝对地址读 4 字节。**只有 3 个参数**。
    /// mach_vm_region 那条路已被删除：它有两个出参，是之前连续出错的来源，
    /// 而读内存根本不需要枚举内存区。
    private static func readAt(port: MachPort, address: MachVmAddress) -> (KernReturn, UInt32) {
        guard let vmRead = vmReadFn else { return (KERN_FAILURE, 0) }
        noteRead(address, 4)
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 4
        let kr = vmRead(port, address, 4, &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen >= 4 else { return (kr, 0) }
        var v: UInt32 = 0
        if let p = UnsafeRawPointer(bitPattern: dataPtr) {
            v = p.assumingMemoryBound(to: UInt32.self).pointee
        }
        _ = vmDeallocateFn?(port, dataPtr, dataLen)
        return (KERN_SUCCESS, v)
    }

    /// 按绝对地址读 8 字节 —— 只给值，供程序判断用。
    private static func readRaw(port: MachPort, address: MachVmAddress) -> (KernReturn, UInt64) {
        guard let vmRead = vmReadFn else { return (KERN_FAILURE, 0) }
        noteRead(address, 8)
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = 8
        let kr = vmRead(port, address, 8, &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen >= 8 else { return (kr, 0) }
        var value: UInt64 = 0
        if let p = UnsafeRawPointer(bitPattern: dataPtr) {
            value = p.load(as: UInt64.self)
        }
        _ = vmDeallocateFn?(port, dataPtr, dataLen)
        return (KERN_SUCCESS, value)
    }

    /// 读一段连续字节（**上限 4096**）。
    ///
    /// 这是唯一允许的块读取，硬上限就卡在 4096：之前用 16KB 步进扫内存
    /// 把目标进程搞成过 jetsam 被杀，连续 fault 太多页是死因。
    private static func readBytes(port: MachPort, address: MachVmAddress, count: Int)
        -> (KernReturn, [UInt8]) {
        guard let vmRead = vmReadFn else { return (KERN_FAILURE, []) }
        guard count > 0, count <= 4096 else { return (KERN_FAILURE, []) }
        noteRead(address, count)
        var dataPtr: UInt = 0
        var dataLen: MachVmSize = MachVmSize(count)
        let kr = vmRead(port, address, MachVmSize(count), &dataPtr, &dataLen)
        guard kr == KERN_SUCCESS, dataPtr != 0, dataLen > 0 else { return (kr, []) }
        let n = min(Int(dataLen), count)
        var out = [UInt8](repeating: 0, count: n)
        if let src = UnsafeRawPointer(bitPattern: dataPtr) {
            out.withUnsafeMutableBytes { dst in
                if let d = dst.baseAddress {
                    d.copyMemory(from: src, byteCount: n)
                }
            }
        }
        _ = vmDeallocateFn?(port, dataPtr, dataLen)
        return (KERN_SUCCESS, out)
    }

    /// 给面板用的指针解读：值 + 是否像有效指针 + 高位（便于看落在哪个地址段）。
    private static func pointerInfo(port: MachPort, address: MachVmAddress)
        -> (KernReturn, UInt64, Bool, String) {
        let (kr, value) = readRaw(port: port, address: address)
        guard kr == KERN_SUCCESS else { return (kr, 0, false, "n/a") }
        // iOS arm64 用户态地址是 36 位宽
        let looksReal = value >= 0x100000000 && value < 0x10000000000
        let hi = String(format: "%04llx", (value >> 32) & 0xFFFF)
        return (KERN_SUCCESS, value, looksReal, hi)
    }

    /// 取目标进程的 task port。
    private static func port(for pid: Int32) -> (KernReturn, MachPort) {
        guard let tfp = taskForPidFn else { return (KERN_FAILURE, 0) }
        var p: MachPort = 0
        let kr = tfp(mach_task_self_, pid, &p)
        return (kr, p)
    }

    /// 释放一个 task port。
    ///
    /// **每次 `task_for_pid` 都会新建一个 send right**，不释放就一直累积。
    /// 之前的版本从来没释放过：每点一次按钮泄漏一个 right，而每个 right 都让
    /// 游戏的 task 对象多背一个引用 —— 游戏崩掉之后那个 task 对象也回收不掉，
    /// 反复"崩→重开→读"会把内核里堆一串收不掉的 task。
    /// 取端口的地方一律用 `defer { dropPort(p) }` 配对。
    private static func dropPort(_ p: MachPort) {
        guard p != 0, let fn = portDeallocateFn else { return }
        _ = fn(mach_task_self_, p)
    }

    /// 给面板调用方用的释放入口（SilentProbe 这类需要跨回调持有端口的场景）。
    static func releasePort(_ p: UInt32) {
        dropPort(MachPort(p))
    }

    // MARK: - 地址换算（唯一入口）

    /// dump 时 __TEXT.vmaddr 恒为 0x100000000 —— 静态域的零点。
    private static let staticImageBase: UInt64 = 0x100000000

    /// 本次运行找到的 image base 与 slide。
    /// 由「找村口」写入；只对同一次进程启动有效（游戏重启后 ASLR 会搬走）。
    private(set) static var imageBase: UInt64 = 0
    private(set) static var imageSlide: UInt64 = 0

    /// **唯一**的地址换算入口：OFFSET_*（静态 vmaddr 域地址）→ 本次运行的绝对地址。
    ///
    ///     slide   = imageBase − 0x100000000
    ///     runtime = slide + staticAddr
    ///
    /// 全仓约定：不出现 `imageBase + OFFSET` 的写法 —— 那是把"静态域地址"
    /// 当成"相对基址的 RVA"用了，会整整多算一个 0x100000000。
    private static func runtime(_ staticAddr: UInt64, slide: UInt64) -> UInt64 {
        slide &+ staticAddr
    }

    /// slide = imageBase − 静态基址。
    private static func slide(ofImageBase base: UInt64) -> UInt64 { base &- staticImageBase }

    /// 候选地址是不是真的 Mach-O 可执行头：magic == 0xFEEDFACF 且 filetype == MH_EXECUTE(2)。
    /// 两次 4 字节小读，不循环、不扫描。
    private static func isExecutableMachO(port: MachPort, _ addr: UInt64) -> (Bool, String) {
        let (rk1, magic) = readAt(port: port, address: MachVmAddress(addr))
        guard rk1 == KERN_SUCCESS else { return (false, "magic读失败/\(rk1)") }
        guard magic == 0xFEEDFACF else { return (false, "magic=0x\(String(magic, radix: 16))") }
        let (rk2, filetype) = readAt(port: port, address: MachVmAddress(addr &+ 12))
        guard rk2 == KERN_SUCCESS else { return (false, "filetype读失败/\(rk2)") }
        guard filetype == 2 else { return (false, "filetype=\(filetype)") }
        return (true, "MH_EXECUTE")
    }

    // MARK: - 面板动作

    /// 读证：在 dump 记录的模块基址处读 Mach-O 头。
    /// 一次读取，不扫描 —— 扫大范围是之前出问题的来源。
    static func stepReadProof(pid: Int32) -> String {
        let off = Offsets.load()
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "读证: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let (rk, magic) = readAt(port: p, address: MachVmAddress(off.moduleBase))
        guard rk == KERN_SUCCESS else {
            return "读证: 读 0x\(String(off.moduleBase, radix: 16)) 失败 \(describe(rk))"
        }
        let isMachO = (magic == 0xFEEDFACF)
        return "读证: 0x\(String(off.moduleBase, radix: 16)) magic=0x\(String(magic, radix: 16)) "
            + (isMachO ? "是Mach-O(基址正确,读通)" : "不是Mach-O(基址被ASLR搬了)")
    }

    /// 定点读：**第一次真实点读**，全部加起来约 20 字节，不写循环、不做扫描。
    ///
    /// ```
    /// slot = runtime(OFFSET_GOBJECTS)     // FUObjectArray
    /// slot + 0x118 → NumElements (UInt32)
    /// slot + 0xE0  → chunk0      (UInt64)
    /// chunk0       → 第一个 FUObjectItem 的 Object (UInt64, FUObjectItem::Object = 0)
    /// ```
    ///
    /// 验收：NumElements 是六位数（10 万 ~ 200 万）即表示 image base 与换算公式同时正确。
    /// 前提：先点过「找村口」—— base/slide 存在这份 static 状态里，不跨进程启动保留。
    static func stepFixedRead(pid: Int32) -> String {
        resetCounters()
        guard imageSlide != 0, imageBase != 0 else {
            return "定点读: 还没有基址 —— 先点「找村口」"
        }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "定点读: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let off = Offsets.load()
        let slot = runtime(off.gObjects, slide: s)

        // ① NumElements（UInt32）—— 唯一的验收数字
        let (rkNum, num) = readAt(port: p, address: MachVmAddress(slot &+ 0x118))
        guard rkNum == KERN_SUCCESS else {
            return "定点读: NumElements 读失败 \(describe(rkNum)) @0x\(String(slot &+ 0x118, radix: 16))"
        }
        // ② chunk0 指针（UInt64）
        let (rkChunk, chunk0) = readRaw(port: p, address: MachVmAddress(slot &+ 0xE0))
        // ③ 第一个 FUObjectItem 的 Object（UInt64）
        var obj0: UInt64 = 0
        var objNote = ""
        if rkChunk == KERN_SUCCESS, chunk0 != 0 {
            let (rkObj, v) = readRaw(port: p, address: MachVmAddress(chunk0))
            if rkObj == KERN_SUCCESS {
                obj0 = v
            } else {
                objNote = "obj0 读失败 \(describe(rkObj))"
            }
        } else {
            objNote = "chunk0 读失败 \(describe(rkChunk))"
        }

        let n = Int(num)
        let hit = (n >= 100_000 && n <= 2_000_000)
        var lines: [String] = []
        lines.append("定点读: NumElements=\(n) " + (hit ? "✓ 命中（六位数）" : "✗ 数量异常"))
        lines.append("base=0x\(String(imageBase, radix: 16)) slide=0x\(String(s, radix: 16))")
        lines.append("slot=0x\(String(slot, radix: 16)) = slide + OFFSET_GOBJECTS")
        lines.append(rkChunk == KERN_SUCCESS
            ? "chunk0=0x\(String(chunk0, radix: 16))"
            : "chunk0 读失败 \(describe(rkChunk))")
        lines.append(objNote.isEmpty
            ? "obj0=0x\(String(obj0, radix: 16))" + (obj0 == 0 ? "（空槽）" : "")
            : objNote)
        if !hit {
            // 数值异常时把两种病因分开：base/slide 错，还是字段偏移错。
            let hi = imageBase &+ 0x13000000
            let slotInRange = (slot >= imageBase && slot < hi)
            let chunkLooksHeap = (chunk0 >= 0x120000000 && chunk0 < 0x140000000)
            lines.append("诊断: slot" + (slotInRange
                ? " 在映像区间内 → base/slide 对得上，可疑点转到字段偏移 0x118/0xE0"
                : " 不在映像区间 → base 或换算公式错"))
            lines.append("诊断: chunk0" + (chunkLooksHeap
                ? " 像堆指针（0x12xxxxxxx 段）"
                : " 不像堆指针（不落在 0x120000000~0x140000000）"))
        }
        lines.append(costLine())
        return lines.joined(separator: "\n")
    }

    // MARK: - GNames（名字表）

    /// FNameEntry 的字符串起点（dump：FNameEntry::String = 0xE）。
    private static let nameEntryStringOffset: UInt64 = 0xE
    /// TNameArray 每个 chunk 的条目数（dump：ElementsPerChunk = 0x4000）。
    private static let namesPerChunk: UInt64 = 0x4000

    /// 「对象」按钮的分批游标：每批详解 4 个，点一次往下走一批。
    private static var objectCursor = 0

    /// 把一段字节按 hex 分行打印，偏移相对段首。
    private static func hexLines(_ bytes: [UInt8], perLine: Int = 16) -> [String] {
        var out: [String] = []
        var i = 0
        while i < bytes.count {
            let end = min(i + perLine, bytes.count)
            var hex = ""
            for j in i..<end {
                hex += String(format: "%02x", bytes[j])
                if j != end - 1 { hex += " " }
            }
            out.append("+" + String(i, radix: 16) + "  " + hex)
            i = end
        }
        return out
    }

    /// 字符串是 2 字节 UCS-2 还是 1 字节窄字符？
    /// ASCII 字符在 UCS-2 里高字节为 0，看第 2/4/6 字节是不是连续的 0。
    private static func looksWide(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 8 else { return false }
        var zeros = 0
        for i in stride(from: 1, to: min(bytes.count, 8), by: 2) where bytes[i] == 0 {
            zeros += 1
        }
        return zeros >= 3
    }

    /// 从 FNameEntry + 0xE 读名字，同时报出用的是哪种字符宽度。
    /// 宽度是逐 entry 判断的：同一个池里窄字符和 UCS-2 可以混存。
    private static func readNameDetail(port: MachPort, entry: UInt64) -> (name: String, width: String) {
        let (rk, bytes) = readBytes(port: port,
                                    address: MachVmAddress(entry &+ nameEntryStringOffset),
                                    count: 96)
        guard rk == KERN_SUCCESS, !bytes.isEmpty else { return ("(读失败)", "?") }
        if looksWide(bytes) {
            var units: [UInt16] = []
            var i = 0
            while i + 1 < bytes.count, units.count < 40 {
                let u = UInt16(bytes[i]) | (UInt16(bytes[i + 1]) << 8)
                if u == 0 { break }
                units.append(u)
                i += 2
            }
            return (units.isEmpty ? "(空)" : String(decoding: units, as: UTF16.self), "宽")
        }
        var raw: [UInt8] = []
        for b in bytes {
            if b == 0 { break }
            raw.append(b)
            if raw.count >= 40 { break }
        }
        return (raw.isEmpty ? "(空)" : String(decoding: raw, as: UTF8.self), "窄")
    }

    /// 从 FNameEntry + 0xE 读名字（不带宽度信息）。
    private static func readName(port: MachPort, entry: UInt64) -> String {
        readNameDetail(port: port, entry: entry).name
    }

    /// GNames：把 FName 索引解成字符串。
    ///
    /// 验收标准（三个全中才算通过）：
    ///   索引 0 → "None"    索引 1 → "ByteProperty"    索引 2 → "IntProperty"
    ///
    /// `Chunks` 是「内联指针数组」还是「指向指针数组」，各 UE4 版本不一致，
    /// 所以两种布局各解一遍，用上面三个已知答案判定 —— 不照抄、不猜。
    static func stepGNames(pid: Int32) -> String {
        resetCounters()
        guard imageSlide != 0, imageBase != 0 else {
            return "GNames: 还没有基址 —— 先点「找村口」"
        }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "GNames: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let slotAddr = runtime(Offsets.load().gNames, slide: s)

        // ① 槽 → 名字池
        let (rkPool, pool) = readRaw(port: p, address: MachVmAddress(slotAddr))
        guard rkPool == KERN_SUCCESS, pool != 0 else {
            return "GNames: 槽 0x\(String(slotAddr, radix: 16)) 读失败 \(describe(rkPool))"
        }

        var lines: [String] = []
        lines.append("GNames: 槽 0x\(String(slotAddr, radix: 16)) → pool=0x\(String(pool, radix: 16))")

        // ② 池头 hex：先看清布局，再决定解哪一层
        let (rkHead, head) = readBytes(port: p, address: MachVmAddress(pool), count: 0x40)
        if rkHead == KERN_SUCCESS, !head.isEmpty {
            lines.append("池头 0x40 字节（偏移相对 pool）:")
            lines.append(contentsOf: hexLines(head, perLine: 16))
            // 池头里若出现 0x4000（ElementsPerChunk），出现位置能反推布局
            var hits: [String] = []
            var k = 0
            while k + 4 <= head.count {
                let v = UInt32(head[k]) | (UInt32(head[k + 1]) << 8)
                    | (UInt32(head[k + 2]) << 16) | (UInt32(head[k + 3]) << 24)
                if v == 0x4000 { hits.append("+" + String(k, radix: 16)) }
                k += 4
            }
            lines.append("池头里 0x4000 出现在: " + (hits.isEmpty ? "无" : hits.joined(separator: " ")))
        } else {
            lines.append("池头读失败 \(describe(rkHead))")
        }

        // ③ 两种布局各解一遍，用已知答案判定
        let (rkA, lvlA) = readRaw(port: p, address: MachVmAddress(pool))
        let (rkB, lvlB) = (rkA == KERN_SUCCESS)
            ? readRaw(port: p, address: MachVmAddress(lvlA))
            : (KERN_FAILURE, 0)
        let expect = ["None", "ByteProperty", "IntProperty"]
        let candidates: [(String, KernReturn, UInt64)] = [
            ("A 池头直接是 chunk（一层）", rkA, lvlA),
            ("B 池头指向 chunk 指针数组（二层）", rkB, lvlB)
        ]
        var passed = false
        for (label, rk, chunk) in candidates {
            guard rk == KERN_SUCCESS, chunk != 0 else {
                lines.append("\(label): 指针无效 \(describe(rk))")
                continue
            }
            var names: [String] = []
            var detail: [String] = []
            var prevEntry: UInt64 = 0
            for i in 0..<3 {
                let (rke, entry) = readRaw(port: p, address: MachVmAddress(chunk &+ UInt64(i) * 8))
                guard rke == KERN_SUCCESS, entry != 0 else {
                    names.append("(失败)")
                    detail.append("   [\(i)] 取 entry 失败 \(describe(rke))")
                    continue
                }
                let (nm, width) = readNameDetail(port: p, entry: entry)
                names.append(nm)
                // entry 自报的索引（dump: FNameEntry::Index = 0x8）：
                // 名字若带 "_0" 之类的后缀，看这行就知道索引基准偏了多少
                let (rkIdx, idxV) = readAt(port: p, address: MachVmAddress(entry &+ 0x8))
                let idxNote = (rkIdx == KERN_SUCCESS)
                    ? "selfIdx=\(Int32(bitPattern: idxV))"
                    : "selfIdx=?"
                // entry 之间的实际间隔：和字符串长度对一下就能确认字符宽度
                let gapNote = (prevEntry == 0)
                    ? ""
                    : " Δ+0x" + String(entry &- prevEntry, radix: 16)
                prevEntry = entry
                detail.append("   [\(i)] \(nm)   @0x\(String(entry, radix: 16)) \(idxNote)\(gapNote) [\(width)]")
            }
            let ok = (names == expect)
            passed = passed || ok
            lines.append("\(label) chunk=0x\(String(chunk, radix: 16))")
            lines.append(contentsOf: detail)
            if ok { lines.append("   → 验收通过：0/1/2 三个名字全对") }
        }
        if !passed {
            lines.append("两个布局都没命中验收标准 —— 按池头 hex 决定下一步")
        }
        lines.append("（chunk 容量 \(namesPerChunk) 条/块，索引 0/1/2 都在第 0 块，暂不需要跨块）")
        lines.append(costLine())
        return lines.joined(separator: "\n")
    }

    /// 把 FName 索引解成字符串。布局用「名字」那步已经验收过的一层结构：
    ///   chunk_k = *(pool + k*8)     k = index / ElementsPerChunk
    ///   entry   = *(chunk_k + (index % ElementsPerChunk) * 8)
    /// chunk0 由调用方传入，索引落在第 0 块时省掉一次小读。
    private static func resolveName(port: MachPort, pool: UInt64, chunk0: UInt64, index: UInt32) -> String {
        let k = UInt64(index) / namesPerChunk
        let within = UInt64(index) % namesPerChunk
        var chunk = chunk0
        if k != 0 {
            let (rkC, c) = readRaw(port: port, address: MachVmAddress(pool &+ k * 8))
            guard rkC == KERN_SUCCESS, c != 0 else { return "(chunk\(k)读失败 \(describe(rkC)))" }
            chunk = c
        }
        let (rkE, entry) = readRaw(port: port, address: MachVmAddress(chunk &+ within * 8))
        guard rkE == KERN_SUCCESS, entry != 0 else { return "(entry读失败 \(describe(rkE)))" }
        return readName(port: port, entry: entry)
    }

    /// 对象表：批量读前 16 个 FUObjectItem，**每批只详解 4 个**。
    ///
    /// 链（偏移全部来自同一份 dump）：
    ///   item_i = items + i*0x18        FUObjectItem::Size = 0x18, Object = 0x0
    ///   class  = *(obj + 0x10)         UObject::Class
    ///   nameIX = *(obj + 0x18)         UObject::Name（FName::ComparisonIndex）
    ///   number = *(obj + 0x1C)         FName::Number（>1 时显示成 Name_(Number-1)）
    ///   clsIX  = *(class + 0x18)       类的 FName
    ///
    /// 为什么收着读：上一版逐个对象读 5 处字段 + 两次名字解析，16 个全解时
    /// 触及约 80 页 —— 点完游戏闪退了。现在改成
    ///   ① items 数组一次读完（16×0x18 = 384 字节，1 页），拿到 16 个对象指针
    ///   ② 每批只详解 4 个，点一次往下走一批（游标存在 static 里）
    /// 每次点击的代价降到 1/4 以下，且报告里直接把触及页数打出来。
    static func stepObjects(pid: Int32) -> String {
        resetCounters()
        guard imageSlide != 0, imageBase != 0 else {
            return "对象: 还没有基址 —— 先点「找村口」"
        }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "对象: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let off = Offsets.load()

        // 名字池（布局已由「名字」按钮验收确认：一层，pool+0 就是 chunk0）
        let (rkPool, pool) = readRaw(port: p, address: MachVmAddress(runtime(off.gNames, slide: s)))
        guard rkPool == KERN_SUCCESS, pool != 0 else {
            return "对象: 名字池槽读取失败 \(describe(rkPool))"
        }
        let (rkChunk, nameChunk0) = readRaw(port: p, address: MachVmAddress(pool))
        guard rkChunk == KERN_SUCCESS, nameChunk0 != 0 else {
            return "对象: 名字池 chunk0 读取失败 \(describe(rkChunk))"
        }

        // 对象表头
        let slot = runtime(off.gObjects, slide: s)
        let (rkNum, num) = readAt(port: p, address: MachVmAddress(slot &+ 0x118))
        guard rkNum == KERN_SUCCESS else { return "对象: NumElements 读失败 \(describe(rkNum))" }
        let (rkItems, items) = readRaw(port: p, address: MachVmAddress(slot &+ 0xE0))
        guard rkItems == KERN_SUCCESS, items != 0 else {
            return "对象: items 指针读失败 \(describe(rkItems))"
        }

        // ① items 数组一次读完：逐项读是 16 次 mach_vm_read，数据在同一页，
        //    调用次数与内核里的 copy 分配却翻 16 倍，没有意义。
        let listCount = min(Int(num), 16)
        let (rkBuf, buf) = readBytes(port: p, address: MachVmAddress(items), count: listCount * 0x18)
        guard rkBuf == KERN_SUCCESS else {
            return "对象: items 数组读取失败 \(describe(rkBuf))"
        }
        var objs: [UInt64] = []
        for i in 0..<listCount {
            objs.append(u64le(buf, i * 0x18))     // FUObjectItem::Object = 0x0
        }

        // ② 分批详解：游标轮转，点一次走一批
        let batch = 4
        let start = objectCursor % max(1, listCount)
        let stop = min(start + batch, listCount)
        objectCursor = (stop >= listCount) ? 0 : stop

        var lines: [String] = []
        lines.append("对象: NumElements=\(num)  items=0x\(String(items, radix: 16))  "
            + "本批 [\(start)..\(stop - 1)] / 列表 \(listCount)")
        for i in 0..<listCount {
            let obj = objs[i]
            guard obj != 0 else {
                lines.append("[\(i)] (空槽)")
                continue
            }
            guard i >= start, i < stop else {
                lines.append("[\(i)] 0x\(String(obj, radix: 16))   （只列指针）")
                continue
            }
            let (rkCls, cls) = readRaw(port: p, address: MachVmAddress(obj &+ 0x10))
            let (rkName, nameIX) = readAt(port: p, address: MachVmAddress(obj &+ 0x18))
            let (rkNo, number) = readAt(port: p, address: MachVmAddress(obj &+ 0x1C))

            var clsName = "类名?"
            if rkCls == KERN_SUCCESS, cls != 0 {
                let (rkCIX, clsIX) = readAt(port: p, address: MachVmAddress(cls &+ 0x18))
                if rkCIX == KERN_SUCCESS {
                    clsName = resolveName(port: p, pool: pool, chunk0: nameChunk0, index: clsIX)
                } else {
                    clsName = "类名读失败 \(describe(rkCIX))"
                }
            } else if rkCls != KERN_SUCCESS {
                clsName = "Class读失败 \(describe(rkCls))"
            }

            var objName = "名字?"
            if rkName == KERN_SUCCESS {
                objName = resolveName(port: p, pool: pool, chunk0: nameChunk0, index: nameIX)
                if rkNo == KERN_SUCCESS, number > 1 {
                    objName += "_\(number - 1)"
                }
            } else {
                objName = "Name读失败 \(describe(rkName))"
            }
            lines.append("[\(i)] \(clsName)  \(objName)   @0x\(String(obj, radix: 16))")
        }
        lines.append(costLine() + " · 再点一次继续下一批")
        return lines.joined(separator: "\n")
    }

    /// 世界链：GWorld → PersistentLevel → Actors（三次小读，个位数页）。
    ///
    /// 这条链刻意**绕开对象表**。理由在崩溃报告里：
    ///   对象表那步触及约 80 页（对象字段多是冷页）→ 点完游戏 SIGSEGV，
    ///   而 GWorld / UWorld / ULevel 是游戏每一帧都在用的热页，读取不改变驻留图。
    ///
    ///   UWorld = *(GWorld槽)
    ///   UWorld + 0xB8 → PersistentLevel (ULevel*)
    ///   ULevel + 0xA0 → Actors TArray { data*(8) count(4) max(4) }
    static func stepWorld(pid: Int32) -> String {
        resetCounters()
        guard imageSlide != 0, imageBase != 0 else {
            return "世界: 还没有基址 —— 先点「找村口」"
        }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "世界: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        let s = imageSlide
        let slot = runtime(Offsets.load().gWorld, slide: s)
        var lines: [String] = []
        lines.append("世界: GWorld槽 0x\(String(slot, radix: 16))")

        // ① UWorld
        let (rkWorld, world) = readRaw(port: p, address: MachVmAddress(slot))
        guard rkWorld == KERN_SUCCESS, world != 0 else {
            return "世界: 读 GWorld 失败 \(describe(rkWorld)) @0x\(String(slot, radix: 16))"
        }
        lines.append("  UWorld=0x\(String(world, radix: 16))"
            + (world < 0x100000000 ? "  ✗ 不像指针" : "  ✓"))

        // ② PersistentLevel
        let (rkLevel, level) = readRaw(port: p, address: MachVmAddress(world &+ 0xB8))
        guard rkLevel == KERN_SUCCESS, level != 0 else {
            return "世界: 读 PersistentLevel 失败 \(describe(rkLevel)) @UWorld+0xB8"
        }
        lines.append("  PersistentLevel=0x\(String(level, radix: 16))"
            + (level < 0x100000000 ? "  ✗ 不像指针" : "  ✓"))

        // ③ Actors TArray：裸指针 + count + max，一次读 16 字节
        let (rkArr, arr) = readBytes(port: p, address: MachVmAddress(level &+ 0xA0), count: 16)
        guard rkArr == KERN_SUCCESS, arr.count >= 16 else {
            return "世界: 读 Actors TArray 失败 \(describe(rkArr)) @ULevel+0xA0"
        }
        let dataPtr = u64le(arr, 0)
        let count = UInt32(arr[8]) | (UInt32(arr[9]) << 8) | (UInt32(arr[10]) << 16) | (UInt32(arr[11]) << 24)
        let cap = UInt32(arr[12]) | (UInt32(arr[13]) << 8) | (UInt32(arr[14]) << 16) | (UInt32(arr[15]) << 24)
        let sane = (count > 0 && count <= 200_000 && count <= cap)
        lines.append("  Actors: data=0x\(String(dataPtr, radix: 16))  count=\(count)  max=\(cap)  "
            + (sane ? "✓ 数量合理" : "✗ 数量异常"))
        lines.append(costLine() + " · 对照：对象表那步约 128 次调用")
        return lines.joined(separator: "\n")
    }

    // MARK: - 内存账本（验证读取是否在给游戏加内存）

    private typealias TaskInfoFn = @convention(c) (UInt32, Int32,
                                                   UnsafeMutablePointer<Int32>,
                                                   UnsafeMutablePointer<UInt32>) -> KernReturn
    private static let taskInfoFn = symbol("task_info", as: TaskInfoFn.self)

    /// 上一次读到的内存账本，用来算差值。
    private static var lastMem: (footprint: UInt64, compressed: UInt64, resident: UInt64)?

    /// 读游戏进程的内存账本。**一个字节的游戏内存都不碰** —— 只是让内核查一下它自己的记账。
    ///
    /// 这是把「读冷页 → 给游戏加内存 → 崩」这条假说变成数字的唯一直接手段：
    ///   phys_footprint  是 jetsam 判定用的那个数（决定游戏会不会被杀）
    ///   compressed      是当前被压缩的内存量 —— 我们读冷页会强制解压，这个数应该往下掉
    /// 在「对象」这类动作前后各点一次，差值自己会说话。
    static func stepMemory(pid: Int32) -> String {
        guard let fn = taskInfoFn else { return "内存: task_info 符号缺失" }
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else { return "内存: 取端口失败 \(describe(kr))" }
        defer { dropPort(p) }

        var raw = [UInt8](repeating: 0, count: 512)
        var count = UInt32(raw.count / 4)
        let rk = raw.withUnsafeMutableBytes { rb -> Int32 in
            guard let base = rb.baseAddress?.assumingMemoryBound(to: Int32.self) else {
                return KERN_FAILURE
            }
            return fn(p, 22, base, &count)          // TASK_VM_INFO = 22
        }
        guard rk == KERN_SUCCESS, count > 0 else {
            return "内存: task_info 失败 \(describe(rk))"
        }

        func field(_ off: Int) -> UInt64 { u64le(raw, off) }
        func mb(_ v: UInt64) -> String { String(format: "%.1f", Double(v) / 1048576.0) }

        let virt = field(0)              // virtual_size
        let resi = field(16)             // resident_size
        let comp = field(120)            // compressed
        let phys = field(144)            // phys_footprint

        // 结构布局是按 task_vm_info 的公开字段顺序取的；数值明显不合理说明偏移不对，
        // 这一行就是给这种情况准备的。
        let sane = (phys > 1_048_576 && phys < (64 * 1024 * 1024 * 1024))
        var lines: [String] = []
        lines.append("内存: pid=\(pid)" + (sane ? "" : "  ✗ 数值不合理（结构偏移可能不匹配这个系统版本）"))
        var delta = ""
        if let last = lastMem {
            let df = Int64(bitPattern: phys) - Int64(bitPattern: last.footprint)
            let dc = Int64(bitPattern: comp) - Int64(bitPattern: last.compressed)
            delta = String(format: "   较上次 %+.1f MB / %+.1f MB",
                           Double(df) / 1048576.0, Double(dc) / 1048576.0)
        }
        lines.append("  phys_footprint = \(mb(phys)) MB   ← jetsam 判定的就是它" + delta)
        lines.append("  compressed     = \(mb(comp)) MB   ← 读冷页会让它往下掉")
        lines.append("  resident       = \(mb(resi)) MB")
        lines.append("  virtual        = \(mb(virt)) MB")
        lines.append("用法：动作前后各点一次这个按钮，差值直接说明读取给游戏加了多少内存")
        lastMem = (phys, comp, resi)
        return lines.joined(separator: "\n")
    }

    /// 单点区域归属：对 dump 基址问一次「这属于哪个文件」。
    ///
    /// 零风险探测：一次调用、不遍历、不写。
    /// 收益却很大 ——
    ///   返回 ShadowTrackerExtra 路径 → 该地址在游戏映像内，且符号可用
    ///   返回别的路径               → 那个地址属于别的映射
    ///   返回 0 / 符号缺失          → 这条路不通，及早知道
    static func stepRegionName(pid: Int32) -> String {
        let off = Offsets.load()
        guard let fn = procRegionFileNameFn else {
            return "区域归属: proc_regionfilename 符号缺失"
        }
        var buf = [CChar](repeating: 0, count: 1024)
        // buf.count 必须在闭包外取：withUnsafeMutableBytes 已对 buf 取独占访问，
        // 闭包内再读 buf.count 会触发 "overlapping accesses" 编译错误。
        let cap = UInt32(buf.count)
        let addr = off.moduleBase
        let n = buf.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return 0 }
            return fn(pid, addr, base, cap)
        }
        guard n > 0 else {
            return "区域归属: 0x\(String(addr, radix: 16)) → 返回 \(n)（该地址不在任何区域?)"
        }
        let path = String(cString: buf)
        let short = path.split(separator: "/").last.map(String.init) ?? path
        let isGame = path.lowercased().contains("shadowtracker")
        return "区域归属: 0x\(String(addr, radix: 16)) → \(short) \(isGame ? "是游戏映像" : "不是游戏")"
    }

    // MARK: - 找基址（枚举 region，零内存读取）

    /// 枚举下一个 region。会把 addr 更新为该 region 的实际起始。
    /// 返回 (成功, size, protection, 文件偏移)
    private static func nextRegion(task: UInt32, addr: inout UInt64)
        -> (ok: Bool, size: UInt64, prot: Int32, offset: UInt32) {
        guard let fn = vmRegionRecurseFn else { return (false, 0, 0, 0) }
        var size: UInt64 = 0
        var depth: UInt32 = 0
        var info = [Int32](repeating: 0, count: 32)
        var count: UInt32 = 19          // VM_REGION_SUBMAP_INFO_COUNT_64
        let kr = info.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return KERN_FAILURE }
            return fn(task, &addr, &size, &depth, base, &count)
        }
        guard kr == KERN_SUCCESS, size > 0 else { return (false, 0, 0, 0) }
        // vm_region_submap_info_64 开头四个字：protection, max_protection, inheritance, offset
        return (true, size, info[0], UInt32(bitPattern: info[3]))
    }

    /// 问某地址属于哪个文件（proc_regionfilename 封装）
    private static func regionFile(pid: Int32, addr: UInt64) -> String? {
        guard let fn = procRegionFileNameFn else { return nil }
        var buf = [CChar](repeating: 0, count: 1024)
        let cap = UInt32(buf.count)
        let n = buf.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return 0 }
            return fn(pid, addr, base, cap)
        }
        guard n > 0 else { return nil }
        let s = String(cString: buf)
        return s.isEmpty ? nil : s
    }

    /// 找基址（主二进制），**全程不读游戏内存内容**。
    ///
    /// 判据（三个条件同时成立才认）：
    ///   1. proc_regionfilename 返回的路径匹配 ShadowTracker
    ///   2. protection 含 VM_PROT_EXECUTE(0x4)  → 可执行段
    ///   3. offset == 0                          → 从文件头映射 = Mach-O 头所在段
    /// 满足这三条的就是 __TEXT 段，它的起始地址 = image base。
    /// 命中后还要读 4 字节校验 magic == 0xFEEDFACF、再读 +12 的 filetype == 2：
    /// 三个 region 条件只说明"像 __TEXT"，最终裁决权在 Mach-O 头上，
    /// 校验不过就继续枚举下一个候选，不把可疑值返回给上层。
    ///
    /// 为什么不用"二分 proc_regionfilename"：实测它的语义是
    /// "返回该地址所在或**之后第一个** region" —— 对未映射的低地址也会返回
    /// 游戏路径，二分因此完全失效（会出现负 slide 这种不可能的结果）。
    /// 所以必须有 region 边界信息，只能靠枚举。
    static func stepFindBase(pid: Int32) -> String {
        resetCounters()
        guard vmRegionRecurseFn != nil else { return "找基址: vm_region_recurse_64 符号缺失" }
        guard procRegionFileNameFn != nil else { return "找基址: proc_regionfilename 符号缺失" }

        // ---- 参数自检：先对自己进程枚举一次，参数错就停在这里，绝不碰游戏 ----
        var selfAddr: UInt64 = 0
        let selfCheck = nextRegion(task: mach_task_self_, addr: &selfAddr)
        guard selfCheck.ok else {
            return "找基址: 参数自检失败（对自己枚举就不成功），未碰游戏"
        }

        // ---- 先确认这个 pid 还是游戏 ----
        // 游戏重启会换 pid。拿一个已经失效、又被系统复用给别人的 pid 去
        // task_for_pid，就会变成读另一个进程的内存 —— 这一步零内存读取，
        // 只是问「0x100000000 这个地址属于哪个文件」。
        guard let gamePath = regionFile(pid: pid, addr: 0x100000000),
              gamePath.lowercased().contains("shadowtracker") else {
            return "找基址: pid \(pid) 不是游戏映像（游戏可能重启过）—— 先点「刷新」"
        }

        // ---- 拿游戏的 task port ----
        let (kr, p) = port(for: pid)
        guard kr == KERN_SUCCESS, p != 0 else {
            return "找基址: 取端口失败 \(describe(kr))"
        }
        defer { dropPort(p) }

        var addr: UInt64 = 0
        var scanned = 0
        var hitBase: UInt64 = 0
        var hitName = ""
        /// 被 Mach-O 校验否掉的候选（用于面板诊断：命中条件太宽还是真没找到）
        var rejects: [String] = []

        while scanned < 6000 {
            let (ok, size, prot, offset) = nextRegion(task: p, addr: &addr)
            guard ok else { break }
            scanned += 1

            // 三个 region 条件全中，只说明「像 __TEXT」
            if let path = regionFile(pid: pid, addr: addr),
               path.lowercased().contains("shadowtracker"),
               (prot & 0x4) != 0,          // VM_PROT_EXECUTE
               offset == 0 {
                // ① 还得它真的是 Mach-O 可执行头（magic + filetype），
                //    否则继续找下一个候选，绝不把可疑值当基址返回。
                let (okMagic, why) = isExecutableMachO(port: p, addr)
                if okMagic {
                    hitBase = addr
                    hitName = path.split(separator: "/").last.map(String.init) ?? "?"
                    break
                }
                rejects.append("0x\(String(addr, radix: 16))(\(why))")
            }

            addr += size
            if addr < size { break }        // 溢出保护
        }

        guard hitBase != 0 else {
            let why = rejects.isEmpty ? "" : " 否掉:" + rejects.prefix(3).joined(separator: " ")
            return "找基址: 枚举\(scanned)个region，未命中(__TEXT & offset=0)" + why
        }

        // ② 记账：base / slide 存下来，后面「定点读」直接用这份状态
        let s = slide(ofImageBase: hitBase)
        imageBase = hitBase
        imageSlide = s

        // ③ 摊开 slide 与三个可用 OFFSET 的运行时落点，目视确认都落在映像区间
        let off = Offsets.load()
        let hi = hitBase &+ 0x13000000
        let slots: [(String, UInt64)] = [
            ("GObjects", off.gObjects),
            ("GNames", off.gNames),
            ("GWorld", off.gWorld)
        ]
        var lines: [String] = []
        lines.append("找基址: ✓ base=0x\(String(hitBase, radix: 16)) region=\(scanned) \(hitName)")
        lines.append("slide=0x\(String(s, radix: 16)) = base − 0x100000000")
        lines.append("映像区间 [0x\(String(hitBase, radix: 16)), 0x\(String(hi, radix: 16)))")
        for (name, staticAddr) in slots {
            let r = runtime(staticAddr, slide: s)
            let inside = (r >= hitBase && r < hi)
            let pad = String(repeating: " ", count: max(0, 9 - name.count))
            lines.append("\(name)\(pad)0x\(String(staticAddr, radix: 16)) → 0x\(String(r, radix: 16)) "
                + (inside ? "✓" : "✗越界"))
        }
        lines.append("（找基址本身不读游戏内存，这里只统计 Mach-O 头校验：" + costLine() + "）")
        return lines.joined(separator: "\n")
    }
}
