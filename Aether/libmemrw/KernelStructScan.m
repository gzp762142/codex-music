//
//  KernelStructScan.m
//  实现见 KernelStructScan.h 的组织说明。这里只补「具体写法为什么这样」与证据指针。
//
//  这个翻译单元里中文只出现在注释里，诊断正文保持英文（与这个模块既有的输出一致，
//  面板原样显示）。tools/clex_check.py 的 CJK 判定（clex_check.py:134）只在
//  「既不在字符串、也不在注释里」的位置报错，状态机在 in_string / in_block_comment
//  内直接 continue（clex_check.py:91-121），所以中文注释是过闸的。
//

#import <Foundation/Foundation.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "KernelMemory.h"
#include "KernelSlide.h"
#include "KernelStructScan.h"

#pragma mark - Scan geometry

/*
 * 一级读允许的唯一窗口：task+0x00 … task+0xF8，步长 8（32 个槽）。
 *
 * 为什么只能是这一段：这些地址全部落在 task 结构自身内部，而 task 那个地址本身
 * 已被证明可读 —— 上一版读过 task+0x28 没有崩（读到的值 0x52bc7e10023e93c0 不在
 * 内核地址域：指针字段带 PAC 签名，还原之后落在哪一类由 km_unsign_ptr 的结果决定，
 * 这正是本版要在分类前做还原、并把原始值与还原值一起打印的原因）。窗口以外的任何
 * 地址都不在本模块的读取范围内，因为「读一个未经确认的地址」在现有 kread 路径下没有
 * 安全形式：kread 让内核替我们解引用，EL1 的 data abort 默认致命（证据在 .h 里）。
 */
#define KM_SS_SCAN_BEGIN 0x00ULL
#define KM_SS_SCAN_END 0x100ULL

/// 小整数上界。用来把「引用计数 / 标志位」这类值单独标一类 —— 纯分类，不解引用。
#define KM_SS_SMALL_INT 0x10000ULL

/*
 * 读预算。km_read64 每次发两次 kread（KernelMemory.m:881-885 的复读确认），
 * 本模块最坏 = 1 次前置读 + 32 个槽 = 33 次 km_read64 = 66 次 kread，所以 64 这个
 * 预算在真实路径上不会被打到。它留着是为了让「窗口没走完就停下」有一个明确的状态
 * （STATE=partial），而不是被静默截断成一次看起来干净的 no_bsd_info —— 半程扫描
 * 读起来像完整结论，是这份诊断唯一不能犯的错。
 */
#define KM_SS_READ_BUDGET 64

/// 能同时记录的槽位数。窗口一共 32 个槽，第 33 个不可能存在。
#define KM_SS_MAX_SLOTS 32

/*
 * 文本缓冲。正文最坏 = 32 行槽 + 固定若干段（1KB 量级），16KB 留足余量。
 * finalText 比正文再多留 KM_SS_SUMMARY_MAX，因为最终文本 = 摘要行 + 正文，
 * 两个来源各自在自己的缓冲里限长，拼接处就不会再出现第三个截断点。
 */
#define KM_SS_TEXT_SIZE 16384
#define KM_SS_SUMMARY_MAX 320

#pragma mark - State

/// 上一次扫描的诊断文本。一次扫描写一次，km_scan_diagnostic() 读。
/// 与 KernelPhysWindow.m 的 g_diagText 同一套纪律：调用方把两次调用放在同一条串行
/// 路径上（AutoTracker.syncExternal），因为 libkfd 的 kread 后端不是线程安全的。
static NSString *g_scanText = nil;

/// 当前这次扫描已发出的 km_read64 次数，以及「预算被打到」的标记。
static uint64_t g_scanReads = 0;
static bool g_scanBudgetHit = false;

#pragma mark - Helpers

/*
 * 形态门 —— 本文件里每一个交给 km_read64 的地址都必须先过它。
 *
 *   (1) 非 0：0 同时是「读失败」与「合法值」的哨兵，不能当读目标。
 *   (2) 内核地址域（高 16 位全 1）：与 km_is_kernel_address（KernelMemory.m:241-244）
 *       同一口径，也与 km_read64 自己的闸门（KernelMemory.m:877）同口径。
 *       刻意不更严：更严的话，被本函数拒掉的读在诊断里会显示成"我拒了"，
 *       而实际上是 km_read64 会拒，诊断就不再描述真实发生了什么。
 *   (3) 8 字节对齐：非对齐的 8 字节读会把相邻两个字段拼成一个值，而那个值
 *       「形如合法指针」，能穿过后面所有形态检查 —— 本工程为此付过两次代价
 *       （KernelMemory.m:1580、KernelMemory.m:1695 记的两次彩屏）。
 *
 * 本次改动之后唯一的读目标是 `task + N`（N ∈ [0x00, 0xF8] 且为 8 的倍数），
 * 这条检查在当前路径上恒真。保留它是因为它是不变式，不是因为现在能挡住什么：
 * 它还负责把「task 本身没对齐」这件事变成一行诊断，而不是一次形态可疑的读。
 */
static bool km_ss_readable(uint64_t addr)
{
    if (addr == 0) {
        return false;
    }
    if ((addr >> 48) != 0xFFFF) {
        return false;
    }
    if ((addr & 0x7ULL) != 0) {
        return false;
    }
    return true;
}

/// 内核虚拟地址域。单独写出来而不是委托给 km_is_kernel_address：那个函数同时是
/// 读闸门，而「这个值在不在 KVA 域」与「我能不能读这个地址」是两个问题 ——
/// 本文件用它只做分类打印。**判据一律作用在 km_unsign_ptr 还原之后的值上**：
/// 原始读数可能整片落在域外（PAC 签名），拿它分类只会把所有内核指针标成 other。
static bool km_ss_is_kva(uint64_t v)
{
    return (v >> 48) == 0xFFFF;
}

/// 小整数分类。判据只有这一条，不带任何结构假设。
static bool km_ss_is_small_int(uint64_t v)
{
    return v < KM_SS_SMALL_INT;
}

/// km_read64 包装：(a) 强制过形态门，(b) 记预算。预算用尽后返回 false，
/// 让调用方干净地停下，而不是发出结果无法记账的读。
static uint64_t km_ss_read64(uint64_t addr, bool *ok)
{
    if (ok != NULL) {
        *ok = false;
    }
    if (!km_ss_readable(addr)) {
        return 0;
    }
    if (g_scanReads >= KM_SS_READ_BUDGET) {
        g_scanBudgetHit = true;
        return 0;
    }
    g_scanReads++;

    /*
     * km_read64 的 *ok 含义是「地址形态合法 且 两次读到了同一个值」
     * （KernelMemory.m:863-870），不是"kread 报告成功"—— kread 返回 void，
     * 什么都报告不了。活着的内核字段两次读必然相同，所以 !ok 是真信号：
     * 这个值不可信，既不能当指针，也不能算成一个正常的值参与分类。
     */
    bool inner = false;
    const uint64_t v = km_read64(addr, &inner);
    if (ok != NULL) {
        *ok = inner;
    }
    return v;
}

/*
 * 文本构建器。按**实际写入的字节数**记账（vsnprintf + strlen），绝不按 vsnprintf
 * 的返回值。本工程在这上面真崩过（KernelMemory.m 的 km_self_test）：截断时
 * vsnprintf 返回的是"本该写多少"，大于剩余空间，于是 `size - used` 在 size_t 上
 * 回绕成一个天文数字，下一次追加就写到缓冲外面。这里的缓冲是 static，越界会砸
 * 掉相邻的静态数据。
 */
typedef struct {
    char *buf;
    size_t size;
    size_t used;
    bool truncated;
} km_ss_text;

static void km_ss_append(km_ss_text *t, const char *fmt, ...)
{
    if (t->used >= t->size) {
        t->truncated = true;
        return;
    }
    const size_t room = t->size - t->used;

    va_list args;
    va_start(args, fmt);
    const int written = vsnprintf(t->buf + t->used, room, fmt, args);
    va_end(args);

    t->used += strlen(t->buf + t->used);
    if (written < 0 || (size_t)written >= room) {
        t->truncated = true;
    }
}

/*
 * 被记录下来的一个槽。两类槽共用它：落在内核地址域的（kvaSlots）、等于
 * current_proc 的（procSlots）。
 *
 * rawValue 与 value 两个都要留：没有 raw 就无从判断还原有没有生效，没有还原后的
 * value 就不知道该按什么分类 —— 真机上 task+0x28 的 raw 是 0x52bc7e10023e93c0
 * （高 16 位 0x52bc），只拿它去看形态，看到的只是「它不在内核地址域」这一件事，
 * 而它究竟是别的什么、还原之后落在哪一类，要靠两个值并排才读得出来。
 *
 * 这里刻意没有旧版的 hitOffset / firstHit 之类字段 —— 那些字段描述的是
 * "读出来的值指向的对象里第几个字段像 pmap"，只有做二级读时才存在，
 * 随二级读一起删除，不留占位。
 */
typedef struct {
    uint64_t offset;      // 相对 task 的偏移
    uint64_t rawValue;    // 该槽读出来的原始值（含 PAC 签名）
    uint64_t value;       // km_unsign_ptr 还原之后的值
} km_ss_slot;

#pragma mark - Probe

uint64_t km_scan_task_map_offset(void)
{
    /*
     * 正文与最终文本都是 static：诊断文本要活到 km_scan_diagnostic() 被调用
     * 之后才被读，栈上的缓冲做不到。
     */
    static char body[KM_SS_TEXT_SIZE];
    static char finalText[KM_SS_TEXT_SIZE + KM_SS_SUMMARY_MAX];
    memset(body, 0, sizeof(body));
    memset(finalText, 0, sizeof(finalText));

    km_ss_text t = { body, sizeof(body), 0, false };
    g_scanReads = 0;
    g_scanBudgetHit = false;

    /*
     * 摘要与全部状态都在第一个 `goto done` 之前声明并初始化。`done:` 之后的代码
     * 要读它们，而 goto 跳过带初始化器的声明只会留下不确定值 —— 旧实现里那段
     * 「为什么 summary 声明在这里」的注释说的就是同一件事，这里把它扩到全部变量。
     */
    char summary[192];
    snprintf(summary, sizeof(summary), "[structscan] STATE=not_ready");

    uint64_t proc = 0;
    uint64_t objectSize = 0;
    uint64_t task = 0;
    uint64_t hitOffset = 0;      // 等于 current_proc 的槽（不止一个时取最低的那个）
    uint64_t procCount = 0;      // 有多少个槽（还原后）等于 current_proc
    uint64_t kvaCount = 0;       // 有多少个槽（还原后）落在内核地址域（**一个都不解引用**）
    uint64_t scannedSlots = 0;
    uint64_t readFail = 0;
    uint64_t smallInts = 0;
    uint64_t otherValues = 0;
    uint64_t unsignChanged = 0;  // 还原改动了值的槽位数
    uint64_t unsignLive = 0;     // 还原改动后落进内核地址域的槽位数（还原是否真的在工作的证据）
    bool scanAborted = false;    // 窗口没走完（地址溢出守卫），与预算耗尽同一种结果

    km_ss_slot kvaSlots[KM_SS_MAX_SLOTS];
    km_ss_slot procSlots[KM_SS_MAX_SLOTS];
    memset(kvaSlots, 0, sizeof(kvaSlots));
    memset(procSlots, 0, sizeof(procSlots));

    const uint64_t knownMapOff = km_task_map_offset();

    /* ---- 1. 前置。这一段不成立时，下面一行代码都不执行。 ---- */
    km_ss_append(&t, "== 1. preconditions ==\n");
    if (!km_ready()) {
        km_ss_append(&t, "km_ready()=false: the kernel read/write layer is not up. "
                         "Zero kreads issued.\n");
        snprintf(summary, sizeof(summary), "[structscan] STATE=not_ready (km_ready()=false)");
        goto done;
    }
    km_ss_append(&t, "km_ready()=true\n");

    proc = km_current_proc();
    objectSize = km_proc_object_size();

    km_ss_append(&t, "km_current_proc()=%#llx  km_proc_object_size()=%#llx  "
                     "km_task_map_offset()=%#llx [version table, printed for reference only: "
                     "never used as a criterion]\n",
                 (unsigned long long)proc, (unsigned long long)objectSize,
                 (unsigned long long)knownMapOff);

    if (proc == 0 || objectSize == 0) {
        km_ss_append(&t, "current_proc or proc__object_size is 0: the version table did not match, "
                         "or the kernel layer is half up. Without both there is no task address to "
                         "scan, so nothing is read.\n");
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=not_ready (current_proc or proc__object_size is 0)");
        goto done;
    }
    if (UINT64_MAX - proc < objectSize) {
        km_ss_append(&t, "proc + proc__object_size overflows\n");
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=not_ready (proc + proc__object_size overflows)");
        goto done;
    }

    task = proc + objectSize;
    if (!km_ss_readable(task)) {
        km_ss_append(&t, "task=%#llx fails the shape gate (kernel domain + 8-byte aligned + "
                         "non-zero)\n",
                     (unsigned long long)task);
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=not_ready (task fails the shape gate)");
        goto done;
    }

    /*
     * ---- 2. 被测对象：task 地址的算术，以及它「是不是真 object」这件事 ----
     *
     * 本节只交代地址怎么来的与可读性；「这个对象是不是真 task」由第 5 节判。
     * 旧版在这里写「proc -> task 是前提」；本版不把任何一边的结论写进标题，
     * 因为本探针不对 proc -> task 这个推导表态（见 KernelStructScan.h）。
     */
    km_ss_append(&t, "== 2. task address under test ==\n");
    km_ss_append(&t, "proc=%#llx + object_size=%#llx = task=%#llx (shape gate OK) -- whether this "
                     "object really is a struct task is what section 5 decides\n",
                 (unsigned long long)proc, (unsigned long long)objectSize,
                 (unsigned long long)task);

    /* ---- 3. task 自身可读性：一次读，一个地址（task+0x00）。 ---- */
    km_ss_append(&t, "== 3. task readability (single read at task+%#llx) ==\n",
                 (unsigned long long)KM_SS_SCAN_BEGIN);

    bool okHead = false;
    const uint64_t head = km_ss_read64(task + KM_SS_SCAN_BEGIN, &okHead);

    if (g_scanBudgetHit) {
        km_ss_append(&t, "read budget %llu exhausted before the readability read at task+%#llx\n",
                     (unsigned long long)KM_SS_READ_BUDGET,
                     (unsigned long long)KM_SS_SCAN_BEGIN);
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=partial (read budget exhausted before the first slot)");
        goto done;
    }
    if (!okHead) {
        km_ss_append(&t, "task+%#llx read failed: two consecutive reads disagreed. This is a "
                         "PRECONDITION failure, not a result -- no slot is scanned and nothing is "
                         "concluded about bsd_info. Candidate causes, in the order worth checking: "
                         "the object_size used to compute task does not land on a live object, "
                         "current_proc is stale, or the read path itself is broken.\n",
                     (unsigned long long)KM_SS_SCAN_BEGIN);
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=task_unreadable (task+0x00: two reads disagreed)");
        goto done;
    }
    km_ss_append(&t, "task+%#llx = %#llx (read twice, agreed): the task object is readable, so "
                     "walking its own slots is safe\n",
                 (unsigned long long)KM_SS_SCAN_BEGIN, (unsigned long long)head);

    /* ---- 4. 槽扫描：本模块唯一的一级读循环。 ---- */
    /*
     * task+0x00 会在下面被再读一次（第 3 节已经读过它）。这是刻意的：「前置可读性」
     * 与「这个槽里是什么」是两个问题，复用同一个变量会让两处逻辑耦合，而代价只是
     * 每槽一次的复读开销 —— 窗口一共 32 个槽。
     */
    km_ss_append(&t, "== 4. slot scan: task+%#llx .. task+%#llx, step 8 (single-level reads only) "
                     "==\n",
                 (unsigned long long)KM_SS_SCAN_BEGIN,
                 (unsigned long long)(KM_SS_SCAN_END - 8));
    km_ss_append(&t, "each slot is printed as `raw <value> -> <value>`: the second value is the raw "
                     "read after km_unsign_ptr (PAC restore), and classification uses THAT value. The "
                     "restore only rewrites bits; it issues no read and dereferences nothing.\n");
    km_ss_append(&t, "read addresses in this section are `task + <compile-time constant>` only. No "
                     "value read here is ever used as an address, before or after the restore.\n");

    for (uint64_t off = KM_SS_SCAN_BEGIN; off < KM_SS_SCAN_END; off += 8) {
        if (UINT64_MAX - task < off) {
            /*
             * 守卫，正常内核对象地址到不了这里（task 高 16 位是 0xffff，加 0xf8 不会
             * 回绕）。真触发时窗口就是没走完，所以按 partial 报，不按 no_bsd_info 报。
             */
            scanAborted = true;
            km_ss_append(&t, "  task+%#llx would overflow the address -- scan stops here\n",
                         (unsigned long long)off);
            break;
        }
        const uint64_t addr = task + off;
        if (!km_ss_readable(addr)) {
            km_ss_append(&t, "  task+%#llx fails the shape gate -- not read\n",
                         (unsigned long long)off);
            continue;
        }

        bool ok = false;
        const uint64_t value = km_ss_read64(addr, &ok);

        if (g_scanBudgetHit) {
            /*
             * 预算把这个读切断了，所以这一槽**没有**被读到，不能算进 scannedSlots。
             * 半程扫描报成完整覆盖，是这份诊断里唯一能让结论看起来可信的记账错误。
             */
            km_ss_append(&t, "  read budget %llu exhausted at task+%#llx -- scan stops here\n",
                         (unsigned long long)KM_SS_READ_BUDGET, (unsigned long long)off);
            break;
        }
        scannedSlots++;
        if (!ok) {
            readFail++;
            km_ss_append(&t, "  task+%#llx read failed (two consecutive reads disagreed) -- not "
                             "treated as zero, not classified\n",
                         (unsigned long long)off);
            continue;
        }

        /*
         * PAC 还原 —— 必须在分类**之前**做，这是本次改动的第一件事。
         *
         * 内核结构里的指针字段带 PAC 签名，高 17 位是签名而不是地址，所以原始读数
         * 常常整片落在内核地址域之外。真机样本：task+0x28 的 raw 是 0x52bc7e10023e93c0
         * （高 16 位 0x52bc）。拿 raw 去跟 0xffff 比，只能得出「不在内核域」这一个
         * 结果；先还原再分类，才有资格说这个槽到底是什么。
         *
         * km_unsign_ptr 对内核地址幂等、对用户态地址会清高位，而这里处理的全是
         * 「刚从内核读出来的槽值」，正落在允许的那一侧（KernelSlide.h:162-177）。
         * 它**纯还原**：不读取、不解引用、不发 kread，所以零二级读那条铁律不受影响。
         *
         * raw 与 unsign 都留着：raw 进诊断（还原有没有生效要看得出来），unsign 进
         * 分类（这个槽到底是什么要判得准）。**两者都不参与任何地址运算** —— 本文件
         * 里没有任何一处把 value 或 unsign 当读目标，除了下面这个函数的入参地址
         * （它是 `task + <编译期常量>`，与任何读到的值无关）。
         */
        const uint64_t raw = value;
        const uint64_t unsign = km_unsign_ptr(raw);
        if (unsign != raw) {
            unsignChanged++;
            if (km_ss_is_kva(unsign)) {
                unsignLive++;
            }
        }

        /*
         * 分类，仅此而已。下面四个分支没有一个把还原后的值当地址再读一次 ——
         * 任何一级读之外的读都会把「未确认的地址」交给内核去解引用，那正是上一版
         * 真机 panic 的成因（证据见 KernelStructScan.h 与第 6 节）。
         */
        if (unsign == proc) {
            km_ss_append(&t, "  task+%#llx = raw %#llx -> %#llx  [== current_proc -> bsd_info]\n",
                         (unsigned long long)off, (unsigned long long)raw,
                         (unsigned long long)unsign);
            if (procCount < KM_SS_MAX_SLOTS) {
                procSlots[procCount].offset = off;
                procSlots[procCount].rawValue = raw;
                procSlots[procCount].value = unsign;
            }
            if (procCount == 0) {
                hitOffset = off;
            }
            procCount++;
            continue;
        }
        if (km_ss_is_kva(unsign)) {
            km_ss_append(&t, "  task+%#llx = raw %#llx -> %#llx  [kernel-domain value -- NOT "
                             "dereferenced]\n",
                         (unsigned long long)off, (unsigned long long)raw,
                         (unsigned long long)unsign);
            if (kvaCount < KM_SS_MAX_SLOTS) {
                kvaSlots[kvaCount].offset = off;
                kvaSlots[kvaCount].rawValue = raw;
                kvaSlots[kvaCount].value = unsign;
            }
            kvaCount++;
            continue;
        }
        if (km_ss_is_small_int(unsign)) {
            smallInts++;
            km_ss_append(&t, "  task+%#llx = raw %#llx -> %#llx  [small int]\n",
                         (unsigned long long)off, (unsigned long long)raw,
                         (unsigned long long)unsign);
            continue;
        }
        otherValues++;
        km_ss_append(&t, "  task+%#llx = raw %#llx -> %#llx  [other]\n",
                     (unsigned long long)off, (unsigned long long)raw,
                     (unsigned long long)unsign);
    }

    /* ---- 5. 结论。 ---- */
    km_ss_append(&t, "== 5. verdict ==\n");
    km_ss_append(&t, "slots scanned=%llu  read failures=%llu  kernel-domain values=%llu  "
                     "small ints=%llu  other=%llu%s\n",
                 (unsigned long long)scannedSlots, (unsigned long long)readFail,
                 (unsigned long long)kvaCount, (unsigned long long)smallInts,
                 (unsigned long long)otherValues,
                 (g_scanBudgetHit || scanAborted) ? "  [scan incomplete: results are PARTIAL]" : "");
    km_ss_append(&t, "slots == current_proc=%llu  values changed by km_unsign_ptr=%llu  of those, "
                     "landing in the kernel address domain=%llu\n",
                 (unsigned long long)procCount, (unsigned long long)unsignChanged,
                 (unsigned long long)unsignLive);

    if (g_scanBudgetHit || scanAborted) {
        /*
         * 窗口没走完。已经有槽命中也不能返回：命中数是窗口全体的性质，而窗口没走完。
         * 返回那个早就命中的偏移，等于把猜测包装成测量。
         */
        if (scanAborted) {
            km_ss_append(&t, "The scan stopped early on the address-overflow guard, so the window "
                             "was not fully walked and no offset is returned. This is NOT the same "
                             "as no_bsd_info: %llu slot(s) equalling current_proc were seen so far, "
                             "and the slots after the stop point were never read.\n",
                         (unsigned long long)procCount);
        } else {
            km_ss_append(&t, "Read budget exhausted before the window was fully walked, so this run "
                             "is PARTIAL and no offset is returned. This is NOT the same as "
                             "no_bsd_info: %llu slot(s) equalling current_proc were seen so far, and "
                             "the slots after the stop point were never read.\n",
                         (unsigned long long)procCount);
        }
        for (uint64_t i = 0; i < procCount && i < KM_SS_MAX_SLOTS; i++) {
            km_ss_append(&t, "  #%llu task+%#llx = %#llx\n", (unsigned long long)(i + 1),
                         (unsigned long long)procSlots[i].offset,
                         (unsigned long long)procSlots[i].value);
        }
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=partial (%llu slot(s) == current_proc so far, window not fully "
                 "walked)",
                 (unsigned long long)procCount);
    } else if (procCount == 0) {
        /*
         * 这一段只报一件事：这个窗口里没有槽等于 current_proc。**不**给上游的
         * proc -> task 推导下结论 —— 那条等式在上游成立（libkfd 两个方向都在用：
         * info.h:137 正方向，kread_sem_open.h:100-101 反方向），所以"没命中"只能
         * 是关于这个窗口的观测。第一行摘要里也必须写出来（面板只读第一行的人很多）。
         */
        km_ss_append(&t, "NO slot of struct task equals current_proc (%#llx) after km_unsign_ptr, "
                         "and %llu of the window's slots were read successfully.\n",
                     (unsigned long long)proc, (unsigned long long)scannedSlots);
        km_ss_append(&t, "  What that observation covers, exactly: struct task carries a reverse "
                         "pointer to its own struct proc (bsd_info), and within "
                         "task+0x00 .. task+0xF8 no slot holds current_proc. That is a statement "
                         "about THIS window on THIS run -- it is not a verdict on the derivation "
                         "task = proc + km_proc_object_size(), and this probe draws no such verdict.\n");
        km_ss_append(&t, "  Why the derivation is not the suspect: the upstream library uses that "
                         "same identity in BOTH directions and does not contradict itself -- "
                         "forward at libkfd/info.h:137 (current_task = current_proc + "
                         "dynamic_info(proc__object_size)) and backward at "
                         "libkfd/krkw/kread/kread_sem_open.h:100-101 (task_kaddr = static_kget("
                         "struct semaphore, owner, ...), then proc_kaddr = task_kaddr - "
                         "dynamic_info(proc__object_size)). Both directions in one library means the "
                         "identity is load-bearing upstream; nothing here says otherwise.\n");
        km_ss_append(&t, "  Candidates that would explain a miss, listed as candidates and not as "
                         "conclusions: the object_size taken from the version table does not match "
                         "this kernel; current_proc is stale by the time the window is walked; or "
                         "what sits at task+<bsd_info offset> is not a plain proc pointer on this "
                         "version. This probe reports the window; ranking those candidates is not "
                         "its job.\n");
        km_ss_append(&t, "  The restore ran: %llu of %llu slots changed value under km_unsign_ptr and "
                         "%llu of those landed in the kernel address domain. So no kernel-domain "
                         "reading was hidden by a missing PAC restore -- the values that were signed "
                         "were classified by their restored form.\n",
                     (unsigned long long)unsignChanged, (unsigned long long)scannedSlots,
                     (unsigned long long)unsignLive);
        km_ss_append(&t, "  Note what was NOT read: the vm_map pointer at the version table's "
                         "task__map offset (%#llx) points outside this window, so the probe never "
                         "followed it -- that is a second-level read and it stays deleted. The "
                         "offsets themselves are not the suspect either: task__map = %#llx is "
                         "confirmed by three independent sources -- Dopamine "
                         "BaseBin/libjailbreak/src/info.c:67 (`kernelStruct.task.map = 0x28`), "
                         "Dopamine Application/Exploits/kfd/kfd.m:175 (fed into the kfd table), and "
                         "this project's kfd/libkfd/info/dynamic_info.h (every entry says "
                         ".task__map = 0x0028).\n",
                     (unsigned long long)knownMapOff, (unsigned long long)knownMapOff);
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=no_bsd_info (no slot == current_proc in this window)");
    } else {
        km_ss_append(&t, "A slot of struct task equals current_proc: task+%#llx = %#llx (raw "
                         "%#llx -> %#llx under km_unsign_ptr).\n",
                     (unsigned long long)hitOffset, (unsigned long long)proc,
                     (unsigned long long)procSlots[0].rawValue, (unsigned long long)proc);
        km_ss_append(&t, "  That slot is struct task's bsd_info -- the reverse pointer to the "
                         "struct proc this task belongs to -- so the object at "
                         "proc + proc__object_size = %#llx carries a back-reference to this process, "
                         "which is the same direction libkfd/info.h:137 uses.\n",
                     (unsigned long long)task);
        km_ss_append(&t, "  Measured bsd_info offset = %#llx. Use it as bsd_info, nothing else.\n",
                     (unsigned long long)hitOffset);
        if (procCount > 1) {
            km_ss_append(&t, "%llu slots equal current_proc (all of them are listed in section 4; "
                             "the value returned is the LOWEST offset, %#llx). Nothing is hidden by "
                             "picking that one, but the \"exactly one bsd_info\" reading is not "
                             "confirmed by this run: a second slot holding the same proc would mean "
                             "this object carries two back-references.\n",
                         (unsigned long long)procCount, (unsigned long long)hitOffset);
        }
        km_ss_append(&t, "What this does NOT answer: the task->map offset. Measuring it requires "
                         "reading inside the candidate vm_map, which is the dereference class this "
                         "version no longer performs (see section 6).\n");
        km_ss_append(&t, "version table task__map = %#llx [reference only]: comparing it with the "
                         "measured bsd_info offset proves nothing -- bsd_info and map are different "
                         "fields, and an equality here would be a coincidence.\n",
                     (unsigned long long)knownMapOff);
        snprintf(summary, sizeof(summary),
                 "[structscan] STATE=hit_bsd_info offset=%#llx (bsd_info == current_proc)",
                 (unsigned long long)hitOffset);
    }

    /*
     * ---- 6. 落在内核地址域（还原之后）的槽：只列出，永不读取。 ----
     *
     * 这一节是写给下一个读这段代码的人看的：他会想知道"这些指针为什么不跟下去"。
     * 所以理由连着真机证据一起摆在这里，而不是只留一句"不安全"。
     */
    km_ss_append(&t, "== 6. kernel-domain slots: listed, never dereferenced ==\n");
    km_ss_append(&t, "a slot belongs here when its PAC-restored value falls in the kernel address "
                     "domain (top 16 bits 0xffff). The raw read is printed next to the restored value "
                     "so a signed read is never mistaken for a garbage one -- and neither form is ever "
                     "used as an address.\n");
    if (kvaCount == 0) {
        km_ss_append(&t, "none of the %llu scanned slots holds a kernel-domain value after "
                         "km_unsign_ptr\n",
                     (unsigned long long)scannedSlots);
    } else {
        km_ss_append(&t, "%llu slot(s) hold a kernel-domain value (top 16 bits 0xffff). They are "
                         "listed so the next reader sees exactly what was NOT followed:\n",
                     (unsigned long long)kvaCount);
        for (uint64_t i = 0; i < kvaCount && i < KM_SS_MAX_SLOTS; i++) {
            km_ss_append(&t, "  task+%#llx = raw %#llx -> %#llx  [not dereferenced]\n",
                         (unsigned long long)kvaSlots[i].offset,
                         (unsigned long long)kvaSlots[i].rawValue,
                         (unsigned long long)kvaSlots[i].value);
        }
        km_ss_append(&t, "Why not one of them is dereferenced -- on-device panic, not caution for "
                         "its own sake. The previous version of this probe read such a value as an "
                         "address and the whole device panicked:\n");
        km_ss_append(&t, "    esr = 0x96000007   (EC = 0b100101 data abort from the same EL; "
                         "DFSC = 0b000111 level-3 translation fault)\n");
        km_ss_append(&t, "    far = 0xfffffe1009577ffc   x8 = 0xfffffe1009577ff4   (far == x8 + 8)\n");
        km_ss_append(&t, "    Zone map: 0xfffffe10f10e4000 - 0xfffffe16f10e4000\n");
        km_ss_append(&t, "    Kernel text base: 0xfffffe0022084000\n");
        km_ss_append(&t, "    Panicked task: 3603 pages, 10 threads: pid 370: Music\n");
        km_ss_append(&t, "  The candidate was shaped like a kernel address but sat in a hole of "
                         "physmap. physmap maps real DRAM only: device MMIO, DRAM bank gaps and "
                         "firmware-reserved ranges have no physical page behind them, so the L2 "
                         "table covers that VA while the L3 entry does not exist -- which is exactly "
                         "what DFSC level-3 reports.\n");
        km_ss_append(&t, "  And our kread makes the KERNEL do the dereference: psemnode->pinfo is "
                         "repointed at the target address, then proc_info(PROC_INFO_CALL_PIDFDINFO) "
                         "reads the content back. An EL1 data abort is fatal by default -- only code "
                         "that registers a fault-recovery handler (copyin/copyout) turns a fault into "
                         "an error return, and this path is not that code.\n");
        km_ss_append(&t, "  Conclusion: under this kread path there is no safe form of \"read an "
                         "address I have not confirmed\", so second-level reads were deleted from "
                         "this module as a class. Do not reintroduce one. The PAC restore above is "
                         "not an exception to that rule: km_unsign_ptr rewrites bits and reads "
                         "nothing, so the restored value is printed and classified and never "
                         "followed.\n");
    }

done:
    /*
     * 这一条空语句不是装饰，**不能删**：C 的 labeled-statement 是
     * `identifier : statement`，而**声明不是语句**。标签后面先跟一个块注释、
     * 再跟 `char finalSummary[...]`，clang 在 C11（本项目用的 `-std=gnu11`）下会
     * 直接报 "expected expression" —— 本文件在 CI 上就挂在 645 行这一处。
     * 旧版标签后面挂的是 `(void)state;`，它本身就是一条语句，所以从没暴露过。
     */
    ;
    /*
     * 状态机的落地就是上面那几个 summary 赋值：每一个分支写一次，没有第二个写入点，
     * 所以不会出现"两个地方各写一遍、然后互相不一致"的那种旧毛病。这里没有额外的
     * state 变量：多个副本就是多个会漂移的真相。
     *
     * 截断与预算都是**限制**，不是结论，两者都不许读成一次干净的 no_bsd_info。
     * 结论在文本写完之前就已经得出、也不依赖文本，所以结论保留，限制折进第一行 ——
     * 只读摘要的消费者也能看到它。
     *
     * 与旧实现的区别：摘要不再是"覆盖第一行占位符"，而是"摘要行 + 正文"整体拼出。
     * 旧写法用 memcpy 往正文头部写摘要，而摘要比占位符
     * （"[structscan] STATE=running"，24 字节）长得多，于是每次都把正文开头几十字节
     * 覆盖掉，诊断第一段就消失了。拼接版本没有这个坑：两块各自限长，加起来仍小于
     * finalText 的容量。
     */
    char finalSummary[KM_SS_SUMMARY_MAX];
    snprintf(finalSummary, sizeof(finalSummary), "%s", summary);
    if (t.truncated || g_scanBudgetHit) {
        const size_t used = strlen(finalSummary);
        if (used + 96 < sizeof(finalSummary)) {
            snprintf(finalSummary + used, sizeof(finalSummary) - used, " (text %s, reads %s)",
                     t.truncated ? "truncated" : "complete",
                     g_scanBudgetHit ? "budget-limited" : "within budget");
        }
    }

    /*
     * 返回值只用于显式确认「这里不可能截断」这个前提：摘要小于 KM_SS_SUMMARY_MAX、
     * 正文小于 KM_SS_TEXT_SIZE，而 finalText 是两者之和 —— 万一常量被改坏，
     * written 会立刻超过缓冲，而 snprintf 仍保证写了终结符、不会越界。
     */
    const int written = snprintf(finalText, sizeof(finalText), "%s\n%s", finalSummary, body);
    (void)written;

    g_scanText = [NSString stringWithUTF8String:finalText];

    /*
     * 返回契约：等于 current_proc 的那个槽的偏移；0 表示「没有可用的偏移」。
     * 0 在这里是安全哨兵：窗口里偏移 0 是 task 的引用计数/状态字，不可能是
     * bsd_info；而且每一种退回 0 的情形都由一个 STATE 单独表达、不许互相冒充 ——
     * 见 KernelStructScan.h 的状态机一节。
     */
    if (procCount == 0 || g_scanBudgetHit || scanAborted) {
        return 0;
    }
    return hitOffset;
}

NSString *km_scan_diagnostic(void)
{
    if (g_scanText == nil) {
        return @"== struct scan ==\n"
                "not run yet. This probe performs SINGLE-LEVEL reads only: every read address is "
                "`task + <compile-time constant>`, no value it read is ever used as an address "
                "(before or after the km_unsign_ptr PAC restore, which itself reads nothing), and it "
                "issues no kernel writes at all.\n"
                "Call km_scan_task_map_offset() (or the panel button) to run it.\n";
    }
    return g_scanText;
}
