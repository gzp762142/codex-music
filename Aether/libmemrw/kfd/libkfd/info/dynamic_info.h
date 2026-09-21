/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef dynamic_info_h
#define dynamic_info_h

struct dynamic_info {
    const char* kern_version;
    bool kread_kqueue_workloop_ctl_supported;
    bool perf_supported;
    // struct proc
    u64 proc__p_list__le_prev;
    u64 proc__p_pid;
    u64 proc__p_fd__fd_ofiles;
    u64 proc__object_size;
    // struct task
    u64 task__map;
    // struct thread
    u64 thread__thread_id;
    // struct IOSurface (kread_IOSurface 后端)
    u64 ios__IndexedTimestampPtr;    // 写路径：改成目标内核地址（样本实测 0x14）
    u64 ios__AllocSize;              // search 判据之一
    u64 ios__PixelFormat;            // search 判据：== IOSURFACE_MAGIC
    u64 ios__UseCountPtr;
    u64 ios__ReadDisplacement;
    // kernelcache static addresses (perf)
    u64 kernelcache__cdevsw;                          // "spec_open type" or "Can't mark ptc as kqueue ok"
    u64 kernelcache__gPhysBase;                       // "%s: illegal PA: 0x%llx; phys base 0x%llx, size 0x%llx"
    u64 kernelcache__gPhysSize;                       // (gPhysBase + 0x8)
    u64 kernelcache__gVirtBase;                       // "%s: illegal PA: 0x%llx; phys base 0x%llx, size 0x%llx"
    u64 kernelcache__perfmon_dev_open;                // "perfmon: attempt to open unsupported source: 0x%x"
    u64 kernelcache__perfmon_devices;                 // "perfmon: %s: devfs_make_node_clone failed"
    u64 kernelcache__ptov_table;                      // "%s: illegal PA: 0x%llx; phys base 0x%llx, size 0x%llx"
    u64 kernelcache__vn_kqfilter;                     // "Invalid knote filter on a vnode!"
};

const struct dynamic_info kern_versions[] = {
    /*
     * Match keys are prefixes, not full banners: info_init() compares the
     * first 29 characters of sysctlbyname("kern.version"), which is exactly
     * "Darwin Kernel Version <major>.<minor>.<patch>". A key therefore only
     * has to carry the Darwin number it represents - the date, xnu build and
     * SoC suffix that follow are never read. Banner text that *is* written
     * out below is the real thing, left in as documentation of where the
     * numbers came from.
     *
     * There is no catch-all entry: the old claim that a line such as "22.0.0"
     * answers for every Darwin 22 banner is wrong under this comparison.
     * "Darwin Kernel Version 22.0.0" and "…22.1.0" diverge at index 24 (the
     * '0' of the minor), well inside the 29 characters that are compared, and
     * strncmp does not stop early at the shorter key's NUL - it compares the
     * full 29 characters (verified in tools/verify_dynamic_info.py section 5).
     * A 22.0.0 key therefore matches nothing but 22.0.x. Every Darwin minor
     * needs an entry of its own: a banner with no entry matches nothing, and
     * info_init() rejects the device instead of silently falling back to a
     * neighbouring version's offsets.
     *
     * The kernelcache__* fields are deliberately nil: this build resolves the
     * kernel base by scanning (see KernelMemory.c), not by reading perf's
     * static address table, so nothing here has to track kernelcache layouts.
     */
    {
        // iOS 15.x - Darwin 21
        /*
         * 注意结尾那个 ':' —— 它不是装饰。
         *
         * info_init / km_version_is_listed 都按 kfd_version_prefix_length = 29
         * 比较（29 = strlen("Darwin Kernel Version 22.5.0:")），而真实 banner 是
         * "Darwin Kernel Version 21.0.0: <date>; ..."。如果这里只写
         * "Darwin Kernel Version 21.0.0"（28 字符），strncmp 会比到第 29 位时
         * 拿 '\0' 对 ':'，判定不等 —— 这条就永远命不中，兜底作用完全失效。
         */
        .kern_version = "Darwin Kernel Version 21.0.0:",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0700,
        .task__map = 0x0028,
        .thread__thread_id = 0,
        /*
         * ios__* 五个偏移：与 iOS 16 那几条用的是同一套值 —— 这不是巧合。
         *
         * 权威来源是 opa334/kfd 的 info/dynamic_types/IOSurface.h，它对
         * iOS 14.0–14.8.1 / 15.0–15.1.1 / 15.2–15.3.1 / 15.4–15.7.8 逐段列出了
         * IOSurface 的布局，**每一段都是同一组值**：
         *     PixelFormat = 0xA4, AllocSize = 0xAC, UseCountPtr = 0xC0,
         *     IndexedTimestampPtr = 0x360, ReadDisplacement = 0x14
         * （同一文件里 iOS 16 那几项是空的，注释写着 "left to the educated
         *   reader to figure out ... only work on arm64" —— 也就是说 IOSurface
         *   布局本身没变，变的是读原语，这也是本工程 iOS 16 走 sem_open 的原因。）
         *
         * 所以这里原本全填 0 是**缺漏**，不是"没有数据可填"。
         */
        .ios__IndexedTimestampPtr = 0x360,
        .ios__AllocSize = 0xac,
        .ios__PixelFormat = 0xa4,
        .ios__UseCountPtr = 0xc0,
        .ios__ReadDisplacement = 0x14,
        .kernelcache__cdevsw = 0,
        .kernelcache__gPhysBase = 0,
        .kernelcache__gPhysSize = 0,
        .kernelcache__gVirtBase = 0,
        .kernelcache__perfmon_dev_open = 0,
        .kernelcache__perfmon_devices = 0,
        .kernelcache__ptov_table = 0,
        .kernelcache__vn_kqfilter = 0,
    },
    /*
     * iOS 16.1 / 16.2 / 16.3 —— Darwin 22.1 / 22.2 / 22.3
     *
     * 为什么是三条而不是一条兜底：info_init 只比前 29 字符，
     * "Darwin Kernel Version 22.0.0:" 与 "…22.1.0:" 在第 25 位（'0' vs '1'）
     * 就分了 —— 一个 22.0.0 的 key 谁也替不了。表头那句
     * "22.0.0 answers for every Darwin 22 banner" 在这个匹配口径下不成立。
     * （回归验证见 tools/verify_dynamic_info.py 第 5、6 节。）
     *
     * 偏移取自公开设备表（camenling/SimpleKFDTrollStore 的 dynamic_info.h）：
     *   proc__object_size：22.1.0 = 0x530（1 条目）；22.2.0 / 22.3.0 = 0x538
     *                      （分别 19 / 41 个设备条目一致）。22.4.0 起才跳到 0x730。
     *   这一点必须守住：kread_sem_open_find_proc 里
     *       proc_kaddr = task_kaddr - dynamic_info(proc__object_size)
     *   拿 0x730 去算 22.1–22.3 会偏 0x200，得到的不是真正的 struct proc。
     *   proc__p_fd__fd_ofiles：22.1.0 与 22.4.0 实测都是 0xf8；22.2/22.3 在公开表里
     *   是空值，这里沿用 0xf8（p_fd 是 proc 内字段位置，不随 object_size 变）。
     *
     * 没有 Darwin 22.0.0（iOS 16.0）条目：公开表里查不到它的偏移。
     * 宁可不支持，也不用 22.4 的值去顶 —— 那会匹配上、然后用错偏移，
     * 比"干净拒绝"难查得多。
     */
    {
        // iOS 16.1 - Darwin 22.1.0
        .kern_version = "Darwin Kernel Version 22.1.0:",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0530,
        .task__map = 0x0028,
        .thread__thread_id = 0,
        .ios__IndexedTimestampPtr = 0x360,
        .ios__AllocSize = 0xac,
        .ios__PixelFormat = 0xa4,
        .ios__UseCountPtr = 0xc0,
        .ios__ReadDisplacement = 0x14,
        .kernelcache__cdevsw = 0,
        .kernelcache__gPhysBase = 0,
        .kernelcache__gPhysSize = 0,
        .kernelcache__gVirtBase = 0,
        .kernelcache__perfmon_dev_open = 0,
        .kernelcache__perfmon_devices = 0,
        .kernelcache__ptov_table = 0,
        .kernelcache__vn_kqfilter = 0,
    },
    {
        // iOS 16.2 - Darwin 22.2.0
        .kern_version = "Darwin Kernel Version 22.2.0:",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0538,
        .task__map = 0x0028,
        .thread__thread_id = 0,
        .ios__IndexedTimestampPtr = 0x360,
        .ios__AllocSize = 0xac,
        .ios__PixelFormat = 0xa4,
        .ios__UseCountPtr = 0xc0,
        .ios__ReadDisplacement = 0x14,
        .kernelcache__cdevsw = 0,
        .kernelcache__gPhysBase = 0,
        .kernelcache__gPhysSize = 0,
        .kernelcache__gVirtBase = 0,
        .kernelcache__perfmon_dev_open = 0,
        .kernelcache__perfmon_devices = 0,
        .kernelcache__ptov_table = 0,
        .kernelcache__vn_kqfilter = 0,
    },
    {
        // iOS 16.3 - Darwin 22.3.0
        .kern_version = "Darwin Kernel Version 22.3.0:",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0538,
        .task__map = 0x0028,
        .thread__thread_id = 0,
        .ios__IndexedTimestampPtr = 0x360,
        .ios__AllocSize = 0xac,
        .ios__PixelFormat = 0xa4,
        .ios__UseCountPtr = 0xc0,
        .ios__ReadDisplacement = 0x14,
        .kernelcache__cdevsw = 0,
        .kernelcache__gPhysBase = 0,
        .kernelcache__gPhysSize = 0,
        .kernelcache__gVirtBase = 0,
        .kernelcache__perfmon_dev_open = 0,
        .kernelcache__perfmon_devices = 0,
        .kernelcache__ptov_table = 0,
        .kernelcache__vn_kqfilter = 0,
    },
    /*
     * iOS 16.4.1 - Darwin 22.4.0
     *
     * 偏移取自 Lrdsnow/kfd_offsets 的 M1/iOS_16.4.1 表，与上面 22.5.0 那条逐字段
     * 核对过：proc__object_size 0x730、task__map 0x28、proc__p_pid 0x60、
     * proc__p_fd__fd_ofiles 0xf8、proc__p_list__le_prev 0x0008 完全一致 ——
     * 16.4 与 16.5 之间这些结构没动。IOSurface 布局同属 iOS 16 世代，也一致。
     *
     * 四份 16.4.1 表（A14/A15/A16/M1）的 xnu 构建号都是 8796.102.5~1，只差
     * RELEASE_ARM64_T8101/T8110/T8112/T8120 这个 SoC 后缀。而 info_init() 只比
     * 前 29 字符，所以一条就覆盖全部芯片。
     *
     * kernelcache__* 按本表开头的约定留 0：本工程靠扫描找内核基址，不读 perf 的
     * 静态地址表。
     *
     * 因此 perf_supported 必须是 false —— perf_run() 的唯一守卫就是它，
     * 一旦为 true 就会拿这些 0 去算：
     *     kernel_slide = vn_kqfilter - kernelcache__vn_kqfilter   // 减 0
     *     kernel_base  = ARM64_LINK_ADDR + kernel_slide          // 回绕成非法地址
     *     kread_sem_open_kread_u32(kfd, kernel_base)             // 打在未映射内核地址上
     * 然后在 kopen 内部失败。而 kopen 的顺序是
     *     puaf_run → krkw_run → info_run → perf_run → puaf_cleanup
     * perf_run 一失败，puaf_cleanup 就被跳过 —— 那正是 "VMSEL: INSERT FAILED
     * @vm_map_store_rb.c:99" 的成因（vm_map 带着未清理的 PUAF 残留被后续操作踩中）。
     *
     * 对照：22.5.0 / 22.6.0 两条是 perf_supported = true 且 kernelcache__* 全部填值
     * （各 8 项非零）。true 与"留 0"不能并存，这条曾经两者兼有，是个错误。
     */
    {
        // iOS 16.4.1 - Darwin 22.4.0
        .kern_version = "Darwin Kernel Version 22.4.0: Mon Mar  6 20:42:59 PST 2023; root:xnu-8796.102.5~1/RELEASE_ARM64_T8101",
        .kread_kqueue_workloop_ctl_supported = false,
        /* 见上方说明：kernelcache__* 全为 0，所以这里必须 false。 */
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0730,
        .task__map = 0x0028,
        /*
         * 0x418，不是 0。
         *
         * 取自公开设备表里 iPad Pro (T8112) / iOS 16.4.1 (20E252) 的条目
         * （camenling/SimpleKFDTrollStore 的 dynamic_info.h），与之交叉核对一致。
         * 早先留 0 是缺值：它唯一的消费者是 kread_kqueue_workloop_ctl，而该后端
         * 被 kread_kqueue_workloop_ctl_supported = false 禁掉，所以这个 0 一直
         * 没暴露；但数据本身该是准的，免得日后启用该后端时踩到。
         */
        .thread__thread_id = 0x418,
        .ios__IndexedTimestampPtr = 0x360,
        .ios__AllocSize = 0xac,
        .ios__PixelFormat = 0xa4,
        .ios__UseCountPtr = 0xc0,
        .ios__ReadDisplacement = 0x14,
        .kernelcache__cdevsw = 0,
        .kernelcache__gPhysBase = 0,
        .kernelcache__gPhysSize = 0,
        .kernelcache__gVirtBase = 0,
        .kernelcache__perfmon_dev_open = 0,
        .kernelcache__perfmon_devices = 0,
        .kernelcache__ptov_table = 0,
        .kernelcache__vn_kqfilter = 0,
    },
    // iOS 16.5 - iPhone 14 Pro Max
    {
        .kern_version = "Darwin Kernel Version 22.5.0: Mon Apr 24 21:09:28 PDT 2023; root:xnu-8796.122.4~1/RELEASE_ARM64_T8120",
        .kread_kqueue_workloop_ctl_supported = false,
        /*
         * perf_supported = false：kernelcache__* 全为 0。
         *
         * 原本这两条（22.5.0 / 22.6.0）填了 8 项 kernelcache 静态地址并把
         * perf_supported 置 true，但那些地址只对注释里声明的那一个机型保证
         * （16.5 = iPhone 14 Pro Max / T8120，16.6 = iPhone 12 Pro / T8101），
         * 而版本匹配只看 Darwin 前缀 —— 于是该版本下【所有】设备都会套用这一份
         * 偏移。perf_run 拿它去算 kernel slide / kernel base，一旦不符就在
         * perf.h:114 的 kread 上打在错误或未映射的内核地址。
         *
         * 对面向多机型的发布版，这个不确定性远大于 perf 的收益：perf 只是把
         * kread 从"半随机游走"升级成高效物理读写，并不是功能必需；而 kernel base
         * 本来就可以靠扫描拿到（KernelMemory.m 的 km_scan_kernel_base）。
         * 因此全表统一：kernelcache__* 留 0，perf_supported = false。
         */
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0730,
        .task__map = 0x0028,
        .thread__thread_id = 0,
        .ios__IndexedTimestampPtr = 0x360,
        .ios__AllocSize = 0xac,
        .ios__PixelFormat = 0xa4,
        .ios__UseCountPtr = 0xc0,
        .ios__ReadDisplacement = 0x14,
        .kernelcache__cdevsw = 0,
        .kernelcache__gPhysBase = 0,
        .kernelcache__gPhysSize = 0,
        .kernelcache__gVirtBase = 0,
        .kernelcache__perfmon_dev_open = 0,
        .kernelcache__perfmon_devices = 0,
        .kernelcache__ptov_table = 0,
        .kernelcache__vn_kqfilter = 0,
    },
    // iOS 16.6 - iPhone 12 Pro
    // 注意：该区间设备若要跑 T1SZ_BOOT=25 的芯片，需要另见 t1sz 的按设备取值问题。
    {
        .kern_version = "Darwin Kernel Version 22.6.0: Wed Jun 28 20:50:15 PDT 2023; root:xnu-8796.142.1~1/RELEASE_ARM64_T8101",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0730,
        .task__map = 0x0028,
        .thread__thread_id = 0,
        .ios__IndexedTimestampPtr = 0x360,
        .ios__AllocSize = 0xac,
        .ios__PixelFormat = 0xa4,
        .ios__UseCountPtr = 0xc0,
        .ios__ReadDisplacement = 0x14,
        .kernelcache__cdevsw = 0,
        .kernelcache__gPhysBase = 0,
        .kernelcache__gPhysSize = 0,
        .kernelcache__gVirtBase = 0,
        .kernelcache__perfmon_dev_open = 0,
        .kernelcache__perfmon_devices = 0,
        .kernelcache__ptov_table = 0,
        .kernelcache__vn_kqfilter = 0,
    },
};

#endif /* dynamic_info_h */
