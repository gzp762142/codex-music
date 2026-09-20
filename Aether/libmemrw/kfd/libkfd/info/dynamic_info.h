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
     * Entries run oldest first so a line such as "22.0.0" answers for every
     * Darwin 22 banner that no later entry claims.
     *
     * The kernelcache__* fields are deliberately nil: this build resolves the
     * kernel base by scanning (see KernelMemory.c), not by reading perf's
     * static address table, so nothing here has to track kernelcache layouts.
     */
    {
        // iOS 15.x - Darwin 21
        .kern_version = "Darwin Kernel Version 21.0.0",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0700,
        .task__map = 0x0028,
        .thread__thread_id = 0,
        .ios__IndexedTimestampPtr = 0,
        .ios__AllocSize = 0,
        .ios__PixelFormat = 0,
        .ios__UseCountPtr = 0,
        .ios__ReadDisplacement = 0,
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
        // iOS 16.0 - 16.4.1 - Darwin 22.0 ... 22.4
        // Verified on an Apple silicon iPad Pro running iOS 16.4.1 (t8112).
        .kern_version = "Darwin Kernel Version 22.0.0",
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
     */
    {
        // iOS 16.4.1 - Darwin 22.4.0
        .kern_version = "Darwin Kernel Version 22.4.0: Mon Mar  6 20:42:59 PST 2023; root:xnu-8796.102.5~1/RELEASE_ARM64_T8101",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = true,
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
    // iOS 16.5 - iPhone 14 Pro Max
    {
        .kern_version = "Darwin Kernel Version 22.5.0: Mon Apr 24 21:09:28 PDT 2023; root:xnu-8796.122.4~1/RELEASE_ARM64_T8120",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = true,
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
        .kernelcache__cdevsw = 0xfffffff00a419208,
        .kernelcache__gPhysBase = 0xfffffff007934010,
        .kernelcache__gPhysSize = 0xfffffff007934018,
        .kernelcache__gVirtBase = 0xfffffff0079321e8,
        .kernelcache__perfmon_dev_open = 0xfffffff007eecfc0,
        .kernelcache__perfmon_devices = 0xfffffff00a457500,
        .kernelcache__ptov_table = 0xfffffff0078e7178,
        .kernelcache__vn_kqfilter = 0xfffffff007f39b28,
    },
    // iOS 16.6 - iPhone 12 Pro
    // T1SZ_BOOT must be changed to 25 instead of 17
    {
        .kern_version = "Darwin Kernel Version 22.6.0: Wed Jun 28 20:50:15 PDT 2023; root:xnu-8796.142.1~1/RELEASE_ARM64_T8101",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = true,
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
        .kernelcache__cdevsw = 0xfffffff00a4a5288,
        .kernelcache__gPhysBase = 0xfffffff0079303b8,
        .kernelcache__gPhysSize = 0xfffffff0079303c0,
        .kernelcache__gVirtBase = 0xfffffff00792e570,
        .kernelcache__perfmon_dev_open = 0xfffffff007ef4278,
        .kernelcache__perfmon_devices = 0xfffffff00a4e5320,
        .kernelcache__ptov_table = 0xfffffff0078e38f0,
        .kernelcache__vn_kqfilter = 0xfffffff007f42f40,
    },
    // macOS 13.4 - MacBook Air (M2, 2022)
    {
        .kern_version = "todo",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0778,
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
    // macOS 13.5 - MacBook Air (M2, 2022)
    {
        .kern_version = "Darwin Kernel Version 22.6.0: Wed Jul  5 22:17:35 PDT 2023; root:xnu-8796.141.3~6/RELEASE_ARM64_T8112",
        .kread_kqueue_workloop_ctl_supported = false,
        .perf_supported = false,
        .proc__p_list__le_prev = 0x0008,
        .proc__p_pid = 0x0060,
        .proc__p_fd__fd_ofiles = 0x00f8,
        .proc__object_size = 0x0778,
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
