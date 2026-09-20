//
//  KernelRW.h
//  内核读写通道 —— 复刻样本的 IOKit / IOSurface 数据通路。
//
//  与 KernelMemory 的分工（对齐样本）：
//     KernelMemory  经 libkfd 的 kopen 建立内核读写原语（PUAFF → KRKW），
//                   并负责地址翻译（pid → proc → task → vm_map → pmap → 页表）。
//     KernelRW      经 IOSurfaceRoot 的 user client 构造/定位 IOSurface 对象，
//                   提供 kread / kwrite 的落笔通道。
//
//  样本实测（见 _kfd_port/physrw追索记录.md §4 与交叉验证报告）：
//     init      IOServiceMatching("IOSurfaceRoot") → IOServiceGetMatchingService
//               → IOServiceOpen(master, service, 0, &conn)
//     allocate  IOConnectCallMethod(conn, selector=6, ...) 建 IOSurface，
//               fds[id] = { conn, surface_id }
//     search    在全局哈希表上探测，命中 0x1EA5CACE 哨兵即认自己的对象
//     kread     改 object_uaddr 指向目标地址后 syscall(336) 取回数据
//
#ifndef KernelRW_h
#define KernelRW_h

#include <stdbool.h>
#include <stdint.h>

/// 建立 IOSurfaceRoot 连接。成功返回 true。
bool krw_init(void);

/// 释放连接与对象表。
void krw_deinit(void);

/// 通道是否可用。
bool krw_ready(void);

/// 读内核地址一段数据。
bool krw_read(uint64_t kaddr, void *out, uint64_t len);

/// 写内核地址一段数据（len 须为 8 的倍数）。
bool krw_write(uint64_t kaddr, const void *in, uint64_t len);

#endif /* KernelRW_h */
