//
//  KernelRW.h
//  通道决策记录 —— 为什么本工程不再单独实现一条 IOSurface 数据通道。
//
//  背景（2026-05 复核）：
//     早先版本的本文件声明过 krw_init/krw_read/krw_write 一套 IOSurface 通道，
//     依据是「样本数据通道 = pipe() + IOSurfaceRoot 的 IOKit user client」。
//     该依据来自错位的反汇编结果（__text 的 fileoff 少算了 0x4000），已作废。
//
//  正确偏移下的样本实测：
//     1) kfd 的 kread 后端 = kread_sem_open。
//        - 单字读 0x100F7B8C4：memset(sp+0x48, 0, 0x4a0)
//                             → syscall(0x150, 3, 4, fd, sp+0x48, 0x4a0)
//                             → cmp w0, #0x4a0
//                             → 读 [sp+0x70]
//          即 syscall(SYS_proc_info=336, PROC_INFO_CALL_PIDFDINFO, pid,
//                     PROC_PIDFDPSEMINFO, fd, buffer, sizeof(struct psem_fdinfo))。
//        - pinfo 写入口 0x100F7B914：sub x8, x1, #0xc  →  offsetof(pseminfo, psem_uid)。
//        - ops.kread 守卫 0x100F8BB3C：cmp [kfd+0x470], 0x100F7B828。
//     2) kwrite 与 kread 共用同一份 sem_open 对象（kwrite_sem_open 转发 kwrite_dup）。
//     3) IOServiceOpen / IOConnectCallMethod 虽在导入表内，但全样本 bl 调用点 0 命中。
//        （本样本 LC_DYSYMTAB.indirectsymoff = 0，间接符号表已剥离，
//          不可用 reserved1 反查符号名，只能靠反汇编形态反推。）
//
//  结论：KernelMemory.m 现有的 kread_sem_open + kwrite_sem_open 组合就是样本的组合。
//        没有需要补的 IOSurface 通道，本文件因此只保留这段溯源记录，不再声明接口。
//
#ifndef KernelRW_h
#define KernelRW_h

#endif /* KernelRW_h */
