//
//  XpfKernelcacheProbe.m
//  Aether
//
//  职责：在把文件交给 XPF 之前，先确认「上游会走哪条分支、走不走得下去」。
//
//  为什么需要它（上游缺陷，源码不动，在这里挡）：
//    xpf_start_with_kernel_path() 的逻辑是：
//      · 文件头是 MH_MAGIC_64 或 FAT_CIGAM → 直接把 mmap 的内存包成 MemoryStream；
//      · 否则 → kdecompress()，成功才包成 MemoryStream，失败则 stream 保持 NULL；
//      · 不管哪种结果，接着都调用 fat_init_from_memory_stream(stream)，
//        而它会先 memory_stream_get_size(stream) → 解引用 NULL → 崩。
//    也就是说「不是 Mach-O 且解压失败」的文件会直接把 App 打崩。
//    kernelcache 是系统文件，正常不会走到那条路，但读取失败、文件被截断、
//    路径实际指向别的文件时都会。这里用**同一份** kdecompress() 先试一次，
//    并要求解压结果本身是 Mach-O：判定通过 ⟹ 上游内部走的是同一个分支、同样会成功。
//
//  代价：非 Mach-O 的 kernelcache（设备上的常态是 IMG4 封装）会被解压两遍，
//        多一次几十 MB 的临时分配（解压完立刻释放）。用一次性初始化换掉一条崩溃路径，值。
//
//  内存管理：本目录（Aether/libmemrw/xpf）在 project.yml 里单独带 -fobjc-arc。
//

#import "XpfKernelcacheProbe.h"

#import "../../libxpf/xpf/decompress.h"

#include <errno.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *string_from_errno(int err)
{
    return [NSString stringWithFormat:@"errno %d (%s)", err, strerror(err)];
}

/// 与上游 xpf.c 里那段 if 逐字对应的两个魔数：单片 Mach-O 与 fat 容器（都不需要解压）。
static bool is_macho_magic(uint32_t magic)
{
    return magic == MH_MAGIC_64 || magic == FAT_CIGAM;
}

static bool file_has_macho_header(int fd)
{
    uint32_t magic = 0;
    if (pread(fd, &magic, sizeof(magic), 0) != (ssize_t)sizeof(magic)) return false;
    return is_macho_magic(magic);
}

/// 用上游同一份 kdecompress() 试解压 IMG4 封装（LZSS / LZFSE 两条路都覆盖），
/// 并要求解压结果本身是 Mach-O —— 只看「解压成功」会漏掉「DER 结构合法但内容不是内核」
/// 的文件，那类文件进上游后会走到 macho_init 里啃垃圾数据。
static bool file_decompresses_to_macho(int fd, size_t fileSize)
{
    void *mappedFile = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mappedFile == MAP_FAILED) return false;

    size_t decompressedSize = 0;
    void *decompressedKernel = kdecompress(mappedFile, fileSize, &decompressedSize);

    bool looksLikeKernel = false;
    if (decompressedKernel && decompressedSize >= sizeof(uint32_t)) {
        uint32_t magic = 0;
        memcpy(&magic, decompressedKernel, sizeof(magic));
        looksLikeKernel = is_macho_magic(magic);
    }

    free(decompressedKernel); // free(NULL) 合法
    munmap(mappedFile, fileSize);
    return looksLikeKernel;
}

/// fd 已经打开：判定形态并组装失败原因。
static bool loadable_kernelcache_fd(int fd, NSString **outReason)
{
    struct stat fileInfo;
    if (fstat(fd, &fileInfo) != 0) {
        *outReason = [NSString stringWithFormat:@"fstat failed (%@)", string_from_errno(errno)];
        return false;
    }
    if (fileInfo.st_size <= 0) {
        *outReason = @"empty file";
        return false;
    }
    if (file_has_macho_header(fd)) return true;
    if (file_decompresses_to_macho(fd, (size_t)fileInfo.st_size)) return true;

    *outReason = @"neither a Mach-O nor an IMG4 kernelcache that unpacks to one";
    return false;
}

bool km_xpf_kernelcache_is_loadable(NSString *path, NSString **outReason)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) {
        *outReason = [NSString stringWithFormat:@"open failed (%@)", string_from_errno(errno)];
        return false;
    }

    bool loadable = loadable_kernelcache_fd(fd, outReason);
    close(fd);
    return loadable;
}
