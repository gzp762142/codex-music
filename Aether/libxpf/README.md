# Aether/libxpf —— XPF（XNU Patch Finder）源码快照

本目录是**第三方源码快照**，用于让 Aether 在运行时从设备上的 kernelcache 解析内核符号。
目录内所有上游文件**逐字节保持原样**（未做任何修改），升级方式就是整目录覆盖。

## 来源与版本（快照取证）

| 组件 | 上游 | 快照 commit |
| --- | --- | --- |
| XPF 主体 | https://github.com/opa334/XPF | `9e12b8faa7444f6fe7f699aec6b6c96d151455d3`（"Fix some metrics not working on higher versions of iOS 26 and on iOS 27 betas"） |
| ChOma（Mach-O 解析） | https://github.com/opa334/ChOma | `7dccded6bc17081c08f5f5cdbd7a4b051543a825` |
| img4lib（IMG4/LZSS/LZFSE/DER） | https://github.com/xerub/img4lib | `69772c72f3c08f021ec9fa4c386f2b3df60a38b7`（1.0-7-g69772c7） |

本地克隆来源：`D:\工作区\_Aether_rev\xpf_src`（含 `external/ChOma`、`external/img4lib` 子模块）。
复制时逐个 SHA256 比对过，74 个文件全部与上游一致。

## 目录结构（以及为什么这样切）

```
libxpf/
├── xpf/                 ← 上游 src/*.{c,h}，不含 cli/（cli/main.c 自带 main()，不能进 App target）
├── choma/               ← 上游 ChOma/src/*（.c 与 .h 同目录，与上游完全一致）
│                           上游把 include/choma 做成指向 ../src 的符号链接，Windows 检出会把
│                           它退化成 6 字节文本文件，所以这里直接照上游原意把 .h 与 .c 放一起，
│                           让 `<choma/Fat.h>` 与 ChOma 源码里的 `"Fat.h"` 都能解析。
├── img4lib/             ← 上游 lzss.c/h、libvfs/*、libDER/*
└── README.md            ← 本文件（不进 App bundle，见 project.yml 的 excludes）
```

`-I` 搜索根（见 `project.yml`）：

- `$(SRCROOT)/Aether/libxpf` → 解析 `<choma/...>`、`"choma/PatchFinder.h"`（`non_ppl.c` 用了引号形式）
- `$(SRCROOT)/Aether/libxpf/img4lib` → 解析 `<libvfs/vfs.h>`、`<libDER/...>`、`"lzss.h"`

## 编译宏（必须逐字保留，否则行为不同）

来自上游 `Makefile` 的 `IMG4LIB_CFLAGS`，经 `project.yml` 的 per-source `compilerFlags` 只作用于本目录：

```
-DUSE_COMMONCRYPTO -DUSE_LIBCOMPRESSION -DiOS10
-DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8
-Wno-variadic-macros -Wno-multichar -Wno-four-char-constants -Wno-unused-parameter
```

- `-DUSE_COMMONCRYPTO`：`libvfs/vfs_img4.c` / `vfs_enc.c` 走 Apple CommonCrypto，而不是 corecrypto 或 OpenSSL。
  上游 `external/img4lib/corecrypto/` 是 Apple 私有代码被摘除后的占位文件（39 字节），**不可用**，所以这条路本来就必须走 CommonCrypto。
- `-DUSE_LIBCOMPRESSION`：`libvfs/vfs_lzfse.c` 用 `libcompression` 的 `compression_decode_buffer`，
  因此**不需要**编译 `external/img4lib/lzfse/`（那份源码含 `lzfse_main.c`，带 `main()`，编进来会撞 App 的 main）。
- `-DiOS10`：`vfs_img4.c` 里 IM4P/KOMP 结构体布局依赖它。
- `-D__unused=...`（上游 Makefile 里有）：**故意不加**。Darwin 的 `<sys/cdefs.h>` 已经定义 `__unused`，
  命令行再定义一次是重复定义（`libDER/oids.c` 就在用 `__unused`）。上游加它只是为了兼容非 Darwin 平台。

## 不参与编译的上游文件

| 文件 | 原因 |
| --- | --- |
| `img4lib/libvfs/vfs_lzvn.c` | 上游 `IMG4LIB_DEP` 用 `filter-out` 明确排除；它还 `#include "LZVN/FastCompression.h"`，该头在本快照内不存在。`project.yml` 里用 `excludes` 排除。 |
| `img4lib/libvfs/*` 之外的 `img4.c` / `img4test.c` | 未复制：CLI 工具，带 `main()`。 |
| `xpf/cli/` | 未复制：带 `main()`。 |
| `README.md`（本文件） | 被 `project.yml` 的 `excludes` 排除，避免被当作资源复制进 App bundle。 |

## 链接依赖

- `libcompression`（`decompress.c` 的 `compression_decode_buffer`、`vfs_lzfse.c`）→ `project.yml` 的 `OTHER_LDFLAGS: -lcompression`
- `Security.framework`（`vfs_img4.c` 的 `SecKey`/`SecItem`）
- `Foundation`（XPF 上游 Makefile 显式链接；`xpf/xpf.c` 走 ChOma，ChOma 用 CoreFoundation）
- `xpc`：`xpf/xpf.h` `#include <xpc/xpc.h>`，`xpf_construct_offset_dictionary()` 用 `xpc_*`。
  上游 iOS dylib 构建没有显式 `-lxpc`，libSystem 会 re-export libxpc，因此本工程同样不显式链接。
  若将来 CI 出现 `_xpc_dictionary_create_empty` 之类的 undefined symbol，在 `OTHER_LDFLAGS` 补 `-lxpc`。

## 升级步骤

1. 在 `D:\工作区\_Aether_rev\xpf_src` 拉新 commit，`git submodule update --init --recursive`。
2. 按上面的目录结构整目录覆盖（注意 `choma` 头文件要重新拆到 `include/choma/`）。
3. 对比上游 `Makefile` 的 `IMG4LIB_CFLAGS` / `IMG4LIB_DEP` / `LDFLAGS` 是否有变化，同步 `project.yml`。
4. 更新本文件顶部的 commit 表。

## 已知风险（详见 `_Aether_rev/_rev/XPF集成/报告.md`）

- `xpf_start_with_kernel_path()` 内部若 `kdecompress()` 失败会得到 `MemoryStream *stream == NULL`，
  紧接着 `fat_init_from_memory_stream(NULL)` → `memory_stream_get_size(NULL)` 解引用空指针。
  这是上游的缺陷，**未修改上游**；`XpfBridge.m` 在调用前用同一份 `kdecompress()` 做预检把这条路径堵掉。
- 本目录代码只做「解析 kernelcache 取符号」，不碰 Aether 现有 `KernelMemory.m` 的读写路径。
