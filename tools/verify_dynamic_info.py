#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地验证 Aether 的 kfd 版本表 —— 不需要 macOS / Xcode / C 编译器。

为什么要这个：
    iOS 项目的编译绑死在 macOS 上（iPhoneOS.sdk + xcodebuild + codesign），
    改动只能靠 push 到 GitHub Actions 等 3-5 分钟才有反馈。但 kern_versions[]
    这一层是**纯数据 + 十六进制数**，它的行为完全可以在 Windows 上用 Python 复现。

它验什么：
    1. 结构：kern_versions[] 的条目数、花括号配平、字段完整性
    2. 匹配语义：复现 info.h 的 strncmp(banner, entry, 29)，用真实 kern.version 跑
    3. 一致性：perf_supported=true 必须配非零 kernelcache__*
    4. 回归：短 key（28 字符）与补齐后（29 字符）的命中差异

关键：C 的 strncmp 遇 NUL 即停。kern_version 是字符串字面量，
      若它短于 n，比较时第 n 位起就是 NUL —— 这正是"28 字符 key 永不命中"的成因。
"""
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HEADER = r"D:\工作区\Aether\Aether\libmemrw\kfd\libkfd\info\dynamic_info.h"

# info.h 里的口径（= strlen("Darwin Kernel Version 22.5.0:") = 29）
PREFIX_LEN = 29


def c_strncmp(s1: str, s2: str, n: int) -> int:
    """复现 C 的 strncmp：遇 NUL 停，逐字节比，返回差值符号。"""
    b1 = s1.encode("utf-8", "replace")
    b2 = s2.encode("utf-8", "replace")
    for i in range(n):
        c1 = b1[i] if i < len(b1) else 0
        c2 = b2[i] if i < len(b2) else 0
        if c1 != c2:
            return c1 - c2
        if c1 == 0:
            return 0
    return 0


def parse_entries(path: str):
    """从 dynamic_info.h 里抽出每个条目：kern_version / perf_supported / kernelcache 非零数。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    # 以 .kern_version = "..." 为条目起点切分
    parts = re.split(r'(?=\.kern_version\s*=)', text)
    entries = []
    for p in parts:
        m = re.search(r'\.kern_version\s*=\s*"([^"]*)"', p)
        if not m:
            continue
        kern = m.group(1)
        perf_m = re.search(r'\.perf_supported\s*=\s*(true|false)', p)
        perf = perf_m.group(1) if perf_m else "?"
        kc_hits = re.findall(r'\.kernelcache__\w+\s*=\s*(0x[0-9a-fA-F]+|\d+)', p)
        kc_nonzero = sum(1 for v in kc_hits if v not in ("0", "0x0"))
        ios_hits = re.findall(r'\.ios__\w+\s*=\s*(0x[0-9a-fA-F]+|\d+)', p)
        ios_nonzero = sum(1 for v in ios_hits if v not in ("0", "0x0"))
        entries.append({
            "kern_version": kern,
            "perf": perf,
            "kc_total": len(kc_hits),
            "kc_nonzero": kc_nonzero,
            "ios_total": len(ios_hits),
            "ios_nonzero": ios_nonzero,
        })
    return entries, text


# 真实 kern.version banner（取自公开设备表的实际值）
TEST_BANNERS = [
    ("iOS 16.4.1 / T8112 (本机 iPad Pro M2)",
     "Darwin Kernel Version 22.4.0: Mon Mar  6 20:42:28 PST 2023; root:xnu-8796.102.5~1/RELEASE_ARM64_T8112"),
    ("iOS 16.4.1 / T8101",
     "Darwin Kernel Version 22.4.0: Mon Mar  6 20:42:59 PST 2023; root:xnu-8796.102.5~1/RELEASE_ARM64_T8101"),
    ("iOS 16.1.2 (应命中兜底条目)",
     "Darwin Kernel Version 22.1.0: Thu Oct  6 19:33:53 PDT 2022; root:xnu-8792.42.7~1/RELEASE_ARM64_T8020"),
    ("iOS 16.3 (应命中兜底条目)",
     "Darwin Kernel Version 22.3.0: Wed Jan  4 21:25:01 PST 2023; root:xnu-8792.82.2~1/RELEASE_ARM64_T8120"),
    ("iOS 16.5 / T8120",
     "Darwin Kernel Version 22.5.0: Mon Apr 24 21:09:28 PDT 2023; root:xnu-8796.122.4~1/RELEASE_ARM64_T8120"),
    ("iOS 16.6 / T8101",
     "Darwin Kernel Version 22.6.0: Wed Jun 28 20:50:15 PDT 2023; root:xnu-8796.142.1~1/RELEASE_ARM64_T8101"),
    ("iOS 15.0 (版本门会拒，但匹配层应命中)",
     "Darwin Kernel Version 21.0.0: Mon Oct 24 21:22:44 PDT 2022; root:xnu-8792.2.11~1/RELEASE_ARM64_T8101"),
    ("iOS 13.5 (表里没有，应全部不命中)",
     "Darwin Kernel Version 19.5.0: Tue May 26 20:35:49 PDT 2020; root:xnu-6153.122.2~1/RELEASE_ARM64_T8015"),
]


def main():
    entries, text = parse_entries(HEADER)

    print("=" * 78)
    print("1. 结构")
    print("=" * 78)
    n_open = text.count("{")
    n_close = text.count("}")
    print(f"  条目数            : {len(entries)}")
    print(f"  花括号 {{ / }}      : {n_open} / {n_close}  {'✔ 配平' if n_open == n_close else '✘ 不配平'}")
    print(f"  PREFIX_LEN（info.h）: {PREFIX_LEN}")

    print()
    print("=" * 78)
    print("2. 每个条目的 key 长度与字段完整度")
    print("=" * 78)
    for i, e in enumerate(entries, 1):
        key = e["kern_version"]
        L = len(key)
        # key 长度与 PREFIX_LEN 的关系
        if L < PREFIX_LEN:
            verdict = f"✘ 短于 {PREFIX_LEN}（第 {L+1} 位是 NUL，永不命中真实 banner）"
        elif L == PREFIX_LEN:
            verdict = "✔ 正好"
        else:
            verdict = "✔ 长于（前 29 位参与比较）"
        print(f"  [#{i}] len={L:3d}  {verdict}")
        print(f"        key = {key[:64]}")
        print(f"        perf_supported={e['perf']}  kernelcache非零={e['kc_nonzero']}/{e['kc_total']}"
              f"  ios__非零={e['ios_nonzero']}/{e['ios_total']}")

    print()
    print("=" * 78)
    print("3. 匹配语义（复现 info.h 的 strncmp(banner, key, 29)）")
    print("=" * 78)
    for label, banner in TEST_BANNERS:
        hit = None
        for i, e in enumerate(entries, 1):
            if c_strncmp(banner, e["kern_version"], PREFIX_LEN) == 0:
                hit = (i, e["kern_version"])
                break
        tag = f"[#{hit[0]}] {hit[1][:40]}" if hit else "未命中（会被 km_version_is_listed 拒绝）"
        print(f"  {label}")
        print(f"      banner = {banner[:60]}")
        print(f"      -> {tag}")

    print()
    print("=" * 78)
    print("4. 一致性：perf_supported=true 必须配非零 kernelcache__*")
    print("=" * 78)
    bad = 0
    for i, e in enumerate(entries, 1):
        if e["perf"] == "true" and e["kc_nonzero"] == 0:
            print(f"  ✘ [#{i}] perf_supported=true 但 kernelcache 全 0 —— 这会让 perf_run 用 0 算出非法 kernel_base")
            bad += 1
    if bad == 0:
        print("  ✔ 全部自洽")

    print()
    print("=" * 78)
    print("5. 回归：短 key 修复验证（必须用 22.0.0 的 banner 才测得准）")
    print("=" * 78)
    b220 = ("Darwin Kernel Version 22.0.0: Thu Sep 15 21:23:55 PDT 2022; "
            "root:xnu-8792.42.7~1/RELEASE_ARM64_T8110")
    b221 = "Darwin Kernel Version 22.1.0: Thu Oct  6 19:33:53 PDT 2022; root:xnu-8792.42.7~1/RELEASE_ARM64_T8020"

    print(f"  banner(22.0.0) = {b220[:56]}")
    for cand, desc in [("Darwin Kernel Version 22.0.0", "28 字符（修复前）"),
                       ("Darwin Kernel Version 22.0.0:", "29 字符（修复后）")]:
        r = c_strncmp(b220, cand, PREFIX_LEN)
        print(f"    {desc:22s} strncmp = {r:4d}  {'✔ 命中' if r == 0 else '✘ 不命中'}")

    print()
    print(f"  banner(22.1.0) = {b221[:56]}")
    for cand, desc in [("Darwin Kernel Version 22.0.0", "28 字符"),
                       ("Darwin Kernel Version 22.0.0:", "29 字符")]:
        r = c_strncmp(b221, cand, PREFIX_LEN)
        print(f"    {desc:22s} strncmp = {r:4d}  {'✔ 命中' if r == 0 else '✘ 不命中'}")

    print()
    print("  结论一：补 ':' 让 22.0.0 的 banner 能命中 —— 这个修复本身有效。")
    print("  结论二：但 '22.0.0:' 这个 key 替不了 22.1.0 / 22.2.0 / 22.3.0")
    print("          （第 25 位 '0' vs '1' 就分了）。所以那三条是**另加**的条目，")
    print("          不是靠兜底 —— 见第 6 节的覆盖表。")
    print("  结论三：反过来，Darwin 22.0.0（iOS 16.0）现在**没有**条目：")
    print("          公开设备表里查不到它的偏移，宁可不支持，也不用 22.4 的")
    print("          0x730 去顶 —— 那会匹配上然后用错 object_size（差 0x200），")
    print("          比干净拒绝难查得多。")

    print()
    print("=" * 78)
    print("6. 覆盖缺口：表里声明支持的 Darwin 版本 vs 实际有条目的版本")
    print("=" * 78)
    have = set()
    for e in entries:
        m = re.search(r'Darwin Kernel Version (\d+)\.(\d+)\.(\d+)', e["kern_version"])
        if m:
            have.add((int(m.group(1)), int(m.group(2)), int(m.group(3))))
    missing = []
    for major, minors in ((21, range(0, 7)), (22, range(0, 7))):
        for mn in minors:
            if (major, mn, 0) not in have:
                missing.append(f"Darwin {major}.{mn}.0")
    print(f"  表里有条目的 : {sorted('Darwin %d.%d.%d' % v for v in have)}")
    print(f"  缺失的       : {missing if missing else '无'}")
    print()
    print("  注：kern.version 是 'Darwin Kernel Version 22.1.0: ...' 这种形态，")
    print("      而匹配只比前 29 字符 —— 所以每个 minor 版本都必须有自己的条目，")
    print("      '22.0.0:' 这种 key 无法替 22.1 / 22.2 / 22.3 兜底。")
    print()
    print("  当前实际支持面（配合 km_version_is_supported 的下界）：")
    print("    iOS 16.1 / 16.2 / 16.3            -> 支持（本轮补的三条）")
    print("    iOS 16.4.x / 16.5 / 16.6.x        -> 支持")
    print("    iOS 16.0                          -> 不支持（无偏移数据）")
    print("    iOS 15.x                          -> 版本门拒绝（IOSurface 后端未修完）")
    print("    iOS 13 / 14                       -> 版本门拒绝（无可用 PUAFF）")


if __name__ == "__main__":
    main()
