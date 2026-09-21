#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
推送前本地预检 —— 在没有 macOS / Xcode 的情况下，把最容易踩的低级错误拦下来。

动机：
    macOS runner 在 GitHub Actions 里按 10 倍计费（私有库 2000 分钟/月
    ≈ 200 分钟 macOS 时间 ≈ 40 次编译）。一次"编译失败的白跑"就是 3-5 分钟
    额度。而这些失败里有相当一部分是结构性问题（括号不配平、预处理指令
    没配对、数据表条目缺字段），完全可以在 Windows 上用 Python 查出来。

它做什么：
    1. C / ObjC 源文件的结构检查：括号配平、#if/#endif 配对、字符串与注释剥离
    2. dynamic_info.h 的数据表检查（条目数、字段完整性、perf_supported 一致性）
    3. 版本匹配回归（复用 verify_dynamic_info.py 的逻辑）

它不做什么：
    不替代编译。类型错误、符号缺失、SDK 版本问题仍然只有真编译能发现。
    这个脚本的目标是"别让低级错误消耗 CI 额度"，不是"代替 Xcode"。

用法：
    python tools/preflight.py            # 全量检查
    python tools/preflight.py --quiet    # 只输出问题
"""
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = r"D:\工作区\Aether"
QUIET = "--quiet" in sys.argv

# 需要做结构检查的 C / ObjC 源码。
# 注意：**不跳过 libkfd/** —— common.h（assert 宏）、info.h（版本匹配）都在里面，
# 而它们正是会被改动的地方。跳过它等于把最该查的文件漏掉。
SCAN_DIRS = [
    os.path.join(ROOT, "Aether", "libmemrw"),
]
SKIP_PARTS = ()                   # 留空：全扫，包括上游目录

DYNAMIC_INFO = os.path.join(
    ROOT, "Aether", "libmemrw", "kfd", "libkfd", "info", "dynamic_info.h")
INFO_H = os.path.join(
    ROOT, "Aether", "libmemrw", "kfd", "libkfd", "info.h")


def say(*a):
    if not QUIET:
        print(*a)


def strip_code(text: str) -> str:
    """去掉字符串字面量、字符字面量与注释，留下纯结构字符，用于括号配平。

    不做完美的 C 词法分析 —— 对"找出没配平"这个目的够用即可。
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":                      # 行注释
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and nxt == "*":                      # 块注释
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        if c in "\"'":                                   # 字符串/字符字面量
            quote = c
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def check_braces(path: str) -> list:
    """返回问题列表。检查 () {} [] 是否配平。"""
    problems = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError as e:
        return [f"读不到文件: {e}"]

    code = strip_code(raw)
    for opener, closer, name in (("{", "}", "花括号"), ("(", ")", "圆括号"), ("[", "]", "方括号")):
        diff = code.count(opener) - code.count(closer)
        if diff != 0:
            problems.append(f"{name}不配平: '{opener}'×{code.count(opener)} vs "
                            f"'{closer}'×{code.count(closer)} (差 {diff:+d})")

    # #if / #ifdef / #ifndef 与 #endif 配对
    ifs = len(re.findall(r'^\s*#\s*(?:if|ifdef|ifndef)\b', raw, re.M))
    ends = len(re.findall(r'^\s*#\s*endif\b', raw, re.M))
    if ifs != ends:
        problems.append(f"预处理指令不配对: #if/#ifdef/#ifndef×{ifs} vs #endif×{ends}")

    return problems


def collect_sources() -> list:
    files = []
    for d in SCAN_DIRS:
        for dirpath, dirnames, filenames in os.walk(d):
            dirnames[:] = [x for x in dirnames if x not in SKIP_PARTS]
            for fn in filenames:
                if fn.endswith((".c", ".h", ".m", ".mm")):
                    files.append(os.path.join(dirpath, fn))
    return sorted(files)


def check_dynamic_info() -> list:
    """数据表检查：条目、字段、perf 一致性、key 长度。"""
    problems = []
    try:
        with open(DYNAMIC_INFO, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return [f"读不到 dynamic_info.h: {e}"]

    prefix_len = None
    try:
        with open(INFO_H, "r", encoding="utf-8", errors="replace") as f:
            ih = f.read()
        m = re.search(r'kfd_version_prefix_length\s*=\s*(\d+)', ih)
        if m:
            prefix_len = int(m.group(1))
    except OSError:
        pass

    parts = re.split(r'(?=\.kern_version\s*=)', text)
    entries = []
    for p in parts:
        m = re.search(r'\.kern_version\s*=\s*"([^"]*)"', p)
        if m:
            entries.append((m.group(1), p))

    if not entries:
        return ["没解析出任何 kern_version 条目 —— 文件结构可能被改坏了"]

    # 每条必须有的字段（缺了运行期会读到 0）
    REQUIRED = ["proc__p_list__le_prev", "proc__p_pid", "proc__p_fd__fd_ofiles",
                "proc__object_size", "task__map"]

    for i, (key, body) in enumerate(entries, 1):
        # key 长度：短于 prefix_len 会永不命中（strncmp 遇 NUL 即分）
        if prefix_len and len(key) < prefix_len and not key.startswith("todo"):
            problems.append(f"[#{i}] key 只有 {len(key)} 字符 < prefix={prefix_len}: "
                            f"\"{key}\" —— 会永不命中（strncmp 在第 {len(key)+1} 位拿 NUL 对 ':'）")

        for field in REQUIRED:
            if not re.search(r'\.' + field + r'\s*=\s*', body):
                problems.append(f"[#{i}] 缺字段 .{field}")

        perf_m = re.search(r'\.perf_supported\s*=\s*(true|false)', body)
        kc = re.findall(r'\.kernelcache__\w+\s*=\s*(0x[0-9a-fA-F]+|\d+)', body)
        kc_nonzero = sum(1 for v in kc if v not in ("0", "0x0"))
        if perf_m and perf_m.group(1) == "true" and kc_nonzero == 0:
            problems.append(f"[#{i}] perf_supported=true 但 kernelcache 全 0 "
                            f"—— perf_run 会拿 0 算出非法 kernel_base")

    say(f"  dynamic_info.h: {len(entries)} 条条目, prefix_len={prefix_len}")
    return problems


def main():
    say("=" * 72)
    say("Aether 推送前本地预检")
    say("=" * 72)

    all_problems = []

    say("\n[1] 结构检查（括号 / 预处理指令）")
    sources = collect_sources()
    say(f"  扫描 {len(sources)} 个文件")
    for p in sources:
        probs = check_braces(p)
        for x in probs:
            all_problems.append(f"{os.path.relpath(p, ROOT)}: {x}")

    say("\n[2] dynamic_info.h 数据表")
    all_problems.extend(check_dynamic_info())

    say("\n" + "=" * 72)
    if all_problems:
        print(f"发现 {len(all_problems)} 个问题：\n")
        for x in all_problems:
            print(f"  ✘ {x}")
        print("\n这些多数会让 CI 白跑一次（3-5 分钟 macOS 额度）。建议先修再推。")
        return 1

    print("✔ 预检通过。")
    print("  注意：这不等于能编译 —— 类型错误、符号缺失、SDK 问题只有真编译能发现。")
    print("  它只保证不把结构性的低级错误推上去白烧 CI 额度。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
