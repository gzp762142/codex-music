#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地 C/ObjC 词法自检 —— 没有编译器时的第一道防线。

动机：
    本机没有 clang/swiftc，Aether 的编译验证只能靠 GitHub CI（macOS runner
    按 10 倍计费）。preflight.py 已经能做括号/预处理配平，但它对
    **字符串字面量内部**的错误是盲的：strip_code() 会把整个字面量连同
    未转义的引号一起"合法地"吃掉，于是
        pw_append(t, "理由是"必须建页表"。\\n");
    这种行在 preflight 下全绿，到 CI 才炸。

它查什么（全部是词法层，不需要语义）：
    1. 字符串字面量在行内闭合 —— 跨行未闭合的字符串是上面那类错的标准形态
    2. 行尾反斜杠续行不在字符串里（会把下一行悄悄吞进字面量）
    3. #if/#ifdef/#ifndef 与 #endif 配对（preflight 也查，这里对同一文件复查）
    4. 字符串里的 %% 之类格式串错误只能靠眼睛，不查

它不查什么：类型、声明、链接。那些只有真编译能发现。

用法：
    python tools/clex_check.py [文件...]      # 不给文件就扫 libmemrw + FangUI
"""
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Aether")
DEFAULT_DIRS = [os.path.join(ROOT, "libmemrw"), os.path.join(ROOT, "FangUI")]
EXTS = (".c", ".h", ".m", ".mm")


def find_files(argv):
    files = []
    for a in argv:
        if os.path.isdir(a):
            for dp, _dn, fns in os.walk(a):
                for fn in fns:
                    if fn.endswith(EXTS):
                        files.append(os.path.join(dp, fn))
        else:
            files.append(a)
    if not files:
        for d in DEFAULT_DIRS:
            for dp, _dn, fns in os.walk(d):
                for fn in fns:
                    if fn.endswith(EXTS):
                        files.append(os.path.join(dp, fn))
    return sorted(files)


def check_strings(path):
    """逐行追踪字符串状态。返回问题列表。

    两类问题各有成因，**第二类才是这个脚本存在的理由**：
      A. 行内未闭合的字符串（真·跨行字面量，C 里非法）；
      B. **裸 CJK 出现在字符串/注释之外** —— 这是本工程最可能犯的错：
         注释和界面文案都是中文，写着写着就在字面量中间打出一个未转义的
         ASCII 双引号，于是 `"理由是"必须建页表"。\\n"` 在词法上**完全合法**
         （引号成对），只是那段中文变成了几个标识符，到 CI 才报
         "expected ';'"。preflight 的 strip_code 也看不见它。
         中文在 C 里只可能出现在字面量与注释里，所以判据干净：不在
         字符串/注释里出现 CJK，就是上面这类错。
    """
    problems = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return ["读不到文件: %s" % e]

    in_block_comment = False
    in_string = False
    string_start_line = 0

    for no, raw in enumerate(lines, 1):
        line = raw.rstrip("\n").rstrip("\r")

        # `#pragma mark - 中文` 在本工程里有几十处，是合法的（预处理指令后面
        # 是注释性质的自由文本）。整行跳过，免得自检一直报假警 —— 一个
        # 每天都报假警的检查等于没有检查。
        if line.lstrip().startswith("#"):
            continue

        i = 0
        n = len(line)
        while i < n:
            c = line[i]
            nxt = line[i + 1] if i + 1 < n else ""

            if in_block_comment:
                if c == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            if in_string:
                if c == "\\":
                    i += 2
                    continue
                if c == '"':
                    in_string = False
                    i += 1
                    continue
                i += 1
                continue

            # 不在字符串、不在块注释里
            if c == "/" and nxt == "/":
                break                      # 行注释，本行结束
            if c == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if c == '"':
                in_string = True
                string_start_line = no
                i += 1
                continue
            if c == "'":
                # 字符字面量：吃掉整个字面量（含转义），不参与配对
                i += 1
                while i < n:
                    if line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == "'":
                        i += 1
                        break
                    i += 1
                continue
            if ord(c) > 0x2FFF and c != "\ufeff":  # CJK / 全角标点：代码里不该出现
                # 已知的不可判定之处，写在这里免得日后误信这个检查的强度：
                # `"理由是"必须建页表"。` 这种"字面量中间多一个 ASCII 引号"的错，
                # 引号在词法上是**成对**的，靠词法无法与合法代码区分。本检查
                # 抓的是它的**后果**：那段中文变成了标识符。所以它只在
                # 多余引号造成中文外露时命中，不是万无一失 —— 该靠眼睛的地方
                # 还是要用眼睛。
                problems.append(
                    "第 %d 行：代码（非字符串、非注释）里出现了中文「%s」——\n"
                    "          最常见的成因是字面量中间打了个未转义的 ASCII 双引号，\n"
                    "          把后面那段文字挤到代码里去了。\n"
                    "          出问题的行：%s" % (no, c, line.strip()[:140]))
                # 一行只报一次，避免刷屏
                while i < n and ord(line[i]) > 0x2FFF and line[i] != "\ufeff":
                    i += 1
                continue
            i += 1

        # 行末仍未闭合的字符串 = 跨行字符串（C 里非法）
        if in_string:
            problems.append(
                "第 %d 行：字符串字面量在行内没有闭合（本行起于第 %d 行）。\n"
                "          出问题的行：%s" % (no, string_start_line, line.strip()[:140]))
            in_string = False              # 只报一次，避免一行错刷出几十条

    if in_block_comment:
        problems.append("块注释 /* 没有闭合")
    if in_string:
        problems.append("字符串字面量没有闭合")

    return problems


def check_cond(path):
    """#if/#endif 配对。与 preflight 同口径，但按嵌套深度给出行号。"""
    problems = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return ["读不到文件: %s" % e]

    import re
    stack = []
    for no, raw in enumerate(lines, 1):
        m = re.match(r"\s*#\s*(if|ifdef|ifndef|endif|else|elif)\b", raw)
        if not m:
            continue
        kw = m.group(1)
        if kw in ("if", "ifdef", "ifndef"):
            stack.append(no)
        elif kw == "endif":
            if not stack:
                problems.append("第 %d 行：#endif 没有对应的 #if" % no)
            else:
                stack.pop()
    for no in stack:
        problems.append("第 %d 行：#if 没有对应的 #endif" % no)
    return problems


def main():
    files = find_files(sys.argv[1:])
    print("clex_check：检查 %d 个文件（词法层）" % len(files))
    base = os.path.abspath(os.path.join(ROOT, os.pardir))
    total = 0
    for p in files:
        probs = check_strings(p) + check_cond(p)
        for x in probs:
            total += 1
            # 临时文件可能在别的盘（不同 mount），relpath 会抛 ValueError。
            try:
                shown = os.path.relpath(p, base)
            except ValueError:
                shown = p
            print("  ✘ %s: %s" % (shown, x))
    if total:
        print("\n发现 %d 个词法层问题。这些都会让 CI 白跑一次。" % total)
        return 1
    print("✔ 词法层通过（字符串/注释/#if 配对 + 代码里无中文）。这仍不等于能编译。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
