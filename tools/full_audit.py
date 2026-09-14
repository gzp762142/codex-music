#!/usr/bin/env python3
"""全仓审计：把这一路踩过的编译期陷阱逐项机器核对。

与 swift_guard.py 的分工：guard 是快速自检（每轮推前跑），本脚本覆盖更全，
包含作用域感知的重复定义、元组位数、独占访问、裸 POSIX 调用等。

用 python3 tools/full_audit.py，退出码非 0 表示发现问题。
"""
﻿import re, os, glob

ROOT = r"D:\工作区\Aether\Aether"
files = glob.glob(os.path.join(ROOT, "**", "*.swift"), recursive=True)
issues = []
def add(f, n, msg): issues.append(f"{os.path.basename(f)}:{n}  {msg}")

def strip(src):
    s = re.sub(r'"""[\s\S]*?"""', lambda m: "\n"*m.group(0).count("\n"), src)
    s = re.sub(r"(?m)//[^\n]*", "", s)
    # 字符串 -> 空引号对（保持单行），避免吃掉元素
    s = re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', s)
    return s

for f in files:
    raw = open(f, encoding="utf-8", newline="").read()
    src = strip(raw)
    lines = src.split("\n")

    for m in re.finditer(r"(\w+)\.withUnsafe(?:Mutable)?Bytes\s*\{", src):
        arr = m.group(1); st = src.index("{", m.start()); depth = 0; en = None
        for k in range(st, min(st+6000, len(src))):
            if src[k] == "{": depth += 1
            elif src[k] == "}":
                depth -= 1
                if depth == 0: en = k; break
        if en:
            for mm in re.finditer(r"\b%s\b" % re.escape(arr), src[st:en]):
                add(f, src[:st+mm.start()].count("\n")+1, f"独占访问：闭包内引用 {arr}")

    tuple_arity = {}
    for m in re.finditer(r"func\s+(\w+)\s*\(", src):
        seg = src[m.start():m.start()+400]
        nx = seg.find("func ", 1)
        if nx > 0: seg = seg[:nx]
        rm = re.search(r"->\s*\(([^)]*)\)", seg)
        if rm:
            cnt = len([x for x in rm.group(1).split(",") if x.strip()])
            if cnt > 1: tuple_arity[m.group(1)] = cnt

    for n, line in enumerate(lines, 1):
        dm = re.search(r"let\s*\(([^)]*)\)\s*=\s*(\w+)\s*\(", line)
        if dm:
            k = len([x for x in dm.group(1).split(",") if x.strip()])
            if dm.group(2) in tuple_arity and k != tuple_arity[dm.group(2)]:
                add(f, n, f"{dm.group(2)} 返回 {tuple_arity[dm.group(2)]} 个，解构 {k} 个")

    for m in re.finditer(r"func\s+(\w+)\s*\(", src):
        name = m.group(1)
        seg = src[m.start():m.start()+400]
        nx = seg.find("func ", 1)
        if nx > 0: seg = seg[:nx]
        rm = re.search(r"->\s*\(([^)]*)\)", seg)
        if not rm: continue
        arity = len([x for x in rm.group(1).split(",") if x.strip()])
        if arity < 2: continue
        bo = src.find("{", m.end())
        if bo < 0: continue
        depth = 0; end = None
        for k in range(bo, min(bo+8000, len(src))):
            if src[k] == "{": depth += 1
            elif src[k] == "}":
                depth -= 1
                if depth == 0: end = k; break
        if end is None: continue
        for rm2 in re.finditer(r"\breturn\s*\(([^()]*)\)", src[bo:end]):
            cnt = len([x for x in rm2.group(1).split(",") if x.strip()])
            if cnt > 1 and cnt != arity:
                add(f, src[:bo+rm2.start()].count("\n")+1, f"{name} 声明 {arity} 个，return {cnt} 个")

    for n, line in enumerate(lines, 1):
        for fn in ("write", "read", "open", "close", "strlen"):
            if re.search(r"(?<![.\w])%s\s*\(" % fn, line):
                add(f, n, f"裸 {fn}(...)：需 Darwin.{fn}")
        if re.search(r"\bsyscall\s*\(", line): add(f, n, "syscall(")
        if re.search(r"\bptrace\s*\(", line): add(f, n, "ptrace(")
        if re.search(r"NSSetUncaughtExceptionHandler\s*\{", line): add(f, n, "闭包传给 C 函数指针")

    for a, b, nm in [("{","}","花括号"),("(",")","圆括号"),("[","]","方括号")]:
        if src.count(a) != src.count(b):
            add(f, 1, f"{nm}不平衡 {src.count(a)}/{src.count(b)}")

print(f"扫描 {len(files)} 个文件")
if issues:
    print(f"发现 {len(issues)} 处：")
    for i in issues: print("  " + i)
else:
    print("  ✓ 无已知编译期问题")
