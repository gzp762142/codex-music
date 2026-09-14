#!/usr/bin/env python3
"""推送前自检：把这一路踩过的 Swift 编译期坑提前抓出来。

用法：python3 tools/swift_guard.py
退出码非 0 表示发现问题。这些规则全部来自本项目实际编译失败记录，
不是泛泛的 lint。
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Aether")

# (正则, 说明)
PATTERNS = [
    (r"NSSetUncaughtExceptionHandler\s*\{",
     "闭包传给 C 函数指针 —— 必须改成不捕获上下文的顶层函数"),
    (r"\bsignal\([^)]*,\s*\{",
     "闭包传给 signal —— 同上"),
    (r"(?<![.\w])write\(",
     "裸 write —— UIKit 上下文会被解析成实例方法，要写 Darwin.write"),
    (r"(?<![.\w])read\(",
     "裸 read —— 同上"),
    (r"\bsyscall\s*\(",
     "syscall 调用 —— syscall() 只走 BSD 表，Mach trap 号交给它会直接崩"),
    (r"\bptrace\s*\(",
     "ptrace —— 有副作用，不要为了试探而调用"),
    (r"(?:scanMachTrap|trapScan|syscallCandidates)",
     "mach trap 编号扫描 —— 未知编号的调用会杀掉进程"),
]

# internal 可见的函数签名里出现私有类型别名：Swift 报
# "method must be declared private because its parameter uses a private type"
PRIVATE_TYPE_RE = re.compile(r"private typealias (\w+)")
FUNC_RE = re.compile(r"^\s{4}((?:static )?func \w+\([^)]*\)[^{]*)\{", re.M)


def strip_comments_and_strings(text):
    """把注释与字符串替换成等量换行，行号保持不变。

    这一步是必须的：上一版直接在原文上匹配，结果把注释里提到的
    `syscall()` 当成了真调用，自检自己误报（还很好笑地报了三次）。
    """
    def blank(m):
        return "\n" * m.group(0).count("\n")

    text = re.sub(r'"""[\s\S]*?"""', blank, text)
    text = re.sub(r"(?m)//[^\n]*", "", text)
    text = re.sub(r'"(?:[^"\\\n]|\\.)*"', lambda m: '"' + "\n" * m.group(0).count("\n") + '"', text)
    return text


def check_file(path):
    problems = []
    raw = open(path, encoding="utf-8", newline="").read()
    # 只在「真代码」上匹配，行号与原文件一致
    text = strip_comments_and_strings(raw)

    for tex, why in PATTERNS:
        for m in re.finditer(tex, text):
            line = text[:m.start()].count("\n") + 1
            problems.append(f"{path}:{line}  {why}")

    priv = set(PRIVATE_TYPE_RE.findall(text))
    if priv:
        for m in FUNC_RE.finditer(text):
            sig = m.group(1)
            if sig.strip().startswith("private"):
                continue
            for t in priv:
                if re.search(r"\b%s\b" % t, sig):
                    line = text[:m.start()].count("\n") + 1
                    problems.append(
                        f"{path}:{line}  internal 函数签名用了私有 typealias {t}"
                        " —— 要么函数声明 private，要么类型别名改 internal")

    # 括号配对（用已经剥掉注释和字符串的文本）
    for a, b, name in [("{", "}", "花括号"), ("(", ")", "圆括号"), ("[", "]", "方括号")]:
        if text.count(a) != text.count(b):
            problems.append(f"{path}  {name}不平衡 {text.count(a)}/{text.count(b)}")
    return problems


def main():
    all_problems = []
    for base, _, files in os.walk(ROOT):
        for f in files:
            if f.endswith(".swift"):
                all_problems += check_file(os.path.join(base, f))

    if all_problems:
        print("发现问题：")
        for p in all_problems:
            print("  " + p)
        return 1
    print("自检通过：无已知编译期陷阱")
    return 0


if __name__ == "__main__":
    sys.exit(main())
