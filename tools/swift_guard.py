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
    # 只抓「直接把 baseAddress 当值用」的写法：
    #   bad : f(buf.baseAddress)      /  return buf.baseAddress
    #   ok  : let p = buf.baseAddress /  buf.baseAddress! / buf.baseAddress ??
    # 上一版没排除 let 绑定，把 guard let ... = buf.baseAddress 这种正确写法
    # 也报了，属于自检自己误报。
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


def check_optional_baseaddress(path, text):
    """withUnsafe…Bytes 的 baseAddress 是 UnsafeMutableRawPointer?，
    直接当非可选参数用会编译失败。

    判断不靠正则上下文（试过两版 lookbehind，不等长/位置关系都出错），
    就直接看这一行：
      前后有 let           -> 解包或绑定，合法
      后面跟 ! ? ??        -> 已解包，合法
      其余                 -> 报
    """
    problems = []
    for n, line in enumerate(text.split("\n"), 1):
        if "baseAddress" not in line:
            continue
        i = line.index("baseAddress")
        before = line[max(0, i - 30):i]
        after = line[i + len("baseAddress"):]
        if "let" in before:
            continue
        if after.lstrip().startswith(("!", "?", "??")):
            continue
        problems.append(f"{path}:{n}  baseAddress 是可选类型，必须解包后再传")
    return problems


def check_file(path):
    problems = []
    raw = open(path, encoding="utf-8", newline="").read()
    # 只在「真代码」上匹配，行号与原文件一致
    text = strip_comments_and_strings(raw)

    for tex, why in PATTERNS:
        for m in re.finditer(tex, text):
            line = text[:m.start()].count("\n") + 1
            problems.append(f"{path}:{line}  {why}")

    problems += check_optional_baseaddress(path, text)

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


def check_api_usage(path, text, static_members):
    """跨文件核对：把 static 成员当实例成员调用会编译失败。

    上一轮就是这样连错三处（stepSymbols/stepDlsym/stepReadProof 都改成了
    static，但调用点还是 obj.method()），所以加这条机器检查。
    """
    problems = []
    for n, line in enumerate(text.split("\n"), 1):
        for m in re.finditer(r"\b(\w+)\.(\w+)\(", line):
            obj, member = m.group(1), m.group(2)
            # 只有「小写开头的对象名」才是实例；大写开头是类名，
            # UIColor.hex() 这种类名调 static 完全合法。
            # 第一版没排除这一点，把 UIColor/PanelOrientation 全报了。
            # 单字符对象名（p / v / q）多为安全指针等系统类型，其成员不是本项目的
            # static；p.load(...) 就是 UnsafeRawPointer 的方法，报它是误报。
            if (member in static_members and obj[:1].islower()
                    and obj != "self" and len(obj) > 1):
                problems.append(f"{path}:{n}  对 static 成员用了实例调用：{obj}.{member}(...)"
                                f" —— 改成 ClassName.{member}(...)")
    return problems


def main():
    all_problems = []
    files = []
    for base, _, names in os.walk(ROOT):
        for f in names:
            if f.endswith(".swift"):
                files.append(os.path.join(base, f))

    # 全仓收集 static 成员名（用于跨文件核对调用方式）
    static_members = set()
    for f in files:
        src = open(f, encoding="utf-8", newline="").read()
        static_members |= set(re.findall(r"static (?:func|var|let) (\w+)", src))

    for f in files:
        all_problems += check_file(f)
        all_problems += check_api_usage(f, open(f, encoding="utf-8", newline="").read(), static_members)

    if all_problems:
        print("发现问题：")
        for p in all_problems:
            print("  " + p)
        return 1
    print("自检通过：无已知编译期陷阱")
    return 0


if __name__ == "__main__":
    sys.exit(main())
