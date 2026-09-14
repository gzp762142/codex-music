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
    (r"(?<![.\w])(?:open|close|strlen)\(",
     "裸 POSIX 调用 —— 统一写 Darwin.open / Darwin.close / Darwin.strlen"),
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
    # 字符串替换成空引号对（保留在同一行）：
    # 换行会破坏元组计数 —— 第一版把 "n/a" 整段吃掉，
    # (kr, 0, false, "n/a") 被看成 3 个元素，报了误报。
    text = re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', text)
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


def extract_sig(lines, i, start_col):
    """从 lines[i] 的 start_col 处开始，提取完整参数表（可能跨多行）。

    第一版只看当前行，参数表跨行时就只拿到函数名，
    于是 AppDelegate 两个不同签名的 application 被当成重复 —— 误报。
    """
    out = []
    depth = 0
    for k in range(i, min(i + 30, len(lines))):
        s = lines[k] if k == i else lines[k]
        begin = start_col if k == i else 0
        for ch in s[begin:]:
            out.append(ch)
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return "".join(out)
        out.append(" ")
    return "".join(out)


def check_duplicate_funcs(path, text):
    """同一作用域内重复定义同名函数。

    只在**同一个类/结构体内部**才算重复 —— 不同类的同名方法完全合法
    （AppDelegate 有两个 application，UnlockView 的 makeUIView 等）。
    第一版按文件全局比对，在全仓报了 17 条误报，就是因为没跟踪作用域。

    它确实抓过真的：stepFindBase / probeBase / stepRegionName 各重复两份，
    是脚本化插入时整段粘了两遍。
    """
    problems = []
    scope = "<global>"
    seen = {}          # (scope, funcName) -> 首次行号
    depth = 0
    pendingType = None

    for n, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()

        m = re.match(r"^\s*(?:final |public |internal |fileprivate |private |open )*"
                     r"(class|struct|enum|extension|protocol)\s+(\w+)", line)
        if m and "{" in line:
            pendingType = m.group(2)
            depth = 0

        fm = re.match(r"\s*(?:private |fileprivate |internal |public |static |class |override )*"
                      r"func\s+(\w+)", line)
        if fm:
            # 用「函数名 + 完整参数表」判重，而不是只用名字 ——
            # 参数表不同就是重载，完全合法（AppDelegate 的两个 application、
            # DebugProcView 的两个 tableView 都是重载，第一版按名字报成了误报）。
            sig = fm.group(1)
            all_lines = text.split("\n")
            j = line.find("(", fm.end())
            if j >= 0:
                sig += extract_sig(all_lines, n - 1, j)
            key = (scope, sig)
            if key in seen:
                problems.append(f"{path}:{n}  函数 {sig} 在 {scope} 内重复定义"
                                f"（首次在 {seen[key]} 行）")
            else:
                seen[key] = n

        if pendingType is not None:
            for ch in stripped:
                if ch == "{":
                    depth += 1
                    if depth == 1:
                        scope = pendingType
                elif ch == "}":
                    depth -= 1
                    if depth <= 0:
                        scope = "<global>"
                        pendingType = None
                        depth = 0
    return problems


def check_tuple_arity(path, text):
    """核对「返回元组的函数」与其解构处的元素个数是否一致。

    编译器只在解构处报错，改起来要等一轮 CI。
    这一路已经踩过：readPointer 返回 4 个元素，三处按 2 个解构。
    """
    problems = []
    # 函数名 -> 返回元组元素数
    arity = {}
    for m in re.finditer(r"func\s+(\w+)\s*\([^)]*\)[^{]*?->\s*\(([^)]*)\)", text, re.S):
        fields = [f for f in m.group(2).split(",") if f.strip()]
        if len(fields) > 1:
            arity[m.group(1)] = len(fields)
    # 解构处
    for n, line in enumerate(text.split("\n"), 1):
        dm = re.search(r"let\s*\(([^)]*)\)\s*=\s*(\w+)\s*\(", line)
        if not dm:
            continue
        names = [x.strip() for x in dm.group(1).split(",") if x.strip()]
        fn = dm.group(2)
        if fn in arity and len(names) != arity[fn]:
            problems.append(f"{path}:{n}  {fn}(...) 返回 {arity[fn]} 个值，"
                            f"这里按 {len(names)} 个解构")
    return problems


def check_return_arity(path, text):
    """核对「函数体内 return 的元组元素数」与「声明的返回类型」是否一致。

    编译器只在出错那一行报，但要等一轮 CI。
    这一路踩过：readRaw 声明返回 2 元组，函数体里却还留着 4 元组的
    `return (KERN_FAILURE, 0, false, "n/a")` —— 拆函数时漏改的提前返回。

    用大括号深度界定函数作用域：签名可能跨行（pointerInfo 就是），
    第一版没做作用域界定，把 pointerInfo 的 return 算到了跨行签名的
    readRaw 头上，报了误报。
    """
    problems = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.search(r"func\s+(\w+)\s*\(", line)
        if not m:
            i += 1
            continue

        # 多行拼接签名，直到看见 "{"
        sig = line
        j = i
        while "{" not in sig and j + 1 < len(lines) and j - i < 8:
            j += 1
            sig += " " + lines[j]
        rm = re.search(r"->\s*\(([^)]*)\)", sig)
        if not rm:
            i = j + 1
            continue
        arity = len([f for f in rm.group(1).split(",") if f.strip()])
        fname = m.group(1)

        # 从 "{ " 起按大括号深度找到函数体结束
        depth = 0
        started = False
        k = j
        body_end = j
        while k < len(lines):
            for ch in lines[k]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
                    if started and depth == 0:
                        body_end = k
                        break
            if started and depth == 0:
                break
            k += 1

        # 在函数体内找单行 return (a, b, ...)
        for ln in range(i, min(body_end + 1, len(lines))):
            rm2 = re.search(r"\breturn\s*\((.*)\)\s*$", lines[ln].strip())
            if not rm2:
                continue
            body = rm2.group(1).strip()
            if "(" in body or ")" in body:
                continue                      # 含调用，跳过避免误判
            cnt = len([x for x in body.split(",") if x.strip()])
            if cnt > 1 and cnt != arity:
                problems.append(f"{path}:{ln + 1}  {fname} 声明返回 {arity} 个值，"
                                f"这里 return 了 {cnt} 个")

        i = body_end + 1
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
        body = open(f, encoding="utf-8", newline="").read()
        all_problems += check_file(f)
        all_problems += check_api_usage(f, body, static_members)
        all_problems += check_duplicate_funcs(f, body)
        all_problems += check_tuple_arity(f, body)
        all_problems += check_return_arity(f, body)

    if all_problems:
        print("发现问题：")
        for p in all_problems:
            print("  " + p)
        return 1
    print("自检通过：无已知编译期陷阱")
    return 0


if __name__ == "__main__":
    sys.exit(main())
