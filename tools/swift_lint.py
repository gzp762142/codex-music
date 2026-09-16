#!/usr/bin/env python3
"""本地静态检查：抓那些 swift_guard.py 和括号平衡都抓不到的问题。

起因是一次真实的编译失败 —— 删掉一个 `let home` 绑定后，只改了自己正开着的那一行，
另外两个错误分支还在引用它，CI 报了两处 "cannot find 'home' in scope"。
本检查专门抓这一类：**字符串插值里引用了文件里没有绑定过的名字**。

不追求完备，只求：不误报（否则没人看），且能抓住"删了声明还在用"。
用法：  python tools/swift_lint.py [文件...]
"""
import re
import sys
import pathlib

SWIFT_KEYWORDS = {
    "true", "false", "nil", "self", "super", "return", "if", "else", "for", "while",
    "switch", "case", "default", "break", "continue", "guard", "in", "is", "as",
    "func", "var", "let", "class", "struct", "enum", "extension", "protocol",
    "import", "init", "deinit", "static", "private", "public", "internal", "fileprivate",
    "open", "final", "override", "mutating", "throws", "rethrows", "try", "catch",
    "do", "defer", "where", "repeat", "inout", "typealias", "associatedtype", "some", "any",
}

# 常见类型名，出现时直接跳过
SWIFT_TYPES = {
    "Int", "Int8", "Int16", "Int32", "Int64",
    "UInt", "UInt8", "UInt16", "UInt32", "UInt64",
    "Float", "Double", "Bool", "String", "Character", "Substring",
    "Array", "Dictionary", "Set", "Optional", "Result",
    "KernReturn", "MachPort", "MachVmAddress", "TimeInterval", "Date",
    "UnicodeScalar", "Data", "URL", "Error", "Any",
}


def strip_noise(src: str) -> str:
    """去掉注释和字符串的**普通文本**，但保留 `\\( ... )` 插值里的代码。

    这一点是关键：插值里引用的是真变量，删掉整个字符串字面量就等于把
    要检查的东西一起删了 —— 第一版就是这么写的，结果连故意插入的
    `\\(home)` 都抓不到。
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if c == "/" and nxt == "/":                      # 行注释
            while i < n and src[i] != "\n":
                i += 1
            continue

        if c == "/" and nxt == "*":                      # 块注释
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i += 2
            continue

        if c == '"':                                     # 字符串
            i += 1
            while i < n:
                if src[i] == "\\":
                    if i + 1 < n and src[i + 1] == "(":  # 插值 → 保留里面的代码
                        out.append("\\(")
                        i += 2
                        depth = 1
                        while i < n and depth > 0:
                            if src[i] == "(":
                                depth += 1
                            elif src[i] == ")":
                                depth -= 1
                                if depth == 0:
                                    break
                            out.append(src[i])
                            i += 1
                        out.append(")")
                        i += 1
                        continue
                    i += 2                               # 普通转义
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue

        out.append(c)
        i += 1
    return "".join(out)


# 语言/标准库里隐式存在或在插值中常见的名字，避免误报
BUILTIN_NAMES = {
    # catch / willSet / didSet 的隐式绑定
    "error", "newValue", "oldValue",
    # 常用标准库函数（可能出现在插值里）
    "min", "max", "abs", "print", "round", "floor", "ceil", "sqrt", "pow",
    "String", "Array", "Dictionary", "Set", "Optional",
    "Int", "Int8", "Int16", "Int32", "Int64", "UInt", "UInt8", "UInt16", "UInt32", "UInt64",
    "Float", "Double", "Bool", "Data", "Date", "URL",
    # 闭包简写参数
    "it", "newElement", "element",
}


def collect_bindings(code: str) -> set:
    """把所有可能引入名字的语法都收一遍 —— 宁可多收，减少误报。"""
    b = set()

    def add(name):
        # 参数可能带外部标签：`_ signo: Int32` → 取 `signo`
        name = name.strip().lstrip("_").strip()
        if re.fullmatch(r"[A-Za-z_]\w*", name):
            b.add(name)

    # let/var 简单绑定（含 static）
    for m in re.findall(r"\b(?:let|var)\s+([A-Za-z_]\w*)\s*[:=]", code):
        add(m)
    # 同一行的多变量绑定：let x = 1, y = 2, z = 3
    for m in re.findall(r",\s*([A-Za-z_]\w*)\s*[:=]", code):
        add(m)
    # let (a, b) / var (a, b) 元组解构
    for grp in re.findall(r"\b(?:let|var)\s*\(([^)]*)\)\s*[:=]", code):
        for part in grp.split(","):
            add(part.split(":")[-1])
    # for (a, b) in / for x in
    for grp in re.findall(r"for\s*\(([^)]*)\)\s+in\b", code):
        for part in grp.split(","):
            add(part)
    for m in re.findall(r"for\s+([A-Za-z_]\w*)\s+in\b", code):
        add(m)
    # if let / guard let / case let / while let
    for m in re.findall(r"\b(?:if|guard|case|while)\s+let\s+([A-Za-z_]\w*)", code):
        add(m)
    # 函数名本身（描述符/工具函数经常在插值里被调用）
    for m in re.findall(r"\bfunc\s+([A-Za-z_]\w*)", code):
        add(m)
    # 函数参数
    for grp in re.findall(r"func\s+[A-Za-z_]\w*\s*\(([^)]*)\)", code):
        for part in grp.split(","):
            name = part.split(":")[0]
            add(name)
    # 闭包参数：{ x in / { (a, b) in / [weak self] 捕获列表 + 参数
    # 捕获列表必须先剥掉，否则 `{ [weak self] stage in` 会被整个当成参数名丢掉。
    for grp in re.findall(r"\{\s*(?:\[[^\]]*\]\s*)?\(?([^){]*?)\)?\s+in\b", code):
        for part in grp.split(","):
            add(part)
    return b


def check(path: pathlib.Path) -> int:
    try:
        src = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        print(f"[FAIL] {path.name}  不是合法 UTF-8：{exc}")
        return 1
    code = strip_noise(src)
    problems = []

    # 1. 括号平衡（保留原有检查）
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack, bad = [], []
    for idx, ch in enumerate(code):
        if ch in pairs:
            stack.append((ch, idx))
        elif ch in ")]}":
            if not stack or pairs[stack[-1][0]] != ch:
                bad.append(ch)
            else:
                stack.pop()
    if stack:
        problems.append(f"未闭合的括号: {[c for c, _ in stack]}")
    if bad:
        problems.append(f"错配的括号: {bad}")

    # 2. 插值标识符必须在文件里被绑定过
    bindings = collect_bindings(code)
    used = set(re.findall(r"\\\(([A-Za-z_]\w*)", code))
    unknown = sorted(
        u for u in used
        if u not in bindings and u not in SWIFT_KEYWORDS and u not in SWIFT_TYPES
        and u not in BUILTIN_NAMES
        and not u[0].isupper()          # 大写开头一律当作类型 / 静态成员，不追
    )
    if unknown:
        problems.append("插值里引用了未绑定过的名字: " + ", ".join(unknown))

    if problems:
        print(f"[FAIL] {path.name}")
        for p in problems:
            print("       " + p)
        return 1
    print(f"[ OK ] {path.name}  括号平衡 · 插值引用全部有绑定")
    return 0


def main(argv):
    if len(argv) > 1:
        targets = [pathlib.Path(a) for a in argv[1:]]
    else:
        root = pathlib.Path(__file__).resolve().parent.parent
        targets = sorted(root.rglob("*.swift"))
    rc = 0
    for t in targets:
        if t.is_file():
            rc |= check(t)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
