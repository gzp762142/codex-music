"""Swift 文件的括号配对与字符串/注释剥离检查（clang 的 clex_check 不覆盖 Swift）。"""
import sys
from pathlib import Path


def strip_swift(text):
    """去掉 // 注释、/* */ 块注释（Swift 支持嵌套块注释）、行内字符串与多行字符串。"""
    out = []
    i = 0
    n = len(text)
    depth = 0  # 块注释嵌套深度
    while i < n:
        c = text[i]
        if depth > 0:
            if c == "/" and i + 1 < n and text[i + 1] == "*":
                depth += 1
                out.append("  ")
                i += 2
                continue
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                depth -= 1
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            out.append("  ")
            i += 2
            continue
        if text.startswith('"""', i):
            j = text.find('"""', i + 3)
            j = n if j < 0 else j + 3
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "\n":
                    break
                j += 1
            j = min(j + 1, n)
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def check(path):
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    text = strip_swift(raw)
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    line = 1
    for ch in text:
        if ch == "\n":
            line += 1
        elif ch in "([{":
            stack.append((ch, line))
        elif ch in ")]}":
            if not stack:
                print(f"✗ {path}:{line} 多出一个 '{ch}'")
                return 1
            top, tl = stack.pop()
            if top != pairs[ch]:
                print(f"✗ {path}:{line} '{ch}' 与第 {tl} 行的 '{top}' 不匹配")
                return 1
    if stack:
        top, tl = stack[-1]
        print(f"✗ {path} 有 {len(stack)} 个未闭合的括号，最内层是第 {tl} 行的 '{top}'")
        return 1
    print(f"✔ {path} 括号配对（剥离注释与字符串后）")
    return 0


if __name__ == "__main__":
    rc = 0
    for p in sys.argv[1:]:
        rc |= check(p)
    sys.exit(rc)
