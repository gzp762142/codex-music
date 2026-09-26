"""检查 C 文件里「先用后定义」——项目里已经犯过两次的错（done: 标签那次、g_physmapWindowDiag 这次）。

只查 file-scope 的 static 对象与 static 函数：C 没有「先引用后定义」，用点必须先于定义点。
"""
import re
import sys
from pathlib import Path

DECL_RE = re.compile(
    r"^static\s+"                       # static
    r"(?:const\s+|volatile\s+|inline\s+|__attribute__\(\([^)]*\)\)\s+)*"
    r"(?:unsigned\s+|signed\s+)?"
    r"(?:void|int|char|short|long|float|double|bool|size_t|ssize_t|uint8_t|uint16_t|uint32_t|uint64_t|"
    r"int8_t|int16_t|int32_t|int64_t|u8|u16|u32|u64|i32|i64|usize|kaddr_t|"
    r"[A-Za-z_]\w*)"                    # 返回类型或 struct 名
    r"(?:\s*\*+)?\s*"
    r"([A-Za-z_]\w*)"                   # 标识符
    r"\s*(?:\[|=|;|\()",
    re.M,
)


def strip_comments(text):
    """去掉注释与字符串，避免注释里的名字被当成使用。保留行结构（等长替换）。

    另有一条不是注释、但同样不该被当成代码的东西：`#pragma mark - 说明文字`。
    它的后半段是编译器忽略的标记文本，可里面常写变量名（KernelSlide.m:221 就写了
    g_slideLock）—— 不剥掉就会报出一条"定义在 233、用于 221"的假警报。
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        # #pragma mark 后面的整段标记文字：保留 `#pragma` 本身，余下清空。
        if c == "\n" or i == 0:
            m = re.match(r"[ \t]*#\s*pragma\s+mark\b[^\n]*", text[i:] if i == 0 else text[i + 1:])
            if m:
                start = i if i == 0 else i + 1
                end = start + m.end()
                head_len = len(re.match(r"[ \t]*#\s*pragma", text[start:end]).group(0))
                out.append(text[start:start + head_len])
                out.append("".join("\n" if ch == "\n" else " " for ch in text[start + head_len:end]))
                i = end
                continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            chunk = text[i:j]
            out.append("".join("\n" if ch == "\n" else " " for ch in chunk))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def main(path):
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    text = strip_comments(raw)
    lines = text.split("\n")

    # 收集 static 定义：标识符 -> 定义行号（1-based）
    defs = {}
    for idx, line in enumerate(lines, start=1):
        m = DECL_RE.match(line)
        if m:
            name = m.group(1)
            defs.setdefault(name, idx)

    # 对每个定义，找它在文件里最早出现的位置
    problems = []
    for name, dline in defs.items():
        pattern = re.compile(r"\b" + re.escape(name) + r"\b")
        first = None
        for idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                first = idx
                break
        if first is not None and first < dline:
            problems.append((name, dline, first, lines[first - 1].strip()[:100]))

    print(f"文件：{path}")
    print(f"static file-scope 定义数：{len(defs)}")
    if not problems:
        print("✔ 没有「先用后定义」")
        return 0
    print(f"✗ 发现 {len(problems)} 处「先用后定义」：")
    for name, dline, first, snippet in sorted(problems, key=lambda x: x[2]):
        print(f"   {name}: 定义在 {dline} 行，但最早出现在 {first} 行")
        print(f"        {first} 行内容：{snippet}")
    return 1


if __name__ == "__main__":
    rc = 0
    for p in sys.argv[1:]:
        rc |= main(p)
    sys.exit(rc)
