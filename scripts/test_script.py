import pathlib
import sys
from pydepgate.parsers.pth import parse_pth, LineKind

for path in pathlib.Path(sys.prefix).rglob("*.pth"):
    try:
        content = path.read_bytes()
        result = parse_pth(content, str(path))
        exec_count = len(result.exec_lines)
        path_count = len(result.path_lines)
        size = result.size_bytes
        marker = "EXEC" if exec_count else "    "
        print(f"{marker} {size:6d}  {exec_count}E/{path_count}P  {path}")
    except Exception as e:
        print(f"FAIL  {path}: {e!r}")