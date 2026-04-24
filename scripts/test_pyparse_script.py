import pathlib
import sys
from pydepgate.parsers.pysource import parse_python_source, ParseStatus

status_counts = {s: 0 for s in ParseStatus}
shebang_count = 0
encoding_decl_count = 0
unusual_encoding_count = 0

for path in pathlib.Path(sys.prefix).rglob("*.py"):
    try:
        content = path.read_bytes()
    except (OSError, PermissionError):
        continue
    result = parse_python_source(content, str(path))
    status_counts[result.status] += 1
    if result.shebang:
        shebang_count += 1
    if result.encoding_declaration:
        encoding_decl_count += 1
        if result.encoding_declaration.encoding_name not in {"utf-8", "utf8", "ascii", "latin-1", "latin1"}:
            unusual_encoding_count += 1
            print(f"Unusual encoding: {result.encoding_declaration.encoding_name} in {path}")

print(f"\nStatus counts: {status_counts}")
print(f"Files with shebang: {shebang_count}")
print(f"Files with encoding declaration: {encoding_decl_count}")
print(f"Files with unusual encoding: {unusual_encoding_count}")