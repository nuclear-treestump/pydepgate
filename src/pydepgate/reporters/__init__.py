"""
pydepgate.reporters.__init__

pydepgate reporters package.

Houses all output rendering for ScanResult and DecodedTree subjects
in a subject-first directory layout. scan_result/ contains the
ScanResult renderers (human, json). decoded_tree/ contains the
DecodedTree renderers (text, sources, iocs, json). SARIF lives at
the top level because it is the only renderer that consumes both
subjects in a single output document.

Each format module exposes a single function named render(). Callers
disambiguate via module imports rather than function imports:

    from pydepgate.reporters.scan_result import human as scan_human
    from pydepgate.reporters.decoded_tree import json as tree_json

    scan_human.render(result, stream, color=color)
    tree_json.render(tree, include_source=True)

No symbols are re-exported at the package or subdirectory level.
Callers always use the full path. This convention matches the
existing pydepgate convention where __init__.py files are kept
empty.
"""