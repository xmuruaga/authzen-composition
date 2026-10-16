"""The coverage gate measures every line of code that can run.

coverage.py drops a whole block when the line that opens it matches an
``exclude_lines`` pattern, and it matches a pattern anywhere in a line. A
pattern for the ``...`` body of a Protocol method must therefore match only
that body: one that also matched a signature such as ``-> tuple[str, ...]:``
would drop the whole function from the gate. Only bodies that never run may
be excluded.
"""

from __future__ import annotations

import ast
import configparser
from pathlib import Path

from coverage.python import PythonParser

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "authzen_composition"


def _exclude_regex() -> str:
    config = configparser.ConfigParser()
    config.read(ROOT / ".coveragerc", encoding="utf-8")
    patterns = [p.strip() for p in config.get("report", "exclude_lines").splitlines()
                if p.strip()]
    return "(?:" + ")|(?:".join(patterns) + ")"


def _stub_lines(tree: ast.Module) -> set[int]:
    """The lines of every function whose whole body is ``...``: a Protocol
    method, which no test can run."""
    lines: set[int] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.FunctionDef) and len(node.body) == 1
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and node.body[0].value.value is Ellipsis):
            assert node.end_lineno is not None
            lines.update(range(node.lineno, node.end_lineno + 1))
    return lines


def test_only_protocol_stubs_are_excluded_from_coverage() -> None:
    regex = _exclude_regex()
    dropped: dict[str, list[int]] = {}
    for path in sorted(PACKAGE.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        parser = PythonParser(text=source, filename=str(path), exclude=regex)
        parser.parse_source()
        # Statements only: coverage also marks the blank lines after a block.
        excluded = set(parser.excluded) & set(parser.raw_statements)
        extra = sorted(excluded - _stub_lines(ast.parse(source)))
        if extra:
            dropped[path.name] = extra
    assert dropped == {}


def test_the_protocol_stubs_are_still_excluded() -> None:
    # The check above must not pass merely because nothing is excluded.
    parser = PythonParser(filename=str(PACKAGE / "mhs.py"), exclude=_exclude_regex())
    parser.parse_source()
    assert parser.excluded
