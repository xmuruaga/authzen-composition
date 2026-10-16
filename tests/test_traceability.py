"""docs/TRACEABILITY.md cites only tests that exist.

A citation is ``file.py::test_name``; a bare ``test_name`` after it in the same
cell belongs to the same file. A renamed or deleted test would otherwise leave
a requirement silently untested while the matrix still claims coverage.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = (ROOT / "docs" / "TRACEABILITY.md").read_text(encoding="utf-8")


def _tests_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")}


def _citations() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in MATRIX.splitlines():
        if not line.startswith("|"):
            continue
        for cell in line.split("|"):
            current: str | None = None
            for token in re.findall(r"`([^`]+)`", cell):
                if "::" in token:
                    current, name = token.split("::", 1)
                    out.append((current, name))
                elif re.fullmatch(r"test_\w+", token) and current is not None:
                    out.append((current, token))
    return out


def _orphans() -> list[str]:
    """Bare test names that no ``file.py::`` citation precedes in their cell."""
    out: list[str] = []
    for line in MATRIX.splitlines():
        if not line.startswith("|"):
            continue
        for cell in line.split("|"):
            seen_file = False
            for token in re.findall(r"`([^`]+)`", cell):
                if "::" in token:
                    seen_file = True
                elif re.fullmatch(r"test_\w+", token) and not seen_file:
                    out.append(token)
    return out


def test_matrix_cites_tests() -> None:
    assert len(_citations()) >= 40


def test_every_cited_test_exists() -> None:
    missing = []
    cache: dict[str, set[str]] = {}
    for file, name in _citations():
        path = ROOT / "tests" / file
        if file not in cache:
            cache[file] = _tests_in(path) if path.exists() else set()
        if name not in cache[file]:
            missing.append(f"{file}::{name}")
    assert missing == []


def test_every_bare_test_name_follows_its_file() -> None:
    # A bare name with no file before it is checked against nothing.
    assert _orphans() == []
