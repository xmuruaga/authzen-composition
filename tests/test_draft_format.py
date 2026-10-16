"""The draft is a kramdown-rfc document that the OpenID toolchain can build.

AuthZEN specifications are written for kramdown-rfc and rendered with
xml2rfc. The structural checks run everywhere; the build itself runs when
both tools are on the PATH (the `draft` CI job installs them).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

DRAFT = Path(__file__).resolve().parents[1] / "docs" / "authzen-composition-profile-1_0.md"
RENDERED = DRAFT.with_suffix(".txt")
TEXT = DRAFT.read_text(encoding="utf-8")
# The YAML front matter runs from the opening "---" to the first section
# marker ("--- abstract"); the body is the rest, markers included.
_MARK = TEXT.find("\n--- ")
FRONT, BODY = (TEXT[len("---\n"):_MARK], TEXT[_MARK:]) if _MARK > 0 else (TEXT, "")


def _declared_references() -> set[str]:
    # Keys of the `normative:` and `informative:` maps in the front matter.
    keys: set[str] = set()
    section = None
    for line in FRONT.splitlines():
        if re.match(r"^(normative|informative):\s*$", line):
            section = line
        elif re.match(r"^\S", line):
            section = None
        elif section and (m := re.match(r"^  ([A-Za-z0-9][A-Za-z0-9.-]*):", line)):
            keys.add(m.group(1))
    return keys


def test_the_draft_has_the_parts_kramdown_rfc_expects() -> None:
    assert re.search(r"^ipr: \S", FRONT, re.M)
    positions = [BODY.find(f"\n--- {part}\n") for part in ("abstract", "middle", "back")]
    assert -1 not in positions and positions == sorted(positions)
    # References come from the front matter, not from a hand-written section.
    assert not re.search(r"^# References\s*$", BODY, re.M)


def test_every_cited_reference_is_declared_and_every_declared_one_cited() -> None:
    cited = set(re.findall(r"\{\{([A-Z][A-Z0-9-]*[A-Z0-9])\}\}", BODY))
    assert cited, "no citation found: the body was not read"
    assert cited == _declared_references()


def test_the_key_words_are_the_bcp14_boilerplate() -> None:
    # The draft uses REQUIRED and OPTIONAL as well as MUST and MAY; the
    # boilerplate covers every BCP 14 key word and adds RFC 2119 and RFC 8174
    # to the normative references itself.
    assert "{::boilerplate bcp14-tagged}" in BODY
    assert "RFC 2119" not in BODY


def test_every_table_is_one_block_with_its_title_after_the_last_row() -> None:
    # A kramdown attribute list (`{: ...}`) ends a table: a row after it is
    # rendered as a paragraph of literal pipes, which the build does not flag.
    lines = BODY.splitlines()
    for i, line in enumerate(lines[:-1]):
        if line.startswith("{:"):
            assert not lines[i + 1].startswith("|"), f"table row after {line!r}"


def test_the_draft_builds_without_errors(tmp_path: Path) -> None:
    kramdown, xml2rfc = shutil.which("kramdown-rfc"), shutil.which("xml2rfc")
    if not (kramdown and xml2rfc):
        # The `draft` CI job sets the variable, so there a missing tool fails.
        if os.environ.get("AZC_REQUIRE_DRAFT_BUILD"):
            pytest.fail("kramdown-rfc and xml2rfc are required")
        pytest.skip("kramdown-rfc and xml2rfc are not installed")
    xml = tmp_path / "draft.xml"
    # Run in the temporary directory: the tools leave caches and logs behind.
    # References come from the committed cache (.refcache), so the rendering
    # does not change with what a reference server returns; with
    # KRAMDOWN_OFFLINE set, as in CI, nothing is fetched.
    env = {**os.environ, "KRAMDOWN_REFCACHEDIR": str(DRAFT.parents[1] / ".refcache")}
    kd = subprocess.run([kramdown, str(DRAFT)], capture_output=True, text=True, encoding="utf-8",
                        cwd=tmp_path, env=env)
    assert kd.returncode == 0 and "***" not in kd.stderr, kd.stderr
    xml.write_text(kd.stdout, encoding="utf-8")
    for fmt in ("--text", "--html"):
        out = subprocess.run([xml2rfc, fmt, str(xml), "-p", str(tmp_path)],
                             capture_output=True, text=True, encoding="utf-8", cwd=tmp_path)
        assert out.returncode == 0, out.stderr
        # Errors, and the text rendering's warnings about lines over 72
        # characters or tables too wide for the page.
        assert not re.search(r"Error|Too long line|table width", out.stderr), out.stderr
    # The rendered text is committed next to the source, so that it can be read
    # on GitHub; it must be what the source builds to.
    built = (tmp_path / "draft.txt").read_text(encoding="utf-8")
    assert RENDERED.read_text(encoding="utf-8") == built, (
        "docs/authzen-composition-profile-1_0.txt is stale: rebuild it (README, 'Run the checks')")
