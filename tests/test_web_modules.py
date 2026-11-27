"""The browser app's modules load: each parses as an ES module, and every name it imports is exported.

Either mistake (a name imported twice, or a name that does not exist) stops the whole single-page app from
booting — a blank screen, with no server error. ``node --check`` on a ``.js`` file does not catch them
(it parses as a script), so these tests parse each module as ESM and resolve the imports statically."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[1] / "argus" / "web"
MODULES = sorted(p for p in (WEB / "js").rglob("*.js") if "vendor" not in p.parts)
IMPORT = re.compile(r'import\s*\{([^}]*)\}\s*from\s*"(\.[^"]+)"', re.S)
EXPORT_DECL = re.compile(r"export\s+(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z_$][\w$]*)")
EXPORT_LIST = re.compile(r"export\s*\{([^}]*)\}")


def exported(path: Path) -> set[str]:
    text = path.read_text()
    names = set(EXPORT_DECL.findall(text))
    for group in EXPORT_LIST.findall(text):
        for part in group.split(","):
            part = part.strip()
            if part:
                names.add(part.split(" as ")[-1].strip())
    return names


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
@pytest.mark.parametrize("path", MODULES, ids=lambda p: str(p.relative_to(WEB)))
def test_each_module_parses_as_an_es_module(path, tmp_path):
    copy = tmp_path / (path.stem + ".mjs")
    copy.write_text(path.read_text())
    result = subprocess.run([shutil.which("node"), "--check", str(copy)], capture_output=True, text=True,  # noqa: S603
                            timeout=60, check=False)  # fmt: skip
    assert result.returncode == 0, result.stderr[-2000:]


@pytest.mark.parametrize("path", MODULES, ids=lambda p: str(p.relative_to(WEB)))
def test_every_imported_name_is_exported(path):
    for names, source in IMPORT.findall(path.read_text()):
        target = (path.parent / source).resolve()
        assert target.exists(), f"{path.name} imports a missing module {source}"
        available = exported(target)
        for name in names.split(","):
            name = name.strip().split(" as ")[0].strip()
            if name:
                assert name in available, f"{path.name} imports {name!r}, which {source} does not export"


def test_navigation_pages_and_titles_agree():
    html = (WEB / "index.html").read_text()
    main = (WEB / "js" / "main.js").read_text()
    views = re.findall(r'"([a-z]+)"', re.search(r"const VIEWS = \[([^\]]*)\]", main).group(1))
    nav = set(re.findall(r'class="nav-item"[^>]*data-view="([a-z]+)"', html))
    sections = set(re.findall(r'<section id="view-([a-z]+)"', html))
    titles = set(re.findall(r"\b([a-z]+): \"", re.search(r"const VIEW_TITLES = \{(.*?)\};", main, re.S).group(1)))
    assert set(views) == nav == sections, (set(views) ^ nav, set(views) ^ sections)
    assert set(views) <= titles, set(views) - titles  # every page names itself in the tab and top bar
    # phones show at most four everyday tabs (plus "More"); the rest live in the sheet
    assert 1 <= len(re.findall(r"data-primary", html)) <= 4
