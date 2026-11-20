"""Browser-side logic with no DOM (argus/web/js/*.js), tested with Node's built-in test runner."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

JS_TESTS = sorted((Path(__file__).parent / "js").glob("*.test.mjs"))


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
@pytest.mark.parametrize("path", JS_TESTS, ids=lambda p: p.name)
def test_javascript(path):
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run([node, "--test", str(path)], capture_output=True, text=True, timeout=120, check=False)  # noqa: S603 - fixed test files
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
