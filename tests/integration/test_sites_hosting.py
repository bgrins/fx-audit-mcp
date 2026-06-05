"""End-to-end check that browser_evaluator's cross-origin SITES hosting works.

Runs only under ``-m integration`` against a real ASAN Firefox. The entry
document opens ``http://victim.site/seed.html`` then
``http://attacker.site/attack.html``; ``attack.html`` calls
``FuzzingFunctions.crash()`` to prove the PAC routed the popup through the
SiteServer docroot.

To run locally, fetch an ASAN fuzzing build into the gitignored
``./firefox/`` at the repo root and point ``FIREFOX_BINARY`` at it::

    uvx fuzzfetch --asan --fuzzing -o . -n firefox

    # Linux:
    FIREFOX_BINARY=$PWD/firefox/firefox uv run pytest -m integration

    # macOS (the binary lives inside the .app bundle):
    FIREFOX_BINARY=$PWD/firefox/Nightly.app/Contents/MacOS/firefox \\
        uv run pytest -m integration

Pass ``--os``/``--cpu`` to ``fuzzfetch`` if the default doesn't match the host.
"""

import os
from pathlib import Path

import pytest

from fx_audit_mcp.browser_evaluator import browser_evaluator

_SITES_DOCROOT = Path(__file__).parent / "sites"

_ENTRY_HTML = """\
<!DOCTYPE html>
<meta charset="utf-8">
<script>
console.log("IPDLVERIFY h1 entry loaded");
window.open("http://victim.site/seed.html");
setTimeout(() => {
  window.open("http://attacker.site/attack.html?armed=1");
}, 3000);
</script>
"""


@pytest.mark.integration
@pytest.mark.anyio
async def test_attacker_site_popup_crashes() -> None:
    """attacker.site/attack.html only loads if the PAC + docroot wiring works."""
    binary = os.environ.get("FIREFOX_BINARY", "")
    if not binary or not Path(binary).is_file():
        pytest.skip("FIREFOX_BINARY not set or not present")
    result = await browser_evaluator(
        content=_ENTRY_HTML,
        filename="test.html",
        firefox_binary=Path(binary),
        timeout=30,
        sites_docroot=_SITES_DOCROOT,
        prefs={"fuzzing.enabled": True},
    )
    assert result.crashed is True
    assert result.logs is not None
    # The crash stack must go through FuzzingFunctions::Crash — anything else
    # means the popup never reached attack.html.
    assert "FuzzingFunctions::Crash" in result.logs.crashdata
