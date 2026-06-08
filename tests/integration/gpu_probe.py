"""Empirical probe: which Gecko process types exist in this harness?

Ad-hoc diagnostic (not collected by pytest). It wraps the module-private
restart counter to dump the process types the sampler observed during a
no-crash run, with default prefs and with the GPU process force-enabled.

Run via:
  docker compose -f tests/integration/docker-compose.yml run --rm \
    integration uv run python tests/integration/gpu_probe.py
"""

# pylint: disable=protected-access

import asyncio
import collections
import os
import sys
from pathlib import Path

import fx_audit_mcp.browser_evaluator  # noqa: F401  # pylint: disable=unused-import

# The package re-exports the browser_evaluator *function*, which shadows the
# submodule on attribute access — go through sys.modules for the module.
be = sys.modules["fx_audit_mcp.browser_evaluator"]

CAPTURED: dict[str, list[str]] = {}
_orig = be._gpu_process_restarts


def probe(label):
    def spy(parent_pid, pid_types):
        CAPTURED[label] = sorted(pid_types.values())
        return _orig(parent_pid, pid_types)

    return spy


async def run(label, prefs):
    be._gpu_process_restarts = probe(label)
    result = await be.browser_evaluator(
        content="<html><body>probe</body></html>",
        filename="test.html",
        firefox_binary=Path(os.environ["FIREFOX_BINARY"]),
        timeout=25,
        prefs=prefs,
    )
    counts = dict(collections.Counter(CAPTURED.get(label, [])))
    reports = (
        None
        if result.crash_reports is None
        else [(r.process_type, r.pid, r.error[:60]) for r in result.crash_reports]
    )
    print(
        f"{label}: crashed={result.crashed} "
        f"gpu_restarts={result.gpu_process_restarts} types={counts}\n"
        f"  message={result.message!r}\n"
        f"  crash_reports={reports}"
    )


def main():
    asyncio.run(run("default-prefs", None))
    asyncio.run(
        run(
            "gpu-forced",
            {
                "layers.gpu-process.enabled": True,
                "layers.gpu-process.force-enabled": True,
            },
        )
    )


if __name__ == "__main__":
    main()
