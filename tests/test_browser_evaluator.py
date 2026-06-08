"""Tests for browser_evaluator.py."""

import asyncio
import json
import os
import re
import sys
from pathlib import Path

import pytest
from psutil import NoSuchProcess
from pytest_mock import MockerFixture

from fx_audit_mcp.browser_evaluator import (
    MAX_LOG_SIZE,
    _collect_dump_files,
    _crash_reports,
    _crashed_parent,
    _extract_crash_pid,
    _gpu_process_restarts,
    _load_ignored_signatures,
    _process_type_from_cmdline,
    _record_child_process_types,
    browser_evaluator,
    package_testcase,
    read_grizzly_logs,
)
from fx_audit_mcp.models import CrashReport, Logs

be_module = sys.modules["fx_audit_mcp.browser_evaluator"]


class TestExtractCrashPid:
    def test_standard_asan_format(self) -> None:
        """Parse a PID from a standard ASAN error header."""
        crashdata = "==12345==ERROR: AddressSanitizer: heap-use-after-free"
        assert _extract_crash_pid(crashdata) == 12345

    def test_returns_none_when_no_match(self) -> None:
        """Return None when the input contains no ASAN PID marker."""
        assert _extract_crash_pid("no pid here") is None

    def test_extracts_first_match(self) -> None:
        """Return the PID from the first ASAN marker when multiple are present."""
        crashdata = "==111==ERROR: AddressSanitizer: ...\n==222==ERROR: something"
        assert _extract_crash_pid(crashdata) == 111


class TestReadGrizzlyLogs:
    def test_empty_directory(self, tmp_path: Path) -> None:
        """Return empty strings for all categories when no log files are present."""
        assert read_grizzly_logs(tmp_path) == Logs(stderr="", stdout="", crashdata="")

    def test_routes_by_filename(self, tmp_path: Path) -> None:
        """Route log files to stderr, stdout, or crashdata based on filename."""
        (tmp_path / "log_stderr.txt").write_text("err")
        (tmp_path / "log_stdout.txt").write_text("out")
        (tmp_path / "log_asan.txt").write_text("crash")
        assert read_grizzly_logs(tmp_path) == Logs(
            stderr="err", stdout="out", crashdata="crash"
        )

    def test_multiple_files_concatenated(self, tmp_path: Path) -> None:
        """Concatenate multiple files that map to the same category."""
        (tmp_path / "log_stderr_0.txt").write_text("first")
        (tmp_path / "log_stderr_1.txt").write_text("second")
        result = read_grizzly_logs(tmp_path)
        assert "first" in result.stderr
        assert "second" in result.stderr

    def test_large_log_tail_truncated(self, tmp_path: Path) -> None:
        """Tail-truncate logs exceeding MAX_LOG_SIZE to exactly MAX_LOG_SIZE bytes."""
        content = "x" * (MAX_LOG_SIZE + 100)
        (tmp_path / "log_stderr.txt").write_text(content)
        result = read_grizzly_logs(tmp_path)
        assert len(result.stderr) == MAX_LOG_SIZE
        assert result.stderr == content[-MAX_LOG_SIZE:]


class TestPackageTestcase:
    def test_packages_files_prefs_and_env(self, tmp_path: Path) -> None:
        """Package a multi-file testcase with custom prefs and env vars."""
        tc_dir = tmp_path / "testcase"
        tc_dir.mkdir()
        (tc_dir / "test.html").write_text("<html><body>exploit</body></html>")
        js_dir = tc_dir / "js"
        js_dir.mkdir()
        (js_dir / "helper.js").write_text("alert(1);")

        custom_prefs: dict[str, str | int | bool] = {"dom.workers.enabled": False}
        env = {"MOZ_LOG": "all:5"}

        output = asyncio.run(
            package_testcase(tc_dir, "test.html", prefs=custom_prefs, env=env)
        )
        output_path = Path(output)

        assert output_path.is_dir()
        content = (output_path / "test.html").read_text()
        assert content == "<html><body>exploit</body></html>"
        assert (output_path / "js/helper.js").read_text() == "alert(1);"

        info = json.loads((output_path / "test_info.json").read_text())
        assert info["target"] == "test.html"
        assert info["adapter"] == "fx-audit"
        assert info["env"] == env
        assert info["assets"] == {"prefs": "prefs.js"}

        prefs_content = (output_path / "_assets_" / "prefs.js").read_text()
        assert "dom.workers.enabled" in prefs_content
        assert "browser.backup.enabled" in prefs_content

    def test_baseline_prefs_without_custom(self, tmp_path: Path) -> None:
        """Baseline prefs are included even when no custom prefs are given."""
        tc_dir = tmp_path / "testcase"
        tc_dir.mkdir()
        (tc_dir / "test.html").write_text("<html></html>")

        output = asyncio.run(package_testcase(tc_dir, "test.html"))
        output_path = Path(output)

        prefs_content = (output_path / "_assets_" / "prefs.js").read_text()
        assert "browser.backup.enabled" in prefs_content


class TestBrowserEvaluator:
    @pytest.mark.anyio
    async def test_missing_firefox_binary(self, tmp_path: Path) -> None:
        """Verify that a missing firefox binary raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Firefox binary not found"):
            await browser_evaluator(
                content="<html></html>",
                filename="test.html",
                firefox_binary=tmp_path / "no_firefox",
            )


class TestCollectDumpFiles:
    def test_empty_dir_returns_empty(self, tmp_path: Path) -> None:
        """No files under the dump dir → empty mapping."""
        assert not _collect_dump_files(tmp_path)

    def test_relative_paths_preserved(self, tmp_path: Path) -> None:
        """File paths are returned relative to the dump dir, not absolute."""
        (tmp_path / "test.html").write_text("<html>x</html>")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "nested.js").write_text("var y = 1;")
        files = _collect_dump_files(tmp_path)
        assert files == {
            "test.html": "<html>x</html>",
            "sub/nested.js": "var y = 1;",
        }

    def test_invalid_utf8_uses_replacement(self, tmp_path: Path) -> None:
        """Files with non-UTF-8 bytes are read with errors='replace'."""
        (tmp_path / "binary.bin").write_bytes(b"\xff\xfe\x80\x00ok")
        files = _collect_dump_files(tmp_path)
        # Replacement character (U+FFFD) appears at each invalid byte; the
        # trailing valid bytes survive.
        assert "ok" in files["binary.bin"]
        assert "�" in files["binary.bin"]


_ASAN_CRASHDATA = "==4242==ERROR: AddressSanitizer: x"


@pytest.mark.parametrize(
    ("parent_pid", "crashdata", "expected"),
    [
        (4242, _ASAN_CRASHDATA, True),
        (9999, _ASAN_CRASHDATA, False),
        (None, _ASAN_CRASHDATA, False),
        (4242, "Segmentation fault (core dumped)", False),
    ],
)
def test_crashed_parent(parent_pid: int | None, crashdata: str, expected: bool) -> None:
    """Verify that _crashed_parent returns True only when PIDs are known and match."""
    assert _crashed_parent(parent_pid, crashdata) is expected


@pytest.mark.parametrize(
    ("cmdline", "expected"),
    [
        (["/b/firefox", "-contentproc", "-childID", "1", "42", "tab"], "content"),
        (["/b/plugin-container", "-parentBuildID", "1", "2", "gpu"], "gpu"),
        (["/b/plugin-container", "-parentBuildID", "1", "4", "rdd"], "rdd"),
        (["/b/plugin-container", "-parentBuildID", "1", "1", "socket"], "socket"),
        (["/b/plugin-container", "-sandboxingKind", "0", "6", "utility"], "utility"),
        # Parent process: no trailing child type token.
        (["/b/firefox", "-foreground"], None),
        (["/b/firefox", "http://127.0.0.1:1234/test.html"], None),
        # Non-Gecko helper processes.
        (["/b/crashhelper", "26572", "pipe.26572"], None),
        ([], None),
    ],
)
def test_process_type_from_cmdline(cmdline: list[str], expected: str | None) -> None:
    """Verify the trailing Gecko process type token maps to a type name."""
    assert _process_type_from_cmdline(cmdline) == expected


# Sanitizer report carrying its own argv (ASAN_OPTIONS=print_cmdline=true);
# print_cmdline emits the args space-separated with a trailing space.
_ASAN_GPU_REPORT = (
    "==555==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\n"
    "    #0 0x7f in mozilla::gfx::Foo()\n"
    "SUMMARY: AddressSanitizer: SEGV\n"
    "\n"
    "Command: /b/plugin-container -parentBuildID 1 -prefsHandle 0:1 2 gpu \n"
)
_ASAN_PARENT_REPORT = (
    "==4242==ERROR: AddressSanitizer: heap-use-after-free\n"
    "SUMMARY: AddressSanitizer: heap-use-after-free\n"
    "\n"
    "Command: /b/firefox -no-remote http://127.0.0.1:1234/test.html \n"
)
_ASAN_NO_CMDLINE_REPORT = "==777==ERROR: AddressSanitizer: SEGV\nSUMMARY: x\n"


def _simplify(
    reports: list[CrashReport] | None,
) -> list[tuple[str, int]] | None:
    """Reduce CrashReports to (process_type, pid) tuples for assertions."""
    if reports is None:
        return None
    return [(r.process_type, r.pid) for r in reports]


class TestCrashReports:
    @pytest.mark.parametrize(
        ("parent_pid", "pid_types", "crashdata", "expected"),
        [
            # No ASAN PID marker at all.
            (4242, {}, "Segmentation fault (core dumped)", None),
            # Command: line in the report wins, no sampler data needed.
            (4242, {}, _ASAN_GPU_REPORT, [("gpu", 555)]),
            # Parent-style Command: line (no type token) falls back to the
            # parent PID match.
            (4242, {}, _ASAN_PARENT_REPORT, [("parent", 4242)]),
            # No Command: line: parent PID match.
            (777, {}, _ASAN_NO_CMDLINE_REPORT, [("parent", 777)]),
            # No Command: line: sampled process-tree map.
            (4242, {777: "rdd"}, _ASAN_NO_CMDLINE_REPORT, [("rdd", 777)]),
            # Crash PID present but never attributed.
            (4242, {888: "content"}, _ASAN_NO_CMDLINE_REPORT, [("unknown", 777)]),
            # Unknown parent PID and nothing else to go on.
            (None, {}, _ASAN_NO_CMDLINE_REPORT, [("unknown", 777)]),
        ],
    )
    def test_attribution(
        self,
        parent_pid: int | None,
        pid_types: dict[int, str],
        crashdata: str,
        expected: list[tuple[str, int]] | None,
    ) -> None:
        """Verify attribution priority: Command: line, parent PID, sampled map."""
        assert _simplify(_crash_reports(parent_pid, pid_types, crashdata)) == expected

    def test_multiple_reports_each_attributed(self) -> None:
        """Concatenated reports from different processes are attributed
        per-block; one report's Command: line must not bleed into another."""
        crashdata = _ASAN_NO_CMDLINE_REPORT + _ASAN_GPU_REPORT
        assert _simplify(_crash_reports(4242, {777: "content"}, crashdata)) == [
            ("content", 777),
            ("gpu", 555),
        ]

    def test_parent_and_child_crash_together(self) -> None:
        """A run where both a child and the parent crash yields both reports."""
        crashdata = _ASAN_GPU_REPORT + _ASAN_PARENT_REPORT
        assert _simplify(_crash_reports(4242, {}, crashdata)) == [
            ("gpu", 555),
            ("parent", 4242),
        ]

    def test_error_summary_extracted(self) -> None:
        """The report's header error line is carried on the CrashReport."""
        reports = _crash_reports(4242, {}, _ASAN_GPU_REPORT)
        assert reports is not None
        assert reports[0].error == (
            "AddressSanitizer: SEGV on unknown address 0x000000000000"
        )


@pytest.mark.parametrize(
    ("parent_pid", "pid_types", "expected"),
    [
        # Browser never launched: the tree was never sampled.
        (None, {}, None),
        # No GPU process observed (e.g. GPU process disabled).
        (4242, {10: "content"}, 0),
        # Single GPU process for the whole run: no restarts.
        (4242, {10: "content", 11: "gpu"}, 0),
        # Three distinct GPU PIDs: two respawns.
        (4242, {10: "gpu", 11: "content", 12: "gpu", 13: "gpu"}, 2),
    ],
)
def test_gpu_process_restarts(
    parent_pid: int | None, pid_types: dict[int, str], expected: int | None
) -> None:
    """Verify GPU respawn counting from the sampled pid -> type map."""
    assert _gpu_process_restarts(parent_pid, pid_types) == expected


class TestRecordChildProcessTypes:
    def test_records_recognized_children(self, mocker: MockerFixture) -> None:
        """Recognized Gecko children are recorded; helpers and vanished
        processes are skipped."""
        gpu = mocker.Mock(pid=10)
        gpu.cmdline.return_value = ["/b/plugin-container", "-x", "2", "gpu"]
        tab = mocker.Mock(pid=11)
        tab.cmdline.return_value = ["/b/plugin-container", "-childID", "1", "tab"]
        helper = mocker.Mock(pid=12)
        helper.cmdline.return_value = ["/b/crashhelper", "26572"]
        gone = mocker.Mock(pid=13)
        gone.cmdline.side_effect = NoSuchProcess(13)
        parent = mocker.patch.object(be_module, "Process")
        parent.return_value.children.return_value = [gpu, tab, helper, gone]
        pid_types: dict[int, str] = {}
        _record_child_process_types(1, pid_types)
        assert pid_types == {10: "gpu", 11: "content"}
        parent.return_value.children.assert_called_once_with(recursive=True)

    def test_existing_entries_kept_without_refetch(self, mocker: MockerFixture) -> None:
        """Already-recorded PIDs are not re-queried, so dead children keep
        their type across samples."""
        child = mocker.Mock(pid=10)
        child.cmdline.side_effect = AssertionError("must not be called")
        parent = mocker.patch.object(be_module, "Process")
        parent.return_value.children.return_value = [child]
        pid_types = {10: "gpu"}
        _record_child_process_types(1, pid_types)
        assert pid_types == {10: "gpu"}

    def test_parent_gone(self, mocker: MockerFixture) -> None:
        """A vanished parent process leaves the map untouched."""
        mocker.patch.object(be_module, "Process", side_effect=NoSuchProcess(1))
        pid_types: dict[int, str] = {}
        _record_child_process_types(1, pid_types)
        assert not pid_types


# MOZ_CRASH -> ASAN SEGV in whichever process hosts the document; needs the
# fuzzing.enabled pref.
_FUZZING_CRASH_HTML = """<!doctype html>
<script>
window.onload = () => { FuzzingFunctions.crash("attribution-check"); };
</script>
"""

# Hard-kills the GPU process via the parent (#ifdef FUZZING); the delay lets
# the sampler record the original GPU pid before it is replaced.
_GPU_KILL_HTML = """<!doctype html>
<script>
window.onload = () => setTimeout(() => FuzzingFunctions.killGPUProcess(), 2000);
</script>
"""


@pytest.mark.integration
@pytest.mark.anyio
async def test_no_crash_sampler_lifecycle_live() -> None:
    """A clean run: the sampler ran (gpu_process_restarts is an int) and
    the crash fields stay unset."""
    binary = os.environ.get("FIREFOX_BINARY", "")
    if not binary or not Path(binary).is_file():
        pytest.skip("FIREFOX_BINARY not set or not present")
    result = await browser_evaluator(
        content="<html><body>no crash</body></html>",
        filename="test.html",
        firefox_binary=Path(binary),
        # A no-crash verdict waits out the full window; keep it short — it
        # only needs child processes to spawn plus a few sampler ticks.
        timeout=10,
    )
    assert result.crashed is False
    assert result.crashed_parent is None
    assert result.crash_reports is None
    assert result.gpu_process_restarts == 0


@pytest.mark.integration
@pytest.mark.anyio
async def test_content_crash_attribution_live() -> None:
    """A content-process crash is attributed via the report's Command: line.

    Requires FIREFOX_BINARY pointing at an ASAN fuzzing build; run with:
    FIREFOX_BINARY=... uv run pytest -m integration
    """
    binary = os.environ.get("FIREFOX_BINARY", "")
    if not binary or not Path(binary).is_file():
        pytest.skip("FIREFOX_BINARY not set or not present")
    result = await browser_evaluator(
        content=_FUZZING_CRASH_HTML,
        filename="test.html",
        firefox_binary=Path(binary),
        timeout=90,
        prefs={"fuzzing.enabled": True},
    )
    assert result.crashed is True
    assert result.crashed_parent is False
    assert result.crash_reports is not None
    assert [r.process_type for r in result.crash_reports] == ["content"]
    # An int (not None) proves the process-tree sampler ran.
    assert result.gpu_process_restarts is not None
    assert result.logs is not None
    # The report PID links the attribution to its full stack in crashdata.
    assert f"=={result.crash_reports[0].pid}==ERROR:" in result.logs.crashdata
    command = re.search(r"^Command: (.+)$", result.logs.crashdata, re.MULTILINE)
    assert command is not None, "print_cmdline did not reach the crash log"
    assert command.group(1).split()[-1] == "tab"


@pytest.mark.integration
@pytest.mark.anyio
async def test_parent_crash_attribution_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parent-process crash is attributed via the parent-PID match.

    MOZ_FORCE_DISABLE_E10S puts the testcase document in the parent, so
    FuzzingFunctions.crash() crashes it; the parent's Command: line has no
    child-type token, forcing the PID-match path.
    """
    binary = os.environ.get("FIREFOX_BINARY", "")
    if not binary or not Path(binary).is_file():
        pytest.skip("FIREFOX_BINARY not set or not present")
    # Official builds honor the force-disable only when non-local
    # connections are also disabled.
    monkeypatch.setenv("MOZ_FORCE_DISABLE_E10S", "1")
    monkeypatch.setenv("MOZ_DISABLE_NONLOCAL_CONNECTIONS", "1")
    result = await browser_evaluator(
        content=_FUZZING_CRASH_HTML,
        filename="test.html",
        firefox_binary=Path(binary),
        timeout=90,
        prefs={"fuzzing.enabled": True},
    )
    assert result.crashed is True
    assert result.crashed_parent is True
    assert result.crash_reports is not None
    assert [r.process_type for r in result.crash_reports] == ["parent"]
    assert result.logs is not None
    assert f"=={result.crash_reports[0].pid}==ERROR:" in result.logs.crashdata


@pytest.mark.integration
@pytest.mark.anyio
async def test_gpu_process_restart_detected_live() -> None:
    """A silent GPU process death (no sanitizer log) surfaces as a restart.

    The GPU process is default-off on Linux, so it is pref-forced;
    killGPUProcess() leaves no crash data, so detection relies entirely on
    the process-tree sampler seeing a second GPU pid.
    """
    binary = os.environ.get("FIREFOX_BINARY", "")
    if not binary or not Path(binary).is_file():
        pytest.skip("FIREFOX_BINARY not set or not present")
    result = await browser_evaluator(
        content=_GPU_KILL_HTML,
        filename="test.html",
        firefox_binary=Path(binary),
        timeout=20,
        prefs={
            "fuzzing.enabled": True,
            "layers.gpu-process.enabled": True,
            "layers.gpu-process.force-enabled": True,
        },
    )
    assert result.crashed is False
    assert result.crash_reports is None
    assert result.gpu_process_restarts == 1
    assert "GPU process restarted" in result.message


class TestIgnoredSignatures:
    def test_missing_directory_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No signatures are loaded when the configured directory is absent."""
        monkeypatch.setattr(
            be_module,
            "IGNORED_SIGNATURES_DIR",
            tmp_path / "missing",
        )
        assert _load_ignored_signatures() == []

    def test_only_json_files_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-.json files in the directory are skipped."""
        sig_dir = tmp_path / "sigs"
        sig_dir.mkdir()
        (sig_dir / "real.json").write_text(
            '{"symptoms": [{"type": "output", "src": "stderr", "value": "x"}]}'
        )
        (sig_dir / "ignore.txt").write_text("not a signature")
        monkeypatch.setattr(be_module, "IGNORED_SIGNATURES_DIR", sig_dir)
        sigs = _load_ignored_signatures()
        assert len(sigs) == 1
