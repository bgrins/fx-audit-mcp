"""Evaluate testcase tool for testing vulnerabilities in Firefox."""

from __future__ import annotations

import os
import re
import sys
import tempfile
import threading
from logging import ERROR, getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Any

from FTB.Signatures.CrashSignature import CrashSignature
from grizzly.common.storage import TestCase
from grizzly.replay.replay import ReplayManager
from grizzly.target import TargetLaunchTimeout
from grizzly.target.firefox_target import FirefoxTarget
from prefpicker import PrefPicker
from psutil import Error as PsutilError
from psutil import Process
from sapphire import Sapphire

from .models import BrowserCrashInfo, CrashReport, Logs

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from grizzly.common.report import Report

MAX_LOG_SIZE = 1_048_576  # bytes; logs are tail-truncated to this limit
IGNORED_SIGNATURES_DIR = Path(__file__).parent / "ignored_signatures"

# Seconds between samples of the Firefox process tree (pid -> process type).
_PROCESS_SAMPLE_INTERVAL = 0.25

# ASAN report header: ==PID==ERROR: AddressSanitizer: ...
_ASAN_ERROR_RE = re.compile(r"==(\d+)==ERROR: ?([^\n]*)")

# Gecko children carry their GeckoProcessType string as the final argv token
# (GeckoChildProcessHost); the parent has no such token. Token -> reported name.
_GECKO_CHILD_TYPES: dict[str, str] = {
    "forkserver": "forkserver",
    "gmplugin": "gmplugin",
    "gpu": "gpu",
    "ipdlunittest": "ipdlunittest",
    "rdd": "rdd",
    "socket": "socket",
    "tab": "content",
    "utility": "utility",
    "vr": "vr",
}

# Suppress grizzly's verbose logging (but allow CRITICAL and ERROR)
getLogger("grizzly").setLevel(ERROR)
getLogger("ffpuppet").setLevel(ERROR)
getLogger("sapphire").setLevel(ERROR)

# Baseline prefs written to every profile launched by browser_evaluator.
# Quiets log spam and prevents network calls that slow down or noise up runs.
_BASELINE_PREFS: dict[str, str | int | bool] = {
    # Disable BackupService (errors about Documents directory)
    "browser.backup.enabled": False,
    # Prevent activity stream feeds from initializing (CDN errors)
    "browser.newtabpage.activity-stream.testing.shouldInitializeFeeds": False,
    # Disable region detection network fetch
    "browser.region.network.url": "",
    "browser.region.update.enabled": False,
    # Disable Merino/URLBar suggestion fetches
    "browser.urlbar.merino.endpointURL": "",
    "browser.urlbar.quicksuggest.enabled": False,
    # Disable system addon and addon repository updates
    "extensions.blocklist.enabled": False,
    # Disable built-in WebExtensions to avoid "context not found" spam
    "extensions.formautofill.addresses.enabled": False,
    "extensions.formautofill.creditCards.enabled": False,
    "extensions.getAddons.cache.enabled": False,
    "extensions.installDistroAddons": False,
    "extensions.systemAddon.update.enabled": False,
    "extensions.update.enabled": False,
    "extensions.webcompat.enabled": False,
    # Disable GMP plugin downloads (OpenH264, Widevine)
    "media.gmp-manager.updateEnabled": False,
    # Quiet remote settings logging and prevent network hits
    "messaging-system.log": "off",
    "services.settings.loglevel": "off",
    "services.settings.server": "data:,#remote-settings-dummy/v1",
}


class _FxAuditFirefoxTarget(FirefoxTarget):
    """Firefox target that records the parent PID and child process types.

    A background thread samples the process tree under the parent PID while
    the browser runs, so a crashed (or silently replaced) child can still be
    attributed to a Firefox process type after it is gone.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover
        super().__init__(*args, **kwargs)
        self.parent_pid: int | None = None
        # pid -> process type for every child ever observed; never evicted.
        self.process_types: dict[int, str] = {}
        self._sampler_stop = threading.Event()
        self._sampler: threading.Thread | None = None
        # Set when launch() catches TargetLaunchTimeout; caller is responsible
        # for reading the report's path and calling its cleanup().
        self.launch_timeout_report: Report | None = None

    def launch(self, location: str) -> None:  # pragma: no cover
        """Override to capture the parent PID and start the type sampler."""
        try:
            super().launch(location)
        except TargetLaunchTimeout:
            # Save logs so caller can surface them; grizzly's launch path
            # discards logs for timeouts (unlike TargetLaunchError).
            self.launch_timeout_report = self.create_report(is_hang=True)
            raise
        # Capture parent PID immediately after launch
        if hasattr(self, "_puppet"):
            self.parent_pid = self._puppet.get_pid()
        if self.parent_pid is not None and self._sampler is None:
            # Fresh Event per launch so a wedged old sampler can't be revived.
            self._sampler_stop = threading.Event()
            self._sampler = threading.Thread(
                target=self._sample_loop,
                args=(self.parent_pid, self._sampler_stop),
                daemon=True,
            )
            self._sampler.start()

    def _sample_loop(
        self, parent_pid: int, stop: threading.Event
    ) -> None:  # pragma: no cover
        while not stop.is_set():
            _record_child_process_types(parent_pid, self.process_types)
            stop.wait(_PROCESS_SAMPLE_INTERVAL)

    def _stop_sampler(self) -> None:  # pragma: no cover
        self._sampler_stop.set()
        if self._sampler is not None:
            self._sampler.join(timeout=5)
            self._sampler = None

    def close(self, force_close: bool = False) -> None:  # pragma: no cover
        """Override to stop the sampler before the browser goes away."""
        self._stop_sampler()
        super().close(force_close=force_close)

    def _cleanup(self) -> None:  # pragma: no cover
        """Override to stop the sampler in case close() was never reached."""
        self._stop_sampler()
        super()._cleanup()


def _extract_crash_pid(crashdata: str) -> int | None:
    """Extract the crashing process PID from ASAN output.

    Args:
        crashdata: ASAN crash output.

    Returns:
        PID of the crashing process, or None if no ASAN PID marker is present.
    """
    match = _ASAN_ERROR_RE.search(crashdata)
    if match:
        return int(match.group(1))
    return None


def _crashed_parent(parent_pid: int | None, crashdata: str) -> bool:
    """Return True when the ASAN crashdata PID matches the known parent PID."""
    crash_pid = _extract_crash_pid(crashdata)
    return parent_pid is not None and crash_pid is not None and crash_pid == parent_pid


def _process_type_from_cmdline(cmdline: Sequence[str]) -> str | None:
    """Map argv to a Gecko child type name; None if there is no child token."""
    if not cmdline:
        return None
    return _GECKO_CHILD_TYPES.get(cmdline[-1])


def _record_child_process_types(parent_pid: int, pid_types: dict[int, str]) -> None:
    """One sampler tick: record types for the live children of *parent_pid*.

    Entries accumulate and are never evicted, so crashed or silently
    replaced children remain attributable after they are gone.
    """
    try:
        children = Process(parent_pid).children(recursive=True)
    except PsutilError:
        return
    for child in children:
        if child.pid in pid_types:
            continue
        try:
            child_type = _process_type_from_cmdline(child.cmdline())
        except PsutilError:
            continue  # child went away mid-sample
        if child_type is not None:
            pid_types[child.pid] = child_type


def _crash_reports(
    parent_pid: int | None,
    pid_types: Mapping[int, str],
    crashdata: str,
) -> list[CrashReport] | None:
    """Attribute every sanitizer report in *crashdata* to a process.

    One ASAN report per crashing process; grizzly concatenates the log
    files, so report order is file order, not chronological. Per block,
    attribution is the report's own ``Command:`` line (from the injected
    print_cmdline=true), then the parent PID, then the sampled process-tree
    map, else "unknown". Returns None when *crashdata* has no ASAN PID
    marker.
    """
    headers = list(_ASAN_ERROR_RE.finditer(crashdata))
    if not headers:
        return None
    reports: list[CrashReport] = []
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(crashdata)
        block = crashdata[header.start() : end]
        command = re.search(r"^Command: (.+)$", block, re.MULTILINE)
        block_type = (
            _process_type_from_cmdline(command.group(1).split())
            if command is not None
            else None
        )
        crash_pid = int(header.group(1))
        if block_type is None:
            if parent_pid is not None and crash_pid == parent_pid:
                block_type = "parent"
            else:
                block_type = pid_types.get(crash_pid, "unknown")
        reports.append(
            CrashReport(
                process_type=block_type,
                pid=crash_pid,
                error=header.group(2).strip(),
            )
        )
    return reports


def _gpu_process_restarts(
    parent_pid: int | None,
    pid_types: Mapping[int, str],
) -> int | None:
    """Return distinct GPU PIDs seen minus one, or None when never sampled.

    Firefox keeps at most one GPU process alive, so a second GPU PID means
    an earlier one died and was replaced — even without a sanitizer log.
    """
    if parent_pid is None:
        return None
    # Snapshot: the sampler thread may still be writing if its join timed out.
    gpu_seen = sum(1 for ptype in list(pid_types.values()) if ptype == "gpu")
    return max(0, gpu_seen - 1)


def _collect_dump_files(dump_dir: Path) -> dict[str, str]:
    """Read all files under *dump_dir* into a relative-path → contents dict.

    Paths in the returned mapping use forward slashes regardless of platform
    so downstream consumers (LLM agents, packaged testcases) see portable
    keys.

    Args:
        dump_dir: Directory containing files dumped by grizzly's testcase.dump().

    Returns:
        Mapping of file path (POSIX-style, relative to *dump_dir*) to file
        contents, decoded as UTF-8 with replacement for invalid sequences.
    """
    files: dict[str, str] = {}
    for file_path in dump_dir.rglob("*"):
        if file_path.is_file():
            relative_name = file_path.relative_to(dump_dir)
            with file_path.open(encoding="utf-8", errors="replace") as f:
                files[relative_name.as_posix()] = f.read()
    return files


def _load_ignored_signatures() -> list[CrashSignature]:
    """Load FuzzManager crash signatures from the ignored_signatures directory.

    Returns:
        List of CrashSignature instances loaded from each ``*.json`` file in
        IGNORED_SIGNATURES_DIR (empty if the directory does not exist).
    """
    if not IGNORED_SIGNATURES_DIR.is_dir():
        return []
    return [
        CrashSignature.fromFile(p)
        for p in sorted(IGNORED_SIGNATURES_DIR.glob("*.json"))
    ]


def read_grizzly_logs(log_dir: Path) -> Logs:
    """Categorize log_*.txt files in *log_dir* into stderr/stdout/crashdata.

    Files larger than MAX_LOG_SIZE are tail-truncated.

    Args:
        log_dir: Directory containing log_*.txt files emitted by grizzly.

    Returns:
        Logs with stderr, stdout, and crashdata populated from matched files.
    """
    logs: dict[str, str] = {"stderr": "", "stdout": "", "crashdata": ""}

    for log_path in log_dir.glob("log_*.txt"):
        with log_path.open(encoding="utf-8", errors="replace") as f:
            size = log_path.stat().st_size
            if size > MAX_LOG_SIZE:
                f.seek(size - MAX_LOG_SIZE)
            log_content = f.read()
            log_name = log_path.name.lower()
            if "stderr" in log_name:
                logs["stderr"] += log_content
            elif "stdout" in log_name:
                logs["stdout"] += log_content
            else:
                logs["crashdata"] += log_content

    return Logs(**logs)


async def package_testcase(
    testcase_path: Path,
    entry_point: str,
    prefs: dict[str, str | int | bool] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Bundle a Firefox crash reproducer directory (HTML/JS files plus prefs
    and env) into a replayable grizzly TestCase suitable for browser_evaluator
    or the standalone grizzly replay tool.

    Custom prefs are merged on top of the prefpicker browser-fuzzing template
    and the baseline prefs; the emitted prefs.js holds the full effective set.

    Args:
        testcase_path: Path to a directory containing all files in the testcase
            (e.g. ``/tmp/my-testcase``).
        entry_point: Filename within ``testcase_path`` that the browser loads
            first; must exist in ``testcase_path`` (e.g. ``test.html``).
        prefs: Optional custom Firefox preferences to layer on top of the
            baseline (e.g. ``{"dom.workers.enabled": False}``).
        env: Optional environment variables to record on the bundled testcase
            (e.g. ``{"MOZ_LOG": "ConsoleAPI:5"}``).

    Returns:
        Path to the bundled grizzly testcase directory.
    """
    testcase = TestCase(
        entry_point=entry_point,
        adapter_name="fx-audit",
        input_fname=entry_point,
    )

    try:
        for file_path in testcase_path.rglob("*"):
            if not file_path.is_file():
                continue
            relative_name = file_path.relative_to(testcase_path).as_posix()
            is_entry = relative_name == entry_point
            testcase.add_from_file(
                file_path,
                file_name=relative_name,
                required=is_entry,
            )

        merged_prefs: dict[str, str | int | bool] = dict(_BASELINE_PREFS)
        if prefs:
            merged_prefs.update(prefs)

        assets_dir = Path(tempfile.mkdtemp(prefix="fx_audit_assets_"))
        prefs_path = assets_dir / "prefs.js"
        template = PrefPicker.lookup_template("browser-fuzzing.yml")
        assert template is not None
        PrefPicker.load_template(template).create_prefsjs(
            prefs_path,
            additional_prefs=merged_prefs,
        )
        testcase.assets = {"prefs": "prefs.js"}
        testcase.assets_path = assets_dir

        if env:
            testcase.env_vars = dict(env)

        output_dir = Path(tempfile.mkdtemp(prefix="fx_audit_pkg_"))
        testcase.dump(output_dir, include_details=True)
    finally:
        testcase.cleanup()

    return str(output_dir)


async def browser_evaluator(  # pragma: no cover
    content: str,
    filename: str,
    firefox_binary: Path,
    timeout: int = 30,
    prefs: dict[str, str | int | bool] | None = None,
) -> BrowserCrashInfo:
    """Reproduce a Firefox crash by running an HTML/JS testcase under
    ASAN-instrumented Firefox and reporting any crash detected.

    Testcases are served over HTTP.

    On Linux, Firefox uses Xvfb (virtual framebuffer X server) as its display.
    On other platforms, the OS default display is used (visible window).

    The following environment variables are always set on the browser process:
    - MOZ_LOG=console:5,PageMessages:5
    - ASAN_OPTIONS/UBSAN_OPTIONS gain print_cmdline=true (appended to any
      existing value) so sanitizer reports identify the crashing process

    The ``prefs`` argument is merged on top of a hardened baseline of Firefox
    prefs; caller-supplied values override the baseline.

    Every sanitizer report in the crash data is attributed to a Firefox
    process in ``crash_reports`` (process_type "parent", "content", "gpu",
    "rdd", "socket", "utility", ...; pid locates the full stack in
    ``logs.crashdata``), and silent GPU process deaths (death + respawn
    without a sanitizer log) surface in ``gpu_process_restarts``.

    The browser launch timeout defaults to 30 seconds; set the
    FX_AUDIT_LAUNCH_TIMEOUT environment variable (seconds) for slow
    environments such as emulated CI containers.

    Ignored-signature matches (loaded from ``ignored_signatures/``) are
    filtered out before this returns. Captured logs are tail-truncated to
    MAX_LOG_SIZE. On crash, the dumped testcase directory contents are
    returned alongside the logs.

    Args:
        content: Testcase file contents as a string, not a path on disk.
        filename: Filename to give the testcase when written to disk; controls
            the extension Firefox uses to dispatch the file.
        firefox_binary: Absolute path to the Firefox binary.
        timeout: Per-run timeout in seconds before closing the browser.
        prefs: Optional custom Firefox prefs to layer on top of the baseline.
    """
    if not firefox_binary.exists():
        raise FileNotFoundError(f"Firefox binary not found at {firefox_binary}")

    testcase = TestCase(
        entry_point=filename,
        adapter_name="fx-audit",
        input_fname=filename,
    )

    # Add testcase content from bytes (creates temp file internally)
    testcase.add_from_bytes(content.encode("utf-8"), filename, required=True)

    # Use our custom target to capture parent PID
    # xvfb is only available on Linux; use default display mode on other platforms
    display_mode = "xvfb" if sys.platform == "linux" else "default"
    try:
        launch_timeout = max(1, int(os.environ.get("FX_AUDIT_LAUNCH_TIMEOUT", "30")))
    except ValueError:
        launch_timeout = 30
    target = _FxAuditFirefoxTarget(
        binary=firefox_binary,
        display_mode=display_mode,
        launch_timeout=launch_timeout,
        log_limit=0,
        memory_limit=0,
    )

    # Enable verbose logging
    target.environ["MOZ_LOG"] = "console:5,PageMessages:5"

    # Minimize log spam from mesa
    target.environ["EGL_LOG_LEVEL"] = "fatal"

    # print_cmdline=true puts each crashing process's own argv ("Command:"
    # line) in its report, so attribution works even for children too
    # short-lived for the sampler. ffpuppet adds its defaults around this.
    for var in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):
        existing = target.environ.get(var)
        target.environ[var] = (
            f"{existing}:print_cmdline=true" if existing else "print_cmdline=true"
        )

    # Always generate prefs.js from prefpicker template with hardcoded
    # baseline prefs, plus any user-supplied custom prefs on top.
    # These are set on the target profile (not the testcase) so they
    # don't appear in testcase dump output.
    merged_prefs = {**_BASELINE_PREFS, **prefs} if prefs else _BASELINE_PREFS
    with tempfile.TemporaryDirectory(prefix="fx_audit_prefs_") as prefs_dir:
        prefs_path = Path(prefs_dir) / "prefs.js"
        template = PrefPicker.lookup_template("browser-fuzzing.yml")
        assert template is not None
        PrefPicker.load_template(template).create_prefsjs(
            prefs_path,
            additional_prefs=merged_prefs,
        )
        target.asset_mgr.add("prefs", prefs_path)

    # Process assets (prefs, etc.) - required for Firefox to launch properly
    target.process_assets()

    results = []
    try:
        with Sapphire(auto_close=1) as server:
            target.reverse(server.port, server.port)
            with ReplayManager(
                ignore=frozenset(["timeout"]),
                server=server,
                target=target,
                ignore_signatures=_load_ignored_signatures(),
                use_harness=False,
            ) as replay:
                try:
                    results = replay.run(
                        testcases=[testcase],
                        time_limit=timeout,
                        expect_hang=False,
                    )
                except TargetLaunchTimeout:
                    if target.launch_timeout_report is None:
                        raise
                    logs = read_grizzly_logs(target.launch_timeout_report.path)
                    # A child process (content/GPU/etc.) can crash with ASAN
                    # while the parent stays alive and the bootstrap times out.
                    if logs.crashdata:
                        return BrowserCrashInfo(
                            crashed=True,
                            crashed_parent=_crashed_parent(
                                target.parent_pid, logs.crashdata
                            ),
                            crash_reports=_crash_reports(
                                target.parent_pid,
                                target.process_types,
                                logs.crashdata,
                            ),
                            gpu_process_restarts=_gpu_process_restarts(
                                target.parent_pid, target.process_types
                            ),
                            files={},
                            logs=logs,
                            message="Crash detected",
                        )
                    return BrowserCrashInfo(
                        crashed=False,
                        message=(
                            "Firefox failed to launch within the timeout - "
                            "check logs for the underlying cause"
                        ),
                        logs=logs,
                    )

        gpu_restarts = _gpu_process_restarts(target.parent_pid, target.process_types)

        if not results:
            with tempfile.TemporaryDirectory(prefix="fx_audit_logs_") as log_dir_str:
                log_dir = Path(log_dir_str)
                target.save_logs(log_dir)
                message = (
                    "No crash detected - check logs for clues "
                    "about why the testcase didn't trigger the vulnerability"
                )
                if gpu_restarts:
                    message += (
                        f"; however, the GPU process restarted {gpu_restarts} "
                        "time(s) - possible silent GPU process death"
                    )
                return BrowserCrashInfo(
                    crashed=False,
                    message=message,
                    gpu_process_restarts=gpu_restarts,
                    logs=read_grizzly_logs(log_dir),
                )

        result_obj = results[0]
        report = result_obj.report
        with tempfile.TemporaryDirectory(prefix="fx_audit_dump_") as dump_dir_str:
            dump_dir = Path(dump_dir_str)
            testcase.dump(dump_dir, include_details=True)
            logs = read_grizzly_logs(report.path)
            return BrowserCrashInfo(
                crashed=True,
                crashed_parent=_crashed_parent(target.parent_pid, logs.crashdata),
                crash_reports=_crash_reports(
                    target.parent_pid, target.process_types, logs.crashdata
                ),
                gpu_process_restarts=gpu_restarts,
                files=_collect_dump_files(dump_dir),
                logs=logs,
                message="Crash detected",
            )

    finally:
        testcase.cleanup()
        if target.launch_timeout_report is not None:
            target.launch_timeout_report.cleanup()
        target.cleanup()
        for result_obj in results:
            result_obj.report.cleanup()
