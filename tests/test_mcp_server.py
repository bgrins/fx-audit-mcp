"""Tests for mcp_server.py."""

import inspect
from typing import TYPE_CHECKING

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.browser_evaluator import browser_evaluator
from fx_audit_mcp.mcp_server import _parse_args, create_server, main

if TYPE_CHECKING:
    from unittest.mock import MagicMock

EXPECTED_TOOLS = {
    "browser_evaluator",
    "package_testcase",
    "js_shell_evaluator",
    "build_firefox",
    "build_nss",
    "nss_gtest_evaluator",
}


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "FX_AUDIT_TRANSPORT",
        "FX_AUDIT_HOST",
        "FX_AUDIT_PORT",
        "FX_AUDIT_DISABLED_TOOLS",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.anyio
@pytest.mark.usefixtures("clean_env")
async def test_all_tools_registered() -> None:
    """All execution tools are registered by default."""
    registered = {t.name for t in await create_server().list_tools()}
    assert registered == EXPECTED_TOOLS


@pytest.mark.anyio
async def test_disabled_tools_env_skips_registration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tools named in FX_AUDIT_DISABLED_TOOLS are not registered."""
    monkeypatch.setenv("FX_AUDIT_DISABLED_TOOLS", "build_firefox, build_nss")
    registered = {t.name for t in await create_server().list_tools()}
    assert registered == EXPECTED_TOOLS - {"build_firefox", "build_nss"}


def test_unknown_disabled_tool_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unknown tool names in FX_AUDIT_DISABLED_TOOLS raise ValueError."""
    monkeypatch.setenv("FX_AUDIT_DISABLED_TOOLS", "not_a_tool")
    with pytest.raises(ValueError, match="not_a_tool"):
        create_server()


class TestBrowserEvaluatorSchema:
    @pytest.mark.anyio
    @pytest.mark.usefixtures("clean_env")
    async def test_docstring_prose_preserved_in_mcp_schema(self) -> None:
        """Verify the browser_evaluator prose docstring appears in the MCP schema."""
        assert browser_evaluator.__doc__ is not None
        # cleandoc to normalize indentation: Python 3.13 strips common leading
        # whitespace from __doc__ at compile time (PEP 257), 3.12 does not.
        prose = (
            inspect.cleandoc(browser_evaluator.__doc__)
            .split("Args:", maxsplit=1)[0]
            .strip()
        )
        tool = await create_server().get_tool("browser_evaluator")
        assert tool is not None
        description: str = tool.to_mcp_tool().model_dump()["description"]
        assert prose == description


@pytest.mark.usefixtures("clean_env")
def test_keyboard_interrupt_exits_zero(mocker: MockerFixture) -> None:
    """KeyboardInterrupt causes main() to exit 0."""
    server: MagicMock = mocker.MagicMock()
    server.run.side_effect = KeyboardInterrupt
    mocker.patch("fx_audit_mcp.mcp_server.create_server", return_value=server)
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 0


@pytest.mark.usefixtures("clean_env")
def test_unexpected_exception_exits_nonzero(
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unexpected exceptions cause main() to exit 1 with an error message."""
    server: MagicMock = mocker.MagicMock()
    server.run.side_effect = RuntimeError("boom")
    mocker.patch("fx_audit_mcp.mcp_server.create_server", return_value=server)
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 1
    assert "boom" in capsys.readouterr().err


def test_bad_disabled_tools_env_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A typo in FX_AUDIT_DISABLED_TOOLS is reported cleanly, not a traceback."""
    monkeypatch.setenv("FX_AUDIT_DISABLED_TOOLS", "build_firfox")
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 1
    assert "build_firfox" in capsys.readouterr().err


@pytest.mark.usefixtures("clean_env")
def test_parse_args_defaults() -> None:
    """Without flags or env vars, defaults are stdio on 127.0.0.1:8000."""
    args = _parse_args([])
    assert args.transport == "stdio"
    assert args.host == "127.0.0.1"
    assert args.port == 8000


def test_parse_args_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """FX_AUDIT_* env vars provide defaults."""
    monkeypatch.setenv("FX_AUDIT_TRANSPORT", "http")
    monkeypatch.setenv("FX_AUDIT_HOST", "0.0.0.0")
    monkeypatch.setenv("FX_AUDIT_PORT", "9000")
    args = _parse_args([])
    assert (args.transport, args.host, args.port) == ("http", "0.0.0.0", 9000)


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("FX_AUDIT_TRANSPORT", "streamable-http"),
        ("FX_AUDIT_PORT", "not-a-port"),
    ],
)
def test_invalid_env_values_exit_with_usage_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    var: str,
    value: str,
) -> None:
    """Malformed env-provided defaults produce a clean usage error, exit 2."""
    monkeypatch.setenv(var, value)
    with pytest.raises(SystemExit) as exc_info:
        _parse_args([])
    assert exc_info.value.code == 2
    assert value in capsys.readouterr().err


@pytest.mark.parametrize(
    ("argv", "expected_kwargs"),
    [
        ([], {"transport": "stdio", "show_banner": False}),
        (
            ["--transport", "http", "--host", "0.0.0.0", "--port", "9000"],
            {
                "transport": "http",
                "host": "0.0.0.0",
                "port": 9000,
                "show_banner": False,
            },
        ),
    ],
)
@pytest.mark.usefixtures("clean_env")
def test_main_passes_transport_to_run(
    mocker: MockerFixture,
    argv: list[str],
    expected_kwargs: dict[str, object],
) -> None:
    """main() forwards the selected transport configuration to the server."""
    server: MagicMock = mocker.MagicMock()
    mocker.patch("fx_audit_mcp.mcp_server.create_server", return_value=server)
    main(argv)
    server.run.assert_called_once_with(**expected_kwargs)
