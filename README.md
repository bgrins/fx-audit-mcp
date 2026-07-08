# fx-audit-mcp

MCP tools for Firefox security auditing. Provides async Python tools and a
FastMCP server for running testcases in Firefox and SpiderMonkey, building
Firefox and NSS with ASAN, and querying Bugzilla — all with structured
Pydantic return types suitable for use with LLM agent frameworks.

## Tools

| Tool | Description |
|------|-------------|
| `browser_evaluator` | Run a testcase in ASAN Firefox via grizzly replay, detect crashes |
| `package_testcase` | Bundle a testcase directory with prefs and env into a grizzly TestCase |
| `js_shell_evaluator` | Run a JS testcase in the SpiderMonkey shell, detect crashes and sanitizer output |
| `nss_gtest_evaluator` | Run an NSS GTest and report any ASan crash |
| `build_firefox` | Build Firefox via `mach build` with a specified MOZCONFIG |
| `build_nss` | Build NSS with ASAN via `security/nss/build.sh` |
| `search_bugs` | Search Bugzilla using raw REST query parameters |
| `get_bugs` | Fetch bugs by ID in bulk |
| `get_bug_comments` | Fetch all comments for a single bug |
| `get_bug_attachments` | Fetch attachments for a bug |

## Installation

```bash
pip install fx-audit-mcp
```

Requires Python 3.12+.

## Usage

### As Python functions

The execution tools (browser, JS shell, NSS gtest, Firefox/NSS build) are
async functions with structured Pydantic return types. The Bugzilla tools
are only available via the MCP server (see below).

```python
import asyncio
from pathlib import Path
from fx_audit_mcp import browser_evaluator, js_shell_evaluator

async def main():
    result = await browser_evaluator(
        content="<script>crashMe()</script>",
        filename="test.html",
        firefox_binary=Path("/path/to/obj-firefox-asan/dist/bin/firefox"),
        timeout=30,
    )
    print(result.crashed, result.message)
    if result.logs:
        print(result.logs.crashdata[:500])

asyncio.run(main())
```

### As an MCP server

`fx-audit-mcp` exposes all execution tools (browser, JS shell, NSS gtest,
Firefox/NSS build) as an MCP server over stdio:

```bash
fx-audit-mcp
```

It can also serve streamable HTTP (MCP endpoint at `/mcp`):

```bash
fx-audit-mcp --transport http --host 0.0.0.0 --port 8000
```

`--transport`, `--host`, and `--port` default from `FX_AUDIT_TRANSPORT`,
`FX_AUDIT_HOST`, and `FX_AUDIT_PORT`.

`fx-audit-bugzilla-mcp` exposes the Bugzilla query tools separately:

```bash
BUGZILLA_API_KEY=your_key fx-audit-bugzilla-mcp
```

Set `BUGZILLA_URL` to override the default Mozilla Bugzilla instance.

**Claude Desktop / Claude Code `.mcp.json` example:**

```json
{
  "mcpServers": {
    "fx-audit": {
      "command": "fx-audit-mcp",
      "env": {
        "FIREFOX_SOURCE_ROOT": "/path/to/firefox",
        "FIREFOX_BINARY": "/path/to/firefox/obj-firefox-asan/dist/bin/firefox"
      }
    },
    "fx-audit-bugzilla": {
      "command": "fx-audit-bugzilla-mcp",
      "env": {
        "BUGZILLA_API_KEY": "your_key_here"
      }
    }
  }
}
```

### With fuzzfetch builds (no local Firefox build needed)

Instead of building Firefox locally, fetch a CI ASAN fuzzing build with
[fuzzfetch](https://github.com/MozillaSecurity/fuzzfetch). Firefox CI
publishes these natively for macOS on Apple Silicon (`macosx-arm64
fuzzing-asan-opt`) as well as linux/windows x86_64:

```bash
# ASAN fuzzing browser + JS shell from the same mozilla-central build task
uvx fuzzfetch --target firefox js --asan --fuzzing -n firefox-asan -o builds
```

Then serve the tools over HTTP (or omit the flags for stdio):

```bash
FIREFOX_BINARY=$PWD/builds/firefox-asan/Nightly.app/Contents/MacOS/firefox \
uvx fx-audit-mcp --transport http --port 8000
```

The MCP endpoint is `http://localhost:8000/mcp`. Pass the fetched paths to
the tools: `firefox_binary=builds/firefox-asan/Nightly.app/Contents/MacOS/firefox`
(on linux: `builds/firefox-asan/firefox`) for `browser_evaluator`, and
`js_binary=builds/firefox-asan/dist/bin/js` for `js_shell_evaluator` — the
evaluator puts the shell's bundled libraries on the library path
automatically. On macOS the browser opens visible windows (xvfb is
linux-only).

For a debug JS shell (assertions instead of ASAN reports), fetch the fuzzing
debug build separately:

```bash
uvx fuzzfetch --target js --fuzzing --debug -n js-debug -o builds
```

On macOS the fetched shells link the clang sanitizer runtime via `@rpath`
but don't ship it, so export a local copy before starting the server (the
`~/.mozbuild` toolchain matches the CI clang; Xcode's
`$(clang -print-resource-dir)/lib/darwin` also works):

```bash
export DYLD_LIBRARY_PATH=$(ls -d ~/.mozbuild/clang/lib/clang/*/lib/darwin)
```

Any MCP client can then submit testcases against the fetched builds:

```python
from fastmcp import Client

async with Client("http://127.0.0.1:8000/mcp") as client:
    result = await client.call_tool("js_shell_evaluator", {
        "content": "print(1 + 1)",
        "js_binary": "builds/js-debug/dist/bin/js",
        "timeout": 30,
    })
    print(result.data.crashed, result.data.message, result.data.logs.stdout)
```

Note that the build tools (`build_firefox`, `build_nss`, and
`nss_gtest_evaluator`) still need a source checkout; disable them with
`FX_AUDIT_DISABLED_TOOLS=build_firefox,build_nss,nss_gtest_evaluator` when
serving fuzzfetch builds only.

### With pydantic-ai

Tools integrate directly with pydantic-ai agents:

```python
from pydantic_ai import Agent
from fx_audit_mcp import browser_evaluator, js_shell_evaluator

agent = Agent(
    "anthropic:claude-opus-4-7",
    tools=[browser_evaluator, js_shell_evaluator],
)
```

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `BUGZILLA_API_KEY` | `fx-audit-bugzilla-mcp` | Required; your Bugzilla API key |
| `BUGZILLA_URL` | `fx-audit-bugzilla-mcp` | Bugzilla REST base URL (default: Mozilla's) |
| `FIREFOX_SOURCE_ROOT` | `fx-audit-build-firefox` | Default `--firefox-dir` for the CLI entry point |
| `FX_AUDIT_TRANSPORT` | `fx-audit-mcp` | Default `--transport` (`stdio` or `http`) |
| `FX_AUDIT_HOST` | `fx-audit-mcp` | Default `--host` for HTTP transport |
| `FX_AUDIT_PORT` | `fx-audit-mcp` | Default `--port` for HTTP transport |
| `FX_AUDIT_DISABLED_TOOLS` | `fx-audit-mcp` | Comma-separated tool names to not register |
| `FX_AUDIT_LAUNCH_TIMEOUT` | `browser_evaluator` | Default for the `launch_timeout` tool parameter (seconds to wait for browser startup, default 30) |

## Crash Detection

- **browser_evaluator**: Crash signatures in `ignored_signatures/` (FuzzManager
  format) are filtered out before returning, so common shutdown hangs don't
  pollute results.
- **js_shell_evaluator**: Detects crashes via negative exit code (signal) or
  `AddressSanitizer`/`UndefinedBehaviorSanitizer` in stderr. JS errors (positive
  exit codes) are not treated as crashes.
- **nss_gtest_evaluator**: Detects `AddressSanitizer` in stdout or stderr.

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run tests
uv run pytest

# Lint and format
uv run ruff check --fix .
uv run ruff format .

# Type check
uv run mypy src/

# Install pre-commit hooks
uv run pre-commit install
```

## License

[Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/)
