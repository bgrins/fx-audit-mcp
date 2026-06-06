/* In-page helper library for matching on live browser output, served by
 * fx-audit-mcp's SiteServer at /_output/lib.js on every site origin.
 *
 * Load from a sites page:
 *   <script src="/_output/lib.js"></script>
 * or from the localhost entry testcase (endpoints resolve via the script's
 * own URL, and carry Access-Control-Allow-Origin: *):
 *   <script src="http://example.site/_output/lib.js"></script>
 *
 * Defines a single global, FxAudit, with two helpers (both poll, resolve
 * with the matching log line, and throw on timeout):
 *
 *   await FxAudit.awaitMarker(/step=client ok/, {timeoutMs, intervalMs})
 *     Waits for a NEW stderr/stdout line matching both the run's
 *     marker_regex and the given regex.
 *
 *   await FxAudit.awaitLog(/some warning/, {log: "stderr", timeoutMs,
 *                          intervalMs})
 *     Same, but over the full raw log — for lines the marker_regex does
 *     not capture.
 *
 * Both helpers consume their stream: each successful await only sees data
 * after the previous match, so back-to-back awaits sequence multi-step
 * testcases without wall-clock sleeps and without matching stale lines
 * from an earlier attempt in the same run. After each successful await,
 * FxAudit.lastAwait holds {line, polls, elapsedMs} for timing evidence.
 *
 * The helpers do not log the matched line themselves: console output lands
 * back in stderr, so echoing a matched marker would feed it back into the
 * marker stream. Log content is decoded as UTF-8; non-ASCII bytes split
 * across a poll boundary may decode as replacement characters.
 */
"use strict";

globalThis.FxAudit = (() => {
  const base = (() => {
    const src = document.currentScript && document.currentScript.src;
    return src ? new URL(".", src).href : "/_output/";
  })();

  const state = { marker: 0, logs: {} };

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function fetchEndpoint(path) {
    const resp = await fetch(base + path, { cache: "no-store" });
    if (!resp.ok) {
      const detail = await resp.text().catch(() => "");
      throw new Error(
        ("FxAudit: GET " + path + " -> HTTP " + resp.status + " " + detail).trim()
      );
    }
    return resp;
  }

  function recordAwait(line, polls, started) {
    api.lastAwait = { line, polls, elapsedMs: Date.now() - started };
    return line;
  }

  async function awaitMarker(re, { timeoutMs = 30000, intervalMs = 250 } = {}) {
    const started = Date.now();
    const deadline = started + timeoutMs;
    for (let polls = 1; ; polls++) {
      const text = await (await fetchEndpoint("markers")).text();
      const lines = text ? text.split("\n") : [];
      for (let i = state.marker; i < lines.length; i++) {
        re.lastIndex = 0;
        if (re.test(lines[i])) {
          state.marker = i + 1;
          return recordAwait(lines[i], polls, started);
        }
      }
      if (Date.now() >= deadline) {
        throw new Error(
          "FxAudit: timed out after " + timeoutMs + "ms awaiting marker " + re
        );
      }
      await sleep(intervalMs);
    }
  }

  async function awaitLog(
    re,
    { log = "stderr", timeoutMs = 30000, intervalMs = 250 } = {}
  ) {
    const logState = (state.logs[log] ??= { offset: 0, buf: "", cursor: 0 });
    const started = Date.now();
    const deadline = started + timeoutMs;
    for (let polls = 1; ; polls++) {
      // Drop already-consumed text so the buffer only retains the unmatched
      // suffix (sanitizer-heavy logs can be large).
      if (logState.cursor > 1048576) {
        logState.buf = logState.buf.slice(logState.cursor);
        logState.cursor = 0;
      }
      const resp = await fetchEndpoint(
        "log?log=" + log + "&offset=" + logState.offset
      );
      const next = Number(resp.headers.get("X-Next-Offset"));
      const chunk = await resp.text();
      if (chunk) {
        logState.buf += chunk;
        // X-Next-Offset is byte-accurate; fall back to the decoded length
        // (correct for ASCII) if the header was stripped.
        logState.offset =
          Number.isFinite(next) && next > logState.offset
            ? next
            : logState.offset + chunk.length;
      }
      re.lastIndex = 0;
      const m = logState.buf.slice(logState.cursor).match(re);
      if (m) {
        const matchStart = logState.cursor + m.index;
        logState.cursor = matchStart + (m[0].length || 1);
        const lineStart = logState.buf.lastIndexOf("\n", matchStart) + 1;
        let lineEnd = logState.buf.indexOf("\n", matchStart);
        if (lineEnd === -1) lineEnd = logState.buf.length;
        return recordAwait(logState.buf.slice(lineStart, lineEnd), polls, started);
      }
      if (Date.now() >= deadline) {
        throw new Error(
          "FxAudit: timed out after " + timeoutMs + "ms awaiting log " + re
        );
      }
      await sleep(intervalMs);
    }
  }

  const api = { awaitMarker, awaitLog, lastAwait: null };
  return api;
})();
