# Product #4 — the Omna plugin (local privacy proxy) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A free, one-line-install local proxy (`omna`) that masks secrets and PII in every request an AI coding tool sends (Claude Code, aider, Anthropic/OpenAI SDKs, Codex CLI), forwards it with the user's own credentials, and restores the masked values in the reply, including while streaming.

**Architecture:** Thin Python shell on top of the compiled `omna-pii-mask` engine wheel (the same Rust L1–L6 engine as the Mac app, extension and Python library). A `MaskingSession` keeps a stable value↔token registry so `[PERSON_1]` means the same person in every request (needed for prompt caching and Claude Code's preserved-thinking check). A Starlette/uvicorn server on 127.0.0.1:7788 masks JSON request bodies with a generic walker, forwards with httpx, and restores non-streamed JSON or SSE deltas through a `StreamRestorer` that holds back partial tokens split across chunks. Every request appends a hash-chained receipt (counts only, never values) to `~/.omna/receipts.jsonl`.

**Tech Stack:** Python ≥3.10, `omna-pii-mask` (binary wheel, macOS arm64 + Linux), `httpx`, `starlette`, `uvicorn`, `pytest` + `pytest-asyncio`. Installed with `uv tool install omna-plugin`.

**Strategy context:** `~/Developer/Omna Notes/:Vision/Omna Plugin — Product Spec.md` §6 (2026-09-17).

---

## File map

| File | Responsibility |
|---|---|
| `src/omna_plugin/config.py` | Paths (`OMNA_HOME`, default `~/.omna`), port, upstream URLs, settings load/save. |
| `src/omna_plugin/engine.py` | `MaskingSession`: wraps the wheel; stable registry (persisted, 0600); per-string cache; allowlist via `ruleset.json`; `mask_text()` / `restore_text()` / token regex. |
| `src/omna_plugin/body.py` | Walk a JSON request body and mask every human-text string (skips base64 blobs, tool schemas, signatures, cache_control); walk a JSON response body and restore. Returns per-entity counts. |
| `src/omna_plugin/stream.py` | `StreamRestorer`: SSE frame parser + hold-back restore for Anthropic (`text_delta`, `input_json_delta`), OpenAI chat (`choices[].delta.content`, tool-call `arguments`) and Responses API (`delta`). Pings and unknown frames pass through untouched. |
| `src/omna_plugin/receipts.py` | Append hash-chained JSONL receipts; read last N; verify chain. |
| `src/omna_plugin/proxy.py` | Starlette app: route selection (Anthropic vs OpenAI upstream), header pass-through, `/omna/health`, `HEAD /api/hello`, streaming + non-streaming forwarding. `run()` starts uvicorn. |
| `src/omna_plugin/claude_code.py` | `init()`/`uninstall()`: merge `env.ANTHROPIC_BASE_URL` + a `SessionStart` hook (`omna ensure`) into a Claude Code `settings.json` (user or project scope); backup first; reversible. |
| `src/omna_plugin/cli.py` | `omna start|stop|ensure|status|log|mask|allow|init|uninstall|version`. argparse, no extra deps. |
| `install.sh` | Installs `uv` if missing, `uv tool install omna-plugin`, runs `omna init`. |
| `tests/` | One test file per module + `test_proxy.py` against a fake upstream (Starlette app served in-process via httpx ASGI transport). |

---

### Task 1: config + MaskingSession (stable registry, cache, allowlist)

**Files:** `src/omna_plugin/config.py`, `src/omna_plugin/engine.py`, `tests/test_engine.py`

- [ ] Write `tests/test_engine.py` covering: secrets redacted irreversibly; PII → tokens and `restore_text` round-trips; the SAME value gets the SAME token across two separate `mask_text` calls (stability); two different people in one text get different numbers; registry survives a new `MaskingSession` on the same `OMNA_HOME`; `allow("john.smith@acme.com")` stops that email being masked; `counts` reports `{"EMAIL": 1, "AWS_KEY": 1}`.
- [ ] Run: `.venv/bin/pytest tests/test_engine.py -v` → FAIL (module missing).
- [ ] Implement `config.py` (`home()`, `ensure_home()`, `DEFAULT_PORT = 7788`, `ANTHROPIC_UPSTREAM`, `OPENAI_UPSTREAM` env-overridable) and `engine.py` (`MaskingSession(smart=False)`, `mask_text(text) -> MaskResult(masked, counts)`, `restore_text(text) -> str`, `allow(value)`, `TOKEN_RE`).
- [ ] Run tests → PASS. Commit: `feat: masking session with stable token registry`.

### Task 2: request/response body walker

**Files:** `src/omna_plugin/body.py`, `tests/test_body.py`

- [ ] Tests: Anthropic body with `system` (string and block list), `messages` with text blocks, `tool_result` (string and block list), `tool_use.input` nested strings; a base64 `source.data` image block is untouched; `tools[]` schemas untouched; `cache_control` and `signature` untouched; OpenAI `messages[].content` string and parts; response restore puts real values back in `content[].text` and `tool_use.input`.
- [ ] Implement `mask_body(session, obj) -> (obj, counts)` and `restore_body(session, obj) -> obj`.
- [ ] PASS + commit: `feat: JSON body masking walker`.

### Task 3: streaming restorer

**Files:** `src/omna_plugin/stream.py`, `tests/test_stream.py`

- [ ] Tests: a token split as `"Hi [PER"` + `"SON_1]!"` restores to `Hi John Smith!`; a lone `[` that never becomes a token is emitted after the block ends; `input_json_delta` restores with JSON escaping (value with a quote); ping frames pass through byte-identical; OpenAI `choices[0].delta.content` restores; unknown event types pass through; `message_stop` flushes pending text.
- [ ] Implement `StreamRestorer(session).feed(chunk: bytes) -> bytes` and `.flush() -> bytes`.
- [ ] PASS + commit: `feat: SSE stream restorer with partial-token hold-back`.

### Task 4: receipts

**Files:** `src/omna_plugin/receipts.py`, `tests/test_receipts.py`

- [ ] Tests: `append(record)` writes a line with `prev` and `hash`; `verify()` is True; editing a middle line makes `verify()` False; `tail(n)` returns last n records; values never appear (record contains counts only).
- [ ] Implement. PASS + commit: `feat: hash-chained local receipts`.

### Task 5: the proxy

**Files:** `src/omna_plugin/proxy.py`, `tests/test_proxy.py`

- [ ] Tests (fake upstream = Starlette app that echoes the masked body it received and streams a canned SSE reply containing `[PERSON_1]`): upstream never sees the real email; `anthropic-beta`/`anthropic-version` forwarded verbatim; `authorization`/`x-api-key` forwarded; streamed reply comes back restored; non-stream JSON restored; `/v1/messages/count_tokens` forwarded masked; `HEAD /api/hello` → 200; `/omna/health` JSON; OpenAI path routes to the OpenAI upstream; a receipt is written per request.
- [ ] Implement with `httpx.AsyncClient(timeout=None)` shared on app state; hop-by-hop headers dropped; upstream errors forwarded unmodified.
- [ ] PASS + commit: `feat: local masking proxy`.

### Task 6: Claude Code wiring + CLI + installer

**Files:** `src/omna_plugin/claude_code.py`, `src/omna_plugin/cli.py`, `install.sh`, `tests/test_claude_code.py`, `tests/test_cli.py`

- [ ] Tests: `init(settings_path)` on a missing file creates `{"env": {...}, "hooks": {"SessionStart": [...]}}`; on an existing file it preserves unrelated keys and writes a `.omna-backup`; `uninstall` removes only our keys; `omna mask "..."` prints masked text; `omna version` prints engine + plugin versions.
- [ ] Implement CLI commands. `start -d` daemonizes with a pidfile; `ensure` starts if `/omna/health` is not answering; `stop` kills the pidfile process.
- [ ] PASS + commit: `feat: CLI, Claude Code init, installer`.

### Task 7: live verification (manual, this machine)

- [ ] `omna start` in one terminal; in a scratch project with a project-scope `.claude/settings.json` from `omna init --project`, run `claude -p "..."` reading a file with a fake AWS key and an email; confirm via `omna log` that the request was masked and Claude's reply shows the real email restored.
- [ ] Record measured numbers (latency added, bytes) in README.

### Task 8: README + tag

- [ ] README: what it is, one-line install, the 4 tools it works with, what leaves the machine, the free/paid line, limits (no Windows wheel yet, L3 opt-in, "secrets and PII", never "compliant").
- [ ] `git tag v0.1.0`. Publishing to GitHub + PyPI is the owner's step.
