# omna-plugin/CLAUDE.md

## What this repo is
Product #4 of Omna: **the plugin** — ONE command that masks everything an AI sees from this machine and will replace the Mac app + Chrome extension. This repo is Stage 1 (the mail-room proxy + coding tools via base URL); Stages 1b–5 (report, Mac system proxy + certificate via mitmproxy, VPN extension, Windows/Linux, sunset) are in the Product Spec §6. Thin Python shell
(`src/omna_plugin/`) over the compiled `omna-pii-mask` engine wheel (built from the private
`omna-workspace/bindings/omna-core-py`; never copy engine code here). Strategy and the blueprint live in
`~/Developer/Omna Notes/:Vision/Omna Plugin — Product Spec.md` §6. The implementation plan is
`docs/superpowers/plans/2026-09-17-product-4-plugin.md`.

## Vocabulary (use these words)
- Product name: **the plugin**. "Proxy" is the plumbing word for how it works.
- Masking layers: L1 Deterministic, L2 Secrets, L3 Contextual (the privacy-filter model), L4 Fusion.
  Fast masking = L1+L2 (default). Smart masking = +L3 (`--smart`).
- Never say "compliant". Say "masks secrets and PII".

## How it works (one paragraph)
`proxy.py` receives a request → `body.py` masks every prose string via `engine.MaskingSession`
(stable token registry in `~/.omna/registry.json`, per-string cache, allowlist from `ruleset.json`) →
forwards with httpx to `api.anthropic.com` or `api.openai.com` (chosen by headers/path) → non-stream
JSON is restored by `body.restore_body`; SSE is restored chunk-by-chunk by `stream.StreamRestorer`
(holds back a partial `[TOKEN` until it completes) → `receipts.py` appends one hash-chained line.

## Rules
- Tests first; `.venv/bin/pytest -q` must be green before any commit. The proxy tests use an in-process
  fake upstream (`tests/test_proxy.py`); no network in tests.
- Never log or persist a real value except in `registry.json` (0600). Receipts are counts only.
- Keep the gateway contract: forward `anthropic-beta`/`anthropic-version` verbatim, never reshape the
  `system` array, never buffer SSE, forward upstream error bodies unmodified, never touch `thinking`,
  `signature`, `cache_control`, or base64 `data`.
- Live verification = a nested headless run: `env -u CLAUDECODE ANTHROPIC_BASE_URL=http://127.0.0.1:7788
  claude -p "..." --allowedTools Read,Write` with a file containing a fake key; check `omna log`.
- Claude Code hooks canNOT rewrite prompts or tool results on 2.1.274 (`updatedPrompt`/`updatedResult`
  are ignored — verified in the debug log). Do not build a hooks-based masker until a release accepts them.

## Publishing (owner-manual)
`git tag vX.Y.Z` → create the public GitHub repo `gaurjin/omna-plugin` → `uv build && uv publish`.
The installer URL in README assumes that repo path.
