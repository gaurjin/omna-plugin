# omna-plugin/CLAUDE.md

## What this repo is
Product #4 of Omna: **the plugin** — ONE command that masks everything an AI sees from this machine and will replace the Mac app + Chrome extension. This repo is Stage 1 (the mail-room proxy + coding tools via base URL); Stages 1b–5 (report, Mac system proxy + certificate via mitmproxy, VPN extension, Windows/Linux, sunset) are in the Product Spec §6. Thin Python shell
(`src/omna_plugin/`) over the compiled `omna-pii-mask` engine wheel (built from the private
`omna-workspace/bindings/omna-core-py`; never copy engine code here). Strategy and the blueprint live in
`~/Developer/Omna Notes/:Vision/Omna Plugin — Product Spec.md` §6. Plans: Stage 1 =
`docs/superpowers/plans/2026-09-17-product-4-plugin.md` (done); **Stages 2+3 =
`docs/superpowers/plans/2026-09-17-stage-2-3-mac-coverage.md`** (the architecture decisions with their
reasons are Product Spec §6.9 — read it before touching Stage 2/3 code).

## Stage 2/3 shape (decided 2026-09-17): three doors, one mail room
- **Mail room** = `pipeline.py` (mask → forward → restore → receipt). Every door calls it; one `MaskingSession`.
- **API door** = `proxy.py` on 127.0.0.1:7788 (Stage 1, unchanged; tools use a base URL).
- **System door** = a `mitmproxy` "regular" listener on 127.0.0.1:7789 behind a macOS PAC that names ONLY
  AI hostnames (`policy.json`); `allow_hosts` decrypts only those; a local CA "Omna Local Certificate
  Authority" in `~/.omna/ca` is trusted once (one `sudo` batch, printed before it runs); `launchd` keeps it alive.
- **Deep door** = `mitmproxy` "local" mode per app name (its signed "Mitmproxy Redirector" network
  extension; no Swift of ours). Only for apps that ignore the system proxy.
- **Policy** = `~/.omna/policy.json`: hosts, tools on/off, apps mask/bypass (by process name via `lsof`),
  deep-capture apps, doors. A bypass is always receipted. Pinned apps are refused and named in `omna status`.
- `mitmproxy` is a library dependency, used as-is (fork-free). Verified hook/option names are listed at the
  top of the Stage 2+3 plan; trust that list over memory.

## Token literals: two pieces, always
Never type a full placeholder token (open bracket, KIND, underscore, digits, close bracket) in any file in
this repo — write it as two adjacent string pieces, e.g. `"[EMAIL_" "1]"` in Python. A Claude Code
session that is itself wired to the plugin restores every full token literal into the real value from the
registry while writing the file (that is the restore-in-tool-calls feature working). On 2026-09-17 this put
the owner's real e-mail into a plan file; caught before commit. Same trick as the runtime-built fake keys.

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
The public GitHub repo `gaurjin/omna-plugin` already exists (tags up to `v0.5.0` pushed). Releasing a
new version: `git tag vX.Y.Z && git push origin vX.Y.Z` → update the version pin in `README.md` and
`install.sh` to match → `uv build && uv publish`. The installer URL in README assumes that repo path.
