# Omna — mask secrets and PII before your prompt leaves the machine

A small local proxy for AI coding tools. Point Claude Code, aider, Codex CLI or any
Anthropic/OpenAI SDK app at `http://127.0.0.1:7788` and every request is masked on
the way out, sent to the provider with **your own key or login**, and un-masked on
the way back. The tool never notices. The model never sees the real values.

```
you type:     "fix the config, SUPPORT_EMAIL=jane.doe@example.com AWS_ACCESS_KEY_ID=AKIA…"
model sees:   "fix the config, SUPPORT_EMAIL=[EMAIL_1] AWS_ACCESS_KEY_ID=[SECRET_GENERIC_SECRET_1]"
you get back: "…set SUPPORT_EMAIL to jane.doe@example.com…"   ← restored, streaming, inside tool calls too
```

- **Secrets** (240 rules: AWS, GitHub, Stripe, OpenAI, Anthropic, database URLs, JWTs, private keys, …) never
  reach the provider. They become numbered tokens like `[SECRET_AWS_KEY_1]` that live only in the proxy's memory,
  never on disk, and are put back only in what comes *back* from the model, so when Claude edits the line that
  holds a key, the edit still matches your file. `--no-restore-secrets` redacts them for good instead.
- **Personal data** (emails, phones, SSNs and 50 international ID formats with real checksum validation,
  cards, IBANs, IPs, names) becomes stable tokens: `[EMAIL_1]` is the same address in every request, so
  prompt caching keeps working.
- **Nothing is sent to Omna.** The only network destination is the provider you were already using.
  A local receipt log (counts only, hash-chained) shows what was caught.
- **16 ms** to mask a 68 KB request — measured, not estimated, on an M5 MacBook Air, and it is on top of a
  call that already takes seconds. You will not feel it. ([How it was measured](#speed).)

Same compiled engine as the Omna Mac app, browser extension and the `omna` Python library.

## Install (macOS Apple Silicon, Linux x86_64/aarch64)

```sh
curl -fsSL https://omna.dev/cli/install.sh | bash
```

That installs the `omna` command (via [uv](https://docs.astral.sh/uv/)), wires Claude Code, and starts the
proxy.

### Installing without piping to a shell

Piping a script from the internet straight into a shell means running it before you have read it.
If that bothers you — and for a privacy tool it reasonably might — **you never have to do it.**
Every step the installer takes, you can take yourself:

```sh
# 1. Read the script first, if you want to see what the one-liner does.
curl -fsSL https://omna.dev/cli/install.sh -o install.sh && less install.sh

# 2. Or skip it entirely — this is all it really does:
uv tool install --python 3.12 omna-plugin        # or: pipx install omna-plugin
omna init            # Claude Code: ANTHROPIC_BASE_URL in ~/.claude/settings.json + a SessionStart hook
omna start -d        # background proxy on 127.0.0.1:7788
omna status
```

The installer has no privileged step of its own: it installs `uv` if you do not have it, runs the
`uv tool install` above, and calls `omna init`. `omna init` is the only part that asks for `sudo`,
it prints the exact commands before it runs them, and `omna uninstall` reverses all of it.

### Or with Homebrew

```sh
brew tap gaurjin/omna https://github.com/gaurjin/omna-plugin
brew install --cask omna
```

This installs a single self-contained binary — Python, every dependency and the masking engine
baked in — signed with our Developer ID and notarized by Apple. Two commands rather than one
because the recipe lives in this repo instead of a separate tap; see
[docs/homebrew.md](docs/homebrew.md) for why, and [docs/signing.md](docs/signing.md) for how to
verify the signature yourself.

Run `omna uninstall` **before** `brew uninstall` — Homebrew cannot remove the encryption keys
Omna stores in your Keychain, and `omna uninstall` does.

`omna init` also wires **aider**, **Codex CLI**, **VS Code** (Copilot Chat and similar chat
extensions), and **Continue** automatically if each is already installed/configured — nothing is
added for a tool you don't have. Wire one later, or a tool you didn't have yet: `omna enable aider`
/ `codex` / `continue`; `omna disable` reverts it. VS Code is Mac-only for now (`omna init`'s Mac
step); see [omna.dev/help/plugin-supported-tools](https://omna.dev/help/plugin-supported-tools) for
the full list, including the tools that only offer an in-app setting (Cursor, Cline, Windsurf — one
line, typed once, inside the tool) and the ones not supported yet, with the real reason why.

On a Mac, `omna init` also does one more thing: it trusts a local certificate ("Omna Local
Certificate Authority") and points the system proxy at Omna via a PAC file that names only AI
hostnames, so apps that don't use `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` (a desktop chat app, a
browser) are masked too — not just Claude Code. That's one `sudo` password prompt, printed before
it runs. Pass `--no-system` to skip it and wire Claude Code only. `omna uninstall` reverts it.

On a Mac, `omna init` also starts a menu-bar icon (`omna menubar`) showing live status — secrets
kept off the wire, personal values tokenised, requests masked, what's covered, and masking
overhead in ms, each on its own line. Its top line is the toggle itself (click, or the native
checkmark, to pause/resume masking), and it's the only thing Omna adds to System Settings → Login
Items: the masking proxy has no login item of its own, the menu-bar process supervises it.
Quitting the icon only stops that one process: relaunch it any time from Spotlight/Launchpad as
**Omna Plugin** (a small `.app` at `/Applications/Omna Plugin.app`, kept distinct from the native
Omna Mac app so the two never collide — though it now shares that app's icon, so look for the name
if you have both installed), or turn on its **Launch at Login** toggle so it comes back on its own
after every reboot or log-out. Its **Keep Local Reports** toggle turns the receipt log off entirely
(not just hides it) for anyone who doesn't want even anonymous counts kept on their machine —
`omna status`/`omna report`/`omna log` still run, they just have nothing new to show while it's off.

Cursor and Cline only offer an in-app setting (paste `http://127.0.0.1:7788` / `/v1` — see the docs
link above for the exact menu path). Any custom SDK app uses the same address, by hand:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:7788   # Anthropic SDK
export OPENAI_BASE_URL=http://127.0.0.1:7788/v1   # OpenAI SDK, Cursor BYOK
```

## What is covered

| Surface | How | Turn it off |
|---|---|---|
| Claude Code, aider, Codex CLI, VS Code, Continue | wired automatically by `omna init` (each only if already installed) | `omna disable claude-code` / `aider` / `codex` / `continue` |
| Cursor, Cline, Windsurf | one in-app setting, typed once — [full instructions](https://omna.dev/help/plugin-supported-tools) | unset it in the tool |
| Custom SDK apps | `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` set by hand | unset the env var |
| Browsers (claude.ai, chatgpt.com, gemini, … — a named list, not every site; add your own with `omna hosts add SITE`) | the system proxy (PAC + a local certificate), set up by `omna init` on a Mac | `omna hosts remove SITE` for one site, `omna init --no-system` or `omna uninstall` for all of them |
| Desktop AI apps that honour the system proxy | same system proxy as browsers | same as above |
| Desktop apps that ignore the system proxy | `omna capture app NAME` (Stage 3, per app, its own signed network extension) | `omna bypass app NAME` (stops masking; there's no command yet to release the app from capture itself) |
| Any specific app, at any layer | `omna bypass app NAME` — tunnelled through untouched, still receipted | `omna mask app NAME` |

## Try it in 30 seconds

```sh
omna mask "email jane.doe@example.com, key AKIAIOSFODNN7EXAMPLE, phone 212-555-0199"
# email [EMAIL_1], key [SECRET_AWS_KEY_1], phone [PHONE_1]

omna mask --realistic "email jane.doe@example.com, key AKIAIOSFODNN7EXAMPLE, phone 212-555-0199"
# email robert.jones@example.org, key [SECRET_AWS_KEY_N], phone 415-555-0128
#  ...the key stays a label on purpose. See "Two masking styles" below.

omna log         # one line per request: time, route, status, ms, what was masked
omna log --verify
```

## Commands

| Command | What it does |
|---|---|
| `omna start [-d] [--smart] [--no-restore-secrets]` | Run the proxy (foreground, or `-d` in the background). `--smart` adds the on-device Contextual model for prose names (809 MB download once, slower). |
| `omna stop` / `omna ensure` | Stop the background proxy / start it if it is not running (the Claude Code hook calls this). |
| `omna status` | Running? Claude Code wired? Receipts today. |
| `omna menubar` | Mac status icon (starts automatically): click the top line to pause/resume, see live counts (secrets kept off the wire, personal values tokenised, requests masked, coverage, masking overhead), toggle Launch at Login, Keep Local Reports or **Restore Real Values in Browser**, or uninstall. |
| `omna log [-n 20] [--verify] [--json]` | Local receipts. `--verify` checks the hash chain. |
| `omna report [--days 7] [--json] [--html FILE]` | Weekly summary from the receipts: requests enabled, distinct secrets kept off the wire, PII tokenised, destinations, chain status, masking cost. |
| `omna report --export FILE` | Write a **counts-only** copy of that report, safe to hand to a company admin — numbers plus your org/department tags. No prompt text, no real values, no usernames, no file paths, no app names. |
| `omna report --merge FILE...` | Add up exported files into one company view plus a per-department view. A machine whose file is collected twice is counted once. |
| `omna enroll [--org NAME] [--dept NAME] [--forget]` | Tag this machine so its exports can be grouped. With no arguments, shows the current tags. Nothing is sent anywhere — see below. |
| `omna mask [TEXT or -]` | Mask a string or stdin. |
| `omna style [tokens\|realistic]` | How a masked value is written: a numbered token (the default, every door) or a realistic fake value (your browser only — refused for anything that writes files). Prints what changed and which doors it affects. |
| `omna allow VALUE` | Never mask this exact value again (false positive). |
| `omna forget` | Wipe the token registry and its encryption key (tokens renumber). |
| `omna crash [--show N] [--send] [--clear]` | What broke on this machine. Masked by Omna's own engine before it is written to disk, and **never sent anywhere** — `--send` opens a GitHub issue pre-filled with the report you just read, and you submit it or close the tab. |
| `omna verify-model` | Re-hash the on-device Contextual model and compare it to the hash this engine was built against. Does the full check every time, never a cached answer. |
| `omna dashboard` | Open the live dashboard. It is protected by a local token (`~/.omna/dashboard.token`, owner-only), so another program on your machine cannot read your numbers over HTTP. |
| `omna mappings` | Open the Mappings Review screen — every value Omna has masked, real values hidden until you click Reveal. Same token as the dashboard. |
| `omna init [--project] [--no-system]` / `omna uninstall` | Wire / un-wire Claude Code, aider, Codex CLI, VS Code and Continue (each only if already installed), and (on a Mac, unless `--no-system`) the system proxy + certificate. `init` backs up every settings file it touches first and removes only its own keys on uninstall. |
| `omna tools` / `omna enable TOOL` / `omna disable TOOL` | Show, or turn on/off, which tools Omna covers. `enable`/`disable claude-code`, `aider`, `codex`, or `continue` also wire/unwire it (same as `init`/`uninstall`); other tool names (Cursor) just record the policy today. |
| `omna apps` / `omna bypass app NAME` / `omna mask app NAME` | Show, or set, what happens to an app's traffic through the system proxy: `mask` (default) tokenises it like everything else, `bypass` tunnels it through untouched (still receipted, so you can see what wasn't masked). |
| `omna capture app NAME` | Stage 3: deep-capture an app that ignores the system proxy, via its own signed network extension. |
| `omna hosts` / `omna hosts add HOST` / `omna hosts remove HOST` | Show, or add/remove, the hostnames the system proxy treats as AI traffic. |

## Speed

Measured on a MacBook Air M5 with Claude Code 2.1.274, a 4-request task (read a file, write a file, answer):

| | direct | through omna |
|---|---|---|
| wall time | 8.8 s | 9.8 s |
| fast masking, 68 KB request body | | **16 ms** |

Fast masking (rules + checksums, the default) is the 16 ms. Smart masking (`--smart`, which adds the
on-device Contextual model for prose names) is slower and off by default — it is a deliberate choice you
make, not a surprise you discover.

`omna status` reports the real average for **your** machine and your traffic
(`avg_mask_ms_this_run`), so you never have to take this table's word for it.

The proxy relays the stream as it arrives (pings included), forwards `anthropic-beta`, `anthropic-version`,
`cache_control` and the `system` array untouched, and forwards provider errors unmodified, per Claude Code's
[gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol).

## What is stored on your machine

| File (`~/.omna/`) | Contents | Permissions |
|---|---|---|
| `registry.json` | token → real value for reversible PII (needed to restore replies). Secrets are never in it; they live in the running proxy's memory only. | 0600 + **encrypted** |
| `receipts.jsonl` | one hash-chained line per request: route, status, ms, counts per entity. No values. | 0600 |
| `ruleset.json` | your allowlist and custom patterns (`{"allowlist": [...], "custom_rules": [{"label": "CUSTOMER_ID", "pattern": "ACME-\\d{6}"}]}`). Created with loopback addresses (`127.0.0.1`, `0.0.0.0`, `::1`, `localhost`) allowlisted. | |
| `proxy.log`, `omna.pid` | background-process housekeeping | |
| `policy.json` | which tools/apps/hosts are covered, and — only if you ran `omna enroll` — an organisation name, a department name, and a random device id. | 0600 |
| `crashes.jsonl` | the last 50 crashes: error type, message, stack frames (filenames only), versions. Masked by the engine before it is written, so a value that leaked into an error message is a token here too. Never sent. | 0600 |
| `dashboard.token` | the local secret the dashboard asks for. | 0600 |

### What Omna sends, and to whom

Nothing, to us. The plugin makes exactly one kind of outbound connection: the request you were
already making, to the AI provider you were already using, with your own key.

There is no analytics call, no crash reporter phoning home, no licence check, no update ping.
When something crashes, it is written to `~/.omna/crashes.jsonl` on your machine and stays there —
`omna crash` shows you the exact bytes, and `omna crash --send` opens a pre-filled GitHub issue
that **you** submit, or close. That is a deliberate difference from tools that ship an opt-in
crash reporter: an opt-in promise is something you have to trust, and a file on your disk is
something you can read.

### Where the real values live, and what protects them

`registry.json` is the only file Omna writes that contains real values, so it is
the only one that needs more than file permissions.

It is sealed with **AES-256-GCM**. The key is 32 random bytes kept in your
**macOS Keychain** — never on disk next to the file it opens, and never sent
anywhere. GCM also authenticates, so a file that someone edited fails to open
instead of quietly handing back changed mappings.

- `omna status` always tells you which state you are in, in plain words.
- If your machine has no Keychain (Linux, CI, a headless box), the registry
  stays as it was before: plaintext at `0600`. Omna says so loudly rather than
  refusing to run — and on that kind of machine, turn on full-disk encryption.
- `OMNA_REGISTRY_ENCRYPTION=off` opts out entirely and touches the Keychain not
  at all.
- If the key is ever lost, Omna keeps masking but stops writing, so it can never
  overwrite mappings it cannot read. `omna forget` starts cleanly from scratch.
- `omna forget` and `omna uninstall` remove the key along with the file.

## Company reports, without a server

A company with 100 laptops does not want 100 separate reports, and Omna does not
want their prompts. So the rollup is done with files, not a backend:

1. IT tags each machine at install time (or later with `omna enroll`):
   `curl -fsSL https://omna.dev/cli/install.sh | sh -s -- --org "Acme Inc" --dept engineering`
2. Each machine writes a counts-only file: `omna report --export machine.json`
3. Whoever is collecting them runs `omna report --merge *.json` and gets a
   company total plus a per-department breakdown.

**Nothing is uploaded.** There is no Omna server in this picture at all — the
files move however that company already moves files. The export is an
allowlist of number fields, so a new field added to the report later cannot
quietly start riding along. It deliberately leaves out your home path (which
carries your username) and which apps you run. The device id is random and
local; it exists so two files can be told apart and a duplicate can be spotted,
and `omna enroll --forget` deletes it.

## Two masking styles: numbered tokens, or realistic fake values

Omna can write a masked value in one of two ways. **Numbered tokens are the
default, everywhere**, and most people never need to change it.

| | what the AI receives | when it suits |
|---|---|---|
| **tokens** (default) | `email [EMAIL_N]` | anything that writes files, and anywhere you want a mistake to be obvious |
| **realistic** | `email robert.jones@example.org` | chat and prose, where ordinary-looking text gets you a better answer |

```sh
omna style              # what is in force, door by door
omna style realistic    # switch on realistic values (browser only — see below)
omna style tokens       # back to the default

omna mask --realistic "email jane.doe@acme.com, key AKIAIOSFODNN7EXAMPLE"
# email michael.jones63@example.org, key [SECRET_AWS_KEY_N]
```

### Why both exist, and why the realistic style is refused for coding tools

A numbered token fails **loudly**. If a restore ever breaks, a leftover
`[EMAIL_N]` sitting in your code is visibly wrong and somebody notices
immediately.

A realistic fake value fails **silently**. A leftover `robert.jones@example.org`
looks like ordinary data. Nobody notices, and it gets committed to a repository
for ever.

So this is a safety trade, not a preference — and Omna decides it for you where
the stakes are one-sided:

| Door | What it reaches | Realistic values |
|---|---|---|
| API door | Claude Code, aider, Codex, Continue, VS Code | **refused** — they all write files |
| System door | your browser and the chat websites | allowed |
| Deep door | a named desktop app, captured individually | **refused** — that list can hold an editor |

A refusal is never quiet: `omna style realistic` prints which doors kept
numbered tokens and why, `omna status` shows the style per door, and every
receipt records which style that request actually used.

**Secrets are never given a fake value, under any style.** An API key, a token,
a password or a private key always becomes a numbered `[SECRET_…]` label. A fake
API key that looked real is the worst thing this program could hand you.

### What the realistic style guarantees

- **Stability** — the same real value always becomes the same fake value, on
  every request and after a restart. Otherwise the provider's prompt cache is
  thrown away and the AI sees the conversation change under it between turns.
- **Uniqueness** — a generated value is checked against the text being masked
  and against every real value Omna already knows, and regenerated on a clash,
  so restoring can never put back the wrong thing. If no unique value can be
  made, Omna falls back to the numbered token.
- **Reversibility** — real values come back in replies, in streamed replies and
  inside tool-call arguments, exactly as they do with tokens.
- **Nothing invented can belong to anybody** — e-mail addresses use the reserved
  `example.org` domains, phone numbers the reserved `555-01xx` range, IP
  addresses the documentation ranges, and Social Security numbers an area
  number that is never issued. A generated card number is deliberately left
  failing its checksum: one that passed might be somebody's real card.

## Reviewing what was masked

`omna mappings` opens a screen showing every personal value Omna has masked on
this machine — behind the same `~/.omna/dashboard.token` as the dashboard,
never a second password to manage. It shows more than "what was masked":
which layer caught it (L1 rules, L2 secrets, L3 the contextual model), whether
a checksum actually validated it, which style it was last written in (tokens
or realistic — a value masked before the two-style feature existed says
"unknown", never a guessed default), how many times it has been sent, when
last, and to which provider and app.

Real values are never on the page until you ask. Each row is hidden by
default; click **reveal** to fetch just that one, or **reveal all** for every
row on the current page. Nothing is embedded in the page source ahead of
time, so a screenshot or a browser extension reading the DOM sees nothing
until you click. Search, filter by entity type, sort any column, and
paginate are all built in.

**Secrets never appear here.** They are memory-only from the moment they are
caught and are never written to the registry — the page says so, rather than
silently omitting them.

**Delete** removes one mapping — its token, its real value, and its
realistic-style fake together, so a "deleted" value can't keep resolving
through the fake path. The same real value gets a brand-new token or fake the
next time it's seen; the deleted one never comes back. **Clear all** is the
same as `omna forget` — it also resets your secret counters and your
encryption key.

## Reading browser replies: real values or labels

**Restore Real Values in Browser** (menu bar, on by default) decides what you
read back in a browser reply: the real name, or the `[EMAIL_1]` label that was
actually sent. **Masking is not affected by it and is never optional** — this
only changes what comes back.

It is scoped to the browser on purpose. The coding tools always get real values
put back, because there a label reaching the tool breaks it: Claude Code would
write `[SECRET_AWS_KEY_1]` into your file instead of editing the real line.

If you also run the Chrome extension, the plugin steps aside and lets the
extension handle the browser reply. It has to: both halves label things
`[EMAIL_1]`, `[PERSON_1]` … and number them independently, so whoever restores
second could swap in a different person's value. The extension tags the
requests it handles so the plugin knows, per request, to leave that reply
alone — masking still happens either way.

## What it refuses

A request to an inference path (`/v1/messages`, `/v1/chat/completions`, `/v1/responses`, …) whose body cannot be
parsed as JSON (compressed, malformed, wrong content type) is answered with `400 omna_refused` and never forwarded.
Non-inference uploads (`/v1/files`, audio) pass through unmasked and are marked `passthrough` in the receipt.
If the proxy is not running, the tool's requests fail to connect: nothing leaves unmasked.

## Honest limits (v1)

- A pinned app (one that rejects our certificate on purpose, e.g. it checks the cert fingerprint itself) is
  refused, never forwarded unmasked, and named: `omna status` shows `refused: AppName → host ×N (pinned)`
  with the exact `omna bypass app "AppName"` command to let it through untouched instead.
- If the daemon goes down, what a browser does next depends on whether it already loaded the PAC file: one
  that hasn't yet falls back to DIRECT (unmasked) until `launchd` restarts the daemon (seconds); one that
  already cached the proxy address instead fails closed (a connection error, nothing loads) until then. This
  Mac's `file://` PAC is not honoured by Safari/Chrome, so the PAC itself is served by the proxy — an honest
  limit either way, not a fail-closed guarantee like the coding-CLI door.
- Firefox, Node, Python, Java, Ruby and Deno keep their own certificate lists and ignore the macOS
  keychain, so each needs one line to trust the local certificate — all of them are in
  [docs/certificate-trust.md](docs/certificate-trust.md). (Firefox: `about:config` →
  `security.enterprise_roots.enabled` = `true`. Node: `NODE_EXTRA_CA_CERTS`, which `omna init`
  already sets for VS Code.) Safari, Chrome, Edge, Brave, curl and Go need nothing.
- Fast masking (rules + checksums) runs by default. Prose names in free text need `--smart`, which loads a
  local model and slows each request; it is off by default.
- Windows: no engine wheel yet (WSL works).
- A tool's own cloud features (for example Cursor tab-completion) never pass through a local proxy.
- Model thinking blocks are passed through untouched in both directions (the API requires it), so a name the
  model mentions inside its thinking shows as a token there.
- Two engine quirks are worked around here and logged upstream: assignment-style secrets keep their variable
  name outside the token (so `AWS_ACCESS_KEY_ID=[SECRET_GENERIC_SECRET_1]`, not one anonymous token), and a
  secret span no longer swallows the newline after it. One known false positive remains: prose like
  "authorization context: something" can be flagged as a generic secret.
- This masks secrets and PII. It does not make anything "compliant".
- No exceptions, not even for us: with Claude Code wired to this proxy, Claude reading this
  README's own demo values (the fake email/AWS key/phone two sections up) sees them as tokens
  too, same as it would see yours. That's the proxy working as designed, not a bug — it is a
  side effect worth knowing if you develop this repo with Claude Code pointed at itself.

## Free vs paid

Everything in this repository is free. The paid layer, for teams, is the proof: a signed weekly evidence pack
built from these receipts, per-machine coverage, and org-wide rulesets. See a sample at
[omna.dev/sample-report](https://omna.dev/sample-report).

## Development

```sh
uv venv .venv && uv pip install -p .venv/bin/python -e '.[dev]'
.venv/bin/pytest -q          # 205 tests, ~7 s (fake upstream, no network)
.venv/bin/omna start          # foreground, then: ANTHROPIC_BASE_URL=http://127.0.0.1:7788 claude
```

MIT for this shell. The engine wheel (`omna-pii-mask`) is binary-only.
