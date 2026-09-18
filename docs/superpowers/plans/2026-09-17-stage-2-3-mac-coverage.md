# Stage 2 + Stage 3 — Mac-wide coverage (system door + deep door) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Token literals in this repo are ALWAYS written as two adjacent string pieces**, e.g. `"[EMAIL_" "1]"` in Python. Reason: when a Claude Code session is itself wired to the plugin, the plugin restores every full token literal the model types into the real value from the registry while writing the file (that is its job for tool calls). A full literal in a test fixture therefore becomes real PII on disk. See CLAUDE.md.

**Goal:** After `curl -fsSL https://omna.dev/cli/install.sh | bash` on a Mac, everything the machine sends to an AI is masked by the one engine — Claude Code and other coding tools (Stage 1, done), browsers on claude.ai / chatgpt.com / gemini.google.com, desktop AI apps that honour the system proxy (Stage 2), and desktop apps that ignore it (Stage 3) — with a per-tool / per-app on/off policy, hash-chained receipts, and `omna report` unchanged.

**Architecture (the one-paragraph version):** One background process, **three doors, one mail room.** The **API door** is the existing Starlette reverse proxy on `127.0.0.1:7788` (tools pointed at it by base URL; unchanged). The **system door** is a `mitmproxy` "regular" listener on `127.0.0.1:7789`, reached through a macOS PAC file that names ONLY AI hostnames; it decrypts HTTPS with a local certificate authority the installer trusts once, and it only intercepts hostnames on the policy list (everything else is tunnelled encrypted, untouched). The **deep door** (Stage 3) is `mitmproxy`'s "local" mode — the Apple-signed network extension that ships inside the `mitmproxy-macos` wheel — turned on per app name for apps that ignore the system proxy. All three doors call the same **mail room** (`pipeline.py`: mask → forward → restore → receipt) over the same `MaskingSession`, so a secret token minted at one door is restored correctly at any door. **Site adapters** (`adapters/`) hold the per-website knowledge (claude.ai, chatgpt.com, gemini) as small declarative refinements of the generic "mask every prose string in the JSON body" walker that Stage 1 already uses. **Policy** (`policy.json`) is one file that says which tools are wired, which apps are masked / bypassed / deep-captured, and which hostnames count as AI — the same file an org can later ship to every machine.

**Tech Stack:** Python ≥3.12 (mitmproxy 12 requires it; the installer already pins 3.12), `omna-pii-mask`, `httpx`, `starlette`, `uvicorn`, **`mitmproxy>=12.2,<13`** (brings `mitmproxy-rs` and, on macOS, `mitmproxy-macos` with the signed Redirector app), macOS tools `security`, `networksetup`, `launchctl`, `lsof`. Tests: `pytest` + `pytest-asyncio`, hermetic (in-process fake upstream; a test CA made with `cryptography`, which mitmproxy already depends on).

**Strategy context:** `~/Developer/Omna Notes/:Vision/Omna Plugin — Product Spec.md` §6.5 (stages) and **§6.9 (the architecture decisions this plan implements, with the reasons).** Read §6.9 first; this file is the "how", that one is the "why".

**Facts verified 2026-09-17 against the installed `mitmproxy==12.2.3` source (not from memory):**
- Embedding: `mitmproxy.tools.dump.DumpMaster(options, loop=None, with_termlog=..., with_dumper=...)`; `await master.run()` blocks until `master.shutdown()`; `master.addons.add(obj)`.
- Options are keyword args to `mitmproxy.options.Options(**kw)`: `listen_host`, `listen_port`, `mode` (list; `"regular@7789"`, `"local:Claude,ChatGPT"`), `confdir`, `allow_hosts` (list of regexes, case-insensitive, matched against `host:port` from CONNECT **and** `sni:port`), `ssl_verify_upstream_trusted_ca`, `ssl_insecure`, `websocket`, `http2`, `store_streamed_bodies`.
- Hook names (module `mitmproxy/proxy/layers/http/_hooks.py` and `.../tls.py`): `requestheaders(flow)`, `request(flow)`, `responseheaders(flow)`, `response(flow)`, `websocket_message(flow)`, `tls_clienthello(data: mitmproxy.tls.ClientHelloData)` with `data.ignore_connection = True` = "forward encrypted, do not intercept", `tls_failed_client(data: mitmproxy.tls.TlsData)` = the app refused our certificate, `client_connected(client)`.
- Streaming contract: set `flow.response.stream = callback` in `responseheaders`; mitmproxy calls `callback(chunk: bytes) -> bytes | Iterable[bytes]` for every chunk and finally `callback(b"")` at end of stream (return the flushed tail there). Chunks are the raw wire bytes, so the request must carry `accept-encoding: identity` or you will be handed gzip.
- WebSocket: in `websocket_message(flow)`, `msg = flow.websocket.messages[-1]`; setting `msg.content` before returning changes what is forwarded (`layers/websocket.py` sends `message.content` after the hook unless `message.dropped`).
- CA files: `mitmproxy.certs.CertStore.create_store(path, basename, key_size, organization=None, cn=None)` writes `<basename>-ca.pem` (private key + cert), `<basename>-ca-cert.pem` (public cert), `<basename>-dhparam.pem`. The `tlsconfig` addon loads `from_store(confdir, "mitmproxy", ...)` — so we pre-create the store with basename `mitmproxy` but organization/CN **"Omna Local Certificate Authority"**, and mitmproxy uses it as-is.
- Local (deep) mode: `mitmproxy_rs.local.start_local_redirector(...)`, spec syntax `"Claude,ChatGPT"` (include) / `"!Cursor"` (exclude), `describe_spec()` validates. The Rust library installs `/Applications/Mitmproxy Redirector.app` from the tar inside the wheel on first use and needs the user to approve the network extension once in System Settings. `mitmproxy_rs.Stream.get_extra_info("pid" | "process_name")` exists on the Rust stream, but the Python `Client` object does **not** carry it (grep found no `process_name` in `mitmproxy/`), so process identity is resolved by us (Task 4).
- macOS: `networksetup` "requires at least admin privileges to change network settings" (root if the security preference is set) → always run in the one `sudo` batch. `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain FILE` (admin store, root required). This Mac: macOS 26.6.2.
- Chrome extension reference: `omna-workspace/extension/src/content/file-input-interceptor.ts` masks the outbound `fetch()` body when the path matches `/(append_message|completion|conversation|stream|chat|generate|backend-api|message|messages|prompt)/i` — reuse that regex as the generic "is this a prompt request" rule.

---

## File map

| File | Responsibility |
|---|---|
| `src/omna_plugin/pipeline.py` | **The mail room.** `Pipeline`: mask a JSON object / a text / form fields, restore JSON, hand out stream restorers, write the receipt. Extracted from `proxy.py` so every door shares it. |
| `src/omna_plugin/policy.py` | `Policy` (load/save `~/.omna/policy.json`): AI hostnames, tools on/off, apps mask/bypass, deep-capture apps, doors on/off. Produces the PAC text and mitmproxy's `allow_hosts` regexes. |
| `src/omna_plugin/adapters/base.py` | `RequestView`, `MaskOutcome`, the `SiteAdapter` protocol, `ENDPOINT_RE`. |
| `src/omna_plugin/adapters/generic.py` | `GenericAdapter`: JSON / form / text masking with the Stage 1 walker; SSE or JSON or text restore. The default for every AI host. |
| `src/omna_plugin/adapters/claude_web.py`, `chatgpt_web.py`, `gemini_web.py` | Per-site refinements (extra skip keys, exact prompt paths, response shapes). Written from captured traffic (Task 8). |
| `src/omna_plugin/adapters/__init__.py` | `for_host(host) -> SiteAdapter` registry. |
| `src/omna_plugin/procs.py` | `ProcessResolver`: client `(ip, port)` → `(pid, app_name)` via `lsof`, cached. |
| `src/omna_plugin/system_door.py` | The mitmproxy addon (`OmnaAddon`) + `build_master(...)`: hostname gate, bypass policy, mask request, stream/JSON/websocket restore, refusals, receipts. Serves both the system door and the deep door. |
| `src/omna_plugin/daemon.py` | Runs the API door (uvicorn) and the mitmproxy master on one asyncio loop; one SIGTERM handler. |
| `src/omna_plugin/mac/certs.py` | Build the trust / untrust commands for the CA. |
| `src/omna_plugin/mac/netproxy.py` | List network services; build `networksetup` PAC on/off commands. |
| `src/omna_plugin/mac/launchd.py` | Write `~/Library/LaunchAgents/dev.omna.plugin.plist`; bootstrap / bootout / kickstart. |
| `src/omna_plugin/mac/setup.py` | `plan()` → the exact privileged lines; `apply()` runs them as ONE `sudo sh` batch (one password prompt); `revert()`. |
| `src/omna_plugin/proxy.py` | API door. Change: use `Pipeline`; serve `GET /omna/proxy.pac`; receipts get `door="api"`. Behaviour otherwise unchanged (its tests must stay green untouched). |
| `src/omna_plugin/cli.py` | New: `omna tools`, `omna enable|disable TOOL`, `omna apps`, `omna bypass app NAME` / `omna mask app NAME`, `omna capture app NAME` (Stage 3), `omna hosts [add|remove HOST]`, `omna init` runs the Mac setup (`--no-system` to skip), `omna uninstall` reverts it, `omna status` shows doors/apps/refusals. |
| `src/omna_plugin/report.py` | Add "by app" and "by door" sections (coverage view). |
| `tests/test_pipeline.py`, `test_policy.py`, `test_adapters.py`, `test_procs.py`, `test_mac_setup.py`, `test_system_door.py`, `test_daemon.py` | One file per module; `test_system_door.py` is the hermetic end-to-end (real TLS through a real mitmproxy listener to an in-process fake AI upstream). Tests never run `sudo`, `networksetup`, `security` or `launchctl` — they only assert the command text. |

**Ports:** API door 7788 (unchanged), system door 7789. Both loopback only.

**Receipt fields added** (counts only, never values): `door` ∈ `api|system|deep`, `host`, `app` (process name or `null`), `note` gains `bypassed-by-policy`, `tls-refused`, `passthrough-nonprompt`.

**Vocabulary (use these words in code, docs and CLI text):** *mail room* = `pipeline.py`; *door* = a listener (API door / system door / deep door); *adapter* = per-site knowledge; *policy* = `policy.json`; *bypass* = forward encrypted and untouched, on purpose, receipted; *refused* = an app rejected our certificate (pinned) and was NOT forwarded.

---

## Task 0: Two spikes on the owner's Mac (owner's clicks; 30 minutes; decide before Task 9)

These change the owner's real machine, so per the house rule they are run by the owner (or with an explicit go-ahead), never silently by an agent.

- [ ] **Spike A — does a `file://` PAC URL work on macOS 26?** If yes, the system door is fail-closed for AI hosts even when the daemon is down (no PAC server needed). If no, the PAC is served by the API door and launchd `KeepAlive` is the mitigation (documented as an honest limit).

```sh
cat > /tmp/omna-test.pac <<'EOF'
function FindProxyForURL(url, host) { if (host == "example.com") return "PROXY 127.0.0.1:7789"; return "DIRECT"; }
EOF
sudo networksetup -setautoproxyurl "Wi-Fi" "file:///tmp/omna-test.pac"
networksetup -getautoproxyurl "Wi-Fi"
# In Safari AND Chrome open https://example.com — with nothing listening on 7789 it must FAIL (proxy refused).
# If it loads normally, the file:// PAC is being ignored → record "file:// PAC: not honoured" in §6.9.
sudo networksetup -setautoproxystate "Wi-Fi" off
```
Record the outcome in Product Spec §6.9 under "Spike results" as one of: `file:// honoured by Safari+Chrome` / `honoured by Safari only` / `not honoured`.

- [ ] **Spike B — does mitmproxy's local (deep) mode run from a `uv tool` install on this Mac?**

```sh
uvx --from "mitmproxy==12.2.3" mitmdump --mode local:curl --set termlog_verbosity=info
# First run: macOS asks to allow "Mitmproxy Redirector" as a network extension
# (System Settings → General → Login Items & Extensions → Network Extensions). Approve once.
# In a second terminal:
curl -sS https://example.com -o /dev/null -w "%{http_code}\n"
# Expected: mitmdump prints a flow line for example.com (the curl process was captured);
# curl prints 200, or a certificate error — which ALSO proves capture (the cert is untrusted in this spike).
```
Record in §6.9: `deep mode: captured curl` / `failed: <error text>`. Then quit mitmdump; the Redirector app may stay in /Applications (harmless; `omna uninstall` removes it in Task 12).

---

## Task 1: Policy file

**Files:** Create `src/omna_plugin/policy.py`, `tests/test_policy.py`. Modify `src/omna_plugin/config.py` (add `policy_path()`, `ca_dir()`, `SYSTEM_PORT`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_policy.py
from omna_plugin import policy


def test_defaults_include_the_big_ai_hosts(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    assert "api.anthropic.com" in p.hosts
    assert "chatgpt.com" in p.hosts
    assert p.tools == {"claude-code": "on"}
    assert p.doors == {"api": True, "system": True, "deep": False}


def test_is_ai_host_matches_exact_and_subdomains(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    assert p.is_ai_host("claude.ai")
    assert p.is_ai_host("api.claude.ai")
    assert p.is_ai_host("CHATGPT.COM")
    assert not p.is_ai_host("notclaude.ai")
    assert not p.is_ai_host("github.com")


def test_save_and_reload_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    p.set_app("Cursor", "bypass")
    p.add_host("api.example-ai.com")
    p.tools["claude-code"] = "off"
    p.save()
    q = policy.Policy.load()
    assert q.apps == {"Cursor": "bypass"}
    assert "api.example-ai.com" in q.hosts
    assert q.tools["claude-code"] == "off"
    assert (tmp_path / "policy.json").stat().st_mode & 0o777 == 0o600


def test_pac_names_only_ai_hosts_and_the_system_door(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    pac = p.pac(system_port=7789)
    assert 'return "PROXY 127.0.0.1:7789"' in pac
    assert 'return "DIRECT"' in pac
    assert '"claude.ai"' in pac
    assert "github.com" not in pac


def test_allow_hosts_regexes_match_host_port_and_sni(tmp_path, monkeypatch):
    import re
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    rx = [re.compile(r, re.IGNORECASE) for r in policy.Policy.load().allow_hosts()]
    assert any(r.search("claude.ai:443") for r in rx)
    assert any(r.search("api.claude.ai:443") for r in rx)
    assert not any(r.search("notclaude.ai:443") for r in rx)
    assert not any(r.search("github.com:443") for r in rx)


def test_app_action_defaults_to_mask(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    assert p.app_action("Google Chrome") == "mask"
    p.set_app("Cursor", "bypass")
    assert p.app_action("Cursor") == "bypass"
    assert p.app_action("cursor") == "bypass"  # case-insensitive
```

- [ ] **Step 2: Run to verify they fail** — `.venv/bin/pytest tests/test_policy.py -q` → `ImportError: cannot import name 'policy'`.

- [ ] **Step 3: Implement**

```python
# src/omna_plugin/config.py — add:
SYSTEM_PORT = 7789


def policy_path() -> Path:
    return home() / "policy.json"


def ca_dir() -> Path:
    return home() / "ca"
```

```python
# src/omna_plugin/policy.py
"""One file that says what the plugin covers: which hostnames count as AI,
which tools are wired, which apps are masked / bypassed / deep-captured,
and which doors are open. ``~/.omna/policy.json`` (0600). This is also the
file an organisation will ship to every machine later; keep it flat."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from . import config

DEFAULT_HOSTS = [
    # the public APIs: the API door already covers tools that use base URLs;
    # these are for apps that call the APIs directly through the system door
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.deepseek.com",
    "api.x.ai",
    "openrouter.ai",
    "api.cohere.com",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.githubcopilot.com",
    # the chat websites
    "claude.ai",
    "chatgpt.com",
    "chat.openai.com",
    "gemini.google.com",
    "perplexity.ai",
    "chat.deepseek.com",
    "chat.mistral.ai",
    "grok.com",
    "copilot.microsoft.com",
]

APP_ACTIONS = ("mask", "bypass")


@dataclass
class Policy:
    version: int = 1
    hosts: list[str] = field(default_factory=lambda: list(DEFAULT_HOSTS))
    tools: dict[str, str] = field(default_factory=lambda: {"claude-code": "on"})
    apps: dict[str, str] = field(default_factory=dict)      # app name -> mask | bypass
    deep_apps: list[str] = field(default_factory=list)      # Stage 3: captured by the deep door
    doors: dict[str, bool] = field(default_factory=lambda: {"api": True, "system": True, "deep": False})

    # ------------------------------------------------------------ persistence
    @classmethod
    def load(cls) -> "Policy":
        p = config.policy_path()
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            return cls()
        pol = cls()
        pol.version = int(data.get("version", 1))
        pol.hosts = [h.lower() for h in data.get("hosts", pol.hosts)]
        pol.tools = dict(data.get("tools", pol.tools))
        pol.apps = dict(data.get("apps", {}))
        pol.deep_apps = list(data.get("deep_apps", []))
        pol.doors = {**pol.doors, **data.get("doors", {})}
        return pol

    def save(self) -> None:
        config.ensure_home()
        p = config.policy_path()
        tmp = p.with_suffix(".json.tmp")
        payload = {
            "version": self.version,
            "hosts": sorted(set(h.lower() for h in self.hosts)),
            "tools": self.tools,
            "apps": self.apps,
            "deep_apps": self.deep_apps,
            "doors": self.doors,
        }
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
        os.replace(tmp, p)

    # ------------------------------------------------------------ hosts
    def is_ai_host(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        return any(h == a or h.endswith("." + a) for a in self.hosts)

    def add_host(self, host: str) -> None:
        h = host.lower().strip()
        if h and h not in self.hosts:
            self.hosts.append(h)

    def remove_host(self, host: str) -> None:
        self.hosts = [h for h in self.hosts if h != host.lower().strip()]

    def allow_hosts(self) -> list[str]:
        """Regexes for mitmproxy's ``allow_hosts`` (matched against ``host:port`` and ``sni:port``)."""
        return [rf"(^|\.){re.escape(h)}:443$" for h in self.hosts]

    def pac(self, system_port: int) -> str:
        hosts = json.dumps(sorted(self.hosts))
        return (
            "function FindProxyForURL(url, host) {\n"
            f"  var hosts = {hosts};\n"
            "  host = host.toLowerCase();\n"
            "  for (var i = 0; i < hosts.length; i++) {\n"
            "    if (host == hosts[i] || dnsDomainIs(host, '.' + hosts[i])) "
            f'return "PROXY 127.0.0.1:{system_port}";\n'
            "  }\n"
            '  return "DIRECT";\n'
            "}\n"
        )

    # ------------------------------------------------------------ apps
    def app_action(self, app: str | None) -> str:
        if not app:
            return "mask"
        for name, action in self.apps.items():
            if name.lower() == app.lower():
                return action
        return "mask"

    def set_app(self, app: str, action: str) -> None:
        if action not in APP_ACTIONS:
            raise ValueError(f"action must be one of {APP_ACTIONS}")
        for name in list(self.apps):
            if name.lower() == app.lower():
                del self.apps[name]
        self.apps[app] = action
```

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_policy.py -q` → all pass.
- [ ] **Step 5: Commit** — `git add src/omna_plugin/policy.py src/omna_plugin/config.py tests/test_policy.py && git commit -m "feat(policy): one policy file for AI hosts, tools, apps and doors"`

---

## Task 2: Extract the mail room (`pipeline.py`) and make the API door use it

**Files:** Create `src/omna_plugin/pipeline.py`, `tests/test_pipeline.py`. Modify `src/omna_plugin/proxy.py`, `src/omna_plugin/stream.py` (rename `_HoldBack` → public `TextRestorer`, keep `_HoldBack = TextRestorer` as an alias).

- [ ] **Step 1: Failing tests**

```python
# tests/test_pipeline.py
import json
from omna_plugin import receipts
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline, MaskStats

EMAIL = "jane.doe@example.com"
TOK = "[EMAIL_" "1]"          # two pieces on purpose, see the note at the top of this plan


def _pipe(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return Pipeline(MaskingSession())


def test_mask_json_returns_masked_copy_and_stats(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    obj = {"messages": [{"role": "user", "content": f"mail {EMAIL} now"}]}
    masked, stats = p.mask_json(obj)
    assert EMAIL not in json.dumps(masked)
    assert TOK in json.dumps(masked)
    assert isinstance(stats, MaskStats)
    assert stats.counts == {"EMAIL": 1} and stats.pii == 1 and stats.secrets == 0
    assert stats.tokens == ["EMAIL_1"]
    assert obj["messages"][0]["content"].startswith("mail jane")  # input untouched


def test_mask_bytes_json_and_refusal(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    out = p.mask_bytes(b'{"prompt": "call 415-555-0134"}', "application/json")
    assert out.refused is None
    assert b"[PHONE_" b"1]" in out.body
    bad = p.mask_bytes(b"\x00\x01 not json", "application/json")
    assert bad.refused == "unparseable"
    assert bad.body is None


def test_mask_bytes_form_urlencoded(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    out = p.mask_bytes(b"q=email+jane.doe%40example.com&page=1", "application/x-www-form-urlencoded")
    assert out.refused is None
    assert b"EMAIL_1" in out.body and b"page=1" in out.body


def test_restore_json_and_text(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    p.mask_json({"t": EMAIL})
    assert p.restore_json({"reply": "wrote to " + TOK}) == {"reply": "wrote to " + EMAIL}
    assert p.restore_text(TOK) == EMAIL


def test_text_restorer_json_escapes_and_holds_back(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    p.mask_json({"t": 'Ann "AJ" Jones <aj@example.com>'})   # a value with quotes around it
    r = p.text_restorer(json_escape=True)
    out = r.feed('{"delta":"[EMA') + r.feed('IL_1]"}')
    assert out == '{"delta":"aj@example.com"}'
    assert r.flush() == ""


def test_receipt_carries_door_host_and_app(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    _, stats = p.mask_json({"t": EMAIL})
    p.receipt(door="system", route="/backend-api/conversation", host="chatgpt.com", status=200,
              stats=stats, nbytes=42, ms=17, stream=True, app="Google Chrome", note=None, session_id=None)
    rec = receipts.tail(1)[0]
    assert rec["door"] == "system" and rec["host"] == "chatgpt.com" and rec["app"] == "Google Chrome"
    assert rec["masked"] == {"EMAIL": 1} and rec["pii"] == 1 and rec["tokens"] == ["EMAIL_1"]
    assert "jane" not in json.dumps(rec)
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_pipeline.py -q` → ImportError.

- [ ] **Step 3: Implement `pipeline.py`**

```python
# src/omna_plugin/pipeline.py
"""The mail room. Every door (API, system, deep) hands its traffic to this
one object: mask on the way out, restore on the way back, one receipt per
request. It owns nothing network-related."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode

from . import receipts
from .body import mask_body, restore_body
from .engine import MaskingSession, TOKEN_RE
from .stream import StreamRestorer, TextRestorer


@dataclass
class MaskStats:
    counts: dict[str, int] = field(default_factory=dict)
    secrets: int = 0
    pii: int = 0
    mask_ms: int = 0
    tokens: list[str] = field(default_factory=list)


@dataclass
class MaskedBody:
    body: bytes | None
    stats: MaskStats
    refused: str | None = None   # "unparseable" | None


def _tokens_in(text: str) -> list[str]:
    return sorted({m.group(0)[1:-1] for m in TOKEN_RE.finditer(text)})


def _merge(total: MaskStats, st: MaskStats) -> None:
    for k, v in st.counts.items():
        total.counts[k] = total.counts.get(k, 0) + v
    total.secrets += st.secrets
    total.pii += st.pii
    total.mask_ms += st.mask_ms
    total.tokens = sorted(set(total.tokens) | set(st.tokens))


class Pipeline:
    def __init__(self, session: MaskingSession):
        self.session = session

    # ------------------------------------------------------------ masking
    def mask_json(self, obj) -> tuple[object, MaskStats]:
        t0 = time.time()
        masked, counts = mask_body(self.session, obj)
        c = dict(counts)
        stats = MaskStats(
            secrets=c.pop("_secrets", 0),
            pii=c.pop("_pii", 0),
            counts=c,
            mask_ms=int((time.time() - t0) * 1000),
            tokens=_tokens_in(json.dumps(masked, ensure_ascii=False)),
        )
        return masked, stats

    def mask_text(self, text: str) -> tuple[str, MaskStats]:
        t0 = time.time()
        r = self.session.mask_text(text)
        return r.masked, MaskStats(counts=dict(r.counts), secrets=r.secrets, pii=r.pii,
                                   mask_ms=int((time.time() - t0) * 1000), tokens=_tokens_in(r.masked))

    def mask_bytes(self, body: bytes, content_type: str) -> MaskedBody:
        """Mask a request body by content type. Unparseable bodies are refused, never forwarded."""
        ct = (content_type or "").lower()
        try:
            if "json" in ct:
                masked, stats = self.mask_json(json.loads(body))
                return MaskedBody(json.dumps(masked, ensure_ascii=False).encode("utf-8"), stats)
            if "x-www-form-urlencoded" in ct:
                total, out = MaskStats(), []
                for k, v in parse_qsl(body.decode("utf-8"), keep_blank_values=True):
                    mv, st = self.mask_text(v)
                    out.append((k, mv))
                    _merge(total, st)
                return MaskedBody(urlencode(out).encode("utf-8"), total)
            if ct.startswith("text/"):
                masked, stats = self.mask_text(body.decode("utf-8"))
                return MaskedBody(masked.encode("utf-8"), stats)
        except (ValueError, UnicodeDecodeError, TypeError):
            pass
        return MaskedBody(None, MaskStats(), refused="unparseable")

    # ------------------------------------------------------------ restoring
    def restore_json(self, obj):
        return restore_body(self.session, obj)

    def restore_text(self, text: str) -> str:
        return self.session.restore_text(text)

    def sse_restorer(self) -> StreamRestorer:
        """For Anthropic / OpenAI shaped SSE (the API door's formats)."""
        return StreamRestorer(self.session)

    def text_restorer(self, json_escape: bool) -> TextRestorer:
        """Token-level restore over any text stream, with partial-token hold-back."""
        return TextRestorer(self.session, json_escape=json_escape)

    # ------------------------------------------------------------ receipts
    def receipt(self, *, door: str, route: str, host: str, status: int, stats: MaskStats,
                nbytes: int, ms: int, stream: bool, app: str | None, note: str | None,
                session_id: str | None) -> None:
        rec = {
            "door": door, "route": route, "host": host, "upstream": host, "status": status,
            "stream": stream, "masked": stats.counts, "secrets": stats.secrets, "pii": stats.pii,
            "mask_ms": stats.mask_ms, "tokens": stats.tokens, "bytes_in": nbytes, "ms": ms,
            "app": app,
        }
        if note:
            rec["note"] = note
        if session_id:
            rec["session"] = session_id
        try:
            receipts.append(rec)
        except OSError:
            pass
```

- [ ] **Step 4: Make `proxy.py` use the pipeline** — replace the inline masking/receipt code with `pipeline.mask_bytes(...)` / `pipeline.sse_restorer()` / `pipeline.restore_json(...)` / `pipeline.receipt(door="api", ...)`. Keep every response byte identical to today. `create_app(session=None, *, pipeline=None, policy=None, doors_state=None, ...)`; add the route (before the catch-all):

```python
    async def pac(_: Request) -> Response:
        return Response((policy or Policy.load()).pac(system_port=config.SYSTEM_PORT),
                        media_type="application/x-ns-proxy-autoconfig")
    # Route("/omna/proxy.pac", pac, methods=["GET"])
```
and include `"doors": doors_state or {"api": True, "system": False, "deep": False}` in `/omna/health`. The receipt `upstream` field stays (report.py reads it).

- [ ] **Step 5: Run the whole suite** — `.venv/bin/pytest -q` → all green, including the untouched `tests/test_proxy.py`. Add one assertion to `tests/test_proxy.py`: `GET /omna/proxy.pac` returns 200 with `PROXY 127.0.0.1:7789` in the body.
- [ ] **Step 6: Commit** — `git commit -am "refactor: extract the mail room (pipeline) from the API door; serve the PAC"`

---

## Task 3: Adapter protocol and the generic adapter

**Files:** Create `src/omna_plugin/adapters/__init__.py`, `base.py`, `generic.py`; `tests/test_adapters.py`.

- [ ] **Step 1: Failing tests**

```python
# tests/test_adapters.py
from omna_plugin.adapters import for_host
from omna_plugin.adapters.base import RequestView
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline


def _req(host, path, body, ct="application/json", method="POST"):
    return RequestView(host=host, method=method, path=path, content_type=ct, body=body, headers={})


def test_unknown_ai_host_gets_the_generic_adapter():
    assert for_host("api.some-new-ai.com").name == "generic"


def test_generic_prompt_detection_uses_the_extension_regex():
    a = for_host("example.com")
    assert a.is_prompt(_req("example.com", "/backend-api/conversation", b"{}"))
    assert a.is_prompt(_req("example.com", "/v1/chat/completions", b"{}"))
    assert not a.is_prompt(_req("example.com", "/assets/app.js", b"", ct="text/javascript", method="GET"))
    assert not a.is_prompt(_req("example.com", "/backend-api/conversation", b"", method="GET"))


def test_generic_masks_json_prompt_and_refuses_garbage(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    a = for_host("example.com")
    ok = a.mask(p, _req("example.com", "/api/chat", b'{"messages":[{"content":"hi jane.doe@example.com"}]}'))
    assert ok.refused is None and b"[EMAIL_" b"1]" in ok.body
    bad = a.mask(p, _req("example.com", "/api/chat", b"{broken"))
    assert bad.refused == "unparseable"


def test_generic_non_prompt_post_is_passthrough(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    a = for_host("example.com")
    out = a.mask(p, _req("example.com", "/telemetry", b"\x00binary", ct="application/octet-stream"))
    assert out.refused is None and out.body is None and out.passthrough


def test_generic_picks_restorer_by_response_type():
    a = for_host("example.com")
    assert a.response_mode("text/event-stream") == "stream-json"
    assert a.response_mode("application/json") == "json"
    assert a.response_mode("text/plain; charset=utf-8") == "stream-text"
    assert a.response_mode("image/png") == "passthrough"
```

- [ ] **Step 2: Run** → ImportError.

- [ ] **Step 3: Implement**

```python
# src/omna_plugin/adapters/base.py
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Protocol

from ..pipeline import MaskStats, Pipeline

# Same rule the Chrome extension uses to decide "this POST carries a prompt".
ENDPOINT_RE = re.compile(
    r"/(append_message|completion|conversation|stream|chat|generate|backend-api|message|messages|prompt|responses|complete|embeddings)",
    re.I,
)

ResponseMode = Literal["stream-json", "stream-text", "json", "passthrough"]


@dataclass
class RequestView:
    host: str
    method: str
    path: str
    content_type: str
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class MaskOutcome:
    body: bytes | None            # the masked body to forward (None = forward original, or refused)
    stats: MaskStats
    refused: str | None = None    # set → do NOT forward; answer 400
    passthrough: bool = False     # forwarded unchanged on purpose (not a prompt)


class SiteAdapter(Protocol):
    name: str
    hosts: tuple[str, ...]

    def is_prompt(self, req: RequestView) -> bool: ...
    def mask(self, pipeline: Pipeline, req: RequestView) -> MaskOutcome: ...
    def response_mode(self, content_type: str) -> ResponseMode: ...
```

```python
# src/omna_plugin/adapters/generic.py
from __future__ import annotations

from ..pipeline import MaskStats, Pipeline
from .base import ENDPOINT_RE, MaskOutcome, RequestView, ResponseMode

_MASKABLE = ("json", "x-www-form-urlencoded", "text/")


class GenericAdapter:
    """Default for every AI host: mask every prose string in a prompt body; refuse what we cannot parse."""

    name = "generic"
    hosts: tuple[str, ...] = ()

    def is_prompt(self, req: RequestView) -> bool:
        return req.method in ("POST", "PUT", "PATCH") and ENDPOINT_RE.search(req.path) is not None

    def mask(self, pipeline: Pipeline, req: RequestView) -> MaskOutcome:
        ct = (req.content_type or "").lower()
        maskable = any(m in ct for m in _MASKABLE)
        if not self.is_prompt(req):
            if maskable and req.body:
                out = pipeline.mask_bytes(req.body, ct)     # best effort on non-prompt text; never refuse
                if out.refused is None:
                    return MaskOutcome(out.body, out.stats)
            return MaskOutcome(None, MaskStats(), passthrough=True)
        if not req.body:
            return MaskOutcome(None, MaskStats(), passthrough=True)
        if not maskable:
            return MaskOutcome(None, MaskStats(), refused="unparseable")
        out = pipeline.mask_bytes(req.body, ct)
        return MaskOutcome(out.body, out.stats, refused=out.refused)

    def response_mode(self, content_type: str) -> ResponseMode:
        ct = (content_type or "").lower()
        if "event-stream" in ct or "x-ndjson" in ct:
            return "stream-json"
        if "json" in ct:
            return "json"
        if ct.startswith("text/"):
            return "stream-text"
        return "passthrough"
```

```python
# src/omna_plugin/adapters/__init__.py
from __future__ import annotations

from .base import SiteAdapter
from .generic import GenericAdapter

_GENERIC = GenericAdapter()
_REGISTRY: list[SiteAdapter] = []   # site adapters register themselves (Task 8)


def register(adapter: SiteAdapter) -> None:
    _REGISTRY.append(adapter)


def for_host(host: str) -> SiteAdapter:
    h = (host or "").lower()
    for a in _REGISTRY:
        if any(h == s or h.endswith("." + s) for s in a.hosts):
            return a
    return _GENERIC
```

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_adapters.py -q` → pass. **Step 5: Commit** `feat(adapters): site adapter protocol + generic adapter`.

---

## Task 4: Process resolver (`procs.py`)

**Files:** Create `src/omna_plugin/procs.py`, `tests/test_procs.py`.

- [ ] **Step 1: Failing tests** — parse real `lsof -F` output; never call lsof in tests.

```python
# tests/test_procs.py
from omna_plugin.procs import ProcessResolver, parse_lsof

LSOF = b"p812\ncGoogle Chrome He\np4242\ncomna\n"


def test_parse_lsof_excludes_our_own_pid():
    assert parse_lsof(LSOF, own_pid=4242) == (812, "Google Chrome He")


def test_parse_lsof_empty():
    assert parse_lsof(b"", own_pid=1) is None


def test_resolver_caches_and_uses_runner():
    calls = []

    def fake_run(port):
        calls.append(port)
        return LSOF

    r = ProcessResolver(runner=fake_run, own_pid=4242, display_name=lambda pid: "Google Chrome")
    assert r.resolve(("127.0.0.1", 50123)) == (812, "Google Chrome")
    assert r.resolve(("127.0.0.1", 50123)) == (812, "Google Chrome")
    assert calls == [50123]
```

- [ ] **Step 2: Run** → ImportError. **Step 3: Implement**

```python
# src/omna_plugin/procs.py
"""Which app opened this connection? mitmproxy gives us the client's (ip, port);
`lsof` tells us which process owns that port. Only called for AI hosts, cached per port."""

from __future__ import annotations

import os
import subprocess
from collections import OrderedDict
from typing import Callable

_CACHE = 512


def _run_lsof(port: int) -> bytes:
    try:
        return subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:ESTABLISHED", "-Fpc"],
            capture_output=True, timeout=1.5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return b""


def parse_lsof(out: bytes, own_pid: int) -> tuple[int, str] | None:
    pid, name = None, None
    for line in out.decode("utf-8", "replace").splitlines():
        if line.startswith("p"):
            if pid is not None and pid != own_pid and name:
                return pid, name
            pid, name = int(line[1:] or 0), None
        elif line.startswith("c"):
            name = line[1:]
    if pid is not None and pid != own_pid and name:
        return pid, name
    return None


def _display_name(pid: int) -> str | None:
    """The .app name for a pid (``/Applications/Google Chrome.app/...`` → ``Google Chrome``), else the command name."""
    try:
        exe = subprocess.run(["ps", "-o", "comm=", "-p", str(pid)], capture_output=True, timeout=1.0, check=False).stdout.decode().strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if ".app/" in exe:
        return exe.split(".app/")[0].rsplit("/", 1)[-1]
    return exe.rsplit("/", 1)[-1] or None


class ProcessResolver:
    def __init__(self, runner: Callable[[int], bytes] = _run_lsof, own_pid: int | None = None,
                 display_name: Callable[[int], str | None] = _display_name):
        self._run = runner
        self._own = own_pid or os.getpid()
        self._name = display_name
        self._cache: OrderedDict[int, tuple[int, str] | None] = OrderedDict()

    def resolve(self, peername: tuple[str, int] | None) -> tuple[int, str] | None:
        if not peername:
            return None
        port = peername[1]
        if port in self._cache:
            return self._cache[port]
        got = parse_lsof(self._run(port), self._own)
        if got:
            pid, comm = got
            got = (pid, self._name(pid) or comm)
        self._cache[port] = got
        if len(self._cache) > _CACHE:
            self._cache.popitem(last=False)
        return got
```

- [ ] **Step 4: Run → pass. Step 5: Commit** `feat(procs): resolve the app behind a loopback connection`.

---

## Task 5: The system door addon (`system_door.py`) — hermetic end-to-end test

**Files:** Create `src/omna_plugin/system_door.py`, `tests/test_system_door.py`, `tests/tls_helpers.py`. Modify `pyproject.toml` (`requires-python = ">=3.12"`, add `"mitmproxy>=12.2,<13"`), then `uv sync --extra dev` (or `.venv/bin/pip install -e ".[dev]"`).

- [ ] **Step 1: Test helper — a real HTTPS "AI upstream" in-process**

```python
# tests/tls_helpers.py
"""A throwaway CA + a leaf cert for 127.0.0.1, and a tiny HTTPS server that speaks
enough HTTP/1.1 to echo the request body it received and stream a canned SSE reply."""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_ca_and_leaf(tmp: Path) -> tuple[Path, Path, Path]:
    ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "omna-test-ca")])
    now = dt.datetime.now(dt.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
          .not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_pem = tmp / "test-ca.pem"
    ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf_pem = tmp / "leaf.pem"
    leaf_pem.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    leaf_keyf = tmp / "leaf-key.pem"
    leaf_keyf.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return ca_pem, leaf_pem, leaf_keyf


# The canned SSE reply: a known token split across two chunks (the hold-back case),
# plus an unknown token that must pass through untouched.
SSE_FRAMES = (
    b'data: {"delta":"Hello [PER',
    b'SON_1], your mail [EMAIL_' b'1] is set"}\n\n',
    b"data: [DONE]\n\n",
)


class FakeUpstream:
    """Records the last request; replies with SSE if the path ends in /stream, else a JSON echo."""

    def __init__(self):
        self.last_body: bytes | None = None
        self.last_headers: dict[str, str] = {}
        self.port = 0
        self._srv = None

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        head = await r.readuntil(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        _method, path, _ = lines[0].split(" ", 2)
        hdrs = {k.lower(): v for k, v in (l.split(": ", 1) for l in lines[1:] if ": " in l)}
        self.last_headers = hdrs
        n = int(hdrs.get("content-length", "0"))
        self.last_body = await r.readexactly(n) if n else b""
        if path.endswith("/stream"):
            w.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n")
            for frame in SSE_FRAMES:
                w.write(f"{len(frame):x}\r\n".encode() + frame + b"\r\n")
                await w.drain()
                await asyncio.sleep(0.01)
            w.write(b"0\r\n\r\n")
        else:
            body = b'{"echo": ' + (self.last_body or b"null") + b', "reply": "hi [EMAIL_' b'1]"}'
            w.write(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await w.drain()
        w.close()

    async def start(self, leaf_pem: Path, leaf_key: Path):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(leaf_pem), str(leaf_key))
        self._srv = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=ctx)
        self.port = self._srv.sockets[0].getsockname()[1]

    async def stop(self):
        self._srv.close()
        await self._srv.wait_closed()
```

- [ ] **Step 2: The end-to-end test (failing)**

```python
# tests/test_system_door.py
import asyncio
import ssl

import httpx
import pytest

from omna_plugin import receipts
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline
from omna_plugin.policy import Policy
from omna_plugin.system_door import OmnaAddon, build_master
from tests.tls_helpers import FakeUpstream, make_ca_and_leaf

EMAIL = "jane.doe@example.com"
TOK = "[EMAIL_" "1]"


@pytest.fixture
async def door(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    ca_pem, leaf, key = make_ca_and_leaf(tmp_path)
    up = FakeUpstream()
    await up.start(leaf, key)
    pol = Policy()
    pol.hosts = ["127.0.0.1"]                                       # the fake upstream is "an AI host" here
    pol.allow_hosts = lambda: [rf"^127\.0\.0\.1:{up.port}$"]      # its port is not 443
    pipe = Pipeline(MaskingSession())
    addon = OmnaAddon(pipe, pol, door="system", resolver=lambda peer: (999, "TestApp"))
    master = build_master(pol, addon, port=0, ca_dir=tmp_path / "ca", upstream_ca=str(ca_pem))
    task = asyncio.create_task(master.run())
    await asyncio.sleep(0.5)                                        # let mitmproxy bind
    port = next(a[1] for inst in master.addons.get("proxyserver").servers for a in inst.listen_addrs)
    client_ctx = ssl.create_default_context(cafile=str(tmp_path / "ca" / "mitmproxy-ca-cert.pem"))
    yield up, port, client_ctx, addon
    master.shutdown()
    await task
    await up.stop()


async def test_prompt_is_masked_and_stream_restored(door):
    up, port, ctx, _ = door
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/backend-api/conversation/stream",
                         json={"messages": [{"content": {"parts": [f"hi, {EMAIL}"]}}]})
    assert r.status_code == 200
    assert EMAIL.encode() not in up.last_body and TOK.encode() in up.last_body   # upstream saw the token only
    assert up.last_headers.get("accept-encoding") == "identity"
    assert EMAIL in r.text and TOK not in r.text                                # restored inside the stream
    assert "[PER" "SON_1]" in r.text                                             # unknown token passes through
    rec = receipts.tail(1)[0]
    assert rec["door"] == "system" and rec["app"] == "TestApp" and rec["masked"].get("EMAIL") == 1


async def test_json_reply_is_restored(door):
    up, port, ctx, _ = door
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": f"for {EMAIL}"})
    assert r.status_code == 200
    assert TOK.encode() in up.last_body
    assert r.json()["reply"] == "hi " + EMAIL
    assert r.json()["echo"]["prompt"] == "for " + EMAIL                         # the echoed token came back restored


async def test_unparseable_prompt_is_refused_not_forwarded(door):
    up, port, ctx, _ = door
    up.last_body = b"UNTOUCHED"
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/api/chat", content=b"{broken", headers={"content-type": "application/json"})
    assert r.status_code == 400 and "omna_refused" in r.text
    assert up.last_body == b"UNTOUCHED"


async def test_bypassed_app_is_tunnelled_untouched(door):
    up, port, _ctx, addon = door
    addon.policy.set_app("TestApp", "bypass")
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=False) as c:   # we now see the UPSTREAM cert
        r = await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": EMAIL})
    assert r.status_code == 200
    assert EMAIL.encode() in up.last_body                                        # bypass = really untouched
    assert receipts.tail(1)[0]["note"] == "bypassed-by-policy"
```

- [ ] **Step 3: Run** → ImportError.

- [ ] **Step 4: Implement `system_door.py`**

```python
# src/omna_plugin/system_door.py
"""The system door and the deep door: one mitmproxy addon in front of the mail room.

Only hostnames on the policy list are ever decrypted (mitmproxy ``allow_hosts``;
everything else is tunnelled encrypted). For those: mask the request through the
site adapter, forward with ``accept-encoding: identity`` so replies arrive
uncompressed, restore streamed / JSON / websocket replies chunk by chunk, write one
receipt. A bypassed app is tunnelled untouched and receipted as such. An app that
refuses our certificate (pinned) is receipted as ``tls-refused`` and never forwarded.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Callable

from mitmproxy import http, tls
from mitmproxy.certs import CertStore
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from .adapters import for_host
from .adapters.base import RequestView
from .pipeline import MaskStats, Pipeline
from .policy import Policy

CA_ORG = "Omna"
CA_CN = "Omna Local Certificate Authority"
REFUSED_BODY = (b'{"type":"error","error":{"type":"omna_refused",'
                b'"message":"omna could not mask this request; refused rather than sent unmasked"}}')

Resolver = Callable[[tuple[str, int] | None], tuple[int, str] | None]


def ensure_ca(ca_dir: Path) -> Path:
    """Create the local CA once (private key 0600). Returns the public cert path."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    ca_dir.chmod(0o700)
    if not (ca_dir / "mitmproxy-ca.pem").exists():
        CertStore.create_store(ca_dir, "mitmproxy", 2048, organization=CA_ORG, cn=CA_CN)
    (ca_dir / "mitmproxy-ca.pem").chmod(0o600)
    return ca_dir / "mitmproxy-ca-cert.pem"


def _utf8_split(buf: bytearray) -> tuple[str, bytes]:
    """Decode all complete UTF-8 characters; keep an incomplete trailing sequence for the next chunk."""
    cut = len(buf)
    back = 0
    while cut > 0 and back < 3 and (buf[cut - 1] & 0xC0) == 0x80:
        cut -= 1
        back += 1
    if cut > 0 and (buf[cut - 1] & 0xC0) == 0xC0:
        cut -= 1
    elif back:
        cut = len(buf)  # the trailing continuation bytes complete a char that already started
    return bytes(buf[:cut]).decode("utf-8", "replace"), bytes(buf[cut:])


class OmnaAddon:
    def __init__(self, pipeline: Pipeline, policy: Policy, door: str, resolver: Resolver):
        self.pipeline = pipeline
        self.policy = policy
        self.door = door
        self.resolver = resolver
        self.refusals: dict[str, int] = {}     # "App → host" -> count this run (also receipted)
        self.seen_apps: dict[str, int] = {}

    # ---------------------------------------------------------------- helpers
    def _app_of(self, client) -> str | None:
        got = self.resolver(getattr(client, "peername", None))
        return got[1] if got else None

    def _door_for(self, flow: http.HTTPFlow) -> str:
        mode = flow.client_conn.proxy_mode
        return "deep" if type(mode).__name__ == "LocalMode" else self.door

    def _receipt(self, flow: http.HTTPFlow, status: int, stream: bool) -> None:
        t0 = flow.metadata.get("omna_t0") or time.time()
        self.pipeline.receipt(
            door=self._door_for(flow), route=flow.request.path.split("?")[0][:80], host=flow.request.pretty_host,
            status=status, stats=flow.metadata.get("omna_stats") or MaskStats(),
            nbytes=flow.metadata.get("omna_nbytes", 0), ms=int((time.time() - t0) * 1000),
            stream=stream, app=flow.metadata.get("omna_app"), note=flow.metadata.get("omna_note"), session_id=None)

    # ---------------------------------------------------------------- TLS
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        app = self._app_of(data.context.client)
        if self.policy.app_action(app) == "bypass":
            data.ignore_connection = True
            self.pipeline.receipt(door=self.door, route="CONNECT", host=data.client_hello.sni or "?", status=0,
                                  stats=MaskStats(), nbytes=0, ms=0, stream=False, app=app,
                                  note="bypassed-by-policy", session_id=None)

    def tls_failed_client(self, data: tls.TlsData) -> None:
        app = self._app_of(data.context.client) or "unknown app"
        host = data.context.client.sni or "?"
        key = f"{app} → {host}"
        self.refusals[key] = self.refusals.get(key, 0) + 1
        self.pipeline.receipt(door=self.door, route="TLS", host=host, status=0, stats=MaskStats(),
                              nbytes=0, ms=0, stream=False, app=app, note="tls-refused", session_id=None)

    # ---------------------------------------------------------------- HTTP
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        flow.request.headers["accept-encoding"] = "identity"
        flow.metadata["omna_t0"] = time.time()

    def request(self, flow: http.HTTPFlow) -> None:
        app = self._app_of(flow.client_conn)
        if app:
            self.seen_apps[app] = self.seen_apps.get(app, 0) + 1
        adapter = for_host(flow.request.pretty_host)
        req = RequestView(host=flow.request.pretty_host, method=flow.request.method, path=flow.request.path,
                          content_type=flow.request.headers.get("content-type", ""),
                          body=flow.request.get_content() or b"", headers=dict(flow.request.headers))
        out = adapter.mask(self.pipeline, req)
        flow.metadata.update(omna_app=app, omna_adapter=adapter, omna_stats=out.stats, omna_nbytes=len(req.body),
                             omna_note="passthrough-nonprompt" if out.passthrough else None)
        if out.refused:
            flow.metadata["omna_note"] = out.refused
            flow.response = http.Response.make(400, REFUSED_BODY, {"content-type": "application/json"})
            self._receipt(flow, 400, stream=False)
            return
        if out.body is not None:
            flow.request.set_content(out.body)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.metadata.get("omna_note") == "unparseable":
            return
        adapter = flow.metadata.get("omna_adapter") or for_host(flow.request.pretty_host)
        mode = adapter.response_mode(flow.response.headers.get("content-type", ""))
        if mode not in ("stream-json", "stream-text"):
            return
        restorer = self.pipeline.text_restorer(json_escape=(mode == "stream-json"))
        buf = bytearray()

        def cb(chunk: bytes) -> bytes:
            if chunk == b"":
                tail = restorer.feed(bytes(buf).decode("utf-8", "replace")) + restorer.flush() if buf else restorer.flush()
                self._receipt(flow, flow.response.status_code if flow.response else 0, stream=True)
                return tail.encode("utf-8")
            buf.extend(chunk)
            text, rest = _utf8_split(buf)
            buf.clear()
            buf.extend(rest)
            return restorer.feed(text).encode("utf-8")

        flow.response.stream = cb
        flow.metadata["omna_streamed"] = True

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.metadata.get("omna_streamed") or flow.metadata.get("omna_note") == "unparseable":
            return
        adapter = flow.metadata.get("omna_adapter") or for_host(flow.request.pretty_host)
        if adapter.response_mode(flow.response.headers.get("content-type", "")) == "json" and flow.response.status_code < 400:
            try:
                obj = json.loads(flow.response.get_content() or b"null")
                flow.response.set_content(json.dumps(self.pipeline.restore_json(obj), ensure_ascii=False).encode("utf-8"))
            except ValueError:
                pass
        self._receipt(flow, flow.response.status_code, stream=False)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert flow.websocket
        msg = flow.websocket.messages[-1]
        if not msg.is_text:
            return
        if msg.from_client:
            masked, stats = self.pipeline.mask_text(msg.text)
            msg.content = masked.encode("utf-8")
            st: MaskStats = flow.metadata.setdefault("omna_stats", MaskStats())
            for k, v in stats.counts.items():
                st.counts[k] = st.counts.get(k, 0) + v
            st.secrets += stats.secrets
            st.pii += stats.pii
        else:
            msg.content = self.pipeline.restore_text(msg.text).encode("utf-8")


def build_master(policy: Policy, addon: OmnaAddon, *, port: int, ca_dir: Path,
                 upstream_ca: str | None = None, deep_apps: list[str] | None = None) -> DumpMaster:
    ensure_ca(ca_dir)
    modes = [f"regular@{port}"]
    if deep_apps:
        modes.append("local:" + ",".join(deep_apps))
    opts = Options(listen_host="127.0.0.1", mode=modes, confdir=str(ca_dir),
                   allow_hosts=policy.allow_hosts(), websocket=True, http2=True,
                   termlog_verbosity="warn", store_streamed_bodies=False)
    if upstream_ca:
        opts.update(ssl_verify_upstream_trusted_ca=upstream_ca)
    master = DumpMaster(opts, loop=asyncio.get_running_loop(), with_termlog=False, with_dumper=False)
    master.addons.add(addon)
    return master
```

Notes for the implementer:
- `data.context.client.peername` is the (ip, port) tuple; `data.client_hello.sni` may be `None`.
- If `Options(...)` rejects a key it raises `KeyError`; every name above was checked against `mitmproxy/options.py`, `addons/proxyserver.py`, `addons/tlsconfig.py` for 12.2.3.
- The test reads the bound port from `master.addons.get("proxyserver").servers`; if that attribute differs in your version, implement a `running()` hook on the addon that records `ctx.master.addons.get("proxyserver").listen_addrs()` and use that.
- `_utf8_split` is the one subtle piece: a multi-byte character cut between two chunks must not be decoded as garbage. Add a unit test with `"é".encode()` split at byte 1.

- [ ] **Step 5: Run** `.venv/bin/pytest tests/test_system_door.py -q -x` → 4 pass (the first run will surface any API-name mismatch; fixing those here is the task's whole point).
- [ ] **Step 6: Commit** `feat(system-door): mitmproxy addon over the mail room; hermetic TLS end-to-end test`.

---

## Task 6: One daemon, all doors (`daemon.py`) + `omna start` uses it

**Files:** Create `src/omna_plugin/daemon.py`, `tests/test_daemon.py`. Modify `cli.py` (`cmd_start` foreground path calls `daemon.run(...)`; `-d` unchanged), `proxy.py` (`run()` removed).

- [ ] **Step 1: Failing test** — start the daemon on two random ports, check both answer, stop it.

```python
# tests/test_daemon.py
import asyncio

import httpx

from omna_plugin import daemon


async def test_daemon_opens_both_doors_and_stops(tmp_path, monkeypatch, unused_tcp_port_factory):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    api, system = unused_tcp_port_factory(), unused_tcp_port_factory()
    stop = asyncio.Event()
    task = asyncio.create_task(daemon.serve(api_port=api, system_port=system, stop=stop))
    h = None
    for _ in range(50):
        try:
            h = httpx.get(f"http://127.0.0.1:{api}/omna/health", timeout=0.5).json()
            break
        except httpx.HTTPError:
            await asyncio.sleep(0.1)
    assert h and h["ok"] and h["doors"] == {"api": True, "system": True, "deep": False}
    r = httpx.get(f"http://127.0.0.1:{api}/omna/proxy.pac")
    assert f"127.0.0.1:{system}" in r.text
    stop.set()
    await asyncio.wait_for(task, 10)
```
(`unused_tcp_port_factory` is a pytest-asyncio fixture.)

- [ ] **Step 2: Implement**

```python
# src/omna_plugin/daemon.py
"""Run every door in one process on one event loop: the API door (uvicorn) and the
mitmproxy master (system door + deep door). One MaskingSession, one policy, one stop."""

from __future__ import annotations

import asyncio
import signal

import uvicorn

from . import config
from .engine import MaskingSession
from .pipeline import Pipeline
from .policy import Policy
from .procs import ProcessResolver
from .proxy import create_app
from .system_door import OmnaAddon, build_master


async def serve(api_port: int = config.DEFAULT_PORT, system_port: int = config.SYSTEM_PORT, *,
                smart: bool = False, restore_secrets: bool = True, stop: asyncio.Event | None = None) -> None:
    policy = Policy.load()
    session = MaskingSession(smart=smart, restore_secrets=restore_secrets)
    pipeline = Pipeline(session)
    stop = stop or asyncio.Event()

    app = create_app(session, pipeline=pipeline, policy=policy, doors_state=policy.doors)
    api = uvicorn.Server(uvicorn.Config(app, host=config.DEFAULT_HOST, port=api_port, log_level="warning", access_log=False))
    api.install_signal_handlers = lambda: None   # one handler for the whole process, below
    tasks = [asyncio.create_task(api.serve())]
    master = None
    if policy.doors.get("system", True):
        addon = OmnaAddon(pipeline, policy, door="system", resolver=ProcessResolver().resolve)
        master = build_master(policy, addon, port=system_port, ca_dir=config.ca_dir(),
                              deep_apps=policy.deep_apps if policy.doors.get("deep") else None)
        tasks.append(asyncio.create_task(master.run()))

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    await stop.wait()
    api.should_exit = True
    if master:
        master.shutdown()
    await asyncio.gather(*tasks, return_exceptions=True)


def run(**kw) -> None:
    asyncio.run(serve(**kw))
```
In `proxy.py`, `create_app(...)` accepts `doors_state` and reports it in `/omna/health` as `"doors"`. In `cli.py`, the foreground `cmd_start` calls `daemon.run(api_port=a.port, smart=a.smart, restore_secrets=not a.no_restore_secrets)`; `--smart` keeps the model download prompt that `proxy.run()` used to print.

- [ ] **Step 3: Run** `.venv/bin/pytest -q` → green. **Step 4: Commit** `feat(daemon): one process runs the API door and the system door`.

---

## Task 7: Mac setup — commands as data, one sudo batch (`mac/`)

**Files:** Create `src/omna_plugin/mac/__init__.py` (empty), `certs.py`, `netproxy.py`, `launchd.py`, `setup.py`; `tests/test_mac_setup.py`. Tests assert command text only.

- [ ] **Step 1: Failing tests**

```python
# tests/test_mac_setup.py
from pathlib import Path

from omna_plugin.mac import certs, launchd, netproxy, setup

SERVICES = "An asterisk (*) denotes that a network service is disabled.\nThunderbolt Bridge\nWi-Fi\n*iPhone USB\n"


def test_services_parsing_skips_header_and_disabled():
    assert netproxy.parse_services(SERVICES) == ["Thunderbolt Bridge", "Wi-Fi"]


def test_pac_on_off_commands():
    on = netproxy.pac_on_commands(["Wi-Fi"], "http://127.0.0.1:7788/omna/proxy.pac")
    assert on == ['networksetup -setautoproxyurl "Wi-Fi" "http://127.0.0.1:7788/omna/proxy.pac"',
                  'networksetup -setautoproxystate "Wi-Fi" on']
    assert netproxy.pac_off_commands(["Wi-Fi"]) == ['networksetup -setautoproxystate "Wi-Fi" off']


def test_trust_commands(tmp_path):
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    assert certs.trust_command(cert) == f'security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{cert}"'
    assert certs.untrust_commands(cert)[0] == f'security remove-trusted-cert -d "{cert}"'


def test_launchd_plist_contents():
    text = launchd.plist_text(omna_bin=Path("/Users/x/.local/bin/omna"), log=Path("/Users/x/.omna/proxy.log"))
    assert "<string>dev.omna.plugin</string>" in text
    assert "<string>/Users/x/.local/bin/omna</string>" in text and "<string>start</string>" in text
    assert "<key>KeepAlive</key>" in text and "<key>RunAtLoad</key>" in text


def test_setup_plan_is_one_batch_with_both_privileged_actions(tmp_path):
    lines = setup.plan(services=["Wi-Fi"], cert=tmp_path / "c.pem", pac_url="http://127.0.0.1:7788/omna/proxy.pac")
    assert lines[0].startswith("security add-trusted-cert")
    assert any(l.startswith("networksetup -setautoproxyurl") for l in lines)
    assert all("sudo" not in l for l in lines)          # sudo wraps the batch, never the lines
```

- [ ] **Step 2: Implement**

```python
# src/omna_plugin/mac/netproxy.py
from __future__ import annotations

import subprocess


def parse_services(text: str) -> list[str]:
    out = []
    for line in text.splitlines()[1:]:
        line = line.strip()
        if line and not line.startswith("*"):
            out.append(line)
    return out


def list_services() -> list[str]:
    r = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True, check=False)
    return parse_services(r.stdout)


def pac_on_commands(services: list[str], pac_url: str) -> list[str]:
    cmds = []
    for s in services:
        cmds.append(f'networksetup -setautoproxyurl "{s}" "{pac_url}"')
        cmds.append(f'networksetup -setautoproxystate "{s}" on')
    return cmds


def pac_off_commands(services: list[str]) -> list[str]:
    return [f'networksetup -setautoproxystate "{s}" off' for s in services]


def current_pac(service: str) -> tuple[str, bool]:
    r = subprocess.run(["networksetup", "-getautoproxyurl", service], capture_output=True, text=True, check=False)
    url, enabled = "", False
    for line in r.stdout.splitlines():
        if line.startswith("URL:"):
            url = line[4:].strip()
        if line.startswith("Enabled:"):
            enabled = line.split(":", 1)[1].strip().lower() == "yes"
    return url, enabled
```

```python
# src/omna_plugin/mac/certs.py
from __future__ import annotations

from pathlib import Path

SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
CA_NAME = "Omna Local Certificate Authority"


def trust_command(cert: Path) -> str:
    return f'security add-trusted-cert -d -r trustRoot -k {SYSTEM_KEYCHAIN} "{cert}"'


def untrust_commands(cert: Path) -> list[str]:
    return [f'security remove-trusted-cert -d "{cert}"',
            f'security delete-certificate -c "{CA_NAME}" {SYSTEM_KEYCHAIN} || true']
```

```python
# src/omna_plugin/mac/launchd.py
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .. import config

LABEL = "dev.omna.plugin"


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def plist_text(omna_bin: Path, log: Path) -> str:
    path_env = f"/usr/bin:/bin:/usr/sbin:/sbin:{omna_bin.parent}"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{omna_bin}</string><string>start</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>{path_env}</string></dict>
</dict>
</plist>
"""


def _domain() -> str:
    return f"gui/{os.getuid()}"


def install(omna_bin: Path) -> Path:
    p = plist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(plist_text(omna_bin, config.log_path()))
    subprocess.run(["launchctl", "bootout", f"{_domain()}/{LABEL}"], capture_output=True, check=False)
    subprocess.run(["launchctl", "bootstrap", _domain(), str(p)], check=False)
    return p


def remove() -> None:
    subprocess.run(["launchctl", "bootout", f"{_domain()}/{LABEL}"], capture_output=True, check=False)
    plist_path().unlink(missing_ok=True)


def restart() -> None:
    subprocess.run(["launchctl", "kickstart", "-k", f"{_domain()}/{LABEL}"], capture_output=True, check=False)


def is_loaded() -> bool:
    r = subprocess.run(["launchctl", "print", f"{_domain()}/{LABEL}"], capture_output=True, check=False)
    return r.returncode == 0
```

```python
# src/omna_plugin/mac/setup.py
"""`omna init` on a Mac: create the CA, trust it, point the system at the PAC, keep the
daemon alive across reboots. The two privileged actions run as ONE `sudo sh` batch so
the person types their password once, and the batch is printed before it runs."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .. import config
from ..system_door import ensure_ca
from . import certs, launchd, netproxy


def plan(*, services: list[str], cert: Path, pac_url: str) -> list[str]:
    return [certs.trust_command(cert), *netproxy.pac_on_commands(services, pac_url)]


def revert_plan(*, services: list[str], cert: Path) -> list[str]:
    return [*netproxy.pac_off_commands(services), *certs.untrust_commands(cert)]


def _run_batch(lines: list[str], why: str) -> int:
    script = config.home() / "setup.sh"
    fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
    with os.fdopen(fd, "w") as f:
        f.write("set -e\n" + "\n".join(lines) + "\n")
    print(f"omna: {why} — these {len(lines)} commands will run as administrator (one password prompt):")
    for l in lines:
        print("      " + l)
    return subprocess.run(["sudo", "sh", str(script)], check=False).returncode


def apply(api_port: int = config.DEFAULT_PORT) -> dict:
    cert = ensure_ca(config.ca_dir())
    services = netproxy.list_services()
    pac_url = f"{config.base_url(api_port)}/omna/proxy.pac"
    rc = _run_batch(plan(services=services, cert=cert, pac_url=pac_url), "certificate + system proxy")
    omna_bin = Path(shutil.which("omna") or sys.argv[0]).resolve()
    plist = launchd.install(omna_bin)
    return {"cert": str(cert), "services": services, "pac_url": pac_url, "sudo_rc": rc, "launchd": str(plist)}


def revert() -> dict:
    cert = config.ca_dir() / "mitmproxy-ca-cert.pem"
    services = netproxy.list_services()
    launchd.remove()
    rc = _run_batch(revert_plan(services=services, cert=cert), "remove certificate + system proxy") if cert.exists() else 0
    return {"services": services, "sudo_rc": rc}


def status() -> dict:
    cert = config.ca_dir() / "mitmproxy-ca-cert.pem"
    services = netproxy.list_services()
    return {"cert_exists": cert.exists(), "pac": {s: netproxy.current_pac(s) for s in services}, "launchd": launchd.is_loaded()}
```

- [ ] **Step 3: Run** `.venv/bin/pytest tests/test_mac_setup.py -q` → pass. **Step 4: Commit** `feat(mac): certificate trust, PAC, launchd — one sudo batch, printed first`.

---

## Task 8: Site adapters from captured traffic (claude.ai, chatgpt.com, gemini)

**Files:** Create `src/omna_plugin/adapters/claude_web.py`, `chatgpt_web.py`, `gemini_web.py`; `tests/test_adapters_sites.py`; fixtures under `tests/fixtures/<site>/` — **masked samples only** (run every captured body through `omna mask` before committing; never commit a real conversation; token literals in fixtures follow the two-piece rule or are loaded from files, never typed).

- [ ] **Step 1: Capture (owner's machine, after Task 9's `omna init`)** — set `OMNA_DEBUG_DUMP=~/omna-captures` and restart the daemon; in Chrome send one message on claude.ai and one on chatgpt.com containing the fake values `jane.doe@example.com` and the standard AWS example key `AKIAIOSFODNN7EXAMPLE`; copy the dumped request bodies and the reply (`omna log -n 5` shows the routes). Record per site: the exact prompt path(s), the JSON fields that carry prose, fields that must NOT be touched (ids, timezone, model, tool schemas), and the reply shape (SSE event names / JSON keys / websocket).
- [ ] **Step 2: Write each adapter as a refinement of `GenericAdapter`** — pattern:

```python
# src/omna_plugin/adapters/claude_web.py
from __future__ import annotations

import re

from . import register
from .base import RequestView
from .generic import GenericAdapter

PROMPT_PATHS = re.compile(r"^/api/organizations/[^/]+/chat_conversations/[^/]+/(completion|retry_completion)$")


class ClaudeWebAdapter(GenericAdapter):
    name = "claude.ai"
    hosts = ("claude.ai",)

    def is_prompt(self, req: RequestView) -> bool:
        return req.method == "POST" and (PROMPT_PATHS.match(req.path) is not None or super().is_prompt(req))


register(ClaudeWebAdapter())
```
Add site-specific skip keys only when the capture shows a field that breaks when masked (e.g. `timezone`, `parent_message_uuid`, `model`, `conversation_id`). Import the three modules at the bottom of `adapters/__init__.py` so they self-register.
- [ ] **Step 3: Tests** — one per site: the fixture request goes through `adapter.mask`; assert the prose field is tokenised and the id fields are byte-identical; the fixture reply stream through `pipeline.text_restorer(json_escape=True)` restores the token. **Step 4: Commit** `feat(adapters): claude.ai, chatgpt.com, gemini from captured traffic`.

---

## Task 9: CLI — policy commands, `omna init` does the Mac setup, `omna status` shows doors/apps/refusals

**Files:** Modify `src/omna_plugin/cli.py`, `tests/test_cli.py`, `README.md`.

- [ ] **Step 1: Failing tests** (CLI functions called directly, `OMNA_HOME` isolated; the Mac setup and Claude Code wiring are monkeypatched to recorders):

```python
def test_tools_enable_disable_updates_policy_and_claude_settings(tmp_path, monkeypatch): ...
    # omna disable claude-code → policy.tools["claude-code"] == "off" AND claude_code.uninstall(...) was called
    # omna enable claude-code  → "on" AND claude_code.init(...) was called
def test_bypass_and_mask_app(tmp_path, monkeypatch): ...
    # omna bypass app Cursor → policy.apps == {"Cursor": "bypass"}; omna mask app Cursor → "mask"
def test_hosts_add_remove(tmp_path, monkeypatch): ...
def test_capture_app_sets_deep_door(tmp_path, monkeypatch): ...
    # omna capture app Claude → deep_apps == ["Claude"] and doors["deep"] is True
def test_init_calls_mac_setup_unless_no_system(tmp_path, monkeypatch): ...
```
- [ ] **Step 2: Implement** the subcommands; every policy change ends with `print("omna: policy saved; restarting → omna restart")` and runs `omna restart` (= `launchd.restart()` when the plist exists, else stop+start). `omna status` adds three lines:
  `doors:        api on · system on (PAC on Wi-Fi) · deep off`
  `apps today:   Google Chrome ×41 · Claude ×3 (bypassed) · Cursor — not seen`
  `refused:      Claude Desktop → api.anthropic.com ×3 (pinned)  → omna bypass app "Claude"`
  Sources: today's receipts (`app`, `note`), `mac.setup.status()`, `/omna/health`.
- [ ] **Step 3: `omna init`** = Claude Code wiring (as today) + `mac.setup.apply()` unless `--no-system` or not macOS; the last line printed is exactly: `Omna is active. Everything you send to an AI from this Mac is masked. \`omna status\` any time.` — `omna uninstall` = Claude Code unwire + `mac.setup.revert()` + (Stage 3) removal of `/Applications/Mitmproxy Redirector.app` inside the sudo batch when it exists.
- [ ] **Step 4: README** — a "What is covered" table (browsers / desktop apps / coding tools / CLI), the per-tool commands, and the honest limits: pinned apps refuse and are named; an app's own cloud features (Cursor tab-completion) never pass through; if the daemon is down, browsers go DIRECT until launchd restarts it (unless Spike A passed); Firefox needs one click (`about:config` → `security.enterprise_roots.enabled` = true).
- [ ] **Step 5:** `.venv/bin/pytest -q` green. **Commit** `feat(cli): per-tool policy, Mac init/uninstall, status shows doors, apps and refusals`.

---

## Task 10: Report — coverage by app and by door

**Files:** `src/omna_plugin/report.py`, `tests/test_report.py`.

- [ ] Add `by_app` (`{app: requests}`), `by_door`, `bypassed` (count), `refused` (count + `app → host` list) to `build()`; render as `SCAN      apps: Google Chrome 41 · Claude 3 (bypassed) · refused: Claude Desktop → api.anthropic.com ×3` plus a `by door: api 12 · system 41 · deep 0` line; HTML gets the same two rows. Tests: fixtures with the new fields; old receipts without `door`/`app` count as `api` / `null` (backward compatible).
- [ ] Commit `feat(report): coverage by app and by door`.

---

## Task 11: Live exit test for Stage 2 (owner's Mac; owner's clicks)

- [ ] `uv tool install --reinstall --force --python 3.12 .` from the repo, then `omna init` (type the admin password once), then `omna status` → doors line shows `system on (PAC on Wi-Fi)`, launchd loaded.
- [ ] Chrome → chatgpt.com: paste `my key AKIAIOSFODNN7EXAMPLE and mail jane.doe@example.com` → send. `omna log -n 3` shows `door=system host=chatgpt.com app=Google Chrome masked: AWS_KEY×1 EMAIL×1`; the reply on screen shows the email (restored) and a secret token where the key was (never restored to a browser page unless the model echoes it back — check which happened and record it).
- [ ] Same on claude.ai, and in Safari.
- [ ] Claude Desktop (if installed): send the same line. Either it works (receipt with `app=Claude`) or `omna status` names it under `refused` with the bypass command. Record which.
- [ ] Reboot → `omna status` still running, PAC still on.
- [ ] `omna uninstall` → PAC off, cert gone from Keychain Access (search "Omna"), launchd unloaded, Claude Code unwired. Reinstall with the public curl line.
- [ ] Record results in Product Spec §6.9 "Exit test".

---

## Task 12: Stage 3 — the deep door (after Spike B passes and Task 11 shows an app slipping past)

**Files:** `system_door.py` (already accepts `deep_apps`), `cli.py` (`omna capture app NAME`, `omna release app NAME`), `mac/setup.py` (uninstall removes the Redirector app), `README.md`.

- [ ] `omna capture app "Claude"` → policy `deep_apps=["Claude"]`, `doors.deep=true`, restart → mitmproxy starts `local:Claude` alongside `regular@7789`; the first time, macOS asks to allow "Mitmproxy Redirector" (print the exact System Settings path before restarting). UDP: add a rule so UDP 443 to AI hosts from captured apps is dropped (forces the app off QUIC onto TCP, which we can read) — find the hook name in `mitmproxy/proxy/layers/udp.py` / `addons/next_layer.py` when implementing.
- [ ] Process identity at the deep door: `flow.client_conn.peername` is the app's original source address in local mode; `ProcessResolver` (lsof) resolves it the same way. If lsof finds nothing for local-mode streams, subclass `mitmproxy.proxy.mode_servers.LocalRedirectorInstance.handle_stream` to read `stream.get_extra_info("process_name")` and attach it to the client — spike first, then decide.
- [ ] Tests: `policy` + CLI unit tests; the live exit test repeats Task 11's Claude Desktop step and must now show `door=deep app=Claude`.
- [ ] Honest limit in README: the extension is named "Mitmproxy Redirector" (it is theirs, signed by them, used as-is — no fork); a pinned app still refuses even at the deep door.
- [ ] Commit `feat(deep-door): per-app capture through mitmproxy local mode`.

---

## Task 13: Ship

- [ ] Bump `pyproject.toml` to `0.2.0`; `requires-python = ">=3.12"`; `install.sh` already pins 3.12. Update `CLAUDE.md` "How it works". `git tag v0.2.0`, push, GitHub release with the wheel (PyPI stays the owner's click).
- [ ] Memory + Product Spec §6.5: mark Stage 2 (and 3, if done) DONE with the exit-test date.

---

## Self-review notes (written with the plan)

- **Spec coverage:** §6.5 Stage 2 (a) CA → Task 5/7; (b) trust → Task 7; (c) PAC with AI hosts only → Tasks 1/2/7; (d) launchd → Task 7; (e) `HTTPS_PROXY` for terminals → **deliberately NOT done** (decision in §6.9: a global `HTTPS_PROXY` makes every CLI fail closed when the daemon is down and routes all terminal traffic through the plugin; coding CLIs are covered by base-URL wiring; `omna env` prints an export line for anyone who wants it). HTTPS interception → Task 5; per-site adapters → Task 8; pinned-app policy + `omna status` naming → Tasks 5/9; Firefox one click → Task 9 README; exit test → Task 11. Stage 3 → Task 12 (mechanism changed per §6.9: mitmproxy local mode instead of our own Swift network extension).
- **Placeholder scan:** Task 8's site adapters and Task 9's CLI tests are specified by behaviour rather than full code on purpose: their exact shapes depend on captured traffic (Task 8) and on Task 9's own choices; everything foundational (policy, pipeline, adapters base/generic, procs, system door, daemon, mac/*) is complete code.
- **Type consistency:** `Pipeline.receipt(...)` has the same signature in Tasks 2 and 5; `MaskStats` fields (`counts, secrets, pii, mask_ms, tokens`) are used the same way everywhere; `Policy.allow_hosts()` returns `list[str]` regexes consumed by `build_master`; `RequestView` fields match between Tasks 3 and 5; `TextRestorer.feed/flush` (Task 2) is what `system_door.responseheaders` (Task 5) calls.
