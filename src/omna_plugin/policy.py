"""One file that says what the plugin covers: which hostnames count as AI,
which tools are wired, which apps are masked / bypassed / deep-captured,
and which doors are open. ``~/.omna/policy.json`` (0600). This is also the
file an organisation will ship to every machine later; keep it flat."""

from __future__ import annotations

import json
import os
import re
import secrets
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
    "meta.ai",
    "muse.ai",  # Meta's personal AI agent, launched 2026-09-08 — handles real tasks: email, bookings, purchases, forms
    "chat.qwen.ai",
    "poe.com",
    "character.ai",
    "pi.ai",
    # general-purpose chatbots
    "duck.ai",
    "huggingface.co",
    "you.com",
    "assistant.kagi.com",
    "lmarena.ai",
    "kimi.com",
    "t3.chat",
    "z.ai",
    "andisearch.com",
    # Chinese / regional AI chatbots
    "chatglm.cn",
    "yiyan.baidu.com",
    "xinghuo.xfyun.cn",
    "doubao.com",
    "hunyuan.tencent.com",
    "minimax.io",
    # AI coding / agent web platforms (browser chat, not IDE extensions)
    "v0.app",
    "bolt.new",
    "lovable.dev",
    "replit.com",
    "warp.dev",
    "devin.ai",
    "manus.im",
    # AI writing / productivity assistants
    "jasper.ai",
    "copy.ai",
    "writesonic.com",
    "rytr.me",
    "wordtune.com",
    "quillbot.com",
    "jenni.ai",
    "fireflies.ai",
    # AI companion / character chat
    "replika.com",
    "chai-research.com",
    "polybuzz.ai",
    "janitorai.com",
    # enterprise AI assistant
    "glean.com",
    # education AI tutor
    "khanmigo.khanacademy.org",
    # legal / medical AI (high sensitivity)
    "harvey.ai",
    "nabla.com",
    # research AI
    "app.reka.ai",
    "elicit.org",
    "deepai.org",
    # creative tools with a real chat/prompt interface
    "midjourney.com",
    "ideogram.ai",
    "leonardo.ai",
    "elevenlabs.io",
    "heygen.com",
    # computation
    "wolframalpha.com",
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
    reports_enabled: bool = True   # local receipts (counts only, never values) — off means none are written
    # Put real values back into BROWSER replies (the system door only). Off means
    # you read `[EMAIL_1]` in the page instead of the name. Deliberately scoped to
    # the browser: the API and deep doors must always restore, because there a
    # token reaching the tool breaks it outright — Claude Code would write
    # `[SECRET_AWS_KEY_1]` into your file instead of editing the real line.
    # Masking is NOT affected by this and never optional.
    restore_browser: bool = True
    # Extra browser origins allowed to read replies through the API door
    # (#137a). Local origins (localhost / 127.0.0.1 / [::1], any port) are
    # always allowed and are not listed here. Anything added here is a
    # deliberate widening — a page from that origin can then use this machine's
    # proxy — so it stays empty unless someone sets it.
    cors_origins: list[str] = field(default_factory=list)
    # Crash reports: "unset" | "on" | "off". OFF until the person says yes —
    # same posture as Kiji, and the only posture consistent with "nothing is
    # sent to Omna". The difference from a hidden opt-in is that we ASK, once,
    # the first time it actually matters. "off" is final and never re-asked.
    crash_reports: str = "unset"
    # Outbound TLS (see upstream_tls.py). Omna opens your request, so verifying
    # the provider on the way out is our job. Both OFF by default:
    #   tls_strict — verify providers against certifi, NOT your machine's trust
    #     store (which `omna init` itself added a CA to, for the inbound side).
    #   tls_pins   — {host: [base64 SHA-256 of SubjectPublicKeyInfo, ...]}.
    #     Empty by design: an unattended pin is a time bomb, because providers
    #     rotate certificates. You add the ones you will maintain.
    tls_strict: bool = False
    tls_pins: dict[str, list[str]] = field(default_factory=dict)
    # Set only when a company enrols this machine (`omna enroll`, or --org/--dept
    # on the install line). Empty on a personal install, and nothing about them
    # ever leaves the machine on its own — they exist so that a report EXPORTED
    # by hand can be grouped by department and company. See report.share().
    org: str = ""
    dept: str = ""
    # Stable, random, machine-local. Lets an admin tell two exported reports
    # apart (and spot a re-send of the same one) without a username, hostname,
    # serial or any other real identifier being involved.
    device_id: str = ""

    # ------------------------------------------------------------ persistence
    @classmethod
    def load(cls) -> "Policy":
        p = config.policy_path()
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text())
            pol = cls()
            pol.version = int(data.get("version", 1))
            pol.hosts = [h.lower() for h in data.get("hosts", pol.hosts)]
            pol.tools = dict(data.get("tools", pol.tools))
            pol.apps = dict(data.get("apps", {}))
            pol.deep_apps = list(data.get("deep_apps", []))
            pol.doors = {**pol.doors, **data.get("doors", {})}
            pol.reports_enabled = bool(data.get("reports_enabled", True))
            pol.restore_browser = bool(data.get("restore_browser", True))
            pol.cors_origins = [str(o) for o in data.get("cors_origins", [])]
            cr = str(data.get("crash_reports", "unset"))
            pol.crash_reports = cr if cr in ("unset", "on", "off") else "unset"
            pol.tls_strict = bool(data.get("tls_strict", False))
            pol.tls_pins = {str(k).lower(): [str(v) for v in (vs or [])]
                            for k, vs in (data.get("tls_pins") or {}).items()}
            pol.org = str(data.get("org", "") or "")
            pol.dept = str(data.get("dept", "") or "")
            pol.device_id = str(data.get("device_id", "") or "")
            return pol
        except Exception:
            return cls()

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
            "reports_enabled": self.reports_enabled,
            "restore_browser": self.restore_browser,
            "cors_origins": self.cors_origins,
            "crash_reports": self.crash_reports,
            "tls_strict": self.tls_strict,
            "tls_pins": self.tls_pins,
            "org": self.org,
            "dept": self.dept,
            "device_id": self.device_id,
        }
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)  # Guarantee 0600 even if tmp file existed at different mode
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
        os.replace(tmp, p)

    # ------------------------------------------------------------ enrolment
    def enroll(self, org: str = "", dept: str = "") -> None:
        """Tag this machine as belonging to a company/department.

        Mints a random device id on first enrolment so exported reports can be
        told apart without ever carrying a username or hostname. Passing an
        empty string leaves that field alone, so `--dept` can be changed later
        without re-stating `--org`.
        """
        if org:
            self.org = org.strip()
        if dept:
            self.dept = dept.strip()
        if (self.org or self.dept) and not self.device_id:
            self.device_id = secrets.token_hex(8)

    def unenroll(self) -> None:
        """Drop the company tags. The device id goes too — keeping it would
        leave a stable identifier behind for a machine that is no longer part
        of any company report."""
        self.org = ""
        self.dept = ""
        self.device_id = ""

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
