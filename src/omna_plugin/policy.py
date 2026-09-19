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
        }
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)  # Guarantee 0600 even if tmp file existed at different mode
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
