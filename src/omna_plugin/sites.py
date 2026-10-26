"""Everything Omna knows about each AI site, in one table.

This used to live in four places that had to be edited together — the host
list (policy.py), the requests sent while you type (while_typing.py), the
site's own security checks and reports (hands_off.py) and which hosts belong
to which site — and adding a site meant finding all four (architecture review,
MASTER #178). Those modules now read from here. The upload handlers stay in
``adapters/`` because they are code, not facts; a test checks every host they
serve belongs to a site listed here.

**A site is the unit real values are put back in** (MASTER #179b, owner "A",
2026-10-25): a reply from one site only gets back values that were sent to
that same site. The site's own page already saw everything typed into it, so
restoring there tells it nothing new; restoring into a different site would.
So a site groups the hosts ONE page talks to (ChatGPT's chat and its file
storage), and two pages of one company (Gemini, AI Studio) stay two sites.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Site:
    name: str
    hosts: tuple[str, ...]
    # Sent while you type, blocked outright (MASTER #156; see while_typing.py):
    # (host, path pattern, only when the request comes from one of these sites).
    typing: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    # The site's own anti-abuse check, forwarded byte-for-byte (hands_off.py).
    security: tuple[tuple[str, str], ...] = ()
    # The site's own usage/error reports, verified live to carry no typed text.
    reports: tuple[tuple[str, str], ...] = ()


_COPILOT = ("copilot.com", "copilot.microsoft.com")

SITES: tuple[Site, ...] = (
    # ---- the public APIs: the API door already covers tools that use base
    # URLs; these are for apps that call the APIs directly through the system door
    Site("Anthropic API", ("api.anthropic.com",)),
    Site("OpenAI API", ("api.openai.com",)),
    Site("Gemini API", ("generativelanguage.googleapis.com",)),
    Site("Mistral API", ("api.mistral.ai",)),
    Site("Groq API", ("api.groq.com",)),
    Site("DeepSeek API", ("api.deepseek.com",)),
    Site("xAI API", ("api.x.ai",)),
    Site("OpenRouter", ("openrouter.ai",)),
    Site("Cohere API", ("api.cohere.com",)),
    Site("Together API", ("api.together.xyz",)),
    Site("Fireworks API", ("api.fireworks.ai",)),
    Site("GitHub Copilot API", ("api.githubcopilot.com",)),
    # ---- the chat websites
    Site("Claude", ("claude.ai",), reports=(
        ("claude.ai", r"^/api/v2/rum\b"),
        ("claude.ai", r"^/api/event_logging/"),
    )),
    Site("ChatGPT", (
        "chatgpt.com", "chat.openai.com",
        # Found by the live upload test 2026-10-24 (MASTER #157): the raw file
        # goes to ChatGPT's own file storage at attach time.
        "oaiusercontent.com",
    ), typing=(
        ("chatgpt.com", r"^/backend-api/f/conversation/prepare$", ()),
    ), security=(
        ("chatgpt.com", r"^/backend-api/sentinel/"),   # ChatGPT's anti-abuse check before each message
    ), reports=(
        ("chatgpt.com", r"/events/statsc/"),
        ("chatgpt.com", r"^/ces/"),
        ("chatgpt.com", r"^/realtime/wm$"),   # device codes + numbers, no text (purpose not public)
    )),
    Site("Gemini", (
        "gemini.google.com",
        "push.clients6.google.com",   # Gemini -> Google's upload server (MASTER #157)
    ), reports=(
        ("gemini.google.com", r"^/_/BardChatUi/(jserror|web-reports)\b"),
    )),
    # Found by the live typing-leak test 2026-10-24 (MASTER #156) — each one
    # received what a person typed BEFORE pressing Send:
    Site("AI Studio", (
        "aistudio.google.com",
        "alkalimakersuite-pa.clients6.google.com",   # AI Studio's prompts and its CountTokens-while-typing
    ), typing=(
        ("alkalimakersuite-pa.clients6.google.com", r"CountTokens", ()),
    )),
    Site("Copilot", (
        "copilot.microsoft.com",
        "copilot.com",                       # Copilot moved here from copilot.microsoft.com
        "substrate.office.com",              # Copilot's suggestions while typing (also Outlook/Teams search — owner chose to mask it)
        "my.microsoftpersonalcontent.com",   # Copilot -> OneDrive (MASTER #157)
    ), typing=(
        # The same address serves Outlook's search-as-you-type, which must keep working.
        ("substrate.office.com", r"^/search/api/v1/suggestions", _COPILOT),
    )),
    Site("Perplexity", (
        "perplexity.ai",
        "ppl-ai-file-upload.s3.amazonaws.com",   # Perplexity -> its own Amazon S3 bucket (MASTER #176)
    ), typing=(
        ("suggest.perplexity.ai", r"^/", ()),   # a WebSocket: blocking the handshake blocks every frame
    )),
    Site("DeepSeek", ("chat.deepseek.com",)),
    Site("Le Chat", ("chat.mistral.ai",)),
    Site("Grok", ("grok.com",), reports=(
        ("grok.com", r"^/monitoring\b"),
        ("grok.com", r"^/ht/v1/"),
    )),
    Site("Meta AI", ("meta.ai",), reports=(
        ("meta.ai", r"^/monitoring\b"),        # rejected 401 once masked
        ("meta.ai", r"^/api/analytics$"),
    )),
    # Meta's personal AI agent, launched 2026-09-08 — handles real tasks:
    # email, bookings, purchases, forms
    Site("Muse", ("muse.ai",)),
)

# Every other listed AI site: one host each, nothing site-specific known yet.
OTHER_HOSTS: tuple[str, ...] = (
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
)


def all_hosts() -> list[str]:
    """The built-in host list (policy.DEFAULT_HOSTS)."""
    return [h for s in SITES for h in s.hosts] + list(OTHER_HOSTS)


def _bare(host: str) -> str:
    return (host or "").lower().rsplit(":", 1)[0]


def on(host: str, entry: str) -> bool:
    """``host`` is ``entry`` or one of its subdomains."""
    h = _bare(host)
    return h == entry or h.endswith("." + entry)


def _site(host: str) -> Site | None:
    return next((s for s in SITES if any(on(host, h) for h in s.hosts)), None)


def listed(host: str) -> bool:
    return _site(host) is not None or any(on(host, h) for h in OTHER_HOSTS)


def site_of(host: str) -> str:
    """The site a host belongs to, as a stable name: real values sent to one
    site are only ever put back in replies from that same site (#179b).

    A host on no list (one the person added with ``omna hosts add``) is its
    own site: the entry it falls under, else the host itself."""
    s = _site(host)
    if s is not None:
        return s.name
    h = _bare(host)
    return next((e for e in OTHER_HOSTS if on(h, e)), h)


def compiled(attr: str) -> list[tuple]:
    """``typing`` / ``security`` / ``reports`` of every site, patterns compiled."""
    return [(rule[0], re.compile(rule[1]), *rule[2:]) for s in SITES for rule in getattr(s, attr)]
