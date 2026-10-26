"""One table for everything Omna knows about each AI site (MASTER #178)."""

import pytest

from omna_plugin import sites
from omna_plugin.adapters import _REGISTRY
from omna_plugin.policy import DEFAULT_HOSTS

# The list as it stood before the table existed: moving the knowledge into
# one place must not add or drop a single host.
HOSTS_BEFORE = [
    'aistudio.google.com', 'alkalimakersuite-pa.clients6.google.com', 'andisearch.com', 'api.anthropic.com',
    'api.cohere.com', 'api.deepseek.com', 'api.fireworks.ai', 'api.githubcopilot.com', 'api.groq.com',
    'api.mistral.ai', 'api.openai.com', 'api.together.xyz', 'api.x.ai', 'app.reka.ai', 'assistant.kagi.com',
    'bolt.new', 'chai-research.com', 'character.ai', 'chat.deepseek.com', 'chat.mistral.ai', 'chat.openai.com',
    'chat.qwen.ai', 'chatglm.cn', 'chatgpt.com', 'claude.ai', 'copilot.com', 'copilot.microsoft.com', 'copy.ai',
    'deepai.org', 'devin.ai', 'doubao.com', 'duck.ai', 'elevenlabs.io', 'elicit.org', 'fireflies.ai',
    'gemini.google.com', 'generativelanguage.googleapis.com', 'glean.com', 'grok.com', 'harvey.ai', 'heygen.com',
    'huggingface.co', 'hunyuan.tencent.com', 'ideogram.ai', 'janitorai.com', 'jasper.ai', 'jenni.ai',
    'khanmigo.khanacademy.org', 'kimi.com', 'leonardo.ai', 'lmarena.ai', 'lovable.dev', 'manus.im', 'meta.ai',
    'midjourney.com', 'minimax.io', 'muse.ai', 'my.microsoftpersonalcontent.com', 'nabla.com', 'oaiusercontent.com',
    'openrouter.ai', 'perplexity.ai', 'pi.ai', 'poe.com', 'polybuzz.ai', 'ppl-ai-file-upload.s3.amazonaws.com',
    'push.clients6.google.com', 'quillbot.com', 'replika.com', 'replit.com', 'rytr.me', 'substrate.office.com',
    't3.chat', 'v0.app', 'warp.dev', 'wolframalpha.com', 'wordtune.com', 'writesonic.com', 'xinghuo.xfyun.cn',
    'yiyan.baidu.com', 'you.com', 'z.ai',
]


def test_the_host_list_is_unchanged():
    assert sorted(DEFAULT_HOSTS) == HOSTS_BEFORE
    assert len(DEFAULT_HOSTS) == len(set(DEFAULT_HOSTS))


def test_every_upload_handler_serves_a_listed_site():
    for adapter in _REGISTRY:
        for host in adapter.hosts:
            assert sites.listed(host), f"{adapter.name}: {host} belongs to no site in sites.py"


@pytest.mark.parametrize("a, b", [
    ("chatgpt.com", "chat.openai.com"),
    ("chatgpt.com", "files.oaiusercontent.com"),
    ("copilot.microsoft.com", "copilot.com"),
    ("copilot.com", "substrate.office.com"),
    ("copilot.com", "my.microsoftpersonalcontent.com"),
    ("gemini.google.com", "push.clients6.google.com"),
    ("aistudio.google.com", "alkalimakersuite-pa.clients6.google.com"),
    ("perplexity.ai", "ppl-ai-file-upload.s3.amazonaws.com"),
    ("perplexity.ai", "suggest.perplexity.ai"),
    ("meta.ai", "rupload.meta.ai"),
    ("you.com", "www.you.com"),
    ("claude.ai", "claude.ai:443"),
])
def test_hosts_of_one_site_are_one_site(a, b):
    assert sites.site_of(a) == sites.site_of(b)


@pytest.mark.parametrize("a, b", [
    ("claude.ai", "chatgpt.com"),
    ("gemini.google.com", "aistudio.google.com"),   # two different pages, even if one company
    ("api.openai.com", "chatgpt.com"),
    ("grok.com", "api.x.ai"),
])
def test_different_sites_stay_different(a, b):
    assert sites.site_of(a) != sites.site_of(b)
