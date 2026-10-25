import pytest

from omna_plugin import hands_off


@pytest.mark.parametrize("host,path", [
    # Cloudflare's robot check: its scripts, and the answer the browser posts back
    ("claude.ai", "/cdn-cgi/challenge-platform/h/b/fo/3986311480:1792894206:tEX20"),
    ("www.perplexity.ai", "/?__cf_chl_tk=abc&__cf_chl_rt_tk=def"),
    ("www.perplexity.ai", "/search?q=x&__cf_chl_f_tk=abc"),
    # ChatGPT's own anti-abuse check before each message
    ("chatgpt.com", "/backend-api/sentinel/chat-requirements"),
])
def test_security_checks_are_hands_off(host, path):
    assert hands_off.reason(host, path) == "passthrough-security-check"


@pytest.mark.parametrize("host,path", [
    ("claude.ai", "/api/v2/rum?ddsource=browser"),
    ("claude.ai", "/api/event_logging/v2/batch"),
    ("chatgpt.com", "/unauth-mweb/events/statsc/flush"),
    ("chatgpt.com", "/ces/v1/t"),
    ("grok.com", "/monitoring?o=1"),
    ("grok.com", "/ht/v1/track"),
    ("gemini.google.com", "/_/BardChatUi/jserror?bl=x"),
    ("gemini.google.com", "/_/BardChatUi/web-reports"),
    ("chatgpt.com", "/realtime/wm"),
    ("www.meta.ai", "/monitoring?o=1"),
    ("www.meta.ai", "/api/analytics"),
])
def test_the_sites_own_reports_are_hands_off(host, path):
    assert hands_off.reason(host, path) == "passthrough-site-report"


@pytest.mark.parametrize("host,path", [
    ("claude.ai", "/api/organizations/x/chat_conversations/y/completion"),
    ("chatgpt.com", "/backend-api/f/conversation"),
    ("gemini.google.com", "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate"),
    ("grok.com", "/rest/app-chat/conversations/new"),
    ("www.perplexity.ai", "/rest/sse/perplexity_ask"),
    ("www.perplexity.ai", "/"),
    # a report path on a site it was not verified on is NOT skipped
    ("chat.deepseek.com", "/monitoring"),
])
def test_what_you_send_is_never_hands_off(host, path):
    assert hands_off.reason(host, path) is None
