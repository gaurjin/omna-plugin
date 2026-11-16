import pytest

from omna_plugin import hands_off


@pytest.mark.parametrize("host,path", [
    # Cloudflare's robot check: its scripts, and the answer the browser posts back
    ("claude.ai", "/cdn-cgi/challenge-platform/h/b/fo/3986311480:1792894206:tEX20"),
    ("www.perplexity.ai", "/?__cf_chl_tk=abc&__cf_chl_rt_tk=def"),
    ("www.perplexity.ai", "/search?q=x&__cf_chl_f_tk=abc"),
    # ChatGPT's own anti-abuse check before each message
    ("chatgpt.com", "/backend-api/sentinel/chat-requirements"),
    ("chatgpt.com", "/backend-api/devicecheck"),        # ChatGPT desktop app: Apple's device token
    ("chatgpt.com", "/api/auth/link-session"),          # ChatGPT desktop app: its own sign-in token
    ("chatgpt.com", "/backend-api/notifications/subscription/register"),   # its push-notification token
    # claude.ai's sign-in (found live 2026-11-15, Claude desktop app): the
    # sign-in email and Anthropic's own "client_attestation" token were
    # masked, and the app answered "Invalid email address". Signing in is
    # not data sent to the AI, and the token is the company's security layer.
    ("claude.ai", "/api/auth/send_magic_link"),
    ("claude.ai", "/api/auth/verify_magic_link"),
    # The Claude desktop app authorising itself with Anthropic (found live the
    # same day): its redirect address, "state" and "code_challenge" were
    # masked and Anthropic answered 400, again and again.
    ("api.anthropic.com", "/v1/oauth/630406c5-9bb6-4069-98cc-2d585006c06a/authorize"),
    # The Claude desktop app registering this computer with Anthropic (same
    # day): its folder "/cowork" was read as a value and masked. The app's own
    # registration, never data sent to the AI.
    ("api.anthropic.com", "/v1/environments/bridge"),
    ("api.anthropic.com", "/v1/environments/env_01AcxzTjbRVjRZht9r3hqko8/bridge/reconnect"),
])
def test_security_checks_are_hands_off(host, path):
    assert hands_off.reason(host, path) == "passthrough-security-check"


@pytest.mark.parametrize("host,path", [
    ("claude.ai", "/api/v2/rum?ddsource=browser"),
    ("claude.ai", "/api/event_logging/v2/batch"),
    ("chatgpt.com", "/unauth-mweb/events/statsc/flush"),
    ("chatgpt.com", "/ces/v1/t"),
    ("chat.openai.com", "/ces/v1/telemetry/intake"),    # the ChatGPT desktop app reports here
    ("ab.chatgpt.com", "/v1/initialize"),               # the app asking which features are switched on
    ("grok.com", "/monitoring?o=1"),
    ("grok.com", "/ht/v1/track"),
    ("grok.com", "/_data/v1/exp/exposures"),
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


CF = "/contact?__cf_chl_f_tk=abc"


@pytest.mark.parametrize("ct,body", [
    ("application/x-www-form-urlencoded", b"md=Zm9v.bar-baz&r=abc123&sh=1&aw=2"),
    ("application/x-www-form-urlencoded", b"cf-turnstile-response=0.abc&md=x"),
    ("application/json", b'{"md": "Zm9v", "r": "abc"}'),
    ("", b""),
])
def test_cloudflares_own_answer_stays_hands_off(ct, body):
    assert hands_off.reason("www.perplexity.ai", CF, body) == "passthrough-security-check"


@pytest.mark.parametrize("ct,body", [
    # A challenged web-form POST is re-sent to the same address with the
    # person's own form in its body (architecture review, MASTER #178).
    ("application/x-www-form-urlencoded", b"name=Jane+Doe&email=jane.doe%40acme.com&message=hi"),
    ("application/json", b'{"prompt": "mail jane.doe@acme.com"}'),
    ("text/plain", b"mail jane.doe@acme.com"),
])
def test_a_body_that_is_not_cloudflares_answer_is_masked(ct, body):
    assert hands_off.reason("www.perplexity.ai", CF, body) is None
