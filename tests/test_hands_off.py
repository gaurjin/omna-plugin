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
    # #25 (2026-11-21): an idle muse.ai tab — 3,776 values masked, 18 reports rejected
    ("muse.ai", "/api/falco"),
    ("muse.ai", "/_vercel/speed-insights/vitals"),
    ("muse.ai", "/api/marketing/x-marketing/pixel/context"),
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
    ("muse.ai", "/api/hatch/vm/wake"),
    ("muse.ai", "/thread/abc"),
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


def test_claude_codes_own_reports_to_anthropic_are_left_alone():
    """Client test 2026-11-21: through the Mac-wide door, Claude Code's own
    usage reports and feature-switch lookups had 4,752 false catches in two
    requests (and timed out). Same reports as claude.ai's /api/event_logging/."""
    assert hands_off.reason("api.anthropic.com", "/api/event_logging/v2/batch", b"{}")
    assert hands_off.reason("api.anthropic.com", "/api/eval/sdk-zAZezfDKGoZuXXKe", b"{}")
    assert not hands_off.reason("api.anthropic.com", "/v1/messages", b"{}")



@pytest.fixture(autouse=True)
def _no_mac_sessions():
    hands_off.forget_sessions()
    yield
    hands_off.forget_sessions()


@pytest.mark.parametrize("path", [
    "/v1/code/sessions/cse_01ABC/worker/events",
    "/v1/code/sessions/cse_01ABC/worker/heartbeat",
    "/v1/code/sessions/cse_01ABC/client/presence",
    "/v1/code/sessions",
])
def test_the_macs_own_claude_code_uploads_are_hands_off(path):
    """#52 row 2 (owner 2026-11-23): Claude Code on this Mac copying its chat
    to the phone / claude.ai is not a message to an AI. Masking it put 121
    stand-ins on the owner's phone in 9 minutes."""
    assert hands_off.reason("api.anthropic.com", path, b'{"events": []}') == hands_off.REMOTE_CONTROL


def test_website_message_to_a_session_on_this_mac_is_masked_once_by_the_mac():
    """#52 row 3 (owner: "one should be masking, no duplication"): typed on
    claude.ai/code to the Claude Code running on this Mac. The Mac masks it
    before the AI sees it, so Chrome's copy is left alone. The site names one
    session two ways (cse_X from the Mac, session_X in the browser)."""
    hands_off.reason("api.anthropic.com", "/v1/code/sessions/cse_01D9NU4GP6N3zbFd3VcqKE6q/worker/heartbeat", b"{}")
    for p in ("/v1/code/sessions/cse_01D9NU4GP6N3zbFd3VcqKE6q/events",
              "/v1/code/sessions/session_01D9NU4GP6N3zbFd3VcqKE6q/events",
              "/v1/code/sessions/session_01D9NU4GP6N3zbFd3VcqKE6q"):
        assert hands_off.reason("claude.ai", p, b'{"text": "mail ana@x.io"}') == hands_off.REMOTE_CONTROL


@pytest.mark.parametrize("path", [
    "/v1/code/sessions/cse_01CLOUD/events",             # a cloud session: no Claude Code on this Mac runs it
    "/v1/code/sessions/session_01CLOUD/events",
    "/v1/code/sessions/session_01D9NU4GP6N3zbFd3VcqKE6qX/events",   # a longer id is another session
    "/v1/code/sessions",                                 # the site's own list: as before #52
])
def test_website_message_to_a_cloud_session_is_masked(path):
    """#52 row 4: Claude Code on the web runs on Anthropic's computers — the
    browser is the only place to mask what is typed there."""
    hands_off.reason("api.anthropic.com", "/v1/code/sessions/cse_01D9NU4GP6N3zbFd3VcqKE6q/worker", b"{}")
    assert hands_off.reason("claude.ai", path, b'{"text": "mail ana@x.io"}') is None


@pytest.mark.parametrize("host,path", [
    ("api.anthropic.com", "/v1/messages"),
    ("claude.ai", "/api/organizations/x/chat_conversations/y/completion"),
    ("example.com", "/v1/code/sessions/cse_01ABC/worker/events"),   # only Anthropic's hosts
])
def test_remote_control_rule_leaves_messages_masked(host, path):
    assert hands_off.reason(host, path, b'{"prompt": "hi"}') is None


@pytest.mark.parametrize("path", [
    "/v1/code/sessions/session_01CLOUD",               # Claude Code on this Mac only LOOKING at a cloud session
    "/v1/code/sessions/cse_01CLOUD/client/presence",
    "/v1/code/sessions/cse_01CLOUD",
])
def test_only_a_session_this_mac_runs_counts_as_a_mac_session(path):
    """Reviewer 2026-11-23: a cloud session id seen on api.anthropic.com
    without this Mac running it (its worker uploads) must stay masked on
    the website."""
    assert hands_off.reason("api.anthropic.com", path, b"{}") == hands_off.REMOTE_CONTROL
    assert hands_off.reason("claude.ai", "/v1/code/sessions/session_01CLOUD/events", b'{"text": "x"}') is None
