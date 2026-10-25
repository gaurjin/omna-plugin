# Live leak tests (manual — not part of pytest)

Prove what an AI website sends to its servers BEFORE you press Send, and whether
the curl command (system door) masks it. Nothing on the Mac changes: Omna runs in a
sandbox folder and only a test Chrome is pointed at it.

    SB=$(mktemp -d); OMNA_HOME=$SB OMNA_REGISTRY_ENCRYPTION=off .venv/bin/omna start --port 7796 -d   # system door on 127.0.0.1:7789
    C=~/.cache/puppeteer/chrome/mac_arm-149*/chrome-mac-arm64/"Google Chrome for Testing.app"/Contents/MacOS/"Google Chrome for Testing"
    PASTE=1   node scripts/live/leak_test.mjs chatgpt "$C" out.json      # paste, never Send
    DELAY=140 node scripts/live/leak_test.mjs copilot "$C" out.json      # type like a person (suggestions need it)
    node scripts/live/upload_test.mjs grok "$C" file.txt out.json        # attach a file, never Send
    OMNA_HOME=$SB .venv/bin/omna stop

- Uses the signed-in test profile `~/.omna-live-profile` (same as the extension's live-sites.mjs). ChatGPT blocks hidden Chrome, so the window opens off-screen.
- `out.json` lists every request sent before Send and which fake values the BROWSER put in it. Prove Omna masked them by (a) the sandbox `registry.json` holding the fake email/phone (secrets are memory-only, never written), or (b) running the captured body through `adapters.for_host(host).mask(...)`.
- Receipts are written only when a reply finishes, so cancelled while-typing requests are missing from `omna log` (MASTER #158).
- Results 2026-10-24: MASTER #156 (typing) and #157 (uploads).
