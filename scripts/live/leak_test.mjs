// Typing-leak test: does the curl command (system door) mask what an AI site
// sends BEFORE Send? Launches the live-test Chrome profile (no extension) with
// ONLY this browser pointed at the sandboxed Omna system door, types fake data
// letter by letter, never presses Send, and records every request the page
// sends while typing (URL + whether the fake values were in the body the
// BROWSER sent — i.e. before Omna). Omna's own receipts show what it masked.
// Usage: node leak_test.mjs <site> <chrome binary> <outfile>
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const SITES = {
  chatgpt: { url: 'https://chatgpt.com/', box: 'div.ProseMirror[contenteditable="true"], #prompt-textarea' },
  aistudio: { url: 'https://aistudio.google.com/prompts/new_chat', box: 'textarea' },
  perplexity: { url: 'https://www.perplexity.ai/', box: '#ask-input, textarea' },
  copilot: { url: 'https://copilot.com/chat', box: '#m365-chat-editor-target-element, textarea' },
  claude: { url: 'https://claude.ai/new', box: 'div[contenteditable="true"]' },
  grok: { url: 'https://grok.com/', box: 'textarea, div[contenteditable="true"]' },
  gemini: { url: 'https://gemini.google.com/app', box: 'div[contenteditable="true"]' },
  deepseek: { url: 'https://chat.deepseek.com/', box: 'textarea' },
};
const [site, CHROME, OUT] = process.argv.slice(2);
const S = SITES[site];
const FAKE_KEY = 'AKIA' + 'Q7WZ' + 'LMNO' + 'PS3X' + 'TUV2';   // fake AWS-style key, built at runtime
const FAKE = ['jane.doe@example.com', '555-123-4567', FAKE_KEY];
const TEXT = `my email is jane.doe@example.com, phone 555-123-4567, key ${FAKE_KEY} `;
const PORT = 9333;

const chrome = spawn(CHROME, [
  `--remote-debugging-port=${PORT}`,
  `--user-data-dir=${join(homedir(), '.omna-live-profile')}`,
  '--proxy-server=http://127.0.0.1:7789',   // ONLY this browser goes through Omna
  '--ignore-certificate-errors',            // trust Omna's sandbox certificate in THIS browser only
  '--disable-extensions',                   // test the curl command alone
  '--window-position=-3000,0', '--window-size=1280,900',
  '--no-first-run', '--no-default-browser-check', 'about:blank',
], { stdio: 'ignore' });

const out = { site, requests: [], signedIn: null, typed: false, error: null };
try {
  let tgt;
  for (let i = 0; i < 80 && !tgt; i++) {
    try { tgt = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === 'page'); } catch {}
    if (!tgt) await sleep(250);
  }
  const ws = new WebSocket(tgt.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  let id = 0; const pend = new Map(); let typingStarted = false; let typedCount = 0;
  ws.addEventListener('message', (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); }
    if (d.method === 'Network.webSocketCreated' && typingStarted) out.wsOpened = (out.wsOpened || []).concat(new URL(d.params.url).host);
    if (d.method === 'Network.webSocketFrameSent' && typingStarted) {
      const p = d.params.response.payloadData || '';
      const hit = FAKE.filter((v) => p.includes(v));
      out.wsFrames = (out.wsFrames || 0) + 1;
      if (hit.length) out.requests.push({ method: 'WS', url: 'websocket frame', host: out.wsHosts?.[d.params.requestId] || '?', bodyBytes: p.length, fakeValuesInBrowserBody: hit, typedSoFar: typedCount, fullBody: p.slice(0, 4000) });
    }
    if (d.method === 'Network.webSocketCreated') { out.wsHosts = out.wsHosts || {}; out.wsHosts[d.params.requestId] = new URL(d.params.url).host; }
    if (d.method === 'Network.requestWillBeSent' && typingStarted) {
      const r = d.params.request;
      if (!/^https?:/.test(r.url)) return;
      if (r.method === 'GET' && !FAKE.some((v) => decodeURIComponent(r.url).includes(v) || decodeURIComponent(r.url).includes(v.split('@')[0]))) return;
      const body = r.postData || '';
      out.requests.push({
        method: r.method, url: r.url.split('?')[0].slice(0, 160),
        bodyBytes: body.length,
        fakeValuesInBrowserBody: FAKE.filter((v) => body.includes(v) || decodeURIComponent(r.url).includes(v)),
        t: Date.now(),
        typedSoFar: typedCount,
        fullBody: FAKE.some((v) => body.includes(v)) ? body.slice(0, 65536) : undefined,
        host: new URL(r.url).host,
        contentType: r.headers['Content-Type'] || r.headers['content-type'] || '',
        bodyPreview: /prepare|conversation/.test(r.url) ? body.replace(/"(conversation_id|parent_message_id|id|client_contextual_info|timezone[^"]*|oai[^"]*)":"[^"]*"/g, '"$1":"…"').slice(0, 600) : undefined,
      });
    }
  });
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async (expression) => (await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })).result?.result?.value;
  await send('Network.enable', { maxPostDataSize: 65536 });
  await send('Page.enable');
  await send('Page.navigate', { url: S.url });
  let found = false;
  for (let i = 0; i < 60 && !found; i++) { await sleep(500); found = await ev(`!!document.querySelector(${JSON.stringify(S.box)})`); }
  out.signedIn = await ev(`!/log ?in|sign ?up|continue with google/i.test(document.body.innerText.slice(0,3000)) || !!document.querySelector('[data-testid*="profile"], [aria-label*="profile" i], img[alt*="profile" i]')`);
  out.pageTitle = await ev('document.title');
  if (!found) {
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(OUT.replace(/\.json$/, '.png'), Buffer.from(shot.result.data, 'base64'));
    out.candidates = await ev(`[...document.querySelectorAll('textarea, [contenteditable="true"], input[type=text]')].map(e => e.tagName + '#' + e.id + '.' + (e.className||'').toString().slice(0,40) + ' ph=' + (e.getAttribute('placeholder')||e.getAttribute('aria-label')||''))`);
    out.bodyStart = await ev('document.body.innerText.slice(0,300)');
    throw new Error('message box not found (page did not load, or not signed in)');
  }
  await ev(`(() => { const el = document.querySelector(${JSON.stringify(S.box)}); el.focus(); return true; })()`);
  // clear any saved draft so only our typing is in the box
  await ev(`(() => { const el = document.querySelector(${JSON.stringify(S.box)}); el.focus(); document.execCommand('selectAll'); document.execCommand('delete'); return true; })()`);
  await sleep(1500);
  typingStarted = true;
  if (process.env.PASTE) {                   // paste the whole thing at once, like Cmd+V
    await send('Input.insertText', { text: TEXT }); typedCount = TEXT.length;
  } else for (const ch of TEXT) {             // type like a person: one letter at a time
    await send('Input.insertText', { text: ch }); typedCount++;
    await sleep(Number(process.env.DELAY || 60)); if (ch === ' ' && process.env.DELAY) await sleep(700);
  }
  out.typed = true;
  await sleep(6000);                          // let any "while typing" requests go out — NEVER press Send
  out.boxStillHasText = await ev(`(document.querySelector(${JSON.stringify(S.box)}).innerText || document.querySelector(${JSON.stringify(S.box)}).value || '').includes('jane.doe')`);
  ws.close();
} catch (e) { out.error = String(e.message || e); }
finally { chrome.kill(); }
writeFileSync(OUT, JSON.stringify(out, null, 2));
console.log(JSON.stringify({ site, signedIn: out.signedIn, typed: out.typed, error: out.error, requestsWhileTyping: out.requests.length,
  withFakeValues: out.requests.filter((r) => r.fakeValuesInBrowserBody.length).map((r) => r.method + ' ' + r.url) }, null, 1));
