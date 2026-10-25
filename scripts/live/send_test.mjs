// Send check: with Omna blocking the requests a site sends WHILE you type
// (MASTER #156), does the site still send your message and answer it?
// Types "hello" one letter at a time (so the while-typing requests fire and get
// blocked), presses Enter, and records whether the AI replied.
// Usage: PROFILE=<dir> [PROXY=1] [EXT=<extension dist>] [MSG=<text>] [WAIT=<ms>] node send_test.mjs <site> <chrome binary> <outfile>
//   PROXY=1 → this test Chrome only goes through the sandboxed system door on 127.0.0.1:7789
//   EXT=dir → load the built Chrome extension (and nothing else)
//   MSG=text → type this instead of "hello" (e.g. fake values, to prove the AI only saw tokens)
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
// Always invisible: an off-screen window still shows up on a second monitor and
// in the Dock (owner, 2026-10-24). Hidden Chrome normally says "HeadlessChrome"
// in its browser ID, which some sites (ChatGPT) refuse — so send the normal one.
const HUMAN_UA = '--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36';

const SITES = {
  chatgpt: { url: 'https://chatgpt.com/', box: 'div.ProseMirror[contenteditable="true"], #prompt-textarea' },
  aistudio: { url: 'https://aistudio.google.com/prompts/new_chat', box: 'textarea' },
  perplexity: { url: 'https://www.perplexity.ai/', box: '#ask-input, textarea' },
  copilot: { url: 'https://copilot.com/chat', box: '#m365-chat-editor-target-element, textarea' },
  claude: { url: 'https://claude.ai/new', box: 'div[contenteditable="true"]' },   // control: no while-typing requests
  grok: { url: 'https://grok.com/', box: 'textarea, div[contenteditable="true"]' },
  gemini: { url: 'https://gemini.google.com/app', box: 'div[contenteditable="true"]' },
  deepseek: { url: 'https://chat.deepseek.com/', box: 'textarea' },
  meta: { url: 'https://www.meta.ai/', box: 'input[aria-label="Ask Meta AI"], input[placeholder^="Ask Meta AI"], textarea, [contenteditable="true"]' },
};
const [site, CHROME, OUT] = process.argv.slice(2);
const S = SITES[site];
const PORT = 9335;
const args = [
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${process.env.PROFILE}`,
  '--headless=new', HUMAN_UA, '--window-size=1280,900', '--no-first-run', '--no-default-browser-check', 'about:blank',
];
if (process.env.PROXY) args.push('--proxy-server=http://127.0.0.1:7789', '--ignore-certificate-errors');
if (process.env.EXT) args.push(`--disable-extensions-except=${process.env.EXT}`, `--load-extension=${process.env.EXT}`);
else args.push('--disable-extensions');
const chrome = spawn(CHROME, args, { stdio: 'ignore' });

const out = { site, proxy: !!process.env.PROXY, extension: !!process.env.EXT, error: null,
              blockedWhileTyping: 0, sendRequests: [], replied: false, textGrowth: 0, omnaConsole: [] };
try {
  let tgt;
  for (let i = 0; i < 80 && !tgt; i++) {
    try { tgt = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === 'page'); } catch {}
    if (!tgt) await sleep(250);
  }
  const ws = new WebSocket(tgt.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  let id = 0; const pend = new Map(); let sent = false; const reqs = new Map();
  ws.addEventListener('message', (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); }
    if (d.method === 'Runtime.consoleAPICalled') {
      const t = (d.params.args || []).map((a) => a.value ?? a.description ?? '').join(' ');
      if (/\[Omna\].*blocked/.test(t)) { out.blockedWhileTyping++; out.omnaConsole.push(t.slice(0, 160)); }
    }
    if (d.method === 'Network.requestWillBeSent' && sent && d.params.request.method === 'POST')
      reqs.set(d.params.requestId, { url: d.params.request.url.split('?')[0].slice(0, 110) });
    if (d.method === 'Network.responseReceived' && reqs.has(d.params.requestId))
      reqs.get(d.params.requestId).status = d.params.response.status;
    if (d.method === 'Network.responseReceived' && d.params.response.status === 403 && !sent)
      out.blockedWhileTyping++;                       // the curl command answers a blocked request with 403
    if (d.method === 'Network.webSocketFrameSent' && sent) out.wsFramesAfterSend = (out.wsFramesAfterSend || 0) + 1;
  });
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async (expr) => (await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true })).result?.result?.value;
  await send('Network.enable'); await send('Runtime.enable'); await send('Page.enable');
  await send('Page.navigate', { url: S.url });
  let found = false;
  for (let i = 0; i < 60 && !found; i++) { await sleep(500); found = await ev(`!!document.querySelector(${JSON.stringify(S.box)})`); }
  if (!found) throw new Error('message box not found (page did not load, or not signed in)');
  await sleep(2000);
  await ev(`(() => { const el = document.querySelector(${JSON.stringify(S.box)}); el.focus(); document.execCommand('selectAll'); document.execCommand('delete'); return true; })()`);
  const MSG = process.env.MSG || 'hello';
  for (const ch of MSG) { await send('Input.insertText', { text: ch }); await sleep(MSG.length > 5 ? 40 : 250); }
  await sleep(3000);                                  // let the while-typing requests fire (and be blocked)
  const before = await ev('document.body.innerText.length');
  sent = true;
  // Click into the box, then a plain Enter — the way a person does it, and the
  // way the extension's own live test (live-sites.mjs) presses Send.
  const c = await ev(`(() => { const r = document.querySelector(${JSON.stringify(S.box)}).getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; })()`);
  for (const type of ['mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', { type, x: c.x, y: c.y, button: 'left', clickCount: 1 });
  await sleep(300);
  for (const type of ['keyDown', 'keyUp']) await send('Input.dispatchKeyEvent', { type, key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  await sleep(4000);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(OUT.replace(/\.json$/, '-after-enter.png'), Buffer.from(shot.result.data, 'base64'));
  out.omnaPopup = await ev(`!!document.querySelector('[class*="omna"][class*="popup"], [class*="omna-confirm"], [id*="omna"]')`);
  await sleep(Number(process.env.WAIT || 21000));      // the AI answers
  const after = await ev('document.body.innerText.length');
  out.textGrowth = after - before;
  out.boxEmptyAfterSend = await ev(`(() => { const el = document.querySelector(${JSON.stringify(S.box)}); return !el || !(el.innerText || el.value || '').includes(${JSON.stringify(MSG.slice(0, 20))}); })()`);
  out.pageTail = (await ev('document.body.innerText.slice(-600)')) || '';
  out.sendRequests = [...reqs.values()];
  // Replied = the box was emptied by Send AND a real amount of new text appeared (the answer).
  out.replied = out.boxEmptyAfterSend && out.textGrowth > 20;
  ws.close();
} catch (e) { out.error = String(e.message || e); }
finally { chrome.kill(); }
writeFileSync(OUT, JSON.stringify(out, null, 2));
console.log(JSON.stringify({ site, proxy: out.proxy, extension: out.extension, error: out.error,
  blockedWhileTyping: out.blockedWhileTyping, replied: out.replied, textGrowth: out.textGrowth }));
