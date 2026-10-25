// Upload-leak test: attach a file with fake data to an AI site WITHOUT pressing
// Send, and record every request the page sends afterwards: where it went and
// whether the fake values were in what the BROWSER sent (before Omna).
// Same isolation as leak_test.mjs: only this test Chrome goes through the
// sandboxed Omna system door; nothing on the Mac changes.
// Usage: node upload_test.mjs <site> <chrome binary> <file to attach> <outfile>
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const SITES = {
  chatgpt: 'https://chatgpt.com/', claude: 'https://claude.ai/new', gemini: 'https://gemini.google.com/app',
  aistudio: 'https://aistudio.google.com/prompts/new_chat', perplexity: 'https://www.perplexity.ai/',
  grok: 'https://grok.com/', deepseek: 'https://chat.deepseek.com/', copilot: 'https://copilot.com/chat',
};
const [site, CHROME, FILE, OUT] = process.argv.slice(2);
const FAKE_KEY = 'AKIA' + 'Q7WZ' + 'LMNO' + 'PS3X' + 'TUV2';
const FAKE = ['jane.doe@example.com', '555-123-4567', FAKE_KEY];
const PORT = 9334;
const chrome = spawn(CHROME, [
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${join(homedir(), '.omna-live-profile')}`,
  '--proxy-server=http://127.0.0.1:7789', '--ignore-certificate-errors', '--disable-extensions',
  '--window-position=-3000,0', '--window-size=1280,900', '--no-first-run', '--no-default-browser-check', 'about:blank',
], { stdio: 'ignore' });

const out = { site, attached: false, inputFound: false, requests: [], error: null };
try {
  let tgt;
  for (let i = 0; i < 80 && !tgt; i++) {
    try { tgt = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === 'page'); } catch {}
    if (!tgt) await sleep(250);
  }
  const ws = new WebSocket(tgt.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  let id = 0; const pend = new Map(); let started = false; const seen = [];
  ws.addEventListener('message', (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); }
    if (d.method === 'Network.requestWillBeSent' && started) {
      const r = d.params.request;
      if (!/^https?:/.test(r.url) || r.method === 'GET' || r.method === 'OPTIONS') return;
      seen.push({ requestId: d.params.requestId, method: r.method, url: r.url.split('?')[0].slice(0, 140),
                  host: new URL(r.url).host, contentType: r.headers['Content-Type'] || r.headers['content-type'] || '',
                  postData: r.postData || null, hasPostData: !!r.hasPostData });
    }
    if (d.method === 'Network.webSocketFrameSent' && started) {
      const p = d.params.response.payloadData || '';
      if (FAKE.some((v) => p.includes(v))) seen.push({ method: 'WS', url: 'websocket frame', host: '?', postData: p, hasPostData: true });
    }
  });
  const send = (method, params = {}) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  await send('Network.enable', { maxPostDataSize: 1048576 });
  await send('Page.enable'); await send('DOM.enable');
  await send('Page.navigate', { url: SITES[site] });
  await sleep(9000);
  const doc = await send('DOM.getDocument', { depth: -1, pierce: true });
  const q = await send('DOM.querySelectorAll', { nodeId: doc.result.root.nodeId, selector: 'input[type=file]' });
  const nodes = q.result?.nodeIds || [];
  out.inputFound = nodes.length > 0;
  if (!nodes.length) throw new Error('no file input on the page');
  started = true;
  const r = await send('DOM.setFileInputFiles', { files: [FILE], nodeId: nodes[0] });
  out.attached = !r.error;
  await sleep(12000);                         // let the site upload it — NEVER press Send
  for (const s of seen) {
    let body = s.postData;
    if (!body && s.hasPostData && s.requestId) {
      const g = await send('Network.getRequestPostData', { requestId: s.requestId });
      body = g.result?.postData || '';
    }
    out.requests.push({ method: s.method, url: s.url, host: s.host, contentType: s.contentType,
                        bytes: (body || '').length, fakeValues: FAKE.filter((v) => (body || '').includes(v)),
                        body: FAKE.some((v) => (body || '').includes(v)) ? body.slice(0, 200000) : undefined });
  }
  ws.close();
} catch (e) { out.error = String(e.message || e); }
finally { chrome.kill(); }
writeFileSync(OUT, JSON.stringify(out, null, 2));
