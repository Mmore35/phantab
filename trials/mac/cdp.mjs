// Minimal CDP client for the macOS trial. Node 22+, or Node 21 with --experimental-websocket.
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inflateSync } from 'node:zlib';

export const CHROME = process.env.TRIAL_CHROME
  || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A separate Chrome on a throwaway profile; never the user's.
export async function launch(extraArgs = []) {
  const dir = mkdtempSync(join(tmpdir(), 'phantab-trial-'));
  const proc = spawn(CHROME, [
    `--user-data-dir=${dir}`, '--remote-debugging-port=0', '--no-first-run',
    '--no-default-browser-check', ...extraArgs, 'about:blank',
  ], { stdio: 'ignore', detached: false });
  const portFile = join(dir, 'DevToolsActivePort');
  for (let i = 0; i < 100 && !existsSync(portFile); i++) await sleep(100);
  const [port, path] = readFileSync(portFile, 'utf8').trim().split('\n');
  const cdp = await connect(`ws://127.0.0.1:${port}${path}`);
  return { dir, proc, cdp, pid: proc.pid };
}

export function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    let id = 0;
    const pending = new Map();
    const listeners = new Set();
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && pending.has(m.id)) {
        const { res, rej } = pending.get(m.id);
        pending.delete(m.id);
        m.error ? rej(new Error(`${m.error.message} (${m.error.code})`)) : res(m.result);
      } else if (m.method) for (const l of listeners) l(m);
    };
    ws.onerror = reject;
    ws.onopen = () => resolve({
      send(method, params = {}, sessionId, timeoutMs = 15000) {
        const msg = { id: ++id, method, params };
        if (sessionId) msg.sessionId = sessionId;
        return new Promise((res, rej) => {
          const t = setTimeout(() => { pending.delete(msg.id); rej(new Error(`${method} timed out`)); }, timeoutMs);
          pending.set(msg.id, { res: (v) => { clearTimeout(t); res(v); }, rej: (e) => { clearTimeout(t); rej(e); } });
          ws.send(JSON.stringify(msg));
        });
      },
      on(fn) { listeners.add(fn); return () => listeners.delete(fn); },
      close() { ws.close(); },
    });
  });
}

// Width, height and the RGB of pixel (0,0). Row 0's first pixel is raw under every PNG filter.
export function pngInfo(b64) {
  const buf = Buffer.from(b64, 'base64');
  const width = buf.readUInt32BE(16), height = buf.readUInt32BE(20);
  const idat = [];
  for (let o = 8; o < buf.length;) {
    const len = buf.readUInt32BE(o), type = buf.toString('ascii', o + 4, o + 8);
    if (type === 'IDAT') idat.push(buf.subarray(o + 8, o + 8 + len));
    o += 12 + len;
  }
  const raw = inflateSync(Buffer.concat(idat));
  return { width, height, rgb: [raw[1], raw[2], raw[3]] };
}
