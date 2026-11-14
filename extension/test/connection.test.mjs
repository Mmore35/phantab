import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startWorker, loadWorker, settle } from './fake-chrome.mjs';

const connects = fake => fake.callsOf('runtime.connectNative').length;

test('a fresh worker cleans up, then says hello to the native host', async () => {
  const fake = await startWorker();
  assert.deepEqual(fake.callsOf('runtime.connectNative'), [['dev.phantab.bridge']]);
  const [hello] = fake.port.sent;
  assert.deepEqual(Object.keys(hello), ['hello']);
  assert.equal(hello.hello.version, '0.1.0');
  assert.equal(hello.hello.protocol, 1);
  assert.match(hello.hello.instance, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  // cleanup ran before connect: its storage write comes first.
  const names = fake.calls.map(c => c.name);
  assert.ok(names.indexOf('storage.session.set') < names.indexOf('runtime.connectNative'));
  assert.deepEqual(fake.callsOf('alarms.create'), [['reconnect', { periodInMinutes: 0.5 }]]);
});

test('each worker instance has its own instance id', async () => {
  const a = await startWorker();
  const b = await startWorker();
  assert.notEqual(a.port.sent[0].hello.instance, b.port.sent[0].hello.instance);
});

test('failed connects back off 1 s, 2 s, ...; welcome resets the backoff to 1 s', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ connectFailures: 2, start: false });
  await loadWorker();
  assert.equal(connects(fake), 1);
  t.mock.timers.tick(999); assert.equal(connects(fake), 1);
  t.mock.timers.tick(1); assert.equal(connects(fake), 2);
  t.mock.timers.tick(1999); assert.equal(connects(fake), 2);
  t.mock.timers.tick(1); assert.equal(connects(fake), 3);
  assert.equal(fake.ports.length, 1);

  // Without the welcome the next delay would be 4 s.
  fake.port.receive({ welcome: true });
  await settle();
  fake.port.disconnect();
  await settle();
  t.mock.timers.tick(999); assert.equal(connects(fake), 3);
  t.mock.timers.tick(1); assert.equal(connects(fake), 4);
  assert.equal(fake.ports.length, 2);
});

test('a welcomed link that stayed up 10 s is retried after 100 ms once, then at 1 s, 2 s, ...', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ start: false });
  await loadWorker();
  assert.equal(connects(fake), 1);
  fake.port.receive({ welcome: true });
  await settle();
  t.mock.timers.tick(10000);
  fake.state.connectFailures = 3;
  fake.port.disconnect();
  await settle();
  for (const wait of [100, 1000, 2000]) {
    const before = connects(fake);
    t.mock.timers.tick(wait - 1); assert.equal(connects(fake), before, `no attempt before ${wait} ms`);
    t.mock.timers.tick(1); assert.equal(connects(fake), before + 1, `an attempt at ${wait} ms`);
  }
  // The third failure is followed by 4 s, and that connect succeeds.
  t.mock.timers.tick(4000); assert.equal(connects(fake), 5);
  assert.equal(fake.ports.length, 2);
});

test('a link that keeps dropping soon after its welcome is retried no more than once a second', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ start: false });
  await loadWorker();
  for (let cycle = 0; cycle < 5; cycle++) {
    fake.port.receive({ welcome: true });
    await settle();
    t.mock.timers.tick(9999); // up just under 10 s
    fake.port.disconnect();
    await settle();
    const before = connects(fake);
    t.mock.timers.tick(999); assert.equal(connects(fake), before, `cycle ${cycle}: no attempt before 1 s`);
    t.mock.timers.tick(1); assert.equal(connects(fake), before + 1, `cycle ${cycle}: an attempt at 1 s`);
  }
  assert.equal(fake.ports.length, 6);

  // And dropping at once, with no time up at all, is also 1 s each time.
  for (let cycle = 0; cycle < 5; cycle++) {
    fake.port.receive({ welcome: true });
    await settle();
    fake.port.disconnect();
    await settle();
    const before = connects(fake);
    t.mock.timers.tick(999); assert.equal(connects(fake), before);
    t.mock.timers.tick(1); assert.equal(connects(fake), before + 1);
  }
});

test('the backoff doubles up to 20 s and the reconnect alarm connects at once', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ connectFailures: 100, start: false });
  await loadWorker();
  for (const wait of [1000, 2000, 4000, 8000, 16000, 20000, 20000]) {
    const before = connects(fake);
    t.mock.timers.tick(wait - 1); assert.equal(connects(fake), before, `no attempt before ${wait} ms`);
    t.mock.timers.tick(1); assert.equal(connects(fake), before + 1, `an attempt at ${wait} ms`);
  }
  fake.state.connectFailures = 0;
  const before = connects(fake);
  fake.chrome.alarms.onAlarm.fire({ name: 'other' });
  assert.equal(connects(fake), before);
  fake.chrome.alarms.onAlarm.fire({ name: 'reconnect' });
  assert.equal(connects(fake), before + 1);
  assert.equal(fake.ports.length, 1);
  // Connected: the pending retry timer was cleared, and further alarms are no-ops.
  t.mock.timers.tick(60000);
  fake.chrome.alarms.onAlarm.fire({ name: 'reconnect' });
  assert.equal(connects(fake), before + 1);
});

test('refused logs, and sets the next reconnect to 20 s', async t => {
  const warn = t.mock.method(console, 'warn', () => {});
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ start: false });
  await loadWorker();
  fake.port.receive({ refused: 'installed in more than one profile' });
  await settle();
  assert.deepEqual(warn.mock.calls.map(c => c.arguments), [['phantab service refused this bridge:', 'installed in more than one profile']]);
  fake.port.disconnect();
  await settle();
  t.mock.timers.tick(19999); assert.equal(connects(fake), 1);
  t.mock.timers.tick(1); assert.equal(connects(fake), 2);
});

test('onStartup connects when there is no link', async () => {
  const fake = await startWorker({ connectFailures: 1 });
  assert.equal(fake.ports.length, 0);
  fake.chrome.runtime.onStartup.fire();
  assert.equal(fake.ports.length, 1);
  fake.chrome.runtime.onStartup.fire();
  assert.equal(fake.ports.length, 1);
});

test('a reply to a port that has since disconnected is dropped', async () => {
  const fake = await startWorker();
  let finish;
  fake.overrides['debugger.attach'] = () => new Promise(resolve => { finish = resolve; });
  const old = fake.port;
  old.receive({ id: 1, op: 'attach', args: { tabId: 4 } });
  await settle();
  old.disconnect();
  fake.chrome.runtime.onStartup.fire();
  finish();
  await settle();
  assert.deepEqual(old.sent.filter(m => m.id === 1), []);
  assert.deepEqual(fake.port.sent.filter(m => m.id === 1), []);
});

test('a late disconnect of a replaced port changes nothing', async () => {
  const fake = await startWorker();
  const old = fake.port;
  old.disconnect();
  fake.chrome.runtime.onStartup.fire();
  const current = fake.port;
  assert.notEqual(current, old);
  const detaches = fake.callsOf('debugger.detach').length;
  old.onDisconnect.fire(old);
  await settle();
  current.receive({ id: 2, op: 'ping' });
  await settle();
  assert.deepEqual(current.sent.at(-1), { id: 2, result: {} });
  assert.equal(fake.callsOf('debugger.detach').length, detaches);
});

test('an extra profile\'s copy names its profile folder in the hello; the usual copy names none', async () => {
  const usual = await startWorker();
  assert.equal('profile' in usual.port.sent[0].hello, false);
  const extra = await startWorker({ files: { 'profile.json': '{"profile":"Profile 1"}' } });
  assert.equal(extra.port.sent[0].hello.profile, 'Profile 1');
  assert.deepEqual(extra.callsOf('fetch'), [['chrome-extension://ownextensionidownextensionidaaaa/profile.json']]);
  // A profile.json that does not parse or names no folder counts as none.
  for (const text of ['not json', '{"profile":""}', '{"profile":4}']) {
    const fake = await startWorker({ files: { 'profile.json': text } });
    assert.equal('profile' in fake.port.sent[0].hello, false, text);
  }
});

test('nothing connects before profile.json is read: an early onStartup or alarm waits for it', async () => {
  let release;
  const fake = await startWorker({ start: false, files: { 'profile.json': '{"profile":"Profile 1"}' } });
  const served = globalThis.fetch;
  globalThis.fetch = url => new Promise(resolve => { release = () => resolve(served(url)); });
  await loadWorker();
  fake.chrome.runtime.onStartup.fire();
  fake.chrome.alarms.onAlarm.fire({ name: 'reconnect' });
  await settle();
  assert.equal(connects(fake), 0);
  release();
  await settle(10);
  assert.equal(connects(fake), 1);
  assert.equal(fake.port.sent[0].hello.profile, 'Profile 1');
});
