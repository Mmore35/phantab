// Writes THIRD-PARTY-LICENSES: the licence texts of every crate linked into the phantab binary for one
// target. scripts/bundle-windows.sh and scripts/bundle-macos.sh ship it beside LICENSE and NOTICE.
//
//   node scripts/third-party-licenses.mjs <target triple> <out file>
//
// The crates come from `cargo metadata --locked --format-version 1 --filter-platform <triple>`, so
// Cargo.lock decides them and nothing is resolved anew: the phantab package's normal dependencies, and
// theirs, for that target. Not dev- or build-dependencies, and not proc-macro crates or what only they
// use: those run at build time and are not linked in. The workspace's own crates (phantab-cdp,
// phantab-window) are phantab's code, under its LICENSE, so they are walked through but not listed.
// Each crate's texts are its published package's licence files (LICENSE*, LICENCE*, COPYING*,
// NOTICE*, UNLICENSE, any file in a LICENSES/ folder, and the manifest's license-file), read from cargo's
// unpacked copy. A crate that ships none is listed with its declared `license` expression and says so.
// A text two crates ship byte for byte is printed once and named again after that.
//
// The output is the same bytes on any machine for the same Cargo.lock and target: crates sorted by name
// and version, files by name, LF line endings, and no local path (the script refuses its own output if
// it holds this checkout's, the home folder's or cargo's paths). It needs only node and cargo, and
// installs nothing. The extension adds nothing here: extension/dist holds only phantab's own compiled
// files (extension/test/manifest.test.mjs checks that), and its npm packages are build tools only.
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const die = msg => { console.error(`third-party-licenses.mjs: ${msg}`); process.exit(1); };
const [triple, outFile, ...extra] = process.argv.slice(2);
if (!triple || !outFile || extra.length) {
  console.error('usage: node scripts/third-party-licenses.mjs <target triple> <out file>');
  process.exit(2);
}
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let raw;
try {
  raw = execFileSync('cargo', ['metadata', '--locked', '--format-version', '1', '--filter-platform', triple],
    { cwd: root, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] });
} catch (e) {
  die(`cargo metadata failed (${e.message.split('\n')[0]})`);
}
const meta = JSON.parse(raw);
const packages = new Map(meta.packages.map(p => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map(n => [n.id, n]));
const members = new Set(meta.workspace_members);
const phantab = meta.packages.find(p => members.has(p.id) && p.name === 'phantab');
if (!phantab) die('no phantab package in this workspace');

const isProcMacro = p => p.targets.some(t => t.kind.includes('proc-macro'));
const linked = new Map(); // id -> package, third-party only
const seen = new Set([phantab.id]);
const queue = [phantab.id];
while (queue.length) {
  const node = nodes.get(queue.shift());
  if (!node) continue;
  for (const dep of node.deps) {
    if (!dep.dep_kinds.some(k => k.kind === null)) continue; // dev- or build-only
    if (seen.has(dep.pkg)) continue;
    seen.add(dep.pkg);
    const pkg = packages.get(dep.pkg);
    if (!pkg || isProcMacro(pkg)) continue;
    if (!members.has(pkg.id)) linked.set(pkg.id, pkg);
    queue.push(pkg.id);
  }
}

const licenceName = /^(licen[cs]e|copying|notice|unlicense)([-._].*)?$/i;
const text = file => readFileSync(file, 'utf8').replace(/^﻿/, '').replace(/\r\n?/g, '\n').replace(/\s+$/, '') + '\n';
function licenceFiles(pkg) {
  const dir = dirname(pkg.manifest_path);
  const found = new Map(); // shown name -> absolute path
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isFile() && licenceName.test(name)) found.set(name, full);
    if (st.isDirectory() && /^licen[cs]es$/i.test(name)) {
      for (const sub of readdirSync(full)) {
        if (statSync(join(full, sub)).isFile()) found.set(`${name}/${sub}`, join(full, sub));
      }
    }
  }
  if (pkg.license_file) {
    const full = resolve(dir, pkg.license_file);
    const shown = pkg.license_file.replace(/\\/g, '/').replace(/^(\.\/)+/, '');
    if (!shown.startsWith('../') && existsSync(full) && ![...found.values()].includes(full)) found.set(shown, full);
  }
  return [...found.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

const crates = [...linked.values()].sort((a, b) =>
  a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : a.version > b.version ? 1 : 0);
const rule = '='.repeat(100);
const printed = new Map(); // sha256 of a text -> "crate version, file"
const lacking = [];
const body = [];
for (const pkg of crates) {
  const label = `${pkg.name} ${pkg.version}`;
  body.push(rule, label, `license: ${pkg.license || '(none declared)'}`);
  if (pkg.repository) body.push(`repository: ${pkg.repository}`);
  const files = licenceFiles(pkg);
  if (!files.length) {
    if (!pkg.license) die(`${label} ships no licence file and declares no license`);
    lacking.push(label);
    body.push('', `${label} ships no licence file in its published package; its declared licence is ${pkg.license}.`);
  }
  for (const [shown, full] of files) {
    const t = text(full);
    const hash = createHash('sha256').update(t).digest('hex');
    body.push('', `--- ${shown}`);
    if (printed.has(hash)) {
      body.push(`(the same text as ${printed.get(hash)}, above)`);
    } else {
      printed.set(hash, `${label}, ${shown}`);
      body.push('', t.replace(/\n$/, ''));
    }
  }
  body.push('');
}

const head = [
  `Third-party licences for phantab ${phantab.version} (${triple})`,
  '',
  `phantab's own code is under LICENSE and NOTICE. This file holds the licence texts of the ${crates.length}`,
  'third-party Rust crates linked into the phantab binary for this target, as Cargo.lock pins them. It is',
  'generated by scripts/third-party-licenses.mjs from `cargo metadata --locked`.',
  '',
  'The extension adds none: extension/ ships only phantab\'s own compiled files; no npm package\'s code is',
  'bundled into it.',
  '',
  lacking.length
    ? `Crates that ship no licence file, listed with their declared licence: ${lacking.join(', ')}.`
    : 'Every crate listed ships its own licence file.',
  '',
];
const out = head.concat(body).join('\n').replace(/\n+$/, '') + '\n';

// No local path may reach a shipped file.
const local = [root, homedir(), process.env.CARGO_HOME || '', ...crates.map(p => dirname(p.manifest_path))]
  .filter(p => p && p.length > 3)
  .flatMap(p => [p, p.replace(/\\/g, '/'), p.replace(/\//g, '\\')]);
const lower = out.toLowerCase();
const hit = local.find(p => lower.includes(p.toLowerCase()));
if (hit) die('the output names a local path; not written');

writeFileSync(outFile, out);
console.log(`third-party-licenses.mjs: ${crates.length} crates for ${triple}` +
  (lacking.length ? `, ${lacking.length} with no licence file (${lacking.join(', ')})` : '') + ` -> ${outFile}`);
