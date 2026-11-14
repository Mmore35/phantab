// The release path gate (scripts/release.sh): fails when a built binary still holds a local path, or
// a needle only a test build holds (a test seam).
//
//   node scripts/path-gate.mjs <file> [--exact <needle>]... [--any-case <needle>]...
//
// Each needle is searched as ASCII and as UTF-16LE, the two forms a path takes in a binary (Rust's
// panic locations are UTF-8; Windows APIs and some data are UTF-16). --exact matches byte for byte,
// case-sensitive, for the generic forms any user's home path starts with (`\Users\`, `/Users/`,
// `/home/`): a shipped binary must not name the folder it was built in, on any machine. --any-case
// ignores ASCII case, for a machine's own paths: Windows paths are case-insensitive, so C:\Users\Name and c:\users\name are the same path.
// Exit 0: none found. Exit 1: found (each hit is printed with its offset). Exit 2: bad usage, or the
// file cannot be read.
import { readFileSync } from 'node:fs';

const [file, ...rest] = process.argv.slice(2);
if (!file || rest.length % 2) {
  console.error('usage: node scripts/path-gate.mjs <file> [--exact <needle>]... [--any-case <needle>]...');
  process.exit(2);
}
const needles = [];
for (let i = 0; i < rest.length; i += 2) {
  const [flag, needle] = [rest[i], rest[i + 1]];
  if (flag !== '--exact' && flag !== '--any-case') {
    console.error(`path-gate: unknown option ${flag}`);
    process.exit(2);
  }
  // A short needle would match by chance; every path checked here is longer.
  if (needle.length < 4) {
    console.error(`path-gate: needle '${needle}' is shorter than 4 characters`);
    process.exit(2);
  }
  needles.push({ needle, anyCase: flag === '--any-case' });
}

// Latin-1 keeps one character per byte, so offsets in the string are offsets in the file.
let text;
try {
  text = readFileSync(file).toString('latin1');
} catch (e) {
  console.error(`path-gate: cannot read ${file}: ${e.message}`);
  process.exit(2);
}
// ASCII-only lowering: a Latin-1 byte above 0x7f is not changed, so lengths and offsets stay put.
const lowerAscii = (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());
const lowered = lowerAscii(text);
const printable = (s) => s.replace(/[^\x20-\x7e]/g, '.');

let hits = 0;
for (const { needle, anyCase } of needles) {
  for (const [encoding, form] of [
    ['ASCII', needle],
    ['UTF-16', Buffer.from(needle, 'utf16le').toString('latin1')],
  ]) {
    const haystack = anyCase ? lowered : text;
    const wanted = anyCase ? lowerAscii(form) : form;
    let at = haystack.indexOf(wanted);
    let shown = 0;
    while (at !== -1) {
      hits++;
      if (shown++ < 5) {
        const context = printable(text.slice(Math.max(0, at - 16), at + wanted.length + 48));
        console.log(`found ${JSON.stringify(needle)} (${encoding}${anyCase ? ', any case' : ''}) at ${at}: ${context}`);
      }
      at = haystack.indexOf(wanted, at + 1);
    }
    if (shown > 5) console.log(`  ... and ${shown - 5} more of ${JSON.stringify(needle)} (${encoding})`);
  }
}
if (hits) {
  console.log(`path-gate: ${file} holds ${hits} hit(s) of a local path or a test seam`);
  process.exit(1);
}
console.log(`path-gate: ${file} holds none of ${needles.length} needle(s), as ASCII or UTF-16`);
