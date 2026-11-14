// node scripts/zip-deterministic.mjs <dir> <out.zip>
//
// Zips every file under <dir> so the same files give the same bytes on any OS. scripts/release.sh uses it
// for extension.zip. Git Bash on Windows has no `zip`, and release.yml's `touch -d` plus `zip -X` also
// depended on the machine's time zone and Info-ZIP's deflate, so this writes the archive itself:
// - entries are the files only (no directory entries), named by their path relative to <dir> with `/`,
//   in byte order of the UTF-8 name (release.yml's `LC_ALL=C sort`);
// - every entry is STORED (no compression), so no zlib version can change the bytes;
// - every time is 2000-01-01 00:00:00 in DOS format, whatever the clock, time zone or file's mtime;
// - no extra fields (zip -X), no comment, mode 0644 recorded as made-by Unix, UTF-8 name flag set.
// A symlink or a non-file refuses; so does anything a plain (non-zip64) archive cannot hold.
import { closeSync, lstatSync, openSync, readdirSync, readFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';

const [dir, out] = process.argv.slice(2);
if (!dir || !out) {
  console.error('usage: node scripts/zip-deterministic.mjs <dir> <out.zip>');
  process.exit(2);
}

function walk(root, rel, acc) {
  for (const name of readdirSync(join(root, rel))) {
    const relName = rel ? `${rel}/${name}` : name;
    const st = lstatSync(join(root, relName));
    if (st.isDirectory()) walk(root, relName, acc);
    else if (st.isFile()) acc.push(relName);
    else throw new Error(`not a regular file: ${relName}`);
  }
  return acc;
}

const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const DOS_TIME = 0; // 00:00:00
const DOS_DATE = ((2000 - 1980) << 9) | (1 << 5) | 1; // 2000-01-01
const FLAG_UTF8 = 0x0800;
const VERSION = 20; // 2.0, the version needed (and made by) for a stored entry with a UTF-8 name
const MADE_BY_UNIX = (3 << 8) | VERSION;
const MODE_0644 = (0o100644 << 16) >>> 0; // regular file, rw-r--r--, in the high half of external attrs
const LIMIT = 0xffffffff;

const names = walk(dir, '', []).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
if (names.length === 0) throw new Error(`no files under ${dir}`);
if (names.length > 0xffff) throw new Error('too many files for a non-zip64 archive');

const parts = [];
const central = [];
let offset = 0;
for (const name of names) {
  const nameBuf = Buffer.from(name, 'utf8');
  const data = readFileSync(join(dir, name));
  if (data.length >= LIMIT || offset >= LIMIT) throw new Error('archive too large for non-zip64');
  const crc = crc32(data);

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(VERSION, 4);
  local.writeUInt16LE(FLAG_UTF8, 6);
  local.writeUInt16LE(0, 8); // stored
  local.writeUInt16LE(DOS_TIME, 10);
  local.writeUInt16LE(DOS_DATE, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);
  local.writeUInt16LE(0, 28); // no extra field
  parts.push(local, nameBuf, data);

  const entry = Buffer.alloc(46);
  entry.writeUInt32LE(0x02014b50, 0);
  entry.writeUInt16LE(MADE_BY_UNIX, 4);
  entry.writeUInt16LE(VERSION, 6);
  entry.writeUInt16LE(FLAG_UTF8, 8);
  entry.writeUInt16LE(0, 10);
  entry.writeUInt16LE(DOS_TIME, 12);
  entry.writeUInt16LE(DOS_DATE, 14);
  entry.writeUInt32LE(crc, 16);
  entry.writeUInt32LE(data.length, 20);
  entry.writeUInt32LE(data.length, 24);
  entry.writeUInt16LE(nameBuf.length, 28);
  entry.writeUInt16LE(0, 30); // extra
  entry.writeUInt16LE(0, 32); // comment
  entry.writeUInt16LE(0, 34); // disk
  entry.writeUInt16LE(0, 36); // internal attrs
  entry.writeUInt32LE(MODE_0644, 38);
  entry.writeUInt32LE(offset, 42);
  central.push(entry, nameBuf);

  offset += local.length + nameBuf.length + data.length;
}

const cdSize = central.reduce((n, b) => n + b.length, 0);
if (offset + cdSize >= LIMIT) throw new Error('archive too large for non-zip64');
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(0, 4);
end.writeUInt16LE(0, 6);
end.writeUInt16LE(names.length, 8);
end.writeUInt16LE(names.length, 10);
end.writeUInt32LE(cdSize, 12);
end.writeUInt32LE(offset, 16);
end.writeUInt16LE(0, 20); // no comment

const fd = openSync(out, 'w');
try {
  for (const b of [...parts, ...central, end]) writeSync(fd, b);
} finally {
  closeSync(fd);
}
console.log(`${out}: ${names.length} files, stored, fixed times`);
