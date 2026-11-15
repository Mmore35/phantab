# Sign-in providers: any password manager, several at once

`browser_sign_in` and `browser_sign_up` take logins from a **sign-in provider**: the built-in Bitwarden
source (`docs/BITWARDEN.md`), or a provider command of the owner's that speaks the sealed protocol below.
Any password manager with a CLI or an API can be one through a small command. Several can be configured
at once. Threat model: `docs/THREAT-MODEL.md` B7, B10, T91, SR-84 to SR-87.

A config with one provider, written before this list existed (`signInProvider`), answers byte for byte as
it did: no chain is made, the request a command provider gets is unchanged, and its account keys are the
same.

## Config

```json
"signInProviders": [
  {"name": "default", "source": "bitwarden", "bitwarden": {"bw": "C:\\Tools\\bw.exe"}},
  {
    "name": "work",
    "command": ["C:\\Tools\\work-vault-provider.exe", "--profile", "work"],
    "caps": ["lookup", "totp", "create"],
    "pin": {"C:\\Tools\\work-vault-provider.exe": "<sha256 of the file, lower-case hex>"},
    "sites": ["https://intranet.example.com"]
  }
],
"signInSaveTo": "work"
```

| Key | Meaning |
|---|---|
| `name` | 1 to 32 lower-case letters, digits or `-`, starting with a letter or digit; unique. The agent's `vault` argument names it. |
| `source` | `bitwarden` (the built-in source, at most one) or `command` (the default). |
| `bitwarden` | The Bitwarden source's block (`docs/BITWARDEN.md` § Config). |
| `command` | An argv array whose first part is the program's absolute path. No shell. |
| `caps` | What a command provider can do: `lookup`, `totp`, `create`. Declaring caps makes it a protocol v2 provider. With none it is v1: sent sign-ins only, exactly as before, and taken as `lookup` and `totp`. |
| `pin` | `{path: sha256}` for the program and any of its arguments that are files it runs. Required with `caps`. The files are held open and hashed before each run; a file that is missing or changed answers `provider-failed` and nothing starts. |
| `sites` | `https` origins the owner pins to this provider. A sign-in or sign-up on a pinned origin uses only the providers pinned to it. |
| `signInSaveTo` | Where a sign-up saves when nothing else picks (below). It must be a provider that declares `create`. |

The legacy `signInProvider` still works. With no list it is the one provider, named `default`. A list
that does not check (a duplicate name, an unknown key or `source`, two Bitwarden sources, caps without a
pin, a site that is not an `https` origin, a `signInSaveTo` that cannot create) fails closed: every call
answers `provider-failed`, and `phantab vaults status` says why.

Install keeps the list in `config.json`:

```text
phantab install --add-sign-in-provider '<json object>'   # adds, or replaces the entry of that name
phantab install --remove-sign-in-provider <name>
phantab install --sign-in-save-to <name>                  # "" removes it
phantab install --sign-in-provider '<json array>'         # the command of the entry named "default"
```

The first add turns a legacy `signInProvider` into the list's `default` entry. Install refuses a list that
does not check and leaves `config.json` as it was.

## Order of choice

A sign-in:

1. A held account key goes back to the provider that issued it. Keys from a provider not named `default`
   (and not the Bitwarden source when there is no `default`) come back as `<name>:<key>`. Such a key goes
   only to `<name>`. A bare key goes only to the bare provider. So held accounts and ask-first files
   written before the list keep working.
2. The agent's `vault` narrows the providers to the one it names; an unknown name is `provider-failed`.
   A site pin narrows them to the providers pinned to the page's origin.
3. A provider that did not declare what the call needs (`lookup`, and `totp` for a code) is skipped.
4. The rest are asked in config order, against the call's one deadline. `none`, `locked`, `busy` and
   `provider-failed` fall through to the next. Any other answer (`refused`, `ask-first`, `wall`,
   `ambiguous`) stops the chain: a second vault never overrules an owner's no.
5. When every provider fell through, the answer is the most telling one seen: `locked`, then `busy`,
   then `provider-failed`, then `none`.

Matches are never merged across vaults: the first provider that has the login answers.

A sign-up saves to exactly one provider that declares `create`. It is the first match in this order:
- the one `vault` names;
- the first provider pinned to the page's origin;
- `signInSaveTo`;
- the first in order.

A provider that fails the save is the answer. The password is never tried in a second vault.

## Status

`phantab vaults status` prints, per provider in the order they are asked:
- its name, source and caps;
- the protocol it is sent;
- whether its keys go out bare;
- its sites;
- its pin's state: `none`, `ok`, `missing` or `changed`. For Bitwarden this is its session's state.
- its lock state: `not-asked` for a command provider, which is asked only by a sign-in. For Bitwarden it
  is the vault's state.

It then prints the sign-up target and every site that more than one provider names. It shows names and
states only: never a value, an item, an account, a command line or a pinned file's path.
`phantab bitwarden …` stays for the Bitwarden source's own steps.

## Writing a provider

phantab starts the command with these:
- the call's public key as its last argument;
- an allow-listed environment;
- stdin as the request;
- stderr discarded.

It reads the first line of stdout. Output over 256 KiB, a crash, an exit with nothing written, or a line
that is not JSON answers `provider-failed`. Running past the call's deadline answers `busy`, and the
provider's whole process tree is killed.

### v1 (no `caps`)

Request: `{"urls":[...],"account":null|"…","accountKey":null|"…","want":["username","password","code"?]}`.

### v2 (`caps` declared)

Every request starts with `"v":2,"operation":"…"`.

- `sign-in`: v1's four fields after them.
- `create` (only with the `create` cap): `{"v":2,"operation":"create","origin","username","name","password","regenerate"}`.
  phantab makes the password. The provider saves it, reads it back, and answers which login it now holds:
  - `new`;
  - `replaced` (a `regenerate` of the saved login);
  - `existing` (the login already saved for this origin and username, kept because no regenerate was
    asked), with its saved password.

  A `new` or `replaced` whose read-back differs from what phantab sent fills nothing.

### Answers

- A plain answer: `{"status": "none" | "ambiguous" | "refused" | "ask-first" | "locked" | "busy" | "wall" | "provider-failed"}`.
  `ambiguous` may carry `"count"`; `wall` carries a `"reason"` (e.g. `code-not-saved`).
- A login: `{"status":"ok","sealed":<seal>}`.
  - The seal is an ECDH P-256 and AES-256-GCM box to the public key (`crates/phantab/src/signin/seal.rs`).
  - Its payload is `{"digest","accountKey","values":{…}}` for a sign-in, and `{"digest","saved","values":{"password"}}` for a create.
  - `digest` is the lower-case hex SHA-256 of the exact request bytes read from stdin.

A sealed answer whose digest does not match, or whose values are in the clear, is `refused`. In v2, a key
the protocol does not name is `provider-failed`. That holds outside the seal, inside it, among the values,
and on a plain answer. A v1 provider's extra keys are ignored, as they always were.

## Conformance kit

`crates/phantab/tests/provider_conformance.rs` drives a provider through the protocol. It runs against
the fixture provider: `crates/phantab/tests/fixtures/fixture_provider.rs`, a stand-in password manager
over a vault file of made-up logins. It checks five things:
- sealed answers bound to the request digest, in both protocols;
- unknown fields rejected;
- a slow, crashing, flooding or garbled provider cut off as `busy` or `provider-failed`;
- a changed or missing pinned program never started;
- sign-up's save, read-back and no-overwrite.

Its leak test runs every outcome with a canary password, then checks that the canary is in none of these:
- the provider's log;
- a file phantab writes;
- a temp file;
- the command line;
- a label;
- `phantab vaults status`.

`crates/phantab/tests/signin_chain.rs` checks the order of choice end to end over two fixture vaults. It
also checks that one provider answers as it did before the list.

To check a provider of your own:
1. Point the kit's `entry` at it.
2. Fill its vault with the kit's logins.
3. Run `cargo test -p phantab --test provider_conformance`.
