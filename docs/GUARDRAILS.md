# Guardrails: confirmation before payments, password changes and deletions

Phantab acts as you, in your own signed-in Chrome. How much it holds an agent back on top of what you
ask is one setting, `guardrails` in `config.json`:

| Mode | What Phantab itself asks for |
|---|---|
| `parity` (default, also when the key is absent) | Nothing. The agent gets the access you have, and its own setup owns the guardrails: its rules, its approvals. |
| `light` | Your explicit confirmation before a step in the sensitive set below. |
| `full` | `light`, plus every guardrail Phantab had before this setting: the sign-in limits and stops, your handback before `resume`, your confirmation before an agent recovers another session's orphaned page. |

`none`, parity's first name, still means `parity`, so a config already written with it keeps working.
Any other value counts as `full`, so a typo never loosens anything. Phantab reads the setting at service
start, so restart the service after you change it. An older Phantab ignores the key, and the installer
keeps it when it rewrites the file.

```json
{ "profileDirectory": "Default", "guardrails": "light" }
```

## The sensitive set (`light`, `full`)
A `click`, `click_xy`, or a press of Enter or Space on a control that reads as one of these:

- **a payment or checkout**: pay, place order, complete purchase, buy now, check out, book now, donate,
  confirm and pay; a submit button in a form with a card field (`autocomplete="cc-…"`); a PayPal, Apple
  Pay or Google Pay frame;
- **a password or two-factor change**: change, reset, set or save a password; turn two-factor, 2-step,
  an authenticator, a passkey or a security key on or off, or add or remove one; a submit button in a
  form with a new-password field (not a sign-up form, nor one `browser_sign_up` filled: your request
  for that account was your word for its submit);
- **deleting an account or vault items**: delete, close or deactivate an account; delete items or delete
  permanently; on a password manager's own site, any delete, trash or remove.

Phantab refuses the step once, with `Confirm first: this looks like <kind>. …`. The agent asks you, and
only after you approve that step does it repeat it with `ownerConfirmed: true`, the same flag `resume`
takes. Phantab reads the page only to decide; the refusal names the kind, never the page's text.

It is a prompt for your word, not a wall. An agent can set `ownerConfirmed` without asking, and a page
Phantab cannot read lets the step through (see § Gaps).

## What each mode removes

| Guardrail | `parity` | `light` | `full` |
|---|---|---|---|
| Sensitive-set confirmation (above) | off | on | on |
| Sign-in send limits: 2 password sends an hour, 6 a day, per account | off | off | on |
| Sign-in stops: an account stops after a rejected or unknown result, and a damaged guard file stops all, until `phantab sign-in-clear` | off | off | on |
| `resume` on a shown tab waits for your handback (`ownerConfirmed` or the viewer's Return to agent) | off | off | on |
| Recovering another session's orphaned page waits for `ownerConfirmed` | off | off | on |
| Opening a closed allowed Chrome profile is left to you: Phantab waits 10 s for a window there instead of starting the profile with none (README § Another Chrome profile) | off | off | on |

Removed outright: the tool description's "Honor user authorization for site actions". It was an
instruction, not a mechanism; the sensitive set replaces it.

With the guard off, Phantab neither reads nor writes `sign-in-guard.json`. A file left from `full` stays
on disk untouched and applies again if you go back to `full`.

## Kept in every mode: protections you never feel
These are not guardrails. They never refuse what you ask; they keep secrets and the machine safe.

- Secrets never reach a tool result, CLI output, log, error or file under the runtime dir, and logs
  carry no page or protocol bodies (THREAT-MODEL SR-39, SR-41). Credential values live only in types
  that print `[redacted]` and are wiped on drop (SR-38).
- The Bitwarden session is tied to Phantab's own program: only the CLI's session key is stored, sealed
  to you (DPAPI or the login Keychain), in `<runtime>/bitwarden`, whatever the mode (SR-62,
  `docs/BITWARDEN.md`). Core dumps are off before the master password is read.
- The sign-in page guards that keep a password where it belongs: HTTPS at every level, no password in
  a GET, the frame checks, and the leak sweep that blanks a password found where it should not be
  (SR-45).
- When a site shows the password or code back on the page, the sign-in goes on and says `echoed`, and
  Phantab redacts the value from everything it returns to the agent for the rest of the service's
  life, and refuses screenshots of that tab until it closes. It stops no account and ends no page for
  it, in any mode.
- The sign-up guards that keep a new password out of the agent's sight: phantab makes it and saves it in
  your Bitwarden before it is typed, no screenshot while it is on the page, and the sweep that blanks a
  copy or ends the page (SR-78 to SR-83).
- The service listens on loopback only, behind its bearer token; the viewer token is never returned to
  an agent.
- An agent reaches a Chrome profile other than your usual one only if you allowed it with
  `phantab install --add-profile`. It reaches that profile through the profile's own copy of the bridge,
  and that copy speaks for no other profile (SR-76).

## Kept in every mode: not guardrails
These are coordination and correctness. They protect your own work, not you from the agent.

- One writer per site: another agent's or your own handoff holds the site for changes.
- A page you are holding (`show`) refuses the agent's writes until it is handed back. Under `parity` and
  `light`, the agent can take it back with `resume` at any time.
- A running sign-in holds its page until it answers.
- The remote viewer's input limit (20 actions a second) guards the viewer, not the agent.
- Phantab never solves an "are you human" check for you.
- Bitwarden's `askFirst` sites and policy file (`docs/BITWARDEN.md` § Ask first) are your own list,
  empty unless you set one, so they are unchanged.

Follow-ups, each its own change:

- **The pay-button sign-in refusal.** `sign_in` will not press a submit button that reads as a payment.
  It sits in `signin_find.js`, a page script shared by every mode, and lifting it alone
  leaves the password filled then blanked. It moves behind the setting once the sign-in sweep (#10)
  lands.
- **HTTP(S) only.** `open` and `navigate` take only website URLs (no `file:`, `chrome:` or `javascript:`).

## Gaps (the light check)
- Buttons inside a cross-origin frame (a payment provider's own card frame) are not read. A submit
  button on your page next to a card field still counts.
- A self-hosted password manager on your own domain is not a "vault site", so only the account and
  item wording counts there.
- Wording outside English is not matched.

A page cannot switch the check off with markup: it reads the page through the browser's own
accessors, so a form field named after one of them (`<input name=querySelector>`) changes nothing
(`docs/THREAT-MODEL.md` SR-77).

The sensitive-set check is `crates/phantab/src/page_js/sensitive.js`; the setting is
`crates/phantab/src/engine/guardrails.rs`.
