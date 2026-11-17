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
A `click`, `click_xy`, a press of Enter or Space (also as the last key of a combination such as
`Shift+Enter`), a `type` whose text has a line break or a space (it presses Enter or Space), or a drop
(`drag` checks its `to` element, `drag_xy` its drop point), on a control that reads as one of these:

- **a payment or checkout**: pay, place order, complete purchase, buy now, check out, book now, donate,
  confirm and pay; a submit button in a form with a card field (`autocomplete="cc-…"`); a PayPal, Apple
  Pay or Google Pay frame;
- **a password or two-factor change**: change, reset, set or save a password; turn two-factor, 2-step,
  an authenticator, a passkey or a security key on or off, or add or remove one; a submit button in a
  form with a new-password field (not a sign-up form, nor one `browser_sign_up` filled: your request
  for that account was your word for its submit);
- **deleting an account or vault items**: delete, close or deactivate an account; delete items or delete
  permanently; on a password manager's own site, any delete, trash or remove.

Three more steps are asked about whatever the page reads as:

- **every `upload`**: it sends a file from your computer to the site, and the service can read any
  file you can;
- **every `["dialog", "accept"]`**: it says yes to the page's next dialog, which may be a deletion, a
  payment or leaving unsaved work. `["dialog", "dismiss"]` is never asked about;
- **`back`, `forward` or `reload` onto a page a form sent** (Chrome's `form_submit` entry): loading it
  again may send the form again. A move onto any other page is not asked about.

A `hover` is never asked about.

Phantab refuses the step once, with `Confirm first: this looks like <kind>. …`. The agent asks you, and
only after you approve that step does it repeat it with `ownerConfirmed: true`, the same flag `resume`
takes. Phantab reads the page only to decide; the refusal names the kind, never the page's text.

It is a prompt for your word, not a wall. An agent can set `ownerConfirmed` without asking, and a page
Phantab cannot read lets the step through (see § Gaps).

## What each mode removes

| Guardrail | `parity` | `light` | `full` |
|---|---|---|---|
| Sensitive-set confirmation (above), with every upload, dialog accept and move onto a page a form sent | off | on | on |
| Sign-in send limits: 2 password sends an hour, 6 a day, per account | off | off | on |
| Sign-in stops: an account stops after a rejected or unknown result, and a damaged guard file stops all, until `phantab sign-in-clear` | off | off | on |
| `resume` on a shown tab waits for your handback (`ownerConfirmed` or the viewer's Return to agent) | off | off | on |
| Recovering another session's orphaned page waits for `ownerConfirmed` | off | off | on |
| Snapshots leave out what text fields hold (`value=`); a password's, and any field of a form that holds a new password, a card field, a code field or two password fields, is left out in every mode (THREAT-MODEL R8) | off | on | on |
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
- An agent reaches a Chrome profile other than your usual one only if install allows it (by default
  every profile but those you leave out with `phantab install --remove-profile`) and you loaded the
  bridge's copy in that profile yourself. phantab never starts a profile where you did not. It reaches
  that profile through the profile's own copy of the bridge, and that copy speaks for no other profile
  (SR-76).

## Kept in every mode: not guardrails
These are coordination and correctness. They protect your own work, not you from the agent.

- Who may change a site at once: the setting `siteLock` in `config.json`, read at service start like
  `guardrails`.
  - `shared` (the default, also when the key is absent): agents work side by side on one site. Another
    agent's page on the site, open or handed to you, refuses nothing. What `shared` gives up: two
    agents, or an agent and you, can change one site at the same moment, and they share what the site
    keeps per signed-in user (a cart, a draft, the current record or workspace). Nothing in phantab
    stops one from changing what the other is in the middle of.
  - `exclusive`: one writer per site. Another agent's page, or a page handed to you, holds the site for
    changes until it is closed or handed back. Any other value counts as `exclusive`, so a typo never
    loosens anything.

  ```json
  { "profileDirectory": "Default", "siteLock": "exclusive" }
  ```
- A page you are holding (`show`) refuses the agent's writes until it is handed back. Every step
  counts as a write there, `hover`, `dialog`, `back`, `forward` and `reload` included. Under `parity` and
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
- A control in a website frame that a `click` finds by selector is read in its own frame. A `click_xy`
  on a point in a website frame (same-origin or not, such as a payment provider's own card frame), and a
  press or a `type` in a field there, are not read: the check reads only the main document, where that
  point or focus is the `<iframe>` element itself.
  A submit button on your page next to a card field still counts.
- A selector's `click`, `fill` or `select` does not reach an element that a website frame holds only
  inside an open shadow root: the wait passes over it and the act fails. `click_xy` at its snapshot
  point reaches it, and is read as any `click_xy` into a frame is: the check sees only the frame there.
- A self-hosted password manager on your own domain is not a "vault site", so only the account and
  item wording counts there.
- Wording outside English is not matched.
- A dialog answer is set only on a page you cannot see (an isolated page or a hidden agent window).
  On a page you can see, its dialogs are yours to answer and the `dialog` step is refused.
- A confirmed `back`, `forward` or `reload` onto a page a form sent may or may not send the form again:
  Chrome decides, and in the tests it served the page from its cache without sending.
- A `drag_xy` dropped into a website frame is read as a `click_xy` there is: the check sees only the
  frame.

A page cannot switch the check off with markup: it reads the page through the browser's own
accessors, so a form field named after one of them (`<input name=querySelector>`) changes nothing
(`docs/THREAT-MODEL.md` SR-77).

The sensitive-set check is `crates/phantab/src/page_js/sensitive.js`; the setting is
`crates/phantab/src/engine/guardrails.rs`.
