# User-agent parity

The idea phantab is built around:

> **Your agent gets the browser you have, and you keep the browser your agent has.**

An agent that works for you should be able to reach what you can reach, the way you reach it. And
whatever it is doing, you should be able to see it, step in and carry on from where it is. Neither of
you is stopped at a door the other one walks through.

## What it means in practice
Parity runs in both directions.

**What you can reach, your agent can reach.**

| You have | Your agent gets |
|---|---|
| A Chrome profile you are signed in to | Pages in that same profile, in windows you never see. No copied profile, no exported cookies. |
| Other Chrome profiles (work, personal) | Each one where you loaded the bridge, by name. |
| A password manager | `browser_sign_in` fills the saved login from it: Bitwarden is built in, and any other answers through a small provider command, several at once (`docs/VAULTS.md`). |
| Two-step codes in that manager | The same call fills the code on the next step. |
| The habit of saving a new account's password | `browser_sign_up` makes a strong password, saves it in your password manager and types it in. |

**What your agent is doing, you can reach.**

| The agent has | You get |
|---|---|
| A page it is working on | The same page, unsaved state and all: `browser_show`, or the `PT` toolbar badge, takes it over; you hand it back when you are done. |
| A session it signed in to | It is in your profile. Open the site and you are signed in. |
| An account it made | Its password is in your password manager, under the site's name. Not in a transcript. |

## Access, not knowledge
Parity is about what the agent can do, not what it gets to know. A person with a password manager
rarely knows their passwords either: the manager types them. phantab does the same for the agent.
The login goes from the manager to the page; the agent gets back a status word. After a fill, phantab
checks the page for copies before the agent reads it again (`docs/THREAT-MODEL.md`).

That is what makes parity safe enough to be the default. The usual way to get an agent past a sign-in
page is to paste the password into the chat, where it stays: in the model's context, in the
transcript on disk, in the provider's logs.

## Where parity stops, on purpose
- **Proof that a person is present stays with the person.** Human checks and passkeys are never
  answered for you. phantab shows you the page and waits.
- **Parity is also the risk.** An agent with your access can do as you whatever it is talked into, by
  you or by a page it reads. `parity` is the name of the default guardrails setting for that reason:
  phantab adds nothing, and your agent's own rules and approvals are the guardrails. `light` and `full`
  put phantab's own confirmations in front of payments, password changes and deletions
  (`docs/GUARDRAILS.md`). On a work machine, or where an agent reads untrusted pages, use `full`.

## Why it matters
Most browser tools start an agent in a browser of its own: a clean profile, signed in to nothing. That
is the right tool for testing a site. For work on your behalf, almost every real task starts at a
sign-in page, and there the agent has three choices: ask you to do it by hand, ask you for the
password, or stop.

## The evidence
We measured that. Four tasks on a small account site that checks the sign-in itself, five runs each,
with phantab and with the two most used browser MCP servers, Playwright MCP (Microsoft) and Chrome
DevTools MCP (Google), run the way their own READMEs set up an agent's browser. Then the same two
again with the workaround: the password pasted into the prompt. 90 runs in all, on 2026-11-15.

### Three tasks that start at a sign-in page
Sign in and read the member number; sign in through an authenticator-code step and read the points
balance; sign in, cancel one named order of three and report the refund reference. 15 runs per row.
Time and cost add up each task's median.

| Tool | What the agent was told about the login | Tasks finished | Time | API cost | Password in the model's context |
|---|---|---|---|---|---|
| phantab | "My login for it is saved in my password manager." | **15 of 15** | 39.5 s | $0.038 | **never** |
| Playwright MCP 0.0.85 | the same sentence | 0 of 15 | 25.6 s, to stop | $0.036 | never |
| Chrome DevTools MCP 1.13.0 | the same sentence | 0 of 15 | 33.9 s, to stop | $0.051 | never |
| Playwright MCP 0.0.85 | the email and password (and the code), pasted in | 15 of 15 | 40.5 s | $0.071 | in 15 of 15 runs |
| Chrome DevTools MCP 1.13.0 | the email and password (and the code), pasted in | 15 of 15 | 37.8 s | $0.069 | in 15 of 15 runs |

### One task that starts at a sign-up page
"Make me an account. Save the new password in my password manager, and tell me my member number."
5 runs per row. There is no login to paste, so there is no pasted-in row.

| Tool | Account made | Password saved in the password manager | Password in the model's context | Time | API cost |
|---|---|---|---|---|---|
| phantab | 5 of 5 | **5 of 5** | **never** | 10.2 s | $0.014 |
| Playwright MCP 0.0.85 | 5 of 5 | 0 of 5 | in 5 of 5 runs | 12.7 s | $0.021 |
| Chrome DevTools MCP 1.13.0 | 5 of 5 | 0 of 5 | in 5 of 5 runs | 12.0 s | $0.020 |

### What the numbers say
- **Told only that the login is saved, phantab finished every task. The other two finished none.** In
  all 30 of their runs the agent opened the page, found the form empty, said it could not reach a
  password manager and asked for the password. None guessed. That is the agent behaving well: the tool
  gave it no other move.
- **Pasting the password in works, and it costs.** With the password in the prompt, both other tools
  finished all 15 runs in about the same time as phantab. The API cost was 1.8 to 1.9 times phantab's.
  And the password was in what the model was sent in every one of the 30 runs, three to five copies
  each: once in the prompt, again in the tool call that typed it, again in what the tool said back.
- **phantab is not faster here.** The seconds are level across the three tools that finish. What
  changes is whether the task can be done at all without handing the password over.
- **Making an account is where the copies cannot be avoided.** All three tools got the account made.
  With the other two the model made the password up itself, so the model knew it; it had no place to
  save it, so it wrote it into its answer and asked the user to save it. The only copies were the site's
  and the chat's. With phantab the password was made outside the model, saved in the password manager
  and typed into the form, and the model's context never held it.
- **A model is a poor password generator.** Of the nine made-up passwords we could read back, four
  began `Nw!Trail-7` and three more were built on "Trail" with one letter swapped for a symbol: the
  site's own words, bent a little. `browser_sign_up` takes the password from the operating system's random source.

### How it was measured
Every run is one sealed `claude -p` (Claude Sonnet 5.5) with exactly one MCP server and no other tools,
one run at a time, a fresh browser each run, on a Windows PC. The site is served on 127.0.0.1 by this
repository's test kit. The account page exists only in the answer to a correct sign-in, so a run passes
only if the site saw the right login and the agent's answer holds what only the signed-in page shows.
The sign-up run passes only if the site made the account, the answer has the new member number and
the password manager holds the password the site was sent. The last column counts the password and
the code, in any encoding, in everything the model was sent.

The whole test is in `bench/parity/`: the tasks, the grader, the runner, the recorded runs and how to
run it yourself. It takes about 20 minutes and cost $1.61 in API use when we ran it.

### What it does not show
- The password manager is a stand-in: this repository's fixture provider over a file of made-up
  logins, answering through the same provider protocol a real password manager's command uses
  (`docs/VAULTS.md`). No real vault or account was used, and no site on the internet saw a request.
- Both other tools can also work in a browser you have already signed in to by hand: Playwright MCP
  through its extension or a kept profile, Chrome DevTools MCP by attaching to your running Chrome.
  Those modes were not measured. In them a task that needs only an existing session can pass. A fresh
  sign-in, a code step or a new account still needs the login from somewhere.
- Playwright MCP's `--secrets` file, which masks listed values in what the model reads and which its
  README calls "a convenience and not a security feature", was not measured.
- The site is a simple one: no human check, no passkey, no email confirmation. Those stop every tool,
  phantab included; phantab shows you the page and waits.
- Five runs per cell, one day, one model, one machine. The pass counts are the finding; the seconds and
  cents are one measurement.
