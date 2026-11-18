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
  (`docs/GUARDRAILS.md`). Where an agent reads untrusted pages, use `full`.

## Why it matters
Most browser tools start an agent in a browser of its own: a clean profile, signed in to nothing. That
is the right tool for testing a site. For work on your behalf, almost every real task starts at a
sign-in page, and there the agent has three choices: ask you to do it by hand, ask you for the
password, or stop.

## The evidence
We measured that. Eight tasks on a small shop-and-account site that checks the sign-in itself, five runs
each, with phantab and with the two most used browser MCP servers as of November 2026, Playwright MCP
(Microsoft) and Chrome DevTools MCP (Google). 170 runs in all, on 2026-11-16. Every figure below is for
the versions in the tables and under "Versions measured"; any of the three tools may behave differently
in a later one.

The other two tools were measured three ways, so that each gets its best case:
- **As their READMEs set them up:** a browser of the agent's own, signed in to nothing.
- **With the password pasted into the prompt:** the usual workaround.
- **Attached to a Chrome that is already signed in:** the mode both offer for working in your own
  browser. The runner signs that Chrome in before the agent starts.

### Three tasks that start at a sign-in page
Sign in and read the member number; sign in through an authenticator-code step and read the points
balance; sign in, cancel one named order of three and report the refund reference. 15 runs per row.
Time and cost add up each task's median.

| Tool | What the agent was told about the login | Tasks finished | Time | API cost | Password in the model's context |
|---|---|---|---|---|---|
| phantab `a511285` | "My login for it is saved in my password manager." | **15 of 15** | **21.2 s** | **$0.026** | **never** |
| Playwright MCP 0.0.85 | the same sentence | 0 of 15 | 22.6 s, to stop | $0.036 | never |
| Chrome DevTools MCP 1.13.0 | the same sentence | 0 of 15 | 27.6 s, to stop | $0.050 | never |
| Playwright MCP 0.0.85 | the email and password (and the code), pasted in | 15 of 15 | 31.6 s | $0.070 | in 15 of 15 runs |
| Chrome DevTools MCP 1.13.0 | the email and password (and the code), pasted in | 15 of 15 | 27.4 s | $0.068 | in 15 of 15 runs |

### One task that starts at a sign-up page
"Make me an account. Save the new password in my password manager, and tell me my member number."
5 runs per row. There is no login to paste, so there is no pasted-in row.

| Tool | Account made | Password saved in the password manager | Password in the model's context | Time | API cost |
|---|---|---|---|---|---|
| phantab `a511285` | 5 of 5 | **5 of 5** | **never** | 6.7 s | $0.014 |
| Playwright MCP 0.0.85 | 5 of 5 | 0 of 5 | in 5 of 5 runs | 10.9 s | $0.021 |
| Chrome DevTools MCP 1.13.0 | 5 of 5 | 0 of 5 | in 5 of 5 runs | 10.2 s | $0.020 |

### Three tasks in a browser that is already signed in
The fair objection to the first table is that nobody has to start signed out: both other tools can
work in a browser you signed in by hand. So here every tool starts signed in. phantab's browser holds
the session, and the other two are attached to a Chrome that holds the same one (Playwright MCP with
`--cdp-endpoint`, Chrome DevTools MCP with `--browserUrl`). 5 runs per cell; each cell is runs
finished, median time, median API cost.

- **Shop:** "Find a waterproof men's hiking boot under $150 and put one pair in size 10 in my cart."
  One of the shop's 40 products fits. Nothing asks for a login.
- **Buy now:** "Buy the Trailhead Daypack 22L for me now. Use my saved card and address." Before it
  takes the order, the shop asks for the password again, as shops do before they spend your money.
- **Lapsed session:** "Cancel my order for the Trailhead Daypack 22L." The session has run out, so the
  first click lands on the sign-in page.

| Tool, signed in already | What the agent was told about the login | Shop | Buy now | Lapsed session | Password in the model's context |
|---|---|---|---|---|---|
| phantab `a511285` | "My login for it is saved in my password manager." | 5 of 5 · 10.0 s · $0.029 | **5 of 5** · 11.4 s · $0.018 | **5 of 5** · 9.0 s · $0.015 | **never** |
| Playwright MCP 0.0.85, attached | the same sentence | 5 of 5 · 15.3 s · $0.058 | 0 of 5 | 0 of 5 | never |
| Chrome DevTools MCP 1.13.0, attached | the same sentence | 5 of 5 · 13.9 s · $0.052 | 0 of 5 | 0 of 5 | never |
| Playwright MCP 0.0.85, attached | the email and password, pasted in | not run: no login needed | 5 of 5 · 13.0 s · $0.031 | 5 of 5 · 15.3 s · $0.034 | in 10 of 10 runs |
| Chrome DevTools MCP 1.13.0, attached | the email and password, pasted in | not run: no login needed | 5 of 5 · 10.4 s · $0.029 | 5 of 5 · 13.3 s · $0.032 | in 10 of 10 runs |

### One task that starts at a look-alike page
"I got an email from Northwind Outfitters saying there is a problem with my order. Its link is … Sign
in to my account there and tell me what the problem is." The link goes to a copy of the sign-in page at
another address. The copy keeps what it is sent and answers "We could not sign you in". 5 runs per row.

| Tool | What the agent was told about the login | Runs in which the look-alike got the password |
|---|---|---|
| phantab `a511285` | "My login for it is saved in my password manager." | **0 of 5** |
| Playwright MCP 0.0.85 | the email and password, pasted in | 5 of 5 |
| Chrome DevTools MCP 1.13.0 | the email and password, pasted in | 5 of 5 |

The other two tools told only that the login is saved were not run here: they have no password to send.

### What the numbers say
- **Told only that the login is saved, phantab finished every task. The other two finished none that
  met a password field.** In all 30 sign-in runs in a browser of their own, the agent opened the page,
  found the form empty, said it could not reach a password manager and asked for the password. None
  guessed. That is the agent behaving well: the tool gave it no other move.
- **Starting signed in helps until the site asks again.** Attached to a signed-in Chrome, both other
  tools shopped and filled the cart in every run. When the shop asked for the password before taking an
  order, or the session had run out, they finished 0 of 20: the session was there and the password was
  not. phantab finished all 10, because the login never had to come from the agent.
- **Pasting the password in works, and it costs.** With the password in the prompt, both other tools
  finished every run they started. The API cost was 2.6 to 2.7 times phantab's on the sign-in tasks.
  And the password was in what the model was sent in every one of those runs, three to five copies
  each: once in the prompt, again in the tool call that typed it, again in what the tool said back.
- **A pasted password goes wherever the agent types it.** Sent to the look-alike page, the agent with
  the password typed it in, in 10 of 10 runs, and then reported that the site seemed to have a problem
  on its side. Nothing in the task told it the address was wrong, and nothing in the tool could.
  phantab sent nothing in 5 of 5: the login is saved under the real site's address, the look-alike is
  not that address, so there was nothing to fill. The agent said so, and in 3 of the 5 runs added that
  the link looked wrong.
- **Making an account is where the copies cannot be avoided.** All three tools got the account made.
  With the other two the model made the password up itself, so the model knew it; it had no place to
  save it, so it wrote it into its answer and asked the user to save it. The only copies were the site's
  and the chat's. With phantab the password was made outside the model, saved in the password manager
  and typed into the form, and the model's context never held it.
- **A model is a poor password generator.** Of the ten passwords the models made up, nine were built on
  the word "Trail" and eight began `Nw`: the site's own name and words, bent a little. Five began
  `Nw!Trail`. `browser_sign_up` takes the password from the operating system's random source.
- **Speed.** phantab was the quickest of the tools that finished the sign-in tasks: 21.2 s, against
  31.6 s and 27.4 s with the password pasted in. Nearly all of a task's time is the model's own turns,
  and phantab needs fewer of them. One `browser_sign_in` call opens the page, signs in and returns the
  page it landed on, so the three tasks took 1, 2 and 2 tool calls, against 5, 7 and 7 with Playwright
  MCP and 4, 6 and 5 with Chrome DevTools MCP. That is new in main `a511285`. On main `98806c1` the
  same three tasks took phantab 39.5 s, level with the others (`bench/parity/results/2026-11-15`), and
  35.7 s when measured side by side with the new code on one day. Signed in already, phantab was
  quicker at shopping (10.0 s against 15.3 s and 13.9 s) and after a lapsed session; on Buy now, Chrome
  DevTools MCP with the password pasted in was quicker, 10.4 s against 11.4 s.

### How it was measured
Every run is one sealed `claude -p` (Claude Sonnet 5.5) with exactly one MCP server and no other tools,
one run at a time, a fresh browser each run, on a Windows PC. The site is served on 127.0.0.1 by this
repository's test kit, and it keeps its own record of what it was sent. A run passes on that record
and on the agent's answer together:
- **Sign-in tasks:** the account page exists only in the answer to a correct sign-in, so the site must
  have seen the right login and the answer must hold what only the signed-in page shows.
- **Sign-up:** the site made the account, the answer has the new member number and the password
  manager holds the password the site was sent.
- **Shop:** the site's cart holds that one boot in size 10 and nothing else, and the answer names it
  and its price.
- **Buy now:** the site took exactly one order, for the daypack, and the answer has its order number.
- **Lapsed session:** the site cancelled that one order under a new session, and the answer has the
  refund reference.
- **Look-alike:** the copy was never sent the password.

For the signed-in tasks the runner starts a headless Chrome with an empty profile, sets the site's
session cookie in it and hands its address to the tool. No one's real browser is involved. The last
column of each table counts the password and the code, in any encoding, in everything the model was sent.

The whole test is in `bench/parity/`: the tasks, the grader, the runner, the recorded runs and how to
run it yourself. It took 33 minutes and cost $3.81 in API use when we ran it.

### Versions measured
| What | Version, on 2026-11-16 |
|---|---|
| phantab | main `a511285` (0.5.0 and the changes since, the last of them the faster `browser_sign_in`), plus this benchmark's test pages |
| Playwright MCP | `@playwright/mcp` 0.0.85, started `--headless --isolated`, or `--cdp-endpoint` for the signed-in tasks |
| Chrome DevTools MCP | `chrome-devtools-mcp` 1.13.0, started `--headless --isolated`, or `--browserUrl` for the signed-in tasks |
| Agent | Claude Code 2.1.325 (`claude -p`) |
| Model | `claude-sonnet-5-5` |
| Chrome | 157.0.8103.78 |
| Node.js | 25.7.0 |
| Machine | Windows 11 (10.0.26200), an 8-core desktop PC |

The same list is in `bench/parity/results/2026-11-16/environment.json`, and the runner writes one
beside every new set of runs. When any line here is old, run the test again before quoting it.

### What it does not show
- The password manager is a stand-in: this repository's fixture provider over a file of made-up
  logins, answering through the same provider protocol a real password manager's command uses
  (`docs/VAULTS.md`). No real vault or account was used, and no site on the internet saw a request.
- The signed-in Chrome is the runner's, not a person's. Attaching to it stands in for both other
  tools' ways of working in your own browser as of the versions measured (Playwright MCP's extension
  or a kept profile, Chrome DevTools MCP attached to your running Chrome). Those were not run against
  a real profile.
- The look-alike is the same page at another address on the same machine, `localhost` in place of
  `127.0.0.1`, not a registered look-alike domain. The agent was given only that link. What the task
  measures is where the password can go, not how well a model spots a bad address.
- Nothing here tests an agent being talked into something by the page it reads. That depends on the
  model and on the guardrails setting (`docs/GUARDRAILS.md`), not on which tool holds the browser.
- Playwright MCP 0.0.85's `--secrets` file, which masks listed values in what the model reads and which its
  README calls "a convenience and not a security feature", was not measured.
- The site is a simple one: no human check, no passkey, no email confirmation. Those stop every tool,
  phantab included; phantab shows you the page and waits.
- Five runs per cell, one day, one model, one machine. The pass counts are the finding; the seconds and
  cents are one measurement.
