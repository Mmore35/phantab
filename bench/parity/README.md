# The parity benchmark

Can an agent finish a task that starts at a sign-in or sign-up page, and what does it cost? This folder
holds the whole test: the tasks, the grader, the runner and the recorded runs. The idea it measures is
in `docs/PARITY.md`.

## What it runs
One small account site, "Northwind Outfitters", served on 127.0.0.1 by this repository's test kit
(`crates/phantab-testkit/src/parity.rs`). The site checks the sign-in itself. The member number, the
points and the orders are built only in the answer to a correct sign-in, so no page an agent can open
without the login holds them: a run passes only if the agent really got in.

Four tasks, each one prompt:

| Task | The agent is asked to | Passes when |
|---|---|---|
| `account` | sign in and say the member number | the site saw a correct sign-in, and the answer has the number |
| `account2fa` | sign in, pass the authenticator-code step, say the points balance | the site saw the correct code, and the answer has the balance |
| `cancel` | sign in, cancel one named order of three, say the refund reference | the site saw exactly one cancel request, for that order, and the answer has the reference |
| `join` | make a new account, save its password in the password manager, say the new member number | the site made the account, the password manager holds the password the site was sent, and the answer has the number |

Five arms:

| Arm | Tool | What the prompt says about the login |
|---|---|---|
| `phantab` | phantab, this checkout | "My login for it is saved in my password manager." |
| `playwright` | Playwright MCP 0.0.85, `--headless --isolated` | the same sentence |
| `devtools` | Chrome DevTools MCP 1.13.0, `--headless --isolated` | the same sentence |
| `playwright-told` | Playwright MCP, as above | the email and password (and the code) are pasted in |
| `devtools-told` | Chrome DevTools MCP, as above | the email and password (and the code) are pasted in |

`join` has no login to paste, so the two `-told` arms skip it. Five runs of everything is 90 runs.

Every run is one sealed `claude -p`: exactly one MCP server, no other tools, no settings, an empty
working folder, the same one-line system prompt, one run at a time, a fresh browser each run. The runner
records whether the run passed, the seconds it took, what the API charged, the tool calls, and how many
times the password or the code appeared in what the model was sent. For `join` it also records whether
the site made the account, whether the password manager holds the new password, and how many times
the model was sent that password.

## What is real and what is a stand-in
- **Real:** the agent, the model, the three MCP servers, Chrome, the pages, and phantab's sign-in and
  sign-up path (the same provider protocol a real password manager's command answers through).
- **Stand-in:** the password manager. It is this repository's fixture provider
  (`crates/phantab/tests/fixtures/fixture_provider.rs`; `docs/VAULTS.md` § Conformance kit) over one
  JSON file that starts with one made-up login, `fixture-user@example.test`. It answers phantab the
  way Bitwarden or your own provider command would. No real vault, account or site is touched.
- **Local:** nothing leaves the machine but the model calls. No site on the internet sees a request, so
  running it cannot get your machine or address flagged.

## The recorded runs
`results/2026-11-15/runs.jsonl` holds the 90 runs behind the tables in `docs/PARITY.md`, one line per
run. They cost $1.61 in API use and took about 20 minutes. `results/2026-11-15/environment.json` names
what they measured:

| What | Version measured on 2026-11-15 |
|---|---|
| phantab | main `98806c1` (after the 0.5.0 release), plus this folder's test pages |
| Playwright MCP | `@playwright/mcp` 0.0.85 |
| Chrome DevTools MCP | `chrome-devtools-mcp` 1.13.0 |
| Agent | Claude Code 2.1.325 (`claude -p`) |
| Model | `claude-sonnet-5-5` |
| Chrome | 157.0.8103.78 |
| Node.js | 25.7.0 |
| Machine | Windows 11 (10.0.26200), an 8-core desktop PC |

Every one of these moves. A result is a result for those versions; a new run writes its own
`environment.json`. To print the tables from the recorded runs:

```sh
python bench/parity/run.py --report bench/parity/results/2026-11-15
```

## Run it
You need Chrome, Node.js 22 or later, Python 3, the Rust toolchain this repository names, and Claude
Code signed in (`claude -p` must work). Each run costs a cent or two of API use.

```sh
# 1. The other two tools, at the versions measured
npm install --prefix "$HOME/parity-npm" @playwright/mcp@0.0.85 chrome-devtools-mcp@1.13.0
export PARITY_NPM="$HOME/parity-npm/node_modules"
export PARITY_CHROME="/path/to/chrome"       # Windows default: C:\Program Files\Google\Chrome\Application\chrome.exe

# 2. Build the test that holds a lane, and note the executable cargo prints
cargo test -p phantab --test cost --locked --no-run

# 3. Run: 5 runs of each task with each arm, one at a time (about 20 minutes)
python bench/parity/run.py <that executable> results --runs 5

# 4. The table again, from the saved runs
python bench/parity/run.py --report results
```

`results/runs.jsonl` gets one line per run, and `results/environment.json` the versions that run
measured (to measure a newer Playwright MCP or Chrome DevTools MCP, install it and change `VERSIONS` at
the top of `run.py`). `results/raw/` gets each run's transcript and full record;
those hold your local paths, so look before you share them. The runner exits 1 when any run fails, and
the two arms told only that the login is saved are expected to fail.

## Reading the result honestly
- The two other tools were run the way their own READMEs set up an agent's browser, as of the versions
  measured. Both can also work
  in a browser you have already signed in to by hand (Playwright MCP through its extension or a kept
  profile, Chrome DevTools MCP by attaching to your Chrome). Those modes were not measured here. In them
  a task that needs only an existing session can pass; a fresh sign-in, a code step or a new account
  still needs the login from somewhere.
- Playwright MCP has a `--secrets` file that masks listed values in what the model reads. Its README
  calls it "a convenience and not a security feature". It was not measured here.
- The `-told` arms show the usual workaround: paste the password into the chat. They pass. The cost is
  the last column: the password is then in the model's context, the transcript and the provider's logs.
- Five runs per cell on one day, one model, one machine. Times move with the API's latency. Take the
  pass counts as the finding and the seconds and cents as one measurement.
