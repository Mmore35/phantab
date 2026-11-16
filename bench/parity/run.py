"""The parity benchmark: can an agent finish a task that starts at a sign-in or sign-up page, and at what cost?

Every run is one sealed `claude -p` with exactly one browser tool, on a private copy of a small account site
that this repository's test kit serves on 127.0.0.1 (crates/phantab-testkit/src/parity.rs). The site checks
the sign-in itself: the member number, the points and the orders exist only in the answer to a correct
sign-in, so a run passes only if the agent really got in. Nothing leaves the machine but the model calls.
The login is a fixture (crates/phantab-testkit/src/sign_in.rs), never a real one. The password manager is a
stand-in too: the repository's fixture provider over a JSON file (docs/VAULTS.md, Conformance kit).

Arms:
  phantab           phantab, with the fixture login in a stand-in password manager (phantab's provider path)
  playwright        Playwright MCP as documented; the prompt is the same as phantab's
  devtools          Chrome DevTools MCP as documented; the prompt is the same as phantab's
  playwright-told   Playwright MCP, with the login (and the code) pasted into the prompt
  devtools-told     Chrome DevTools MCP, with the login (and the code) pasted into the prompt
The `join` task (make a new account) has no login to paste, so the two -told arms skip it.

Usage:
  python run.py <cost test exe> <out dir> [--arms a,b] [--tasks a,b] [--runs 5] [--first 1] [--model m]
  python run.py --report <out dir>

Runs go strictly one at a time, arms interleaved, each on a fresh lane. Each run appends one line to
<out>/runs.jsonl; its transcript and full record go to <out>/raw/ (they hold local paths: not for publishing).
See README.md for what to install and how the exe is built.
"""
import argparse
import datetime
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse

sys.dont_write_bytecode = True

CHROME = os.environ.get("PARITY_CHROME", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
NPM = os.environ.get("PARITY_NPM", os.path.join(tempfile.gettempdir(), "phantab-competition-npm", "node_modules"))
VERSIONS = {"phantab": "this checkout", "playwright": "@playwright/mcp@0.0.85",
            "devtools": "chrome-devtools-mcp@1.13.0"}
NAMES = {"phantab": "phantab", "playwright": "Playwright", "devtools": "Chrome DevTools"}
SERVER = {"phantab": "phantab", "playwright": "playwright", "devtools": "chrome-devtools"}
ARMS = ["phantab", "playwright", "devtools", "playwright-told", "devtools-told"]

# The fixture login (crates/phantab-testkit/src/sign_in.rs). Not a credential.
USERNAME, PASSWORD, CODE = "fixture-user@example.test", "S3ntinel pw+/=!", "914207"

SYSTEM = ("You complete web tasks using only the {name} browser tools. Do not ask the user anything; "
          "finish the task yourself. When you are done, reply with one short final answer.")
TASKS = {
    "account": "Sign in to my Northwind Outfitters account at {url} and tell me my member number.",
    "account2fa": ("Sign in to my Northwind Outfitters account at {url} (it asks for an authenticator code "
                   "after the password) and tell me my Trail Rewards balance."),
    "cancel": ("Sign in to my Northwind Outfitters account at {url} and cancel my order for the Trailhead "
               "Daypack 22L. Leave my other orders as they are. Tell me the refund reference."),
    "join": ("Make me an account at Northwind Outfitters: {url} My name is {name} and my email is {email}. "
             "Save the new password in my password manager, and tell me my member number."),
}
NEW_NAME, NEW_EMAIL = "Ava Lindqvist", "ava.lindqvist@example.test"
SAVED = " My login for it is saved in my password manager."
TOLD = " My login is email {user} and password {password}"
TOLD_CODE = " and the authenticator code is {code}"


def prompt_for(arm, task, url):
    if task == "join":
        return TASKS[task].format(url=url, name=NEW_NAME, email=NEW_EMAIL)
    text = TASKS[task].format(url=url)
    if not arm.endswith("-told"):
        return text + SAVED
    text += TOLD.format(user=USERNAME, password=PASSWORD)
    return text + (TOLD_CODE.format(code=CODE) if task == "account2fa" else "") + "."


def scrubbed_env():
    env = dict(os.environ)
    for k in list(env):
        if k.startswith(("PHANTAB_", "CARGO", "RUST")) or k in (
                "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "CODEX_SESSION_ID",
                "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"):
            del env[k]
    return env


class Lane:
    """One private lane held by the cost test: the account site, and for phantab its own service, its own
    headless Chrome and the stand-in password manager. The other tools use only the site."""

    def __init__(self, exe, work, secs=900):
        self.hold = os.path.join(work, "hold")
        os.makedirs(self.hold)
        env = scrubbed_env()
        env.update(PHANTAB_TEST_COST_HOLD=self.hold, PHANTAB_TEST_CHROME=CHROME,
                   PHANTAB_TEST_COST_HOLD_SECS=str(secs), PHANTAB_TEST_COST_SIGNIN="1")
        self.log = open(os.path.join(work, "lane.log"), "w")
        self.proc = subprocess.Popen([exe, "hold_a_lane_for_real_agents", "--exact", "--nocapture"], env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        lane_json = os.path.join(self.hold, "lane.json")
        end = time.time() + 90
        while not os.path.exists(lane_json):
            if self.proc.poll() is not None or time.time() > end:
                self.stop()
                raise RuntimeError("the lane never came up: " + open(os.path.join(work, "lane.log")).read()[-2000:])
            time.sleep(0.2)
        with open(lane_json, encoding="utf-8") as f:
            self.info = json.load(f)

    def posts(self):
        path = os.path.join(self.hold, "posts.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def vault(self):
        """The stand-in password manager's saved logins."""
        try:
            with open(os.path.join(self.hold, "vault.json"), encoding="utf-8") as f:
                return json.load(f).get("logins", [])
        except (OSError, ValueError):
            return []

    def stop(self):
        open(os.path.join(self.hold, "stop"), "w").close()
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


def server(tool, work, lane_info):
    """(command, args, env) of one tool's MCP server. The competitors get their documented defaults for an
    agent's own browser: headless, an isolated profile."""
    if tool == "phantab":
        return lane_info["bin"], ["mcp"], dict(lane_info["env"])
    if tool == "playwright":
        out = os.path.join(work, "pw-out")
        os.makedirs(out)
        return "node", [os.path.join(NPM, "@playwright", "mcp", "cli.js"), "--headless", "--isolated",
                        "--browser", "chrome", "--executable-path", CHROME, "--output-dir", out], {}
    if tool == "devtools":
        return "node", [os.path.join(NPM, "chrome-devtools-mcp", "out", "Default", "gen", "src", "bin",
                                     "chrome-devtools-mcp.js"),
                        "--headless", "--isolated", "--executablePath", CHROME, "--usageStatistics=false",
                        "--performanceCrux=false"], {"CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS": "1"}
    raise ValueError(tool)


def form(post):
    return dict(post.get("form", []))


def joined(posts):
    """The form of the join the site accepted (its rules are in parity.rs), or None."""
    for p in reversed(posts):
        f = form(p)
        pw = f.get("password", "")
        if (p["path"] == "/post/parity-join" and f.get("name") and "@" in f.get("email", "") and len(pw) >= 12
                and pw == f.get("confirm")):
            return f
    return None


def kept(made, vault, origin):
    """Whether the password manager holds the login the site accepted."""
    return bool(made) and any(v.get("origin") == origin and v.get("username") == made["email"]
                              and v.get("password") == made["password"] for v in vault)


def grade(task, posts, answer, vault=(), origin=""):
    """Passed only if the site saw the right thing and the answer holds what only a signed-in page shows."""
    a = (answer or "").replace(",", "")
    fails = []
    if task == "account":
        if not any(p["path"] == "/post/parity-signin" and form(p).get("password") == PASSWORD for p in posts):
            fails.append("the site saw no correct sign-in")
        if "TR-204-881" not in a:
            fails.append("the answer lacks the member number")
    elif task == "account2fa":
        if not any(p["path"] == "/post/parity-code" and form(p).get("otp") == CODE for p in posts):
            fails.append("the site saw no correct code")
        if "4360" not in a:
            fails.append("the answer lacks the points balance")
    elif task == "cancel":
        cancels = [form(p).get("order") for p in posts if p["path"] == "/post/parity-cancel"]
        if cancels != ["NW-10912"]:
            fails.append(f"cancel requests {cancels}")
        if "RF-66027" not in a:
            fails.append("the answer lacks the refund reference")
    elif task == "join":
        made = joined(posts)
        if not made:
            fails.append("the site made no account")
        elif not kept(made, vault, origin):
            fails.append("the new password is not in the password manager")
        if "TR-311-507" not in a:
            fails.append("the answer lacks the member number")
    return not fails, "; ".join(fails)


def secret_forms(secret):
    return {secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret),
            json.dumps(secret)[1:-1]}


def shown(text, new_password=None):
    """How many times the model's context held the password and the code, in any written form; and, after a
    join, the new account's password."""
    out = {"password": sum(text.count(f) for f in secret_forms(PASSWORD)), "code": text.count(CODE)}
    if new_password:
        out["newPassword"] = sum(text.count(f) for f in secret_forms(new_password))
    return out


def one_run(exe, out, arm, task, n, model):
    tool = arm.split("-")[0]
    tag = f"{arm}-{task}-{n:02d}"
    work = tempfile.mkdtemp(prefix=f"parity-{tag}-")
    cwd = os.path.join(work, "cwd")
    os.makedirs(cwd)
    rec = {"arm": arm, "tool": tool, "version": VERSIONS[tool], "task": task, "run": n, "model": model,
           "started": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
    full, lane, stdout, prompt = {}, None, "", ""
    try:
        lane = Lane(exe, work)
        tool_dir = os.path.join(work, "server")
        os.makedirs(tool_dir)
        command, args, env = server(tool, tool_dir, lane.info)
        name = SERVER[tool]
        config = os.path.join(work, "mcp.json")
        with open(config, "w") as f:
            json.dump({"mcpServers": {name: {"command": command, "args": args, "env": env}}}, f)
        prompt = prompt_for(arm, task, lane.info["urls"][task])
        cmd = [shutil.which("claude") or "claude", "-p", prompt, "--model", model, "--strict-mcp-config",
               "--mcp-config", config, "--tools", "", "--allowedTools", f"mcp__{name}", "--setting-sources", "",
               "--system-prompt", SYSTEM.format(name=NAMES[tool]), "--output-format", "stream-json", "--verbose"]
        full["command"] = cmd
        t0 = time.time()
        r = subprocess.run(cmd, cwd=cwd, env=scrubbed_env(), capture_output=True, text=True, encoding="utf-8",
                           timeout=900)
        rec["wall_s"] = round(time.time() - t0, 1)
        stdout = r.stdout
        events = [json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{")]
        final = next((e for e in reversed(events) if e.get("type") == "result"), {})
        calls = [c for e in events if e.get("type") == "assistant" for c in e["message"].get("content", [])
                 if c.get("type") == "tool_use"]
        tools = {}
        for c in calls:
            key = c["name"].split("__", 2)[-1]
            tools[key] = tools.get(key, 0) + 1
        usage = final.get("usage") or {}
        rec.update(cost=final.get("total_cost_usd"), turns=final.get("num_turns"), toolCalls=len(calls),
                   tools=tools, answer=final.get("result"), subtype=final.get("subtype"),
                   tokens=sum(usage.get(k, 0) or 0 for k in ("input_tokens", "output_tokens",
                                                              "cache_creation_input_tokens",
                                                              "cache_read_input_tokens")))
        full.update(rc=r.returncode, stderr=r.stderr[-800:], usage=usage)
    except subprocess.TimeoutExpired:
        rec["error"] = "claude timed out"
    except Exception as e:  # the referee's own failure: recorded, never a pass
        rec["error"] = f"referee error: {e!r}"
    finally:
        posts, vault, origin = [], [], ""
        if lane is not None:
            lane.stop()
            posts, vault, origin = lane.posts(), lane.vault(), lane.info.get("origin", "")
        rec["posts"] = [p["path"] for p in posts]
        made = joined(posts) if task == "join" else None
        rec["shown"] = shown(prompt + "\n" + stdout, made and made["password"])
        if task == "join":
            rec["made"], rec["saved"] = bool(made), kept(made, vault, origin)
        if "error" in rec:
            rec["ok"], rec["why"] = False, rec["error"]
        else:
            rec["ok"], rec["why"] = grade(task, posts, rec.get("answer"), vault, origin)
        raw = os.path.join(out, "raw")
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, f"{tag}.jsonl"), "w", encoding="utf-8") as f:
            f.write(stdout)
        with open(os.path.join(raw, f"{tag}.json"), "w", encoding="utf-8") as f:
            json.dump(dict(rec, prompt=prompt, **full), f, indent=1)
        shutil.rmtree(work, ignore_errors=True)
    return rec


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def cell(value, spec):
    return "-" if value is None else format(value, spec)


def report(out):
    """Prints the results table (Markdown) from <out>/runs.jsonl."""
    with open(os.path.join(out, "runs.jsonl"), encoding="utf-8") as f:
        runs = [json.loads(line) for line in f if line.strip()]
    print("| Arm | Task | Finished | Median seconds | Median cost | Median tool calls | Login shown to the model |")
    print("|---|---|---|---|---|---|---|")
    for arm in ARMS:
        mine = [r for r in runs if r["arm"] == arm]
        for task in TASKS:
            rs = [r for r in mine if r["task"] == task]
            if not rs:
                continue
            seen = sum(1 for r in rs if any(r["shown"].values()))
            leak = "never" if not seen else f"in {seen}/{len(rs)} runs"
            print(f"| {arm} | {task} | {sum(1 for r in rs if r['ok'])}/{len(rs)} "
                  f"| {cell(median([r.get('wall_s') for r in rs]), '.1f')} "
                  f"| ${cell(median([r.get('cost') for r in rs]), '.4f')} "
                  f"| {cell(median([r.get('toolCalls') for r in rs]), 'g')} | {leak} |")
    for arm in ARMS:
        rs = [r for r in runs if r["arm"] == arm and r["task"] == "join"]
        if rs:
            n = len(rs)
            print(f"\njoin, {arm}: the site made the account in {sum(1 for r in rs if r.get('made'))}/{n} runs; "
                  f"the new password was in the password manager after {sum(1 for r in rs if r.get('saved'))}/{n}; "
                  f"the model was shown it in {sum(1 for r in rs if r['shown'].get('newPassword'))}/{n}.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe", nargs="?")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--report", metavar="OUT")
    ap.add_argument("--arms", default=",".join(ARMS))
    ap.add_argument("--tasks", default=",".join(TASKS))
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--first", type=int, default=1)
    ap.add_argument("--model", default="claude-sonnet-5-5")
    a = ap.parse_args()
    if a.report:
        report(a.report)
        return 0
    if not a.exe or not a.out:
        ap.error("give the cost test exe and an out dir, or --report <out dir>")
    os.makedirs(a.out, exist_ok=True)
    bad = 0
    with open(os.path.join(a.out, "runs.jsonl"), "a", encoding="utf-8") as log:
        for n in range(a.first, a.first + a.runs):
            for task in a.tasks.split(","):
                for arm in a.arms.split(","):
                    if task == "join" and arm.endswith("-told"):
                        continue
                    rec = one_run(a.exe, a.out, arm, task, n, a.model)
                    log.write(json.dumps(rec) + "\n")
                    log.flush()
                    bad += 0 if rec["ok"] else 1
                    print(f"{arm} {task}-{n:02d} ok={rec['ok']} s={rec.get('wall_s')} cost={rec.get('cost')} "
                          f"calls={rec.get('toolCalls')} shown={rec['shown']} {rec['why'][:160]}", flush=True)
    report(a.out)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
