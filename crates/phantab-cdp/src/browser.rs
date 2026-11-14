//! Launching a browser over its debugging pipe, or connecting to one over its devtools WebSocket.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::{CdpError, Connection, Page, PageOptions, SessionId, Transport};

/// How long Chrome gets to answer on its pipe, or to write `DevToolsActivePort` (puppeteer's launch
/// `timeout`, 30 s).
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a port launch looks for `DevToolsActivePort`: a stat and a read of a tiny file, so a
/// short wait adds little and the launch ends soon after Chrome writes it.
const PORT_POLL: Duration = Duration::from_millis(10);
/// Limit for browser-session commands (`Target.*`, `Browser.close`).
const BROWSER_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// How long `Browser.close` may take before the launched process is killed.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// How to start Chrome.
#[derive(Debug, Clone, Default)]
pub struct LaunchOptions {
    pub executable: PathBuf,
    /// `--headless=new` plus puppeteer's headless companions.
    pub headless: bool,
    /// A profile to use. `None` makes a temporary one that [`Browser::close`] removes.
    pub user_data_dir: Option<PathBuf>,
    /// Extra arguments, appended after the defaults (feature flags are merged, as puppeteer does).
    pub args: Vec<String>,
}

/// Puppeteer's `ChromeLauncher.defaultArgs` plus the debugging channel from `computeLaunchArguments`.
/// User `--enable-features=`/`--disable-features=` values are merged into the default lists.
///
/// Deliberate differences: `--user-data-dir` is always present (puppeteer appends a temp one later in
/// the list), only `--headless=new` is offered (no `'shell'` mode), and the channel is
/// `--remote-debugging-pipe` (puppeteer's `pipe: true`) unless the caller asks for a port: Chrome's
/// port has no authentication, so any local process could drive the browser through it (THREAT-MODEL
/// R13). On Windows [`Browser::launch`] adds `--remote-debugging-io-pipes` with the handles.
pub fn default_args(headless: bool, user_data_dir: &Path, user_args: &[String]) -> Vec<String> {
    let features = |flag: &str| -> Vec<String> {
        let prefix = format!("{flag}=");
        user_args
            .iter()
            .filter(|a| a.starts_with(&prefix))
            .flat_map(|a| {
                a[prefix.len()..].trim().split(',').map(|f| f.trim().to_owned()).collect::<Vec<_>>()
            })
            .filter(|f| !f.is_empty())
            .collect()
    };
    let user_disabled = features("--disable-features");
    let user_enabled = features("--enable-features");
    let rest: Vec<&String> = user_args
        .iter()
        .filter(|a| !a.starts_with("--disable-features=") && !a.starts_with("--enable-features="))
        .collect();

    let mut enabled = vec!["PdfOopif".to_owned()];
    enabled.extend(user_enabled);
    let mut disabled: Vec<String> = [
        "Translate",
        // crbug.com/1348106
        "AcceptCHFrame",
        "MediaRouter",
        "OptimizationHints",
        "WebUIReloadButton",
        "WebUIOmniboxPopup",
        "WebUIOmniboxAimPopup",
        // crbug.com/1492053
        "ProcessPerSiteUpToMainFrameThreshold",
        // puppeteer#10715
        "IsolateSandboxedIframes",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    disabled.extend(user_disabled);
    disabled.retain(|f| !f.is_empty() && !enabled.contains(f));

    let mut args: Vec<String> = [
        "--allow-pre-commit-input",
        "--disable-background-networking",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-breakpad",
        "--disable-client-side-phishing-detection",
        "--disable-component-extensions-with-background-pages",
        "--disable-crash-reporter",
        "--disable-default-apps",
        "--disable-dev-shm-usage",
        "--disable-hang-monitor",
        "--disable-infobars",
        "--disable-ipc-flooding-protection",
        "--disable-popup-blocking",
        "--disable-prompt-on-repost",
        "--disable-renderer-backgrounding",
        "--disable-search-engine-choice-screen",
        "--disable-sync",
        "--enable-automation",
        "--export-tagged-pdf",
        "--force-color-profile=srgb",
        "--generate-pdf-document-outline",
        "--metrics-recording-only",
        "--no-first-run",
        "--password-store=basic",
        "--use-mock-keychain",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    args.push(format!("--disable-features={}", disabled.join(",")));
    args.push(format!("--enable-features={}", enabled.join(",")));
    args.push(format!("--user-data-dir={}", user_data_dir.display()));
    if headless {
        args.extend(["--headless=new", "--hide-scrollbars", "--mute-audio"].map(str::to_owned));
    }
    args.push("--disable-extensions".to_owned());
    if rest.iter().all(|a| a.starts_with('-')) {
        args.push("about:blank".to_owned());
    }
    args.extend(rest.into_iter().cloned());
    if !args.iter().any(|a| a.starts_with("--remote-debugging-port") || a == "--remote-debugging-pipe") {
        args.push("--remote-debugging-pipe".to_owned());
    }
    args
}

/// A browser reached over one connection: launched by us (over its debugging pipe, unless a port was
/// asked for) or connected to over its WebSocket.
pub struct Browser {
    conn: Connection,
    /// Only a browser we launched has a process; closing never touches any other Chrome.
    child: Mutex<Option<tokio::process::Child>>,
    /// The temporary profile we created, removed on close. A caller's `user_data_dir` is never removed.
    temp_profile: Option<PathBuf>,
    pages: Mutex<HashMap<String, Page>>,
    closed: AtomicBool,
}

impl fmt::Debug for Browser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Browser")
            .field("ws_url", &self.conn.url())
            .field("pid", &self.pid())
            .field("temp_profile", &self.temp_profile)
            .finish_non_exhaustive()
    }
}

fn unique_temp_profile() -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("phantab-cdp-profile-{}-{nanos}-{n}", std::process::id()))
}

async fn remove_dir_with_retries(dir: &Path) {
    // Windows keeps profile files locked for a moment after the process exits.
    for _ in 0..20 {
        match tokio::fs::remove_dir_all(dir).await {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    tracing::debug!(dir = %dir.display(), "could not remove temporary profile");
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Reads `DevToolsActivePort` (port, then browser path) into a WebSocket URL.
fn read_active_port(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let port: u16 = lines.next()?.trim().parse().ok()?;
    let ws_path = lines.next()?.trim();
    (port != 0 && ws_path.starts_with('/')).then(|| format!("ws://127.0.0.1:{port}{ws_path}"))
}

/// The parent's two ends of Chrome's debugging pipe: the one Chrome writes, the one it reads.
type PipeEnds = (std::io::PipeReader, std::io::PipeWriter);

static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Hold this while starting any child process. On Windows a launch marks Chrome's pipe ends
/// inheritable for the moment of its spawn, and every child started then inherits them too: one that
/// outlives Chrome would keep its pipe from closing, so a crash would go unseen until that child exits.
pub fn spawn_guard() -> std::sync::MutexGuard<'static, ()> {
    SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The proxy variables, which the service may carry for `bw` (phantab SR-14). Chrome on Windows and
/// macOS takes its proxy from the system settings and ignores these, but Chromium on Linux reads them,
/// so they are taken out of every Chrome phantab starts: a proxy set in a client's environment then
/// never sees the pages phantab opens, on any platform.
const PROXY_VARS: [&str; 8] = [
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
];

/// The names to take out of a child's environment: each of [`PROXY_VARS`], and each `inherited` name
/// that is one of them in another case (`Https_Proxy`). Windows matches names in any case anyway; on
/// macOS and Linux the service may hold such a name, since its allow-list ignores case.
fn proxy_names(inherited: impl Iterator<Item = std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let mut names: Vec<std::ffi::OsString> = PROXY_VARS.iter().map(Into::into).collect();
    names.extend(inherited.filter(|k| {
        let k = k.to_string_lossy();
        PROXY_VARS.iter().any(|p| p.eq_ignore_ascii_case(&k) && *p != k)
    }));
    names
}

/// A command for `program` without the proxy variables ([`proxy_names`]). Every Chrome phantab starts
/// is built here, so none can miss the removal.
fn chrome_command(program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    for name in proxy_names(std::env::vars_os().map(|(k, _)| k)) {
        cmd.env_remove(name);
    }
    cmd
}

/// Starts Chrome with `--remote-debugging-pipe` on two fresh OS pipes, and returns the parent's ends.
///
/// Windows: Chrome adopts the pipe handles named in `--remote-debugging-io-pipes=<read>,<write>`
/// (Chromium `devtools_agent_host_impl.cc`, `AdoptPipes`; decimal handle values, which an inherited
/// handle keeps in the child). std spawns with handle inheritance on, so marking Chrome's two ends
/// inheritable is all it takes. They are inheritable only from just before this spawn until they are
/// closed just after it, under a lock, so two launches never hand each other's ends to their Chrome.
#[cfg(windows)]
fn spawn_piped(executable: &Path, args: &[String]) -> std::io::Result<(tokio::process::Child, PipeEnds)> {
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _};

    let (browser_reads, to_browser) = std::io::pipe()?;
    let (from_browser, browser_writes) = std::io::pipe()?;
    let _one_at_a_time = spawn_guard();
    phantab_window::set_handle_inheritable(browser_reads.as_handle(), true)?;
    phantab_window::set_handle_inheritable(browser_writes.as_handle(), true)?;
    let io_pipes = format!(
        "--remote-debugging-io-pipes={},{}",
        browser_reads.as_raw_handle().addr(),
        browser_writes.as_raw_handle().addr()
    );
    let child = chrome_command(executable)
        .args(args)
        .arg(io_pipes)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    // Chrome holds its own copies now; ours must go, or the pipe never reports Chrome's end.
    drop((browser_reads, browser_writes));
    Ok((child?, (from_browser, to_browser)))
}

/// Starts Chrome with `--remote-debugging-pipe` on two fresh OS pipes, and returns the parent's ends.
///
/// Unix: Chrome reads fd 3 and writes fd 4. std places only a child's fds 0 to 2, and moving others
/// needs `pre_exec`, which is `unsafe` (SR-58). So `/bin/sh` moves them: the pipes arrive as its stdin
/// and stdout, become 3 and 4, 0 and 1 go back to `/dev/null`, and Chrome replaces the shell (same
/// pid, so [`Browser::pid`] and the kill on close still name Chrome).
#[cfg(unix)]
fn spawn_piped(executable: &Path, args: &[String]) -> std::io::Result<(tokio::process::Child, PipeEnds)> {
    // A missing executable would only show as the shell's exit 127; say what it is.
    std::fs::metadata(executable)?;
    let (browser_reads, to_browser) = std::io::pipe()?;
    let (from_browser, browser_writes) = std::io::pipe()?;
    let mut cmd = chrome_command("/bin/sh");
    cmd.arg("-c")
        .arg(r#"exec "$0" "$@" 3<&0 4>&1 0</dev/null 1>/dev/null"#)
        .arg(executable)
        .args(args)
        .stdin(Stdio::from(browser_reads))
        .stdout(Stdio::from(browser_writes))
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let child = cmd.spawn();
    // The command holds the child's ends until dropped; the pipe reports Chrome's end only after.
    drop(cmd);
    Ok((child?, (from_browser, to_browser)))
}

#[cfg(not(any(unix, windows)))]
fn spawn_piped(_: &Path, _: &[String]) -> std::io::Result<(tokio::process::Child, PipeEnds)> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no debugging pipe on this platform"))
}

impl Browser {
    /// Starts Chrome with puppeteer's default arguments and connects to it over its debugging pipe, so
    /// no port is open. With `--remote-debugging-port` in `args` it uses that port and a WebSocket
    /// instead.
    pub async fn launch(options: LaunchOptions) -> Result<Browser, CdpError> {
        let (profile, temp_profile) = if let Some(d) = &options.user_data_dir {
            (d.clone(), None)
        } else {
            let d = unique_temp_profile();
            (d.clone(), Some(d))
        };
        std::fs::create_dir_all(&profile)
            .map_err(|e| CdpError::Launch(format!("cannot create profile {}: {e}", profile.display())))?;
        let result = Self::launch_in(&options, &profile).await;
        match result {
            Ok((conn, child)) => Ok(Browser {
                conn,
                child: Mutex::new(Some(child)),
                temp_profile,
                pages: Mutex::new(HashMap::new()),
                closed: AtomicBool::new(false),
            }),
            Err(e) => {
                if let Some(d) = &temp_profile {
                    remove_dir_with_retries(d).await;
                }
                Err(e)
            }
        }
    }

    async fn launch_in(
        options: &LaunchOptions,
        profile: &Path,
    ) -> Result<(Connection, tokio::process::Child), CdpError> {
        let args = default_args(options.headless, profile, &options.args);
        if args.iter().any(|a| a.starts_with("--remote-debugging-io-pipes")) {
            return Err(CdpError::Launch(
                "--remote-debugging-io-pipes is the launcher's own; pass no pipe handles".to_owned(),
            ));
        }
        if args.iter().any(|a| a.starts_with("--remote-debugging-port")) {
            Self::launch_over_port(options, profile, &args).await
        } else {
            Self::launch_over_pipe(options, &args).await
        }
    }

    fn spawn_error(executable: &Path, e: &std::io::Error) -> CdpError {
        CdpError::Launch(format!("Failed to launch the browser process {}: {e}", executable.display()))
    }

    /// The default: CDP over the debugging pipe, with no port open (THREAT-MODEL R13).
    async fn launch_over_pipe(
        options: &LaunchOptions,
        args: &[String],
    ) -> Result<(Connection, tokio::process::Child), CdpError> {
        let (mut child, (from_browser, to_browser)) =
            spawn_piped(&options.executable, args).map_err(|e| Self::spawn_error(&options.executable, &e))?;
        let conn = match Connection::pipe(from_browser, to_browser) {
            Ok(conn) => conn,
            Err(e) => {
                let _ = child.kill().await;
                return Err(CdpError::Launch(e.to_string()));
            }
        };
        // The pipe exists before Chrome does; its first answer says Chrome is up and speaking on it.
        // A Chrome that cannot start (a profile in use) or cannot adopt the pipe exits, which closes it.
        let first =
            tokio::time::timeout(LAUNCH_TIMEOUT, conn.send(None, "Browser.getVersion", json!({}))).await;
        let failure = match first {
            Ok(Ok(_)) => return Ok((conn, child)),
            Ok(Err(e)) => match tokio::time::timeout(CLOSE_GRACE, child.wait()).await {
                Ok(Ok(status)) => format!(
                    "Failed to launch the browser process: exited with {status} before answering on the \
                     debugging pipe (is the profile already in use?)"
                ),
                _ => format!("Failed to launch the browser process: the debugging pipe failed: {e}"),
            },
            Err(_) => format!(
                "Timed out after {} ms while waiting for the browser on its debugging pipe",
                LAUNCH_TIMEOUT.as_millis()
            ),
        };
        conn.close();
        let _ = child.kill().await;
        Err(CdpError::Launch(failure))
    }

    /// A caller asked for `--remote-debugging-port`: the endpoint comes from `DevToolsActivePort` in the
    /// profile, not from parsing stderr, so stdio stays detached.
    async fn launch_over_port(
        options: &LaunchOptions,
        profile: &Path,
        args: &[String],
    ) -> Result<(Connection, tokio::process::Child), CdpError> {
        let port_file = profile.join("DevToolsActivePort");
        // A file left by an earlier run must not be mistaken for ours.
        let stale = modified(&port_file);
        let spawned = {
            let _no_pipe_ends = spawn_guard();
            chrome_command(&options.executable)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
        };
        let mut child = spawned.map_err(|e| Self::spawn_error(&options.executable, &e))?;
        let deadline = Instant::now() + LAUNCH_TIMEOUT;
        let ws_url = loop {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(CdpError::Launch(format!(
                    "Failed to launch the browser process: exited with {status} before opening DevTools \
                     (is the profile already in use?)"
                )));
            }
            if (stale.is_none() || modified(&port_file) != stale)
                && let Some(url) = read_active_port(&port_file)
            {
                break url;
            }
            if Instant::now() >= deadline {
                let _ = child.kill().await;
                return Err(CdpError::Launch(format!(
                    "Timed out after {} ms while waiting for the browser's DevToolsActivePort",
                    LAUNCH_TIMEOUT.as_millis()
                )));
            }
            tokio::time::sleep(PORT_POLL).await;
        };
        match Connection::connect(&ws_url).await {
            Ok(conn) => Ok((conn, child)),
            Err(e) => {
                let _ = child.kill().await;
                Err(CdpError::Launch(e.to_string()))
            }
        }
    }

    /// Connects to a running browser's devtools WebSocket (`ws://…/devtools/browser/<id>`).
    pub async fn connect(ws_url: &str) -> Result<Browser, CdpError> {
        let conn = Connection::connect(ws_url).await?;
        Ok(Browser {
            conn,
            child: Mutex::new(None),
            temp_profile: None,
            pages: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        })
    }

    /// The devtools WebSocket URL; `None` for a browser launched over its pipe.
    pub fn ws_url(&self) -> Option<&str> {
        self.conn.url()
    }

    /// The shared connection, for browser-level commands of your own.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The process id of a browser we launched.
    pub fn pid(&self) -> Option<u32> {
        self.child.lock().as_ref().and_then(tokio::process::Child::id)
    }

    async fn browser_send(&self, method: &str, params: Value) -> Result<Value, CdpError> {
        match tokio::time::timeout(BROWSER_COMMAND_TIMEOUT, self.conn.send(None, method, params)).await {
            Ok(r) => r,
            Err(_) => Err(CdpError::Timeout { method: method.to_owned() }),
        }
    }

    /// Opens a new `about:blank` tab and attaches to it.
    pub async fn new_page(&self) -> Result<Page, CdpError> {
        self.new_page_with(PageOptions::default()).await
    }

    /// [`Browser::new_page`] with page options (`target_id` is filled in).
    pub async fn new_page_with(&self, options: PageOptions) -> Result<Page, CdpError> {
        let created = self.browser_send("Target.createTarget", json!({"url": "about:blank"})).await?;
        let target_id = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| CdpError::Other("Target.createTarget returned no targetId".into()))?
            .to_owned();
        self.attach_target(&target_id, options).await
    }

    /// Attaches to an existing page target with its own flat session as the page's root.
    pub async fn attach_target(&self, target_id: &str, options: PageOptions) -> Result<Page, CdpError> {
        let res = self
            .browser_send("Target.attachToTarget", json!({"targetId": target_id, "flatten": true}))
            .await?;
        let sid = res
            .get("sessionId")
            .and_then(Value::as_str)
            .map(SessionId::from)
            .ok_or_else(|| CdpError::Other("Target.attachToTarget returned no sessionId".into()))?;
        let events = self.conn.take_events(&sid);
        let options = PageOptions { target_id: Some(target_id.to_owned()), ..options };
        let transport: Arc<dyn Transport> = Arc::new(self.conn.clone());
        let page = Page::attach(transport, Some(sid), events, options).await?;
        self.pages.lock().insert(target_id.to_owned(), page.clone());
        Ok(page)
    }

    /// Every open page target, attaching to those not attached yet.
    pub async fn pages(&self) -> Result<Vec<Page>, CdpError> {
        let res = self.browser_send("Target.getTargets", json!({})).await?;
        let ids: Vec<String> = res
            .get("targetInfos")
            .and_then(Value::as_array)
            .map(|infos| {
                infos
                    .iter()
                    .filter(|t| t.get("type").and_then(Value::as_str) == Some("page"))
                    .filter_map(|t| t.get("targetId").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        self.pages.lock().retain(|id, p| !p.is_closed() && ids.contains(id));
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let cached = self.pages.lock().get(&id).cloned();
            match cached {
                Some(p) => out.push(p),
                None => match self.attach_target(&id, PageOptions::default()).await {
                    Ok(p) => out.push(p),
                    // The tab closed between listing and attaching.
                    Err(e) if e.is_closed() || matches!(e, CdpError::Protocol { .. }) => {}
                    Err(e) => return Err(e),
                },
            }
        }
        Ok(out)
    }

    /// Closes the browser: `Browser.close`, then (for a browser we launched) waits for the process, kills
    /// only that process if it lingers, and removes the temporary profile.
    ///
    /// Like puppeteer, this also closes a browser obtained with [`Browser::connect`]; use
    /// [`Browser::disconnect`] to leave it running.
    pub async fn close(&self) -> Result<(), CdpError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let child = self.child.lock().take();
        if !self.conn.is_closed() {
            // Chrome may drop the socket before answering; that is success.
            let _ = tokio::time::timeout(CLOSE_GRACE, self.conn.send(None, "Browser.close", json!({}))).await;
        }
        if let Some(mut child) = child
            && tokio::time::timeout(CLOSE_GRACE, child.wait()).await.is_err()
        {
            let _ = child.kill().await;
        }
        self.conn.close();
        if let Some(dir) = &self.temp_profile {
            remove_dir_with_retries(dir).await;
        }
        Ok(())
    }

    /// Closes the connection without sending `Browser.close`. A browser on a WebSocket keeps running;
    /// one launched over its pipe exits, since Chrome ends when its debugging pipe closes.
    pub fn disconnect(&self) {
        self.conn.close();
    }
}

impl Drop for Browser {
    /// Best effort when [`Browser::close`] was not awaited: kill our process (never any other) and try
    /// to remove the temporary profile, which can fail while the process is still exiting.
    fn drop(&mut self) {
        if let Some(mut child) = self.child.get_mut().take() {
            let _ = child.start_kill();
            self.conn.close();
            if let Some(dir) = &self.temp_profile {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SR-14, L1: Chrome is started with every proxy variable removed, in any case, whatever the service
    /// was given; and every process this file starts is built by `chrome_command`.
    #[test]
    fn chrome_never_gets_the_proxy_variables() {
        let inherited = ["Https_Proxy", "PATH", "http_proxy"].map(std::ffi::OsString::from);
        let names = proxy_names(inherited.into_iter());
        for name in PROXY_VARS.iter().chain(&["Https_Proxy"]) {
            assert!(names.iter().any(|k| k == name), "{name} reaches Chrome");
        }
        assert!(!names.iter().any(|k| k == "PATH"));
        let cmd = chrome_command("chrome");
        let removed: Vec<_> =
            cmd.as_std().get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_owned()).collect();
        for name in PROXY_VARS {
            assert!(removed.iter().any(|k| k.eq_ignore_ascii_case(name)), "{name} reaches Chrome");
        }
        let source = include_str!("browser.rs");
        let code = source.split("mod tests {").next().unwrap_or(source);
        assert_eq!(code.matches("Command::new(").count(), 1, "a process started outside chrome_command");
    }

    #[test]
    fn default_args_match_puppeteer() {
        let user = vec!["--enable-features=Foo".to_owned(), "--disable-features=Bar,PdfOopif".to_owned()];
        let args = default_args(true, Path::new("/tmp/p"), &user);
        assert_eq!(args[0], "--allow-pre-commit-input");
        assert!(args.contains(&"--disable-features=Translate,AcceptCHFrame,MediaRouter,OptimizationHints,WebUIReloadButton,WebUIOmniboxPopup,WebUIOmniboxAimPopup,ProcessPerSiteUpToMainFrameThreshold,IsolateSandboxedIframes,Bar".to_owned()));
        assert!(args.contains(&"--enable-features=PdfOopif,Foo".to_owned()));
        assert!(args.contains(&"--headless=new".to_owned()));
        assert!(args.contains(&"--user-data-dir=/tmp/p".to_owned()));
        assert_eq!(args.iter().filter(|a| a.starts_with("--enable-features")).count(), 1);
        assert_eq!(args[args.len() - 2], "about:blank");
        // R13: the pipe, never a port, unless the caller asks for one.
        assert_eq!(args.last().map(String::as_str), Some("--remote-debugging-pipe"));
        assert!(!args.iter().any(|a| a.starts_with("--remote-debugging-port")));

        let args = default_args(
            false,
            Path::new("p"),
            &["https://x/".to_owned(), "--remote-debugging-pipe".to_owned()],
        );
        assert!(!args.contains(&"about:blank".to_owned()));
        assert!(!args.contains(&"--headless=new".to_owned()));
        assert!(!args.iter().any(|a| a.starts_with("--remote-debugging-port")));
        assert_eq!(args.iter().filter(|a| *a == "--remote-debugging-pipe").count(), 1);

        let args = default_args(true, Path::new("p"), &["--remote-debugging-port=0".to_owned()]);
        assert!(args.contains(&"--remote-debugging-port=0".to_owned()));
        assert!(!args.contains(&"--remote-debugging-pipe".to_owned()));
    }

    #[test]
    fn active_port_file() {
        let dir = unique_temp_profile();
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("DevToolsActivePort");
        std::fs::write(&f, "9222\n/devtools/browser/abc\n").unwrap();
        assert_eq!(read_active_port(&f).as_deref(), Some("ws://127.0.0.1:9222/devtools/browser/abc"));
        std::fs::write(&f, "9222\n").unwrap();
        assert_eq!(read_active_port(&f), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A program that exits at once in Chrome's place: both routes say so in one plain sentence.
    #[tokio::test]
    async fn a_browser_that_exits_before_answering_is_named_plainly() {
        let executable = if cfg!(windows) {
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("whoami.exe")
        } else {
            PathBuf::from("/usr/bin/true")
        };
        for (args, said) in [
            (vec![], "before answering on the debugging pipe (is the profile already in use?)"),
            (
                vec!["--remote-debugging-port=0".to_owned()],
                "before opening DevTools (is the profile already in use?)",
            ),
        ] {
            let options =
                LaunchOptions { executable: executable.clone(), headless: true, user_data_dir: None, args };
            let Err(CdpError::Launch(message)) = Browser::launch(options).await else { panic!("launched") };
            assert!(message.ends_with(said) && !message.contains("  "), "{message}");
        }
    }
}
