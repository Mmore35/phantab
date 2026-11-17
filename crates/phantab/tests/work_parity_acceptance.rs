//! Lane 3: the acceptance run for phantab on a work laptop at parity with Chrome `DevTools` MCP
//! (`docs/COMING-FROM-DEVTOOLS-MCP.md`), in three parts:
//!
//! 1. Every row of the parity table that names a phase has a test page and a test that passes on it
//!    ([`PARITY`]; the rows earlier phases proved name their tests, and the one row with none,
//!    `get_css_styles`, is a call in part 2).
//! 2. Two agents through `phantab mcp`, as an agent runs it, with the config `phantab install --work`
//!    writes: agent A fills the seven fields of a task form in a frame inside shadow roots in one
//!    `browser_act`, reads the seven values back in a snapshot, saves a PNG of the form and hands the
//!    page over; while it is held, agent B fills a second copy of the form on the same site.
//! 3. With `work` on, the tool list has no sign-in or sign-up tool and `browser_status` names what is
//!    off.
//!
//! Parts 2 and 3 skip without `PHANTAB_TEST_CHROME`. Headless (`PHANTAB_TEST_WINDOWS=none`), against the
//! fake extension that does every bridge op on a real Chrome (`common/cdp_extension.rs`). Nothing here
//! reads anything outside the repository and its temp folders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/cdp_extension.rs"]
mod cdp_extension;
mod common;

use std::io::{BufRead as _, BufReader, Lines, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cdp_extension::CdpExtension;
use common::{Runtime, Service, upgrade};
use phantab_cdp::Browser;
use phantab_testkit::FixtureServer;
use serde_json::{Value, json};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One parity row: the Chrome `DevTools` MCP tools, the phase that closed the gap, the test page (a
/// fixture key) and the test that passes on it (`<file in crates/phantab/tests>`, `<test name>`).
struct Row {
    tools: &'static str,
    phase: &'static str,
    page: &'static str,
    file: &'static str,
    test: &'static str,
}

const fn row(
    tools: &'static str,
    phase: &'static str,
    page: &'static str,
    file: &'static str,
    test: &'static str,
) -> Row {
    Row { tools, phase, page, file, test }
}

/// The parity table's rows that name a phase, each with its page and test. `docs/COMING-FROM-DEVTOOLS-MCP.md`
/// shows the same table with an example call per row; keep the two in step.
const PARITY: [Row; 18] = [
    row(
        "take_snapshot",
        "1",
        "engine/record",
        "engine_chrome",
        "framed_forms_are_filled_by_selector_and_show_their_values_at_parity",
    ),
    row(
        "take_snapshot (to a file)",
        "3",
        "engine/shots",
        "engine_chrome",
        "screenshots_and_snapshots_are_saved_as_files_at_the_size_asked",
    ),
    row(
        "fill, fill_form",
        "1",
        "engine/framed-task",
        "engine_chrome",
        "framed_forms_are_filled_by_selector_and_show_their_values_at_parity",
    ),
    row(
        "type_text",
        "1",
        "engine/framed-task",
        "engine_chrome",
        "framed_forms_are_filled_by_selector_and_show_their_values_at_parity",
    ),
    row(
        "click",
        "1",
        "engine/two-frames",
        "engine_chrome",
        "a_selector_acts_on_the_element_its_wait_and_check_read",
    ),
    row(
        "click_at",
        "1",
        "snapshot/deep",
        "engine_chrome",
        "snapshots_read_shadow_roots_and_website_frames_and_click_xy_reaches_them",
    ),
    row(
        "press_key",
        "4",
        "engine/basic",
        "engine_chrome",
        "a_key_combination_selects_all_and_typing_replaces_it",
    ),
    row("hover", "4", "engine/hover", "engine_chrome", "hover_and_hover_xy_open_a_menu_that_opens_on_hover"),
    row("drag", "4", "engine/drag", "engine_chrome", "drag_and_drag_xy_sort_a_list"),
    row(
        "upload_file",
        "4",
        "engine/upload",
        "engine_chrome",
        "upload_sets_a_file_input_and_refuses_what_it_cannot_send",
    ),
    row(
        "handle_dialog",
        "4",
        "engine/dialogs",
        "engine_chrome",
        "a_dialog_step_answers_the_next_dialog_once_and_every_dialog_is_reported",
    ),
    row(
        "navigate_page",
        "4",
        "engine/history",
        "engine_chrome",
        "back_forward_and_reload_move_through_the_tabs_history",
    ),
    row(
        "take_screenshot, resize_page, emulate (viewport)",
        "3",
        "engine/shots",
        "engine_chrome",
        "screenshots_and_snapshots_are_saved_as_files_at_the_size_asked",
    ),
    row(
        "evaluate_script",
        "5",
        "engine/devtools-frame",
        "engine_chrome",
        "evaluate_reads_a_frame_cuts_saves_throws_and_times_out",
    ),
    row(
        "get_css_styles",
        "5",
        "engine/framed-task",
        "work_parity_acceptance",
        "agent_a_fills_saves_and_hands_over_a_framed_form_while_agent_b_fills_another_copy",
    ),
    row(
        "list_console_messages, get_console_message, list_network_requests, get_network_request",
        "5",
        "engine/devtools",
        "engine_chrome",
        "developer_tools_read_the_console_and_network_and_run_scripts",
    ),
    row(
        "emulate (CPU, network, location, user agent, colour scheme)",
        "6",
        "engine/basic",
        "engine_chrome",
        "emulation_reaches_the_page_and_clears_on_clear_and_close",
    ),
    row(
        "performance_start_trace, performance_stop_trace, and in part performance_analyze_insight and lighthouse_audit",
        "6",
        "engine/measure",
        "engine_chrome",
        "trace_saves_a_performance_trace_and_the_page_s_own_numbers",
    ),
];

/// Part 1: each row's page is a fixture page and its test is a test in that file, so a renamed test or
/// page fails here. The tests themselves run in their own files' headless runs.
#[test]
fn every_parity_row_has_a_test_page_and_a_test_that_passes_on_it() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest.join("../phantab-testkit/fixtures");
    for r in &PARITY {
        assert!(!r.phase.is_empty(), "{}", r.tools);
        let page = fixtures.join(format!("{}.html", r.page));
        assert!(page.is_file(), "{}: no test page {}", r.tools, page.display());
        let source = std::fs::read_to_string(manifest.join("tests").join(format!("{}.rs", r.file))).unwrap();
        let test = format!("async fn {}()", r.test);
        assert!(source.contains(&test), "{}: no test {} in {}.rs", r.tools, r.test, r.file);
        let at = source.find(&test).unwrap();
        let before = &source[..at];
        let attribute = before.rfind("#[tokio::test").unwrap_or(0);
        assert!(!before[attribute..].contains("#[ignore"), "{}: {} is ignored", r.tools, r.test);
        let body = &source[at..];
        let body = &body[..body[1..].find("\nasync fn ").map_or(body.len(), |n| n + 1)];
        let key = format!("/{}", r.page);
        assert!(body.contains(&key), "{}: {} does not open {key}", r.tools, r.test);
    }
}

/// A service on a temp runtime with the config `phantab install --work` writes (`work` and `devTools` on,
/// guardrails left at its default, `parity`), and the CDP-backed extension connected to it.
struct Lane {
    ext: CdpExtension,
    browser: Arc<Browser>,
    svc: Service,
    rt: Runtime,
    fixtures: FixtureServer,
}

impl Lane {
    async fn start(chrome: &PathBuf) -> Self {
        let fixtures = FixtureServer::start().unwrap();
        let rt = Runtime::new();
        rt.install_extension_in_profile();
        rt.write_config(&json!({
            "profileDirectory": "test", "userDataDir": rt.user_data_dir(), "chromeExecutable": chrome,
            "work": true, "devTools": true,
        }));
        let svc = tokio::task::block_in_place(|| {
            let child = rt
                .command(&["serve"])
                .env("PHANTAB_TEST_WINDOWS", "none")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Service { child: Some(child), endpoint: rt.wait_endpoint() }
        });
        let browser = cdp_extension::launch_chrome(chrome).await;
        let auth = format!("Bearer {}", svc.endpoint.token);
        let port = svc.endpoint.port;
        let stream = tokio::task::block_in_place(|| upgrade(port, &[("Authorization", &auth)], "/bridge").1)
            .expect("the bridge upgrade");
        let ext =
            tokio::task::block_in_place(|| CdpExtension::connect(stream, "accept", Arc::clone(&browser)));
        let lane = Self { ext, browser, svc, rt, fixtures };
        let end = Instant::now() + Duration::from_secs(10);
        while lane.rpc("status")["connected"] != json!(true) {
            assert!(Instant::now() < end, "the extension did not connect");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(lane.rpc("connect")["profileVerified"], json!(true));
        lane
    }

    fn rpc(&self, method: &str) -> Value {
        let (port, token) = (self.svc.endpoint.port, self.svc.endpoint.token.clone());
        tokio::task::block_in_place(|| common::rpc(port, &token, method, &json!({}), "test"))["result"]
            .clone()
    }

    async fn finish(self) {
        let Self { ext, browser, svc, rt, fixtures } = self;
        drop(ext);
        tokio::task::block_in_place(|| drop(svc));
        let _ = browser.close().await;
        drop(rt);
        drop(fixtures);
    }
}

/// One agent: `phantab mcp` on the lane's runtime, with its own client id.
struct Agent {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    id: u64,
}

impl Agent {
    fn start(rt: &Runtime, client: &str) -> Self {
        let mut child = rt
            .command(&["mcp"])
            .env("PHANTAB_CLIENT", client)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut agent = Self { child, stdin, lines, id: 0 };
        agent.request(
            "initialize",
            &json!({ "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": { "name": client, "version": "1" } }),
        );
        agent.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        agent
    }

    fn send(&mut self, v: &Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    /// A request's `result`.
    fn request(&mut self, method: &str, params: &Value) -> Value {
        self.id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": self.id, "method": method, "params": params }));
        let answer: Value = serde_json::from_str(&self.lines.next().unwrap().unwrap()).unwrap();
        answer["result"].clone()
    }

    /// A tool call's text, or a panic with it when the call failed.
    fn ok(&mut self, name: &str, arguments: &Value) -> String {
        let r = self.request("tools/call", &json!({ "name": name, "arguments": arguments }));
        assert_eq!(r["isError"], Value::Null, "{name} {arguments}: {r}");
        r["content"][0]["text"].as_str().unwrap_or_default().to_owned()
    }

    /// A tool call that fails: its text.
    fn refused(&mut self, name: &str, arguments: &Value) -> String {
        let r = self.request("tools/call", &json!({ "name": name, "arguments": arguments }));
        assert_eq!(r["isError"], json!(true), "{name} {arguments}: {r}");
        r["content"][0]["text"].as_str().unwrap_or_default().to_owned()
    }

    /// The first line of a tool call's text, as JSON.
    fn head(text: &str) -> Value {
        serde_json::from_str(text.lines().next().unwrap_or_default()).unwrap()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The seven fields of `engine/task-form`, with what one agent puts in each.
fn form(values: [&str; 7]) -> Vec<(&'static str, String)> {
    let fields = [
        "#task\\.short_description",
        "#sys_display\\.task\\.assignment_group",
        "#task\\.state",
        "#task\\.priority",
        "#task\\.due_date",
        "#task\\.work_notes",
        "#task\\.description",
    ];
    fields.into_iter().zip(values.map(str::to_owned)).collect()
}

fn is_select(selector: &str) -> bool {
    selector.ends_with("state") || selector.ends_with("priority")
}

/// The seven steps that fill `fields`, for one `browser_act`.
fn fill_steps(fields: &[(&str, String)]) -> Value {
    fields.iter().map(|(sel, v)| json!([if is_select(sel) { "select" } else { "fill" }, sel, v])).collect()
}

/// Asserts a snapshot's text shows every field's value: `value="..."`, or `selected="..."` for a select.
fn assert_shows(snapshot: &str, fields: &[(&str, String)]) {
    for (sel, v) in fields {
        let shown =
            if is_select(sel) { format!("selected={}", json!(v)) } else { format!("value={}", json!(v)) };
        assert!(snapshot.contains(&shown), "{sel}: {shown} in {snapshot}");
    }
}

/// Part 2, and the `get_css_styles` row: agent A fills the framed form's seven fields in one call, reads
/// them back in a snapshot, reads a computed style, saves a PNG of the form and hands the page over.
/// While A's page is held, its own writes are refused, and agent B fills a second copy of the form on
/// the same site with no refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_a_fills_saves_and_hands_over_a_framed_form_while_agent_b_fills_another_copy() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;
    let url = lane.fixtures.url("/engine/framed-task");
    let dir = tempfile::tempdir().unwrap();
    let png = dir.path().join("task form.png");

    tokio::task::block_in_place(|| {
        let mut a = Agent::start(&lane.rt, "agent-a");
        let mut b = Agent::start(&lane.rt, "agent-b");
        let a_fields = form([
            "VPN token expired",
            "Network Operations",
            "Work in Progress",
            "2 - High",
            "2026-12-01",
            "Called the user.",
            "The token expired overnight.",
        ]);
        let page = Agent::head(&a.ok("browser_open", &json!({ "url": url })))["pageId"].clone();
        let filled = a.ok("browser_act", &json!({ "pageId": page, "steps": fill_steps(&a_fields) }));
        assert!(!filled.contains("failed"), "{filled}");
        let read = a.ok("browser_snapshot", &json!({ "pageId": page, "full": true }));
        assert_shows(&read, &a_fields);

        // DevTools MCP's get_css_styles: browser_evaluate with getComputedStyle.
        let style = a.ok(
            "browser_evaluate",
            &json!({ "pageId": page,
                "function": "() => getComputedStyle(document.getElementById('global-search')).display" }),
        );
        assert_eq!(Agent::head(&style)["result"], json!("inline-block"), "{style}");

        let saved = Agent::head(&a.ok(
            "browser_screenshot",
            &json!({ "pageId": page, "selector": "#task", "format": "png", "path": png }),
        ));
        assert_eq!(saved["path"], json!(png.display().to_string()), "{saved}");
        assert_eq!(saved["mimeType"], json!("image/png"), "{saved}");
        let bytes = std::fs::read(&png).unwrap();
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"), "not a PNG");
        assert_eq!(saved["bytes"], json!(bytes.len()), "{saved}");

        a.ok("browser_show", &json!({ "pageId": page }));
        let own = a.refused(
            "browser_act",
            &json!({ "pageId": page, "steps": [["fill", "#task\\.short_description", "after"]] }),
        );
        assert!(own.contains("handed to the owner"), "{own}");

        let b_fields = form([
            "Printer offline",
            "Desk Support",
            "Open",
            "3 - Moderate",
            "2026-12-02",
            "Asked for the asset tag.",
            "The printer on floor two is offline.",
        ]);
        let second = Agent::head(&b.ok("browser_open", &json!({ "url": url })))["pageId"].clone();
        assert_ne!(second, page);
        let filled = b.ok("browser_act", &json!({ "pageId": second, "steps": fill_steps(&b_fields) }));
        assert!(!filled.contains("failed"), "{filled}");
        assert_shows(&b.ok("browser_snapshot", &json!({ "pageId": second, "full": true })), &b_fields);
        // A's draft is still its own.
        assert_shows(&a.ok("browser_snapshot", &json!({ "pageId": page, "full": true })), &a_fields);
        b.ok("browser_close", &json!({ "pageId": second }));
        // The page stays the owner's until handback, so A cannot close it either.
        let close = a.refused("browser_close", &json!({ "pageId": page }));
        assert!(close.contains("handed to the owner"), "{close}");
    });
    lane.finish().await;
}

/// Part 3: with `work` on, `tools/list` has no sign-in or sign-up tool (and has the developer tools,
/// which `devTools` turns on), and `browser_status` names the four things `work` turned off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_work_on_no_sign_in_tool_is_listed_and_status_names_what_is_off() {
    let Some(chrome) = phantab_testkit::skip_unless_chrome() else { return };
    let _turn = SERIAL.lock().await;
    let lane = Lane::start(&chrome).await;
    tokio::task::block_in_place(|| {
        let mut a = Agent::start(&lane.rt, "agent-a");
        let listed = a.request("tools/list", &json!({}));
        let names: Vec<&str> =
            listed["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        for gone in ["browser_sign_in", "browser_sign_up"] {
            assert!(!names.contains(&gone), "{gone} in {names:?}");
        }
        for kept in [
            "browser_show",
            "browser_evaluate",
            "browser_console",
            "browser_network",
            "browser_emulate",
            "browser_trace",
        ] {
            assert!(names.contains(&kept), "{kept} not in {names:?}");
        }
        let status = Agent::head(&a.ok("browser_status", &json!({})));
        assert_eq!(status["work"]["on"], json!(true), "{status}");
        let off: Vec<&str> =
            status["work"]["off"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(off, phantab::work::OFF, "{status}");
        assert_eq!(status["work"].get("note"), None, "{status}");
        // An agent that calls it anyway, from an old tool list, is told there is no such tool.
        let refused = a.refused("browser_sign_in", &json!({ "url": "https://example.test/login" }));
        assert_eq!(refused, "Unknown tool");
    });
    lane.finish().await;
}
