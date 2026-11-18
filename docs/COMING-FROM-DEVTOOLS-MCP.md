# Coming from Chrome DevTools MCP

For an agent, or the person setting one up, that used Chrome DevTools MCP until now. Chrome DevTools
MCP starts its own Chrome with its own profile. Phantab drives the owner's Chrome, signed in as they
are, through an extension, in windows the owner does not see until a page is handed over. Most
DevTools MCP tools have a phantab call; a few are left out (§ Not included).

The developer tools (`browser_evaluate`, `browser_console`, `browser_network`, `browser_emulate`,
`browser_trace`) are off unless `config.json` has `"devTools": true` (`docs/GUARDRAILS.md`).
`phantab install --dev-tools` turns them on (`docs/INSTALL-WINDOWS.md` § 4).

## Tool by tool
Each example is a call a test makes and checks, written as the agent sends it (the test named in the
last column, in `crates/phantab/tests/`). `"p"` stands for the page id `browser_open` answered.
Leave `pageId` out for the page your last call named.

| DevTools MCP | Phantab | Example | Test |
|---|---|---|---|
| `new_page`, `close_page`, `list_pages`, `select_page`, `wait_for` | `browser_open`, `browser_close`, `browser_pages`, the `pageId` of each call, `browser_wait` | `browser_wait {"pageId": "p", "selector": "#ok", "text": "Visible words"}` | `engine_chrome` `shared_pages_through_the_service_ownership_site_locks_waits_actions_and_tab_end` |
| `take_snapshot` | `browser_snapshot`; a text field shows what it holds as `value=`, a select `selected=` | `browser_snapshot {"pageId": "p", "full": true}` | `work_parity_acceptance` `agent_a_fills_saves_and_hands_over_a_framed_form_while_agent_b_fills_another_copy` |
| `take_snapshot` to a file | `browser_snapshot` with `path` (JSON) | `browser_snapshot {"pageId": "p", "path": "C:\\tmp\\page.json"}` | `engine_chrome` `screenshots_and_snapshots_are_saved_as_files_at_the_size_asked` |
| `fill`, `fill_form` | `browser_act` `fill` and `select` steps, any number in one call, in a frame or shadow root too | `browser_act {"pageId": "p", "steps": [["fill", "#task\\.short_description", "VPN token expired"], ["select", "#task\\.state", "Work in Progress"]]}` | `work_parity_acceptance` (all seven fields of a framed form), `engine_chrome` `framed_forms_are_filled_by_selector_and_show_their_values_at_parity` |
| `type_text` | `browser_act` `type`: typed at the focus | `browser_act {"pageId": "p", "steps": [["type", "Reset the VPN token"]]}`, after a `click_xy` on the field | `engine_chrome` `framed_forms_are_filled_by_selector_and_show_their_values_at_parity` |
| `click` | `browser_act` `click` with a selector | `browser_act {"pageId": "p", "steps": [["click", "#go"]]}` | `engine_chrome` `a_selector_acts_on_the_element_its_wait_and_check_read` |
| `click_at` | `browser_act` `click_xy`, at a snapshot's `x,y` | `browser_act {"pageId": "p", "steps": [["click_xy", 263, 219]]}`, the `x,y` the snapshot lists for the control | `engine_chrome` `snapshots_read_shadow_roots_and_website_frames_and_click_xy_reaches_them` |
| `press_key` | `browser_act` `press`, a key or a combination | `browser_act {"pageId": "p", "steps": [["press", "Control+A"], ["type", "new"]]}` | `engine_chrome` `a_key_combination_selects_all_and_typing_replaces_it` |
| `hover` | `browser_act` `hover`, `hover_xy` | `browser_act {"pageId": "p", "steps": [["hover", "#account"]]}` | `engine_chrome` `hover_and_hover_xy_open_a_menu_that_opens_on_hover` |
| `drag` | `browser_act` `drag` (onto an element), `drag_xy` (onto a point) | `browser_act {"pageId": "p", "steps": [["drag", "#first", "#second"]]}`, `["drag_xy", 100, 121, 100, 29]` | `engine_chrome` `drag_and_drag_xy_sort_a_list` |
| `upload_file` | `browser_act` `upload`: full paths into a file input, no file chooser | `browser_act {"pageId": "p", "steps": [["upload", "#file", "C:\\tmp\\notes.txt"]]}` | `engine_chrome` `upload_sets_a_file_input_and_refuses_what_it_cannot_send` |
| `handle_dialog` | `browser_act` `dialog`, before the step that opens one | `browser_act {"pageId": "p", "steps": [["dialog", "accept", "Ada"]]}`, then the step that opens the prompt | `engine_chrome` `a_dialog_step_answers_the_next_dialog_once_and_every_dialog_is_reported` |
| `navigate_page` | `browser_act` `navigate`, `back`, `forward`, `reload` | `browser_act {"pageId": "p", "steps": [["back"]]}` | `engine_chrome` `back_forward_and_reload_move_through_the_tabs_history` |
| `take_screenshot` | `browser_screenshot`: the view, `fullPage`, or one element by `selector`; `path` saves it | `browser_screenshot {"pageId": "p", "selector": "#task", "format": "png", "path": "C:\\tmp\\task form.png"}` | `work_parity_acceptance` `agent_a_fills_saves_and_hands_over_a_framed_form_while_agent_b_fills_another_copy` |
| `resize_page`, `emulate` (viewport) | `browser_screenshot` `width` and `height`, for that picture alone | `browser_screenshot {"pageId": "p", "path": "C:\\tmp\\phone.png", "format": "png", "width": 390}` | `engine_chrome` `screenshots_and_snapshots_are_saved_as_files_at_the_size_asked` |
| `evaluate_script` | `browser_evaluate`: a function, its `args`, and a `frame` by origin | `browser_evaluate {"pageId": "p", "function": "(a, b) => a + b", "args": [2, 3]}` | `engine_chrome` `evaluate_reads_a_frame_cuts_saves_throws_and_times_out` |
| `get_css_styles` | `browser_evaluate` with `getComputedStyle` | `browser_evaluate {"pageId": "p", "function": "() => getComputedStyle(document.getElementById('global-search')).display"}` | `work_parity_acceptance` `agent_a_fills_saves_and_hands_over_a_framed_form_while_agent_b_fills_another_copy` |
| `list_console_messages`, `get_console_message` | `browser_console`: the page's errors, warnings and uncaught exceptions | `browser_console {"pageId": "p"}` | `engine_chrome` `developer_tools_read_the_console_and_network_and_run_scripts` |
| `list_network_requests`, `get_network_request` | `browser_network`: the requests, failed ones first; `id` for one, `filter` by URL | `browser_network {"pageId": "p", "filter": "/cookie/"}` | `engine_chrome` `developer_tools_read_the_console_and_network_and_run_scripts` |
| `emulate` (CPU, network, location, user agent, colour scheme) | `browser_emulate`, on one page until `clear` or the page closes | `browser_emulate {"pageId": "p", "userAgent": "phantab-test-agent", "colorScheme": "dark", "location": {"latitude": 51.5, "longitude": -0.12}, "network": {"latencyMs": 400}}`, `browser_emulate {"pageId": "p", "cpu": 4}`, `browser_emulate {"pageId": "p", "clear": true}` | `engine_chrome` `emulation_reaches_the_page_and_clears_on_clear_and_close`, `a_cpu_slowdown_lengthens_the_load_and_a_trace_ends_at_its_time_limit` |
| `performance_start_trace`, `performance_stop_trace` | `browser_trace` `start` (with `reload` to trace a load) and `stop`: a trace file and the page's own numbers | `browser_trace {"pageId": "p", "action": "start", "reload": true, "path": "C:\\tmp\\load.json"}`, then `browser_trace {"pageId": "p", "action": "stop"}` | `engine_chrome` `trace_saves_a_performance_trace_and_the_page_s_own_numbers` |
| `performance_analyze_insight`, `lighthouse_audit` | In part: `browser_trace stop` answers the load's numbers (largest paint and its element, layout shift, first paint, the slowest requests) and saves the trace in Chrome's trace event format, which DevTools' Performance panel loads | as above | as above |

The `steps` form is the one to use. The tests in `engine_chrome` send each step in its older form,
`{"action": "drag", "selector": "#first", "to": "#second"}`, which `browser_act` still takes.

## Different on purpose
- **Hidden windows.** Phantab's pages open in windows the owner does not see, so an agent's work does
  not take over the screen. `browser_show` hands a page to the owner: its window comes up, and until
  the owner hands it back the agent's writes to it are refused (`release: true` gives it to the owner
  for good). On a page that is shown, the view is the owner's window, so a screenshot's `fullPage`,
  `selector`, `width` and `height` are refused until handback.
- **Selectors and coordinates, not uids.** DevTools MCP names an element by the uid its snapshot gave.
  Phantab's steps take a CSS selector, found in the main document and then in each website frame,
  open shadow roots included; or the `x,y` a snapshot lists beside each control, for `click_xy`,
  `hover_xy` and `drag_xy`. A control marked `shadow` in a snapshot takes coordinates.
- **Agents share a site.** Two agents can each work a page on the same site at once; only a page
  handed to the owner refuses its own agent's writes. A site keeps one sign-in, cookies and storage
  per Chrome profile, so two pages on it are the same user: a draft one agent saves, the other sees.
  `"siteLock": "exclusive"` lets one agent at a time change a site (`docs/GUARDRAILS.md`).
- **The owner's sign-ins, guarded.** The pages are the owner's Chrome, signed in. With `guardrails`
  `parity` (the default) the agent's own setup owns its approvals; `light` and `full` make it repeat a
  payment, a password change and the like with the owner's yes (`docs/GUARDRAILS.md`). In every mode,
  `browser_network` never shows a cookie or an authorization header, and a saved trace leaves them out.
- **`devTools`.** Off by default: the five developer tools are not listed and are refused.

## Not included
- **Insight analysis** (`performance_analyze_insight`): phantab gives the numbers and the trace file,
  not DevTools' insights. The file is in the trace event format, for DevTools' Performance panel or
  another trace viewer.
- **Lighthouse** (`lighthouse_audit`).
- **Screencast** (`screencast_start`, `screencast_stop`).
- **Logpoints** (`set_logpoints`).

For these, keep Chrome DevTools MCP as a second MCP entry beside phantab. It drives its own Chrome,
with none of the owner's sign-ins, so the two never share a page.
