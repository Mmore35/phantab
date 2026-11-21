# Solving a human check (CAPTCHA) from another device

When a page hits a verification check, Phantab pops it up on the computer for the owner (README
§ When a site asks if you're human). With a remote view set up, the agent also gets a link to the check that works from the owner's
phone or another computer. The owner does the check there; Phantab only relays their own taps, drags and
keys to the page. It never solves the check itself.

The remote view is off unless the runtime config turns it on.

## How it is reached
Phantab opens a second listener, on loopback only, that serves just the live view (`GET /view`) and its
calls (`POST /viewer`). Everything else there is 404. The owner reaches it through a route they control
that puts their identity on each request: Tailscale Serve, here. Phantab checks, on every request:
1. the `Host` is exactly the public address's host and port;
2. an `Origin`, if sent, is the public address's origin;
3. the identity header is the owner's (when `trustedIdentity` is set);
4. the link's token is a live link for this listener (the local viewer does not take it, and its tokens
   do not work here).

A link is `http://<host>:<port>/view#<token>`. The token is in the fragment, so no proxy or log sees it,
and the page drops it from the address bar at once. It dies when the check clears, the owner declines it,
15 minutes pass, or the page closes. It is never written to disk or shown in `status`.

## Waking the agent
The owner may solve the check long after the agent's turn has ended, and a solved check expires in about
two minutes. So with the link the agent gets a `wake` command (`verification.wake`,
`"<phantab>" check-wait <token>`): it starts it as a background command before it ends its turn, the
command exits the moment the check ends, and the agent's harness wakes the agent to carry on. The wake token only reads the check's state; it opens no view (THREAT-MODEL SR-72).

## Setup (Tailscale)
1. Add to `%LOCALAPPDATA%\phantab\config.json` (on a Mac,
   `~/Library/Application Support/phantab/config.json`):
   ```json
   "remoteViewer": {
     "listen": "127.0.0.1:8491",
     "publicBaseUrl": "http://mypc:8490",
     "trustedIdentity": { "header": "Tailscale-User-Login", "equals": "<owner's tailnet login>" }
   }
   ```
   `publicBaseUrl` is the address the owner's devices use, with no path. Use the short MagicDNS name
   *or* the full `*.ts.net` name, not both: the `Host` check is exact, and Tailscale Serve forwards the
   `Host` the device sent.
2. Forward the tailnet port to the listener:
   `tailscale serve --bg --http=8490 http://127.0.0.1:8491`
3. Restart the service: stop the `phantab` service process, once its pages are drained (never close
   Chrome). The next call from an agent client starts it again. Restarting the clients alone is not
   enough: the service keeps running after they close.
4. Check: the MCP `browser_status` result has `remoteViewer: {listening: true, url, identityChecked:
   true}`. A bad config shows `listening: false` with the reason, and the rest of Phantab runs as usual.
5. From a device on the tailnet, `http://mypc:8490/view` shows "Nothing is waiting for you."

## Identity header
Tailscale Serve sets `Tailscale-User-Login` for a request from a tailnet user. Before trusting it, check
that Serve replaces a header the device itself sends: from another device,
`curl -H "Tailscale-User-Login: someone@example.test" http://mypc:8490/view` must still answer 200
(Serve put the real login in). A 403 means Serve passed the forged one through; then rely on the tailnet's
own access rules instead.

## Turning it off
Remove `remoteViewer` from the config and run `tailscale serve --http=8490 off`.
