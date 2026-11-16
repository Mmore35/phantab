//! The parity benchmark's account site (`bench/parity`): a sign-in the server checks, and pages only a
//! signed-in visitor is sent.
//!
//! The two sign-in pages and the join page are fixtures (`parity/signin`, `parity/signin2`, `parity/join`).
//! Everything behind them is built here, per answer, so no page a visitor can open without the saved login
//! holds the member number, the points, the orders, the session or the code step's ticket, and only a
//! completed join is sent the new member number. The login is the fake provider's
//! ([`crate::sign_in`]): fixtures, not credentials.

use crate::http;
use crate::sign_in::{CODE, PASSWORD, USERNAME};

/// What the account page carries in its cancel forms: only a signed-in visitor has it.
const SESSION: &str = "s-7f3a91c2d5";
/// What the code step carries: only a visitor whose password was right has it.
const TICKET: &str = "t-52c8e07b1a";
/// The orders a signed-in visitor may cancel, and the refund reference each gives.
const OPEN_ORDERS: &[(&str, &str)] = &[("NW-10912", "RF-66027"), ("NW-10931", "RF-66031")];

const STYLE: &str = "<style>body{font-family:system-ui,sans-serif;margin:0;color:#222}\
header{background:#1d3b2a;color:#fff;padding:8px 16px}main{padding:24px 16px}\
table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:6px 10px;text-align:left}\
.error{color:#b00020}form.inline{display:inline}</style>";

fn shell(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title} · Northwind Outfitters</title>\
         {STYLE}</head><body><header><strong>Northwind Outfitters</strong></header><main>{body}</main></body></html>"
    )
}

fn sign_in(action: &str, error: &str) -> String {
    shell(
        "Sign in",
        &format!(
            "<h1>Sign in to your account</h1><p class=\"error\">{error}</p>\
             <form method=\"post\" action=\"/post/{action}\">\
             <label for=\"email\">Email address</label> \
             <input type=\"email\" id=\"email\" name=\"email\" autocomplete=\"username\"> \
             <label for=\"password\">Password</label> \
             <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\"> \
             <button type=\"submit\">Sign in</button></form>"
        ),
    )
}

fn code_step(error: &str) -> String {
    shell(
        "Two-step verification",
        &format!(
            "<h1>Two-step verification</h1><p>Enter the 6-digit code from your authenticator app.</p>\
             <p class=\"error\">{error}</p><form method=\"post\" action=\"/post/parity-code\">\
             <input type=\"hidden\" name=\"ticket\" value=\"{TICKET}\">\
             <label for=\"otp\">Code</label> \
             <input id=\"otp\" name=\"otp\" autocomplete=\"one-time-code\" inputmode=\"numeric\"> \
             <button type=\"submit\">Verify</button></form>"
        ),
    )
}

fn cancel_form(order: &str) -> String {
    format!(
        "<form class=\"inline\" method=\"post\" action=\"/post/parity-cancel\">\
         <input type=\"hidden\" name=\"session\" value=\"{SESSION}\">\
         <input type=\"hidden\" name=\"order\" value=\"{order}\">\
         <button type=\"submit\" aria-label=\"Cancel order {order}\">Cancel order</button></form>"
    )
}

fn account() -> String {
    shell(
        "Your account",
        &format!(
            "<h1>Welcome back, Ava</h1>\
             <p>Member number: <strong>TR-204-881</strong></p>\
             <p>Trail Rewards balance: <strong>4,360 points</strong></p>\
             <h2>Your orders</h2><table>\
             <tr><th>Order</th><th>Placed</th><th>Item</th><th>Total</th><th>Status</th><th></th></tr>\
             <tr><td>NW-10877</td><td>2026-08-08</td><td>Ridgeline Rain Shell, M, Slate</td><td>$149.00</td>\
             <td>Delivered</td><td></td></tr>\
             <tr><td>NW-10912</td><td>2026-10-29</td><td>Trailhead Daypack 22L</td><td>$89.00</td>\
             <td>Processing</td><td>{}</td></tr>\
             <tr><td>NW-10931</td><td>2026-11-03</td><td>Summit Wool Socks, 3-pack</td><td>$24.00</td>\
             <td>Processing</td><td>{}</td></tr></table>",
            cancel_form("NW-10912"),
            cancel_form("NW-10931")
        ),
    )
}

/// The join page again, with what was wrong.
fn join(error: &str) -> String {
    shell(
        "Create an account",
        &format!(
            "<h1>Create your account</h1><p class=\"error\">{error}</p>             <form method=\"post\" action=\"/post/parity-join\">             <label for=\"name\">Full name</label>              <input type=\"text\" id=\"name\" name=\"name\" autocomplete=\"name\">              <label for=\"email\">Email address</label>              <input type=\"email\" id=\"email\" name=\"email\" autocomplete=\"username\">              <label for=\"password\">Password (12 characters or more)</label>              <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"new-password\">              <label for=\"confirm\">Confirm password</label>              <input type=\"password\" id=\"confirm\" name=\"confirm\" autocomplete=\"new-password\">              <button type=\"submit\">Create account</button></form>"
        ),
    )
}

/// The page a POST to `/post/parity-<step>` is answered with; any other step, and a GET, asks for a sign-in.
pub(crate) fn answer(step: &str, body: &str) -> String {
    let pairs = http::form_pairs(body);
    let field = |name: &str| pairs.iter().find(|(n, _)| n == name).map_or("", |(_, v)| v.as_str());
    let login_ok = field("email") == USERNAME && field("password") == PASSWORD;
    let wrong = "That email and password do not match our records.";
    match step {
        "signin" if login_ok => account(),
        "signin" => sign_in("parity-signin", wrong),
        "signin2" if login_ok => code_step(""),
        "signin2" => sign_in("parity-signin2", wrong),
        "code" if field("ticket") == TICKET && field("otp") == CODE => account(),
        "code" if field("ticket") == TICKET => code_step("That code is not right. Try again."),
        "cancel" if field("session") == SESSION => {
            match OPEN_ORDERS.iter().find(|(order, _)| *order == field("order")) {
                Some((order, refund)) => shell(
                    "Order cancelled",
                    &format!(
                        "<h1>Order {order} is cancelled</h1>\
                         <p>Refund reference: <strong>{refund}</strong>. The refund reaches your card in 3 to 5 days.</p>"
                    ),
                ),
                None => shell("Your account", "<h1>That order cannot be cancelled</h1>"),
            }
        }
        "join" if !field("email").contains('@') || field("name").is_empty() => {
            join("Enter your name and a valid email address.")
        }
        "join" if field("password").chars().count() < 12 => {
            join("Choose a password of 12 characters or more.")
        }
        "join" if field("password") != field("confirm") => join("The two passwords do not match."),
        "join" => shell(
            "Welcome",
            "<h1>Your account is ready</h1><p>Welcome to Trail Rewards. Your member number is              <strong>TR-311-507</strong>.</p><p>Use your email address and password to sign in next time.</p>",
        ),
        _ => sign_in("parity-signin", "Sign in to see your account."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(password: &str) -> String {
        use crate::sign_in::form_urlencode;
        format!("email={}&password={}", form_urlencode(USERNAME), form_urlencode(password))
    }

    #[test]
    fn only_the_saved_login_reaches_the_account() {
        assert!(answer("signin", &login(PASSWORD)).contains("TR-204-881"));
        for page in [
            answer("signin", &login("guess")),
            answer("signin", ""),
            answer("", ""),
            answer("signin2", &login(PASSWORD)),
            answer("code", &format!("ticket=x&otp={CODE}")),
            answer("code", &format!("ticket={TICKET}&otp=000000")),
            answer("cancel", "session=x&order=NW-10912"),
        ] {
            assert!(
                !page.contains("TR-204-881") && !page.contains(SESSION) && !page.contains("RF-"),
                "{page}"
            );
        }
        assert!(answer("code", &format!("ticket={TICKET}&otp={CODE}")).contains("4,360 points"));
        assert!(answer("cancel", &format!("session={SESSION}&order=NW-10912")).contains("RF-66027"));
        assert!(!answer("cancel", &format!("session={SESSION}&order=NW-10877")).contains("RF-"));
    }

    #[test]
    fn only_a_completed_join_is_given_a_member_number() {
        let join = |password: &str, confirm: &str| {
            answer(
                "join",
                &format!("name=Ava&email=ava%40example.test&password={password}&confirm={confirm}"),
            )
        };
        assert!(join("a-long-enough-pw", "a-long-enough-pw").contains("TR-311-507"));
        for page in [join("short", "short"), join("a-long-enough-pw", "another-long-pw"), answer("join", "")]
        {
            assert!(!page.contains("TR-311-507"), "{page}");
        }
    }
}
