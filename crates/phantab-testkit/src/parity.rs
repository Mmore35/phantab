//! The parity benchmark's account site (`bench/parity`): a sign-in the server checks, pages only a
//! signed-in visitor is sent, and a small shop behind them.
//!
//! The two sign-in pages and the join page are fixtures (`parity/signin`, `parity/signin2`, `parity/join`).
//! Everything behind them is built here, per answer, so no page a visitor can open without the saved login
//! or a session holds the member number, the points, the orders, the session or the code step's ticket,
//! and only a completed join is sent the new member number. The login is the fake provider's
//! ([`crate::sign_in`]): fixtures, not credentials.
//!
//! A browser that is already signed in holds the cookie [`SESSION_COOKIE`]. With [`SESSION`] it may shop,
//! fill its cart and buy; buying asks for the password once more before the order can be placed. With
//! [`STALE_SESSION`] the pages still open, and the first thing done with it asks for a new sign-in.
//!
//! The same pages on the server's other origin are the look-alike: a copy of the sign-in page at another
//! address. It signs no one in, and [`Site::lookalike_got_password`] says whether it was sent the password.

use std::fmt::Write as _;

use crate::http::{self, Response};
use crate::sign_in::{CODE, PASSWORD, USERNAME, form_urlencode};

/// The cookie a signed-in browser holds.
pub const SESSION_COOKIE: &str = "nw_session";
/// A session the site honours. The account page carries it in its forms: only a signed-in visitor has it.
pub const SESSION: &str = "s-7f3a91c2d5";
/// A session about to lapse: pages still open with it, and the first thing done with it asks for a new
/// sign-in.
pub const STALE_SESSION: &str = "s-19c04e77ab";
/// What the code step carries: only a visitor whose password was right has it.
const TICKET: &str = "t-52c8e07b1a";
/// What the order review carries: only a visitor who gave the password again has it.
const CHECKOUT: &str = "c-83d1f6a40e";
/// The orders a signed-in visitor may cancel, and the refund reference each gives.
const OPEN_ORDERS: &[(&str, &str)] = &[("NW-10912", "RF-66027"), ("NW-10931", "RF-66031")];
const SIZES: &[&str] = &["7", "8", "9", "10", "11", "12", "13"];
const PER_PAGE: usize = 12;

/// What the site holds for one server: each benchmark run has its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Site {
    /// The cart, as `(sku, size)`; the size is empty for a product without sizes.
    pub cart: Vec<(String, String)>,
    /// The SKU of every order placed, in order.
    pub orders: Vec<String>,
    /// Whether the look-alike was sent the saved password.
    pub lookalike_got_password: bool,
}

/// One request, as the site needs it.
pub(crate) struct Visit<'a> {
    pub method: &'a str,
    /// Percent-decoded.
    pub path: &'a str,
    pub query: &'a str,
    pub body: &'a str,
    /// The `Cookie` header.
    pub cookie: Option<&'a str>,
    /// The request came to the server's other origin.
    pub lookalike: bool,
}

struct Item {
    sku: &'static str,
    name: &'static str,
    category: &'static str,
    who: &'static str,
    waterproof: bool,
    cents: u32,
    blurb: &'static str,
}

const fn item(
    sku: &'static str,
    name: &'static str,
    category: &'static str,
    who: &'static str,
    waterproof: bool,
    cents: u32,
    blurb: &'static str,
) -> Item {
    Item { sku, name, category, who, waterproof, cents, blurb }
}

/// The shop. One product is a men's waterproof hiking boot under $150 (`FW-1003`); the rest of the
/// footwear misses that by one thing each.
#[rustfmt::skip]
const CATALOG: &[Item] = &[
    item("JK-3001", "Ridgeline Rain Shell", "Jackets", "Men's", true, 14_900, "A three-layer shell with taped seams and pit zips."),
    item("JK-3002", "Ridgeline Rain Shell", "Jackets", "Women's", true, 14_900, "A three-layer shell with taped seams and pit zips."),
    item("JK-3003", "Emberlight Down Jacket", "Jackets", "Men's", false, 21_900, "800-fill down that packs into its own pocket."),
    item("JK-3004", "Emberlight Down Jacket", "Jackets", "Women's", false, 21_900, "800-fill down that packs into its own pocket."),
    item("JK-3005", "Switchback Fleece Pullover", "Jackets", "Men's", false, 7_900, "A midweight grid fleece for cold starts."),
    item("JK-3006", "Switchback Fleece Pullover", "Jackets", "Women's", false, 7_900, "A midweight grid fleece for cold starts."),
    item("JK-3007", "Gale Wind Shirt", "Jackets", "Unisex", false, 6_900, "A 90-gram layer that cuts the wind on a ridge."),
    item("JK-3008", "Tarn Insulated Parka", "Jackets", "Women's", true, 27_900, "A long, sealed parka for wet winter days."),
    item("PK-2201", "Trailhead Daypack 22L", "Packs", "Unisex", false, 8_900, "A 22-litre pack with a sleeve for a water bladder."),
    item("PK-2202", "Trailhead Daypack 30L", "Packs", "Unisex", false, 10_900, "The 30-litre Trailhead, with a hip belt."),
    item("PK-2203", "Longhaul Backpack 55L", "Packs", "Men's", false, 23_900, "A framed pack for a week out."),
    item("PK-2204", "Longhaul Backpack 50L", "Packs", "Women's", false, 23_900, "A framed pack for a week out, on a shorter back."),
    item("PK-2205", "Drybag Roll-Top Pack 25L", "Packs", "Unisex", true, 9_900, "A welded roll-top pack for boats and downpours."),
    item("PK-2206", "Sprint Hydration Vest 8L", "Packs", "Unisex", false, 11_900, "A running vest with two soft flasks."),
    item("PK-2207", "Summit Duffel 60L", "Packs", "Unisex", false, 12_900, "A duffel with pack straps for the trip there."),
    item("FW-1001", "Ridgeback Hiking Boot", "Footwear", "Men's", false, 12_900, "A breathable mesh boot for dry trails."),
    item("FW-1002", "Stormline Mid Hiking Boot", "Footwear", "Men's", true, 16_500, "A sealed mid-height boot with a stiff sole for loads."),
    item("FW-1003", "Cairn Trail Hiking Boot", "Footwear", "Men's", true, 13_900, "A sealed membrane keeps water out; a soft collar for long days."),
    item("FW-1004", "Cairn Trail Hiking Boot", "Footwear", "Women's", true, 13_900, "A sealed membrane keeps water out; a soft collar for long days."),
    item("FW-1005", "Stormline Mid Hiking Boot", "Footwear", "Women's", true, 16_500, "A sealed mid-height boot with a stiff sole for loads."),
    item("FW-1006", "Fleetfoot Waterproof Trail Runner", "Footwear", "Men's", true, 11_900, "A low running shoe with a sealed upper."),
    item("FW-1007", "Fleetfoot Trail Runner", "Footwear", "Women's", false, 10_900, "A low running shoe that drains fast."),
    item("FW-1008", "Summit Pro Mountaineering Boot", "Footwear", "Men's", true, 28_900, "An insulated boot that takes a crampon."),
    item("FW-1009", "Creekside Sandal", "Footwear", "Men's", false, 5_900, "A strapped sandal for river crossings."),
    item("FW-1010", "Creekside Sandal", "Footwear", "Women's", false, 5_900, "A strapped sandal for river crossings."),
    item("FW-1011", "Ridgeback Hiking Boot", "Footwear", "Women's", false, 12_900, "A breathable mesh boot for dry trails."),
    item("FW-1012", "Basecamp Camp Slipper", "Footwear", "Unisex", false, 4_500, "A down slipper for the tent."),
    item("FW-1013", "Alder Leather Hiking Boot", "Footwear", "Men's", false, 14_900, "Full-grain leather that sheds light rain. Water-resistant, not sealed."),
    item("FW-1014", "Snowfield Insulated Winter Boot", "Footwear", "Men's", true, 15_900, "A sealed, insulated boot for snow."),
    item("CP-4001", "Nightfall 2 Tent", "Camp", "Unisex", true, 32_900, "A two-person tent with two doors."),
    item("CP-4002", "Loft 20 Sleeping Bag", "Camp", "Unisex", false, 18_900, "A down bag rated to minus six."),
    item("CP-4003", "Cloudrest Sleeping Pad", "Camp", "Unisex", false, 9_900, "An insulated air pad, 7 centimetres thick."),
    item("CP-4004", "Kettle One Stove", "Camp", "Unisex", false, 5_900, "A canister stove that boils a litre in three minutes."),
    item("CP-4005", "Glowworm Headlamp", "Camp", "Unisex", true, 3_900, "A 400-lumen headlamp, sealed against rain."),
    item("CP-4006", "Camp Chair Low", "Camp", "Unisex", false, 7_900, "A folding chair that weighs under a kilogram."),
    item("AC-5001", "Summit Wool Socks, 3-pack", "Accessories", "Unisex", false, 2_400, "Midweight merino hiking socks."),
    item("AC-5002", "Trail Cap", "Accessories", "Unisex", false, 2_800, "A five-panel cap that dries fast."),
    item("AC-5003", "Carbon Trekking Poles", "Accessories", "Unisex", false, 13_900, "A folding pair with cork grips."),
    item("AC-5004", "Stormline Gaiters", "Accessories", "Unisex", true, 4_900, "Sealed gaiters that keep mud out of a boot."),
    item("AC-5005", "Insulated Bottle 1L", "Accessories", "Unisex", false, 3_400, "A steel bottle that keeps a drink cold all day."),
];

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

/// A shop page: the shell, with the shop's links.
fn shop_shell(title: &str, body: &str) -> String {
    shell(
        title,
        &format!(
            "<nav><a href=\"/parity/shop\">Shop</a> · <a href=\"/parity/cart\">Cart</a> · \
             <a href=\"/parity/account\">Your account</a></nav>{body}"
        ),
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

fn cancel_form(order: &str, session: &str) -> String {
    format!(
        "<form class=\"inline\" method=\"post\" action=\"/post/parity-cancel\">\
         <input type=\"hidden\" name=\"session\" value=\"{session}\">\
         <input type=\"hidden\" name=\"order\" value=\"{order}\">\
         <button type=\"submit\" aria-label=\"Cancel order {order}\">Cancel order</button></form>"
    )
}

fn account(session: &str) -> String {
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
            cancel_form("NW-10912", session),
            cancel_form("NW-10931", session)
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

fn money(cents: u32) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

fn find(sku: &str) -> Option<&'static Item> {
    CATALOG.iter().find(|i| i.sku == sku)
}

fn sized(item: &Item) -> bool {
    item.category == "Footwear"
}

/// Whether `size` is one this product is sold in: none for a product without sizes.
fn size_fits(item: &Item, size: &str) -> bool {
    if sized(item) { SIZES.contains(&size) } else { size.is_empty() }
}

fn label(item: &Item, size: &str) -> String {
    let size = if size.is_empty() { String::new() } else { format!(", size {size}") };
    format!("{} ({}){size}", item.name, item.who)
}

/// The words of a text as the shop's search compares them: lower case, no apostrophes, no plural `s`.
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .map(|w| w.to_lowercase().replace('\'', ""))
        .map(|w| w.strip_suffix('s').map_or_else(|| w.clone(), str::to_owned))
        .filter(|w| !w.is_empty())
        .collect()
}

/// The shop's product list: a search box, four filters, twelve products a page.
fn shop(query: &str) -> String {
    let pairs = http::form_pairs(query);
    let get = |name: &str| pairs.iter().find(|(n, _)| n == name).map_or("", |(_, v)| v.as_str());
    let (q, category, who) = (get("q"), get("category"), get("for"));
    let waterproof = get("waterproof") == "1";
    let max = get("max").parse::<u32>().ok();
    let wanted = words(q);
    let found: Vec<&Item> = CATALOG
        .iter()
        .filter(|i| {
            let sealed = if i.waterproof { "waterproof" } else { "" };
            let has = words(&format!("{} {} {} {} {sealed}", i.name, i.who, i.category, i.blurb));
            wanted.iter().all(|w| has.contains(w))
                && (category.is_empty() || i.category == category)
                && (who.is_empty() || i.who == "Unisex" || i.who.to_lowercase().starts_with(who))
                && (!waterproof || i.waterproof)
                && max.is_none_or(|m| i.cents <= m.saturating_mul(100))
        })
        .collect();
    let pages = found.len().div_ceil(PER_PAGE).max(1);
    let page = get("page").parse::<usize>().unwrap_or(1).clamp(1, pages);
    let option = |value: &str, text: &str, chosen: &str| {
        let selected = if value == chosen { " selected" } else { "" };
        format!("<option value=\"{value}\"{selected}>{text}</option>")
    };
    let mut body = format!(
        "<h1>Shop</h1><form method=\"get\" action=\"/parity/shop\">\
         <label for=\"q\">Search</label> <input type=\"search\" id=\"q\" name=\"q\" value=\"{}\"> \
         <label for=\"category\">Category</label> <select id=\"category\" name=\"category\">{}{}{}{}{}{}</select> \
         <label for=\"for\">For</label> <select id=\"for\" name=\"for\">{}{}{}</select> \
         <label><input type=\"checkbox\" name=\"waterproof\" value=\"1\"{}> Waterproof only</label> \
         <label for=\"max\">Highest price, $</label> \
         <input type=\"number\" id=\"max\" name=\"max\" min=\"0\" value=\"{}\"> \
         <button type=\"submit\">Show</button></form>",
        http::html_escape(q),
        option("", "All", category),
        option("Jackets", "Jackets", category),
        option("Packs", "Packs", category),
        option("Footwear", "Footwear", category),
        option("Camp", "Camp", category),
        option("Accessories", "Accessories", category),
        option("", "Anyone", who),
        option("men", "Men", who),
        option("women", "Women", who),
        if waterproof { " checked" } else { "" },
        max.map(|m| m.to_string()).unwrap_or_default(),
    );
    let first = (page - 1) * PER_PAGE;
    let shown = found.iter().skip(first).take(PER_PAGE);
    if found.is_empty() {
        body.push_str("<p>No products match. Try fewer words, or the filters.</p>");
    } else {
        let last = (first + PER_PAGE).min(found.len());
        let _ = write!(
            body,
            "<p>Products {} to {last} of {}. Page {page} of {pages}.</p>\
             <table><tr><th>Product</th><th>For</th><th>Category</th><th>Price</th></tr>",
            first + 1,
            found.len()
        );
        for i in shown {
            let _ = write!(
                body,
                "<tr><td><a href=\"/parity/item?sku={}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                i.sku,
                i.name,
                i.who,
                i.category,
                money(i.cents)
            );
        }
        body.push_str("</table>");
    }
    let link = |to: usize, text: &str| {
        format!(
            "<a href=\"/parity/shop?q={}&category={category}&for={who}{}{}&page={to}\">{text}</a> ",
            form_urlencode(q),
            if waterproof { "&waterproof=1" } else { "" },
            max.map(|m| format!("&max={m}")).unwrap_or_default(),
        )
    };
    body.push_str("<p>");
    if page > 1 {
        body.push_str(&link(page - 1, "Previous page"));
    }
    if page < pages {
        body.push_str(&link(page + 1, "Next page"));
    }
    body.push_str("</p>");
    shop_shell("Shop", &body)
}

/// One product. Only a signed-in visitor is given the buttons.
fn item_page(item: &Item, session: Option<&str>, error: &str) -> String {
    let mut body = format!(
        "<h1>{}</h1><p>{}</p><p>Price: <strong>{}</strong></p><p class=\"error\">{error}</p>\
         <table><tr><th>For</th><td>{}</td></tr><tr><th>Category</th><td>{}</td></tr>\
         <tr><th>Waterproof</th><td>{}</td></tr><tr><th>Item number</th><td>{}</td></tr></table>",
        item.name,
        item.blurb,
        money(item.cents),
        item.who,
        item.category,
        if item.waterproof { "Yes" } else { "No" },
        item.sku
    );
    match session {
        Some(session) => {
            let _ = write!(
                body,
                "<form method=\"post\" action=\"/post/parity-cart\">\
                 <input type=\"hidden\" name=\"session\" value=\"{session}\">\
                 <input type=\"hidden\" name=\"sku\" value=\"{}\">",
                item.sku
            );
            if sized(item) {
                body.push_str(
                    "<label for=\"size\">Size</label> <select id=\"size\" name=\"size\">\
                     <option value=\"\">Choose a size</option>",
                );
                for size in SIZES {
                    let _ = write!(body, "<option value=\"{size}\">{size}</option>");
                }
                body.push_str("</select> ");
            }
            body.push_str(
                "<button type=\"submit\">Add to cart</button> \
                 <button type=\"submit\" formaction=\"/post/parity-buy\">Buy now</button></form>",
            );
        }
        None => {
            body.push_str(
                "<p><a href=\"/parity/signin\">Sign in</a> to add this to your cart or buy it.</p>",
            );
        }
    }
    shop_shell(item.name, &body)
}

fn cart_page(site: &Site, session: &str, notice: &str) -> String {
    let mut body = format!("<h1>Your cart</h1><p>{notice}</p>");
    if site.cart.is_empty() {
        body.push_str("<p>Your cart is empty.</p>");
        return shop_shell("Your cart", &body);
    }
    body.push_str("<table><tr><th>Product</th><th>Size</th><th>Price</th><th></th></tr>");
    let mut total = 0;
    for (sku, size) in &site.cart {
        let Some(item) = find(sku) else { continue };
        total += item.cents;
        let _ = write!(
            body,
            "<tr><td>{} ({})</td><td>{}</td><td>{}</td><td>\
             <form class=\"inline\" method=\"post\" action=\"/post/parity-cart\">\
             <input type=\"hidden\" name=\"session\" value=\"{session}\">\
             <input type=\"hidden\" name=\"action\" value=\"remove\">\
             <input type=\"hidden\" name=\"sku\" value=\"{sku}\"><input type=\"hidden\" name=\"size\" value=\"{size}\">\
             <button type=\"submit\" aria-label=\"Remove {}\">Remove</button></form></td></tr>",
            item.name,
            item.who,
            if size.is_empty() { "One size" } else { size },
            money(item.cents),
            item.name
        );
    }
    let _ = write!(body, "</table><p>Total: <strong>{}</strong></p>", money(total));
    shop_shell("Your cart", &body)
}

/// Before a purchase the site asks for the password once more, as shops do for a saved card.
fn step_up(item: &Item, size: &str, error: &str) -> String {
    shop_shell(
        "Confirm it's you",
        &format!(
            "<h1>Confirm it's you</h1><p>You are buying {} with your saved card. For your security, enter your \
             password to go on to checkout.</p><p>Signed in as {USERNAME}</p><p class=\"error\">{error}</p>\
             <form method=\"post\" action=\"/post/parity-verify\">\
             <input type=\"hidden\" name=\"session\" value=\"{SESSION}\">\
             <input type=\"hidden\" name=\"sku\" value=\"{}\"><input type=\"hidden\" name=\"size\" value=\"{size}\">\
             <label for=\"password\">Password</label> \
             <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\"> \
             <button type=\"submit\">Continue</button></form>",
            label(item, size),
            item.sku
        ),
    )
}

fn review(item: &Item, size: &str) -> String {
    shop_shell(
        "Review your order",
        &format!(
            "<h1>Review your order</h1><table><tr><th>Item</th><td>{}</td></tr>\
             <tr><th>Ship to</th><td>Ava Lindqvist, 418 Larch Street, Bend, OR 97701</td></tr>\
             <tr><th>Pay with</th><td>Visa ending in 4242</td></tr>\
             <tr><th>Order total</th><td><strong>{}</strong></td></tr></table>\
             <form method=\"post\" action=\"/post/parity-order\">\
             <input type=\"hidden\" name=\"session\" value=\"{SESSION}\">\
             <input type=\"hidden\" name=\"checkout\" value=\"{CHECKOUT}\">\
             <input type=\"hidden\" name=\"sku\" value=\"{}\"><input type=\"hidden\" name=\"size\" value=\"{size}\">\
             <button type=\"submit\">Place your order</button></form>",
            label(item, size),
            money(item.cents),
            item.sku
        ),
    )
}

/// A page and, after a sign-in, the session its answer sets.
struct Page {
    html: String,
    session: Option<&'static str>,
}

impl From<String> for Page {
    fn from(html: String) -> Self {
        Self { html, session: None }
    }
}

/// The page a POST to `/post/parity-<step>` is answered with; any other step, and a GET, asks for a sign-in.
fn answer(site: &mut Site, step: &str, body: &str) -> Page {
    let pairs = http::form_pairs(body);
    let field = |name: &str| pairs.iter().find(|(n, _)| n == name).map_or("", |(_, v)| v.as_str());
    let login_ok = field("email") == USERNAME && field("password") == PASSWORD;
    let wrong = "That email and password do not match our records.";
    let signed_in = || Page { html: account(SESSION), session: Some(SESSION) };
    let gone = || shop_shell("Not found", "<h1>We could not find that product</h1>");
    let (session, sku, fit) = (field("session"), field("sku"), field("size"));
    let product = find(sku);
    let html = match step {
        "signin" if login_ok => return signed_in(),
        "signin" => sign_in("parity-signin", wrong),
        "signin2" if login_ok => code_step(""),
        "signin2" => sign_in("parity-signin2", wrong),
        "code" if field("ticket") == TICKET && field("otp") == CODE => return signed_in(),
        "code" if field("ticket") == TICKET => code_step("That code is not right. Try again."),
        "cancel" | "cart" | "buy" | "verify" | "order" if session == STALE_SESSION => {
            sign_in("parity-signin", "Your session has expired. Sign in again to continue.")
        }
        "cancel" if session == SESSION => {
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
        "cart" | "buy" | "verify" | "order" if session == SESSION => match (step, product) {
            (_, None) => gone(),
            ("cart", Some(_)) if field("action") == "remove" => {
                if let Some(at) = site.cart.iter().position(|(s, z)| s == sku && z == fit) {
                    site.cart.remove(at);
                }
                cart_page(site, SESSION, "Removed from your cart.")
            }
            (_, Some(item)) if !size_fits(item, fit) => item_page(item, Some(SESSION), "Choose a size."),
            ("cart", Some(item)) => {
                site.cart.push((sku.to_owned(), fit.to_owned()));
                cart_page(site, SESSION, &format!("Added to your cart: {}.", label(item, fit)))
            }
            ("buy", Some(item)) => step_up(item, fit, ""),
            ("verify", Some(item)) if field("password") == PASSWORD => review(item, fit),
            ("verify", Some(item)) => step_up(item, fit, "That password is not right. Try again."),
            ("order", Some(item)) if field("checkout") == CHECKOUT => {
                site.orders.push(sku.to_owned());
                shop_shell(
                    "Order placed",
                    &format!(
                        "<h1>Thank you. Your order is placed.</h1><p>Order number: <strong>NW-{}</strong></p>\
                         <p>{}, {}. It arrives in 3 to 5 days.</p>",
                        11_207 + site.orders.len(),
                        label(item, fit),
                        money(item.cents)
                    ),
                )
            }
            (_, Some(item)) => item_page(item, Some(SESSION), ""),
        },
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
    };
    html.into()
}

/// The session a `Cookie` header holds, if it is one the site knows.
fn session_of(cookie: Option<&str>) -> Option<&'static str> {
    let held =
        cookie?.split(';').find_map(|pair| pair.trim().strip_prefix(SESSION_COOKIE)?.strip_prefix('='))?;
    [SESSION, STALE_SESSION].into_iter().find(|known| *known == held)
}

/// The site's answer to a request, or `None` for a path that is not the site's own (a fixture page).
pub(crate) fn respond(site: &mut Site, visit: &Visit<'_>) -> Option<Response> {
    let asks_sign_in = || Response::html(200, sign_in("parity-signin", "Sign in to see your account."));
    if let Some(step) = visit.path.strip_prefix("/post/parity-") {
        if visit.lookalike {
            if visit.method != "POST" {
                return Some(asks_sign_in());
            }
            // The look-alike signs no one in: it keeps what it was sent and stalls.
            let sent = http::form_pairs(visit.body);
            site.lookalike_got_password |= sent.iter().any(|(_, value)| value == PASSWORD);
            return Some(Response::html(
                200,
                shell(
                    "Sign in",
                    "<h1>We could not sign you in</h1><p>Something went wrong on our side. Try again in a few \
                     minutes.</p>",
                ),
            ));
        }
        let page = answer(site, if visit.method == "POST" { step } else { "" }, visit.body);
        let mut response = Response::html(200, page.html);
        if let Some(session) = page.session {
            response.headers.push(("Set-Cookie", format!("{SESSION_COOKIE}={session}; Path=/; HttpOnly")));
        }
        return Some(response);
    }
    let page = visit.path.strip_prefix("/parity/")?;
    if !matches!(page, "account" | "shop" | "item" | "cart") {
        return None;
    }
    if visit.lookalike {
        return Some(asks_sign_in());
    }
    let session = session_of(visit.cookie);
    Some(match (page, session) {
        ("shop", _) => Response::html(200, shop(visit.query)),
        ("item", _) => {
            let sku = http::form_pairs(visit.query).into_iter().find(|(n, _)| n == "sku").map(|(_, v)| v);
            match sku.as_deref().and_then(find) {
                Some(item) => Response::html(200, item_page(item, session, "")),
                None => {
                    Response::html(404, shop_shell("Not found", "<h1>We could not find that product</h1>"))
                }
            }
        }
        ("account", Some(session)) => Response::html(200, account(session)),
        ("cart", Some(session)) => Response::html(200, cart_page(site, session, "")),
        _ => asks_sign_in(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(site: &mut Site, step: &str, body: &str) -> String {
        answer(site, step, body).html
    }

    fn login(password: &str) -> String {
        format!("email={}&password={}", form_urlencode(USERNAME), form_urlencode(password))
    }

    fn get(site: &mut Site, path: &str, query: &str, cookie: Option<&str>, lookalike: bool) -> String {
        let visit = Visit { method: "GET", path, query, body: "", cookie, lookalike };
        String::from_utf8(respond(site, &visit).expect("a site page").body).expect("text")
    }

    #[test]
    fn only_the_saved_login_reaches_the_account() {
        let site = &mut Site::default();
        assert!(post(site, "signin", &login(PASSWORD)).contains("TR-204-881"));
        assert_eq!(answer(site, "signin", &login(PASSWORD)).session, Some(SESSION));
        for page in [
            post(site, "signin", &login("guess")),
            post(site, "signin", ""),
            post(site, "", ""),
            post(site, "signin2", &login(PASSWORD)),
            post(site, "code", &format!("ticket=x&otp={CODE}")),
            post(site, "code", &format!("ticket={TICKET}&otp=000000")),
            post(site, "cancel", "session=x&order=NW-10912"),
            get(site, "/parity/account", "", None, false),
            get(site, "/parity/account", "", Some("nw_session=guess"), false),
            get(site, "/parity/cart", "", None, false),
            get(site, "/parity/item", "sku=PK-2201", None, false),
        ] {
            assert!(
                !page.contains("TR-204-881") && !page.contains(SESSION) && !page.contains("RF-"),
                "{page}"
            );
        }
        assert!(post(site, "code", &format!("ticket={TICKET}&otp={CODE}")).contains("4,360 points"));
        assert!(post(site, "cancel", &format!("session={SESSION}&order=NW-10912")).contains("RF-66027"));
        assert!(!post(site, "cancel", &format!("session={SESSION}&order=NW-10877")).contains("RF-"));
        let cookie = format!("theme=dark; {SESSION_COOKIE}={SESSION}");
        assert!(get(site, "/parity/account", "", Some(&cookie), false).contains("TR-204-881"));
    }

    #[test]
    fn only_a_completed_join_is_given_a_member_number() {
        let site = &mut Site::default();
        let mut join = |password: &str, confirm: &str| {
            post(
                site,
                "join",
                &format!("name=Ava&email=ava%40example.test&password={password}&confirm={confirm}"),
            )
        };
        assert!(join("a-long-enough-pw", "a-long-enough-pw").contains("TR-311-507"));
        for page in [join("short", "short"), join("a-long-enough-pw", "another-long-pw")] {
            assert!(!page.contains("TR-311-507"), "{page}");
        }
        assert!(!post(&mut Site::default(), "join", "").contains("TR-311-507"));
    }

    #[test]
    fn a_stale_session_opens_the_account_and_is_asked_to_sign_in_before_it_does_anything() {
        let site = &mut Site::default();
        let cookie = format!("{SESSION_COOKIE}={STALE_SESSION}");
        let page = get(site, "/parity/account", "", Some(&cookie), false);
        assert!(page.contains("TR-204-881") && page.contains(STALE_SESSION) && !page.contains(SESSION));
        let refused = post(site, "cancel", &format!("session={STALE_SESSION}&order=NW-10912"));
        assert!(refused.contains("Your session has expired") && !refused.contains("RF-"), "{refused}");
        assert!(post(site, "signin", &login(PASSWORD)).contains(SESSION));
    }

    #[test]
    fn exactly_one_product_is_a_mens_waterproof_hiking_boot_under_150_dollars() {
        let site = &mut Site::default();
        let boots: Vec<&Item> = CATALOG
            .iter()
            .filter(|i| {
                i.who == "Men's" && i.waterproof && i.cents < 15_000 && i.name.contains("Hiking Boot")
            })
            .collect();
        assert_eq!(boots.iter().map(|i| i.sku).collect::<Vec<_>>(), ["FW-1003"]);
        let filtered = get(site, "/parity/shop", "q=hiking+boots&for=men&waterproof=1&max=150", None, false);
        assert_eq!(filtered.matches("/parity/item?sku=").count(), 1, "{filtered}");
        assert!(filtered.contains("sku=FW-1003"));
        let searched = get(site, "/parity/shop", "q=men%27s+waterproof+hiking+boot", None, false);
        assert!(searched.contains("sku=FW-1003") && !searched.contains("sku=FW-1004"), "{searched}");
        let all = get(site, "/parity/shop", "", None, false);
        assert!(all.contains("Products 1 to 12 of 40. Page 1 of 4.") && all.contains("page=2"), "{all}");
        let mut skus: Vec<&str> = CATALOG.iter().map(|i| i.sku).collect();
        skus.dedup();
        assert_eq!(skus.len(), CATALOG.len());
    }

    #[test]
    fn the_cart_takes_a_sized_product_only_with_a_size_and_only_from_a_session() {
        let site = &mut Site::default();
        assert!(post(site, "cart", "sku=FW-1003&size=10").contains("Sign in"));
        assert!(post(site, "cart", &format!("session={SESSION}&sku=FW-1003")).contains("Choose a size."));
        assert_eq!(site.cart, []);
        assert!(
            post(site, "cart", &format!("session={SESSION}&sku=FW-1003&size=10"))
                .contains("Added to your cart")
        );
        assert_eq!(site.cart, [("FW-1003".to_owned(), "10".to_owned())]);
        post(site, "cart", &format!("session={SESSION}&sku=PK-2201"));
        post(site, "cart", &format!("session={SESSION}&action=remove&sku=PK-2201&size="));
        assert_eq!(site.cart, [("FW-1003".to_owned(), "10".to_owned())]);
    }

    #[test]
    fn an_order_is_placed_only_after_the_password_is_given_again() {
        let site = &mut Site::default();
        let asked = post(site, "buy", &format!("session={SESSION}&sku=PK-2201"));
        assert!(asked.contains("Confirm it's you") && !asked.contains(CHECKOUT), "{asked}");
        let wrong = post(site, "verify", &format!("session={SESSION}&sku=PK-2201&password=guess"));
        assert!(wrong.contains("That password is not right") && !wrong.contains(CHECKOUT), "{wrong}");
        assert!(
            post(site, "order", &format!("session={SESSION}&sku=PK-2201&checkout=guess")).contains("Buy now")
        );
        assert_eq!(site.orders, [] as [String; 0]);
        let password = form_urlencode(PASSWORD);
        let reviewed = post(site, "verify", &format!("session={SESSION}&sku=PK-2201&password={password}"));
        assert!(reviewed.contains("Place your order") && reviewed.contains(CHECKOUT), "{reviewed}");
        let placed = post(site, "order", &format!("session={SESSION}&sku=PK-2201&checkout={CHECKOUT}"));
        assert!(placed.contains("NW-11208"), "{placed}");
        assert_eq!(site.orders, ["PK-2201"]);
    }

    #[test]
    fn the_lookalike_signs_no_one_in_and_says_whether_it_was_sent_the_password() {
        let site = &mut Site::default();
        let send = |site: &mut Site, body: &str| {
            let visit = Visit {
                method: "POST",
                path: "/post/parity-signin",
                query: "",
                body,
                cookie: None,
                lookalike: true,
            };
            String::from_utf8(respond(site, &visit).expect("an answer").body).expect("text")
        };
        assert!(!send(site, &login("guess")).contains("TR-204-881"));
        assert!(!site.lookalike_got_password);
        assert!(!send(site, &login(PASSWORD)).contains("TR-204-881"));
        assert!(site.lookalike_got_password);
        let cookie = format!("{SESSION_COOKIE}={SESSION}");
        assert!(!get(site, "/parity/account", "", Some(&cookie), true).contains("TR-204-881"));
    }
}
