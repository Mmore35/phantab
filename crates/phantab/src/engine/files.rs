//! Results saved as files: `screenshot` and `snapshot` with `path` (THREAT-MODEL SR-88). The service runs
//! as the user whose MCP client asks, so a file it writes is one that client could write itself. What is
//! refused: a path that is not absolute (it would land wherever the service was started), a folder that
//! does not exist, and an existing file unless `overwrite` is true.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use phantab_cdp::{BoundingBox, Page};
use serde_json::{Value, json};

use super::read::{Abort, poll_pictured};
use super::recover::Failed;
use crate::engine_api::{EngineError, EngineResult};
use crate::util::truthy;

/// The largest view `width` or `height` a screenshot emulates, in CSS pixels.
const MOST_PIXELS: u64 = 8192;

/// Where a result is saved: `path` and `overwrite`.
pub(crate) struct Target {
    path: PathBuf,
    overwrite: bool,
}

impl Target {
    /// `args`' `path`, checked: `None` without one.
    ///
    /// # Errors
    /// A `path` that is not a string, not absolute, a folder, in a folder that does not exist, or a file
    /// that exists while `overwrite` is not true.
    pub(crate) fn of(args: &Value) -> EngineResult<Option<Self>> {
        let Some(path) = args.get("path").filter(|v| !v.is_null()) else { return Ok(None) };
        let Some(path) = path.as_str().filter(|p| !p.is_empty()) else {
            return Err(EngineError("path: give a whole file path as a string.".to_owned()));
        };
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(EngineError(format!(
                "path: {} is not an absolute path. Give the whole path, from its drive or root.",
                path.display()
            )));
        }
        let overwrite = args.get("overwrite").is_some_and(truthy);
        let target = Self { path, overwrite };
        target.check()?;
        Ok(Some(target))
    }

    /// The checks [`Target::of`] makes, again before the write: the folder is there, and the file is
    /// not, unless it may be replaced.
    fn check(&self) -> EngineResult<()> {
        let parent = self.path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("/"));
        if !parent.is_dir() {
            return Err(EngineError(format!(
                "path: the folder {} does not exist. Make it first, or save somewhere else.",
                parent.display()
            )));
        }
        if self.path.is_dir() {
            return Err(EngineError(format!("path: {} is a folder, not a file.", self.path.display())));
        }
        if !self.overwrite && self.path.exists() {
            return Err(self.exists());
        }
        Ok(())
    }

    /// Where it is saved.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn exists(&self) -> EngineError {
        EngineError(format!(
            "path: {} already exists. Pass overwrite true to replace it, or give another name.",
            self.path.display()
        ))
    }

    /// Writes `bytes` there and answers `{path, bytes}`. Without `overwrite` the file is made new, so one
    /// that appeared since the check is still not replaced.
    ///
    /// # Errors
    /// As [`Target::of`], or the system's own error on the write.
    pub(crate) async fn write(self, bytes: Vec<u8>) -> EngineResult<serde_json::Map<String, Value>> {
        let len = bytes.len();
        let path = self.path.clone();
        let done = tokio::task::spawn_blocking(move || {
            self.check()?;
            let mut open = std::fs::OpenOptions::new();
            open.write(true);
            if self.overwrite {
                open.create(true).truncate(true);
            } else {
                open.create_new(true);
            }
            let mut file = open.open(&self.path).map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => self.exists(),
                _ => EngineError(format!("path: {} could not be written: {e}.", self.path.display())),
            })?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| EngineError(format!("path: {} could not be written: {e}.", self.path.display())))
        })
        .await
        .map_err(|e| EngineError(format!("path: the write did not finish: {e}.")))?;
        done?;
        let mut out = serde_json::Map::new();
        out.insert("path".into(), json!(path.display().to_string()));
        out.insert("bytes".into(), json!(len));
        Ok(out)
    }
}

/// What a screenshot takes: its format, and a full page, one element, or the view at a given size.
#[derive(Clone)]
pub(crate) struct Shot {
    pub(crate) png: bool,
    full_page: bool,
    selector: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
}

impl Shot {
    /// `args`' `format`, `fullPage`, `selector`, `width` and `height`. Without `format`, a `path` ending
    /// `.png` asks for a PNG; otherwise JPEG.
    ///
    /// # Errors
    /// An unknown format, `fullPage` with `selector`, or a size that is not a whole number from 1 to 8192.
    pub(crate) fn of(args: &Value) -> EngineResult<Self> {
        let png = match args.get("format").filter(|v| !v.is_null()) {
            None => args
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|p| Path::new(p).extension().is_some_and(|e| e.eq_ignore_ascii_case("png"))),
            Some(Value::String(f)) if f == "png" => true,
            Some(Value::String(f)) if f == "jpeg" => false,
            Some(other) => return Err(EngineError(format!("format: {other} is not png or jpeg."))),
        };
        let full_page = args.get("fullPage").is_some_and(truthy);
        let selector =
            args.get("selector").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
        if full_page && selector.is_some() {
            return Err(EngineError(
                "fullPage and selector: give one; a selector's picture is the element's own size.".to_owned(),
            ));
        }
        let size = |key: &str| -> EngineResult<Option<u32>> {
            match args.get(key).filter(|v| !v.is_null()) {
                None => Ok(None),
                Some(v) => v
                    .as_u64()
                    .filter(|n| (1..=MOST_PIXELS).contains(n))
                    .and_then(|n| u32::try_from(n).ok())
                    .map(Some)
                    .ok_or_else(|| {
                        EngineError(format!(
                            "{key}: {v} is not a whole number of CSS pixels from 1 to {MOST_PIXELS}."
                        ))
                    }),
            }
        };
        Ok(Self { png, full_page, selector, width: size("width")?, height: size("height")? })
    }

    /// Whether it changes the view's size.
    pub(crate) fn resizes(&self) -> bool {
        self.width.is_some() || self.height.is_some()
    }

    /// The arguments given that change the view for the picture, as a refusal names them: `fullPage`
    /// (Chrome stretches the view to the whole page while it captures), `selector` (the element is
    /// scrolled into view, and captured beyond it), `width` and `height` (the view is resized). `None`
    /// for the plain picture of the view, which changes nothing.
    pub(crate) fn moves_view(&self) -> Option<String> {
        let given = [
            ("fullPage", self.full_page),
            ("selector", self.selector.is_some()),
            ("width", self.width.is_some()),
            ("height", self.height.is_some()),
        ];
        let names: Vec<&str> = given.iter().filter(|(_, on)| *on).map(|(name, _)| *name).collect();
        match names.as_slice() {
            [] => None,
            [one] => Some((*one).to_owned()),
            [rest @ .., last] => Some(format!("{} and {last}", rest.join(", "))),
        }
    }

    pub(crate) fn mime(&self) -> &'static str {
        if self.png { "image/png" } else { "image/jpeg" }
    }

    /// Takes the picture, base64-encoded. A view size asked for is emulated first and the page's own put
    /// back afterwards, whether the picture was taken or not.
    pub(crate) async fn take(&self, page: &Page, signal: &Abort) -> Result<String, Failed> {
        let before = page.viewport();
        if self.resizes() {
            let usual = if let Some(size) = before {
                size
            } else {
                let v = page.visual_viewport().await.map_err(Failed::from)?;
                (round(v.width), round(v.height))
            };
            let size = (self.width.unwrap_or(usual.0), self.height.unwrap_or(usual.1));
            page.set_viewport(Some(size)).await.map_err(Failed::from)?;
        }
        let shot = self.picture(page, signal).await;
        if self.resizes()
            && let Err(e) = page.set_viewport(before).await
        {
            tracing::debug!(error = %e, "putting the view back after a screenshot failed");
        }
        shot
    }

    async fn picture(&self, page: &Page, signal: &Abort) -> Result<String, Failed> {
        let clip = if self.full_page {
            Some(page.full_page().await.map_err(Failed::from)?)
        } else if let Some(selector) = &self.selector {
            Some(element(page, selector, signal).await?)
        } else {
            None
        };
        if clip.is_none() && !self.png {
            return super::read::capture(page, 80).await.map_err(Failed::from);
        }
        page.capture(self.png, 80, clip).await.map_err(Failed::from)
    }
}

/// The box of the element `selector` names, as an act finds it: the main document first, then each
/// website frame. One that only the main document's open shadow roots hold, which an act reaches by
/// `click_xy` alone, is found as the snapshot finds it, and a disabled one is pictured as it is: a picture
/// changes nothing on the page.
async fn element(page: &Page, selector: &str, signal: &Abort) -> Result<BoundingBox, Failed> {
    let found = match poll_pictured(page, selector, Duration::from_secs(10), Some(signal)).await {
        Ok(frame) => page.query_selector_in(&frame, selector).await,
        Err(e) if super::ops::in_shadow_at(&e).is_some() => page.query_selector(selector).await,
        Err(e) => return Err(e),
    };
    let found = found.map_err(Failed::from)?;
    let Some(el) = found else {
        return Err(Failed::Settled(EngineError(format!("selector: {selector} is no longer on the page."))));
    };
    let clip = page.element_clip(&el).await;
    el.dispose().await;
    match clip.map_err(Failed::from)? {
        Some(b) if b.width >= 1.0 && b.height >= 1.0 => Ok(b),
        _ => Err(Failed::Settled(EngineError(format!(
            "selector: {selector} has no size on the page to picture."
        )))),
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a view's size, clamped to 1..8192"
)]
fn round(css: f64) -> u32 {
    css.round().clamp(1.0, 8192.0) as u32
}

/// An image's bytes from its base64.
///
/// # Errors
/// Data Chrome sent that is not base64.
pub(crate) fn decode(data: &str) -> EngineResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| EngineError(format!("Screenshot: Chrome's image did not decode: {e}.")))
}

/// A PNG's or JPEG's size in pixels, from its header.
pub(crate) fn image_size(bytes: &[u8]) -> Option<(u32, u32)> {
    let be32 = |i: usize| bytes.get(i..i + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    let be16 = |i: usize| bytes.get(i..i + 2).map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])));
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some((be32(16)?, be32(20)?));
    }
    if !bytes.starts_with(&[0xFF, 0xD8]) {
        return None;
    }
    let mut i = 2;
    while i + 4 <= bytes.len() {
        if bytes[i] != 0xFF {
            return None;
        }
        let marker = bytes[i + 1];
        // A frame header: baseline, extended, progressive or lossless, not DHT (C4), JPG (C8) or DAC (CC).
        if (0xC0..=0xCF).contains(&marker) && ![0xC4, 0xC8, 0xCC].contains(&marker) {
            return Some((be16(i + 7)?, be16(i + 5)?));
        }
        i += 2 + usize::try_from(be16(i + 2)?).ok()?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_refused_unless_absolute_in_a_folder_that_exists_and_new_or_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let at = |p: &Path, overwrite: bool| Target::of(&json!({ "path": p, "overwrite": overwrite }));
        let err = |r: EngineResult<Option<Target>>| r.err().map(|e| e.0).unwrap_or_default();
        assert!(Target::of(&json!({})).unwrap().is_none());
        assert!(err(at(Path::new("shot.png"), true)).contains("is not an absolute path"));
        assert!(err(Target::of(&json!({ "path": 5 }))).contains("as a string"));
        let missing = dir.path().join("none");
        let told = err(at(&missing.join("shot.png"), false));
        assert!(told.contains(&missing.display().to_string()) && told.contains("does not exist"), "{told}");
        assert!(err(at(dir.path(), true)).contains("is a folder"));
        let taken = dir.path().join("taken.png");
        std::fs::write(&taken, b"old").unwrap();
        assert!(err(at(&taken, false)).contains("already exists"));
        assert!(at(&taken, true).unwrap().is_some());
        assert!(at(&dir.path().join("new.png"), false).unwrap().is_some());
    }

    #[tokio::test]
    async fn a_write_makes_the_file_new_or_replaces_it_only_with_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.json");
        let target = Target::of(&json!({ "path": path })).unwrap().unwrap();
        std::fs::write(&path, b"appeared since the check").unwrap();
        assert!(target.write(b"new".to_vec()).await.unwrap_err().0.contains("already exists"));
        assert_eq!(std::fs::read(&path).unwrap(), b"appeared since the check");
        let target = Target::of(&json!({ "path": path, "overwrite": true })).unwrap().unwrap();
        let out = target.write(b"new".to_vec()).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(Value::Object(out), json!({ "path": path.display().to_string(), "bytes": 3 }));
    }

    #[test]
    fn shot_arguments_and_image_sizes() {
        assert!(!Shot::of(&json!({})).unwrap().png);
        assert!(Shot::of(&json!({ "path": "/x/a.PNG" })).unwrap().png);
        assert!(!Shot::of(&json!({ "path": "/x/a.png", "format": "jpeg" })).unwrap().png);
        assert!(Shot::of(&json!({ "format": "gif" })).err().unwrap().0.contains("not png or jpeg"));
        assert!(
            Shot::of(&json!({ "fullPage": true, "selector": "#a" })).err().unwrap().0.contains("give one")
        );
        for bad in [json!(0), json!(-5), json!(1.5), json!(9000), json!("390")] {
            assert!(Shot::of(&json!({ "width": bad })).is_err(), "{bad}");
        }
        assert!(Shot::of(&json!({ "height": 700 })).unwrap().resizes());
        // What a page the owner holds refuses, named as given; the plain picture moves nothing.
        let moves = |args: Value| Shot::of(&args).unwrap().moves_view();
        assert_eq!(moves(json!({ "path": "/x/a.png", "format": "png" })), None);
        assert_eq!(moves(json!({ "fullPage": false, "selector": "" })), None);
        assert_eq!(moves(json!({ "fullPage": true })).as_deref(), Some("fullPage"));
        assert_eq!(moves(json!({ "selector": "#a" })).as_deref(), Some("selector"));
        assert_eq!(moves(json!({ "width": 390, "height": 844 })).as_deref(), Some("width and height"));
        assert_eq!(
            moves(json!({ "selector": "#a", "width": 390, "height": 844 })).as_deref(),
            Some("selector, width and height")
        );
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend(390u32.to_be_bytes());
        png.extend(844u32.to_be_bytes());
        assert_eq!(image_size(&png), Some((390, 844)));
        // SOI, an APP0 of 4 bytes, then SOF0: length, precision, height 120, width 200.
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 4, 0, 0, 0xFF, 0xC0, 0, 17, 8, 0, 120, 0, 200];
        assert_eq!(image_size(&jpeg), Some((200, 120)));
        assert_eq!(image_size(b"GIF89a"), None);
    }
}
