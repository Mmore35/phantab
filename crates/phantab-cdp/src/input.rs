//! Keyboard and mouse state, ported from puppeteer's `cdp/Input.ts`. These types only compute the
//! `Input.*` parameters and track state; [`crate::Page`] sends them.
//!
//! Copyright 2017 Google Inc. Licensed under the Apache License, Version 2.0 (SPDX-License-Identifier:
//! Apache-2.0). This file holds code ported from puppeteer; see `NOTICE`.

use std::collections::HashSet;

use serde_json::{Value, json};

use crate::CdpError;
use crate::keyboard_layout::key_definition;

const ALT: u32 = 1;
const CONTROL: u32 = 2;
const META: u32 = 4;
const SHIFT: u32 = 8;

fn modifier_bit(key: &str) -> u32 {
    match key {
        "Alt" => ALT,
        "Control" => CONTROL,
        "Meta" => META,
        "Shift" => SHIFT,
        _ => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyDescription {
    key: String,
    key_code: u32,
    code: String,
    text: String,
    location: u32,
}

/// Held modifiers and keys, as puppeteer's `CdpKeyboard` keeps them.
#[derive(Debug, Default)]
pub(crate) struct Keyboard {
    modifiers: u32,
    pressed: HashSet<String>,
}

impl Keyboard {
    pub(crate) fn modifiers(&self) -> u32 {
        self.modifiers
    }

    fn describe(&self, name: &str) -> Result<KeyDescription, CdpError> {
        let def = key_definition(name).ok_or_else(|| CdpError::Other(format!("Unknown key: \"{name}\"")))?;
        let shift = self.modifiers & SHIFT != 0;
        let mut d = KeyDescription {
            key: String::new(),
            key_code: 0,
            code: String::new(),
            text: String::new(),
            location: 0,
        };
        if let Some(k) = def.key {
            k.clone_into(&mut d.key);
        }
        if shift && let Some(k) = def.shift_key {
            k.clone_into(&mut d.key);
        }
        if let Some(c) = def.key_code {
            d.key_code = c;
        }
        if shift && let Some(c) = def.shift_key_code {
            d.key_code = c;
        }
        if let Some(c) = def.code {
            c.clone_into(&mut d.code);
        }
        if let Some(l) = def.location {
            d.location = l;
        }
        // Puppeteer tests `key.length === 1` (UTF-16 units); every key in the table is in the BMP.
        if d.key.encode_utf16().count() == 1 {
            d.text.clone_from(&d.key);
        }
        if let Some(t) = def.text {
            t.clone_into(&mut d.text);
        }
        if shift && let Some(t) = def.shift_text {
            t.clone_into(&mut d.text);
        }
        // Any modifier other than Shift suppresses text, so Control+A selects instead of typing.
        if self.modifiers & !SHIFT != 0 {
            d.text.clear();
        }
        Ok(d)
    }

    /// Updates state for a key press and returns the `Input.dispatchKeyEvent` params.
    pub(crate) fn down(&mut self, name: &str) -> Result<Value, CdpError> {
        let d = self.describe(name)?;
        let auto_repeat = self.pressed.contains(&d.code);
        self.pressed.insert(d.code.clone());
        self.modifiers |= modifier_bit(&d.key);
        let kind = if d.text.is_empty() { "rawKeyDown" } else { "keyDown" };
        Ok(json!({
            "type": kind,
            "modifiers": self.modifiers,
            "windowsVirtualKeyCode": d.key_code,
            "code": d.code,
            "key": d.key,
            "text": d.text,
            "unmodifiedText": d.text,
            "autoRepeat": auto_repeat,
            "location": d.location,
            "isKeypad": d.location == 3,
        }))
    }

    /// Updates state for a key release and returns the `Input.dispatchKeyEvent` params.
    pub(crate) fn up(&mut self, name: &str) -> Result<Value, CdpError> {
        let d = self.describe(name)?;
        self.modifiers &= !modifier_bit(&d.key);
        self.pressed.remove(&d.code);
        Ok(json!({
            "type": "keyUp",
            "modifiers": self.modifiers,
            "key": d.key,
            "windowsVirtualKeyCode": d.key_code,
            "code": d.code,
            "location": d.location,
        }))
    }
}

/// Whether `keyboard.type` presses this character as a key (otherwise it is inserted as text).
pub(crate) fn char_is_key(c: char) -> bool {
    let mut buf = [0u8; 4];
    key_definition(c.encode_utf8(&mut buf)).is_some()
}

/// Mouse buttons as CDP's `buttons` bit field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MouseButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

impl MouseButton {
    const ALL: [MouseButton; 5] =
        [MouseButton::Left, MouseButton::Middle, MouseButton::Right, MouseButton::Forward, MouseButton::Back];

    fn flag(self) -> u32 {
        match self {
            MouseButton::Left => 1,
            MouseButton::Right => 2,
            MouseButton::Middle => 4,
            MouseButton::Back => 8,
            MouseButton::Forward => 16,
        }
    }

    fn name(self) -> &'static str {
        match self {
            MouseButton::Left => "left",
            MouseButton::Right => "right",
            MouseButton::Middle => "middle",
            MouseButton::Back => "back",
            MouseButton::Forward => "forward",
        }
    }
}

/// Puppeteer's `getButtonFromPressedButtons`: the button a move reports while others are held.
fn button_from_pressed(buttons: u32) -> &'static str {
    [MouseButton::Left, MouseButton::Right, MouseButton::Middle, MouseButton::Back, MouseButton::Forward]
        .into_iter()
        .find(|b| buttons & b.flag() != 0)
        .map_or("none", MouseButton::name)
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct MouseState {
    x: f64,
    y: f64,
    buttons: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct Change {
    position: Option<(f64, f64)>,
    buttons: Option<u32>,
}

/// Mouse state with puppeteer's transactions: each operation stages its change at once, so operations
/// issued together (a click's move, press and release) build on each other, and the change is kept only
/// if its command succeeds.
#[derive(Debug, Default)]
pub(crate) struct Mouse {
    base: MouseState,
    pending: Vec<(u64, Change)>,
    next: u64,
}

/// A staged mouse change; settle it with [`Mouse::settle`] once its command has answered.
pub(crate) type Txn = u64;

impl Mouse {
    fn state(&self) -> MouseState {
        let mut s = self.base;
        for (_, c) in &self.pending {
            apply(&mut s, *c);
        }
        s
    }

    fn stage(&mut self, change: Change) -> Txn {
        self.next += 1;
        self.pending.push((self.next, change));
        self.next
    }

    /// Keeps the change if the command succeeded, drops it otherwise.
    pub(crate) fn settle(&mut self, txn: Txn, ok: bool) {
        if let Some(i) = self.pending.iter().position(|(id, _)| *id == txn) {
            let (_, change) = self.pending.remove(i);
            if ok {
                apply(&mut self.base, change);
            }
        }
    }

    pub(crate) fn move_to(&mut self, x: f64, y: f64, modifiers: u32) -> (Txn, Value) {
        let txn = self.stage(Change { position: Some((x, y)), buttons: None });
        let s = self.state();
        let params = json!({
            "type": "mouseMoved",
            "modifiers": modifiers,
            "buttons": s.buttons,
            "button": button_from_pressed(s.buttons),
            "x": s.x,
            "y": s.y,
        });
        (txn, params)
    }

    pub(crate) fn down(
        &mut self,
        button: MouseButton,
        click_count: u32,
        modifiers: u32,
    ) -> Result<(Txn, Value), CdpError> {
        let s = self.state();
        if s.buttons & button.flag() != 0 {
            return Err(CdpError::Other(format!("'{}' is already pressed.", button.name())));
        }
        let txn = self.stage(Change { position: None, buttons: Some(s.buttons | button.flag()) });
        let s = self.state();
        Ok((txn, press_params("mousePressed", button, click_count, modifiers, s)))
    }

    pub(crate) fn up(
        &mut self,
        button: MouseButton,
        click_count: u32,
        modifiers: u32,
    ) -> Result<(Txn, Value), CdpError> {
        let s = self.state();
        if s.buttons & button.flag() == 0 {
            return Err(CdpError::Other(format!("'{}' is not pressed.", button.name())));
        }
        let txn = self.stage(Change { position: None, buttons: Some(s.buttons & !button.flag()) });
        let s = self.state();
        Ok((txn, press_params("mouseReleased", button, click_count, modifiers, s)))
    }

    pub(crate) fn wheel(&self, delta_x: f64, delta_y: f64, modifiers: u32) -> Value {
        let s = self.state();
        json!({
            "type": "mouseWheel",
            "pointerType": "mouse",
            "modifiers": modifiers,
            "deltaY": delta_y,
            "deltaX": delta_x,
            "buttons": s.buttons,
            "x": s.x,
            "y": s.y,
        })
    }

    /// Puppeteer's `reset`: release every held button and move back to the origin.
    pub(crate) fn reset(&mut self, modifiers: u32) -> Vec<(Txn, Value)> {
        let mut ops = Vec::new();
        for b in MouseButton::ALL {
            if self.state().buttons & b.flag() != 0
                && let Ok(op) = self.up(b, 1, modifiers)
            {
                ops.push(op);
            }
        }
        let s = self.state();
        if s.x != 0.0 || s.y != 0.0 {
            ops.push(self.move_to(0.0, 0.0, modifiers));
        }
        ops
    }
}

fn press_params(kind: &str, button: MouseButton, click_count: u32, modifiers: u32, s: MouseState) -> Value {
    json!({
        "type": kind,
        "modifiers": modifiers,
        "clickCount": click_count,
        "buttons": s.buttons,
        "button": button.name(),
        "x": s.x,
        "y": s.y,
    })
}

fn apply(s: &mut MouseState, c: Change) {
    if let Some((x, y)) = c.position {
        s.x = x;
        s.y = y;
    }
    if let Some(b) = c.buttons {
        s.buttons = b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_sends_carriage_return_text() {
        let mut k = Keyboard::default();
        let p = k.down("Enter").unwrap();
        assert_eq!(
            p,
            json!({"type": "keyDown", "modifiers": 0, "windowsVirtualKeyCode": 13, "code": "Enter",
                   "key": "Enter", "text": "\r", "unmodifiedText": "\r", "autoRepeat": false,
                   "location": 0, "isKeypad": false})
        );
        let p = k.up("Enter").unwrap();
        assert_eq!(
            p,
            json!({"type": "keyUp", "modifiers": 0, "key": "Enter", "windowsVirtualKeyCode": 13,
                   "code": "Enter", "location": 0})
        );
    }

    #[test]
    fn tab_is_raw_key_down() {
        let mut k = Keyboard::default();
        let p = k.down("Tab").unwrap();
        assert_eq!(p["type"], "rawKeyDown");
        assert_eq!(p["text"], "");
        assert_eq!(p["windowsVirtualKeyCode"], 9);
    }

    #[test]
    fn shift_changes_key_and_text() {
        let mut k = Keyboard::default();
        let p = k.down("Shift").unwrap();
        assert_eq!(p["modifiers"], 8);
        assert_eq!(p["location"], 1);
        let p = k.down("KeyA").unwrap();
        assert_eq!(p["key"], "A");
        assert_eq!(p["text"], "A");
        assert_eq!(p["modifiers"], 8);
        k.up("KeyA").unwrap();
        let p = k.up("Shift").unwrap();
        assert_eq!(p["modifiers"], 0);
        assert_eq!(k.modifiers(), 0);
    }

    #[test]
    fn control_suppresses_text() {
        let mut k = Keyboard::default();
        k.down("Control").unwrap();
        let p = k.down("a").unwrap();
        assert_eq!(p["type"], "rawKeyDown");
        assert_eq!(p["text"], "");
        assert_eq!(p["modifiers"], 2);
    }

    #[test]
    fn repeat_and_numpad() {
        let mut k = Keyboard::default();
        assert_eq!(k.down("a").unwrap()["autoRepeat"], false);
        assert_eq!(k.down("a").unwrap()["autoRepeat"], true);
        let p = k.down("Numpad5").unwrap();
        assert_eq!(p["isKeypad"], true);
        assert_eq!(p["location"], 3);
    }

    #[test]
    fn unknown_key_is_an_error() {
        let mut k = Keyboard::default();
        assert_eq!(k.down("Nope").unwrap_err().to_string(), "Unknown key: \"Nope\"");
        assert!(char_is_key('a'));
        assert!(char_is_key('\n'));
        assert!(!char_is_key('é'));
    }

    #[test]
    fn click_stages_move_press_release_together() {
        let mut m = Mouse::default();
        let (t1, mv) = m.move_to(10.0, 20.0, 0);
        let (t2, dn) = m.down(MouseButton::Left, 1, 0).unwrap();
        let (t3, up) = m.up(MouseButton::Left, 1, 0).unwrap();
        assert_eq!(
            mv,
            json!({"type": "mouseMoved", "modifiers": 0, "buttons": 0, "button": "none", "x": 10.0, "y": 20.0})
        );
        assert_eq!(dn["buttons"], 1);
        assert_eq!(dn["x"], 10.0);
        assert_eq!(dn["clickCount"], 1);
        assert_eq!(up["type"], "mouseReleased");
        assert_eq!(up["buttons"], 0);
        m.settle(t1, true);
        m.settle(t2, true);
        // The release failed: the button stays pressed, as in puppeteer.
        m.settle(t3, false);
        assert_eq!(m.state(), MouseState { x: 10.0, y: 20.0, buttons: 1 });
        assert_eq!(m.down(MouseButton::Left, 1, 0).unwrap_err().to_string(), "'left' is already pressed.");
        let ops = m.reset(0);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].1["type"], "mouseReleased");
        assert_eq!(ops[1].1["type"], "mouseMoved");
        assert_eq!(ops[1].1["x"], 0.0);
        for (t, _) in ops {
            m.settle(t, true);
        }
        assert_eq!(m.state(), MouseState::default());
        assert_eq!(m.up(MouseButton::Left, 1, 0).unwrap_err().to_string(), "'left' is not pressed.");
    }

    #[test]
    fn move_while_pressed_reports_button() {
        let mut m = Mouse::default();
        let (t, _) = m.down(MouseButton::Left, 1, 0).unwrap();
        m.settle(t, true);
        let (_, mv) = m.move_to(1.0, 1.0, 0);
        assert_eq!(mv["button"], "left");
        assert_eq!(mv["buttons"], 1);
        let w = m.wheel(0.0, 120.0, 0);
        assert_eq!(
            w,
            json!({"type": "mouseWheel", "pointerType": "mouse", "modifiers": 0, "deltaY": 120.0,
                             "deltaX": 0.0, "buttons": 1, "x": 1.0, "y": 1.0})
        );
    }
}
