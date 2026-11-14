//! Remote object handles and the value conversions around `Runtime.callFunctionOn`.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use crate::page::{ContextRef, Inner};
use crate::{CdpError, FrameId};

/// An argument to a page function.
#[derive(Debug, Clone)]
pub enum Arg<'a> {
    /// Passed by value (JSON).
    Value(Value),
    /// Passed by reference; must belong to the same execution context as the call.
    Handle(&'a JsHandle),
}

impl From<Value> for Arg<'_> {
    fn from(v: Value) -> Self {
        Arg::Value(v)
    }
}

impl<'a> From<&'a JsHandle> for Arg<'a> {
    fn from(h: &'a JsHandle) -> Self {
        Arg::Handle(h)
    }
}

impl Arg<'_> {
    /// Puppeteer's `convertArgument`.
    fn to_call_argument(&self, ctx: &ContextRef) -> Result<Value, CdpError> {
        match self {
            Arg::Value(v) => Ok(json!({ "value": v })),
            Arg::Handle(h) => {
                if h.ctx.session != ctx.session || h.ctx.id != ctx.id {
                    return Err(CdpError::Other(
                        "JSHandles can be evaluated only in the context they were created!".into(),
                    ));
                }
                if h.is_disposed() {
                    return Err(CdpError::Other("JSHandle is disposed!".into()));
                }
                if let Some(u) = h.remote.get("unserializableValue") {
                    return Ok(json!({ "unserializableValue": u }));
                }
                match h.remote.get("objectId") {
                    Some(id) => Ok(json!({ "objectId": id })),
                    None => Ok(json!({ "value": h.remote.get("value").cloned().unwrap_or(Value::Null) })),
                }
            }
        }
    }
}

/// A reference to a JavaScript value living in one execution context of the page.
///
/// Like puppeteer, a handle is not released when dropped; call [`JsHandle::dispose`]. A navigation
/// releases everything in the old context anyway.
pub struct JsHandle {
    inner: Arc<Inner>,
    ctx: ContextRef,
    remote: Value,
    disposed: AtomicBool,
}

impl fmt::Debug for JsHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsHandle")
            .field("frame", &self.ctx.frame)
            .field("context", &self.ctx.id)
            .field("remote", &self.remote)
            .field("disposed", &self.is_disposed())
            .finish_non_exhaustive()
    }
}

impl JsHandle {
    pub(crate) fn new(inner: Arc<Inner>, ctx: ContextRef, remote: Value) -> Self {
        JsHandle { inner, ctx, remote, disposed: AtomicBool::new(false) }
    }

    /// The frame this value lives in (in its isolated world, unless it came from a main-world call).
    pub fn frame(&self) -> &FrameId {
        &self.ctx.frame
    }

    /// The raw CDP `RemoteObject`.
    pub fn remote_object(&self) -> &Value {
        &self.remote
    }

    /// The remote object id, absent for primitives.
    pub fn object_id(&self) -> Option<&str> {
        self.remote.get("objectId").and_then(Value::as_str)
    }

    /// True when the handle points at `null` or `undefined`.
    pub fn is_nullish(&self) -> bool {
        let t = self.remote.get("type").and_then(Value::as_str);
        let st = self.remote.get("subtype").and_then(Value::as_str);
        t == Some("undefined") || st == Some("null")
    }

    pub fn is_disposed(&self) -> bool {
        self.disposed.load(Ordering::Acquire)
    }

    pub(crate) fn context(&self) -> &ContextRef {
        &self.ctx
    }

    /// Runs `js` (a function source) with this handle as its first argument; returns the result by value.
    pub async fn evaluate(&self, js: &str, args: Vec<Arg<'_>>) -> Result<Value, CdpError> {
        let mut all = Vec::with_capacity(args.len() + 1);
        all.push(Arg::Handle(self));
        all.extend(args);
        let remote = call_function(&self.inner, &self.ctx, js, &all, true).await?;
        Ok(value_from_remote(&remote))
    }

    /// Like [`JsHandle::evaluate`], but returns a handle to the result.
    pub async fn evaluate_handle(&self, js: &str, args: Vec<Arg<'_>>) -> Result<JsHandle, CdpError> {
        let mut all = Vec::with_capacity(args.len() + 1);
        all.push(Arg::Handle(self));
        all.extend(args);
        let remote = call_function(&self.inner, &self.ctx, js, &all, false).await?;
        Ok(JsHandle::new(self.inner.clone(), self.ctx.clone(), remote))
    }

    /// Releases the remote object. Failures are ignored (the context may already be gone), as puppeteer
    /// does.
    pub async fn dispose(&self) {
        if self.disposed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(id) = self.object_id() {
            let _ = self
                .inner
                .send(self.ctx.session.as_ref(), "Runtime.releaseObject", json!({ "objectId": id }))
                .await;
        }
    }

    /// [`JsHandle::dispose`] without waiting for the answer: the release goes out from a task of its
    /// own, and its failure is ignored all the same. For a path where every round trip counts (the
    /// click check), with a handle nothing uses again. Needs a Tokio runtime, as every call here does.
    pub(crate) fn release(&self) {
        if self.disposed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(id) = self.object_id() {
            let (inner, session, id) = (self.inner.clone(), self.ctx.session.clone(), id.to_owned());
            tokio::spawn(async move {
                let _ =
                    inner.send(session.as_ref(), "Runtime.releaseObject", json!({ "objectId": id })).await;
            });
        }
    }
}

/// Owns a handle and releases it when dropped, so a read cancelled while it holds one (a frame read that
/// timed out, or whose snapshot failed or was aborted) does not leave the object in the page until its
/// context goes. [`JsHandle::dispose`] on the handle first makes the drop a no-op. Outside a tokio
/// runtime the drop releases nothing, as a plain drop does.
pub(crate) struct DisposeOnDrop(pub(crate) JsHandle);

impl Drop for DisposeOnDrop {
    fn drop(&mut self) {
        let h = &self.0;
        if h.is_disposed() || h.object_id().is_none() {
            return;
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let release = JsHandle::new(Arc::clone(&h.inner), h.ctx.clone(), h.remote.clone());
            h.disposed.store(true, Ordering::Release);
            rt.spawn(async move { release.dispose().await });
        }
    }
}

/// `Runtime.callFunctionOn` in `ctx`, with puppeteer's error rewriting. Returns the `RemoteObject`.
pub(crate) async fn call_function(
    inner: &Inner,
    ctx: &ContextRef,
    js: &str,
    args: &[Arg<'_>],
    by_value: bool,
) -> Result<Value, CdpError> {
    let arguments = args.iter().map(|a| a.to_call_argument(ctx)).collect::<Result<Vec<_>, _>>()?;
    let mut params = json!({
        "functionDeclaration": js,
        "arguments": arguments,
        "returnByValue": by_value,
        "awaitPromise": true,
        "userGesture": true,
    });
    // By the unique id when Chrome gave one: it names this context or none, where a number can name a
    // later one. Chrome takes one or the other, never both.
    params[if ctx.unique.is_some() { "uniqueContextId" } else { "executionContextId" }] =
        ctx.unique.as_ref().map_or_else(|| json!(ctx.id), |u| json!(u));
    let res = match inner.send(ctx.session.as_ref(), "Runtime.callFunctionOn", params).await {
        Ok(v) => v,
        Err(e) if e.is_unreturnable_value() => return Ok(json!({ "type": "undefined" })),
        Err(e) => {
            let e = e.rewrite_for_evaluation();
            if e == CdpError::ContextDestroyed {
                inner.forget_context(ctx);
            }
            return Err(e);
        }
    };
    if let Some(details) = res.get("exceptionDetails") {
        return Err(evaluation_error(details));
    }
    Ok(res.get("result").cloned().unwrap_or_else(|| json!({ "type": "undefined" })))
}

/// Puppeteer's `valueFromRemoteObject`. JSON cannot hold `NaN`/`Infinity`, so those become `null`;
/// a bigint becomes a number when it fits, else its decimal string.
pub(crate) fn value_from_remote(remote: &Value) -> Value {
    if let Some(u) = remote.get("unserializableValue").and_then(Value::as_str) {
        if u == "-0" {
            return json!(-0.0);
        }
        if let Some(digits) = u.strip_suffix('n') {
            return digits
                .parse::<i64>()
                .map(Value::from)
                .or_else(|_| digits.parse::<u64>().map(Value::from))
                .unwrap_or_else(|_| Value::String(digits.to_owned()));
        }
        return Value::Null;
    }
    remote.get("value").cloned().unwrap_or(Value::Null)
}

/// Puppeteer's `createEvaluationError` / `getErrorDetails`.
pub(crate) fn evaluation_error(details: &Value) -> CdpError {
    let Some(exception) = details.get("exception") else {
        let text = details.get("text").and_then(Value::as_str).unwrap_or("Evaluation failed").to_owned();
        return CdpError::Evaluation { name: Some("Error".into()), message: text, value: None };
    };
    let is_error = exception.get("type").and_then(Value::as_str) == Some("object")
        && exception.get("subtype").and_then(Value::as_str) == Some("error");
    if !is_error && exception.get("objectId").is_none() {
        // A thrown primitive (`throw 'x'`): puppeteer rethrows the value itself.
        let value = value_from_remote(exception);
        let message = match &value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        return CdpError::Evaluation { name: None, message, value: Some(value) };
    }
    let description = exception.get("description").and_then(Value::as_str).unwrap_or("");
    let mut lines: Vec<&str> =
        if description.is_empty() { Vec::new() } else { description.split("\n    at ").collect() };
    let frames = details.pointer("/stackTrace/callFrames").and_then(Value::as_array).map_or(0, Vec::len);
    let size = frames.min(lines.len().saturating_sub(1));
    lines.truncate(lines.len() - size);
    let name = exception.get("className").and_then(Value::as_str).unwrap_or("").to_owned();
    let mut message = lines.join("\n");
    if !name.is_empty()
        && let Some(rest) = message.strip_prefix(&format!("{name}: "))
    {
        message = rest.to_owned();
    }
    CdpError::Evaluation { name: (!name.is_empty()).then_some(name), message, value: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_values() {
        assert_eq!(value_from_remote(&json!({"type": "number", "value": 3})), json!(3));
        assert_eq!(value_from_remote(&json!({"type": "undefined"})), Value::Null);
        assert_eq!(value_from_remote(&json!({"type": "bigint", "unserializableValue": "12n"})), json!(12));
        assert_eq!(value_from_remote(&json!({"type": "number", "unserializableValue": "NaN"})), Value::Null);
    }

    #[test]
    fn error_details_strip_stack_and_name() {
        let details = json!({
            "text": "Uncaught",
            "exception": {"type": "object", "subtype": "error", "className": "TypeError", "objectId": "1",
                          "description": "TypeError: x is not a function\n    at foo (a.js:1:1)\n    at <anonymous>:2:3"},
            "stackTrace": {"callFrames": [{}, {}]}
        });
        assert_eq!(
            evaluation_error(&details),
            CdpError::Evaluation {
                name: Some("TypeError".into()),
                message: "x is not a function".into(),
                value: None
            }
        );
    }

    #[test]
    fn thrown_primitive_keeps_value() {
        let details = json!({"text": "Uncaught", "exception": {"type": "string", "value": "nope"}});
        let e = evaluation_error(&details);
        assert_eq!(e.to_string(), "nope");
        assert!(matches!(e, CdpError::Evaluation { value: Some(Value::String(_)), .. }));
        let details = json!({"text": "Uncaught SyntaxError"});
        assert_eq!(evaluation_error(&details).to_string(), "Uncaught SyntaxError");
    }
}
