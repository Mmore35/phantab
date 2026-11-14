// Driven over CDP: the trial evaluates ping(name) in this worker.
self.ping = (name) => new Promise((resolve) => {
  chrome.runtime.sendNativeMessage(name, { hello: 1 }, (resp) => {
    resolve({ resp, error: chrome.runtime.lastError ? chrome.runtime.lastError.message : null });
  });
});
