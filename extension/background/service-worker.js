// Relays ANALYZE_EMAIL messages from content scripts to the local backend.
//
// This fetch MUST happen here, not in a content script: once the backend's
// DEV_MODE is turned off, main.py's _check_origin() only accepts requests
// whose Origin header is "chrome-extension://<this extension's id>". A
// fetch issued from a content script runs in the page's origin (e.g.
// https://mail.google.com) and could never satisfy that check, and would
// also risk being blocked as mixed content (http:// from an https:// page).

const BACKEND_URL = "http://127.0.0.1:8765";

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "ANALYZE_EMAIL") return false;

  fetch(`${BACKEND_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg.email),
  })
    .then(async (r) => {
      if (!r.ok) throw new Error(`backend returned ${r.status}`);
      const verdict = await r.json();
      sendResponse({ ok: true, verdict });
    })
    .catch((err) => {
      sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
    });

  return true; // keep the message channel open for the async sendResponse above
});
