# Phish Checker — Chrome extension

Manifest V3 extension that reads the currently-open email in Gmail or Outlook
web, sends it to the local backend (`../backend`), and shows the verdict as
an inline banner above the message.

## Layout

```
manifest.json
background/service-worker.js   fetch() to the backend — must run here, not in
                                a content script, so the Origin header the
                                backend checks is chrome-extension://<id>
content-scripts/gmail.js       Gmail detection + DOM extraction
content-scripts/outlook.js     Outlook detection + DOM extraction
shared/extract.js              unwrapRedirect(), fingerprint(), debounce()
shared/banner.js                renderBanner()/removeBanner() (Shadow DOM)
```

## Setup

1. Start the backend first:
   ```bash
   cd ../backend
   pip install -r requirements.txt
   uvicorn main:app --host 127.0.0.1 --port 8765
   ```
2. Open `chrome://extensions`, enable **Developer mode**, click **Load
   unpacked**, and select this `extension/` folder.
3. (Dev mode) `backend/main.py` has `DEV_MODE = True`, which allows CORS
   from anywhere — the extension works immediately, skip to Testing.
4. (Locking it down) Copy the extension's ID shown on `chrome://extensions`,
   paste it into `ALLOWED_ORIGINS` in `backend/main.py` as
   `"chrome-extension://<id>"`, set `DEV_MODE = False`, and restart the
   backend.

## Testing

1. Confirm `curl http://127.0.0.1:8765/health` returns `{"status":"ok"}`.
2. Open `chrome://extensions` → this extension → **Inspect views: service
   worker**, to watch for errors during the steps below.
3. Open Gmail (`mail.google.com`), open an email — a colored banner should
   appear above the message body within about a second.
4. Open a different email without reloading the page — the banner should
   update, not stack or stay stale.
5. Go back to the inbox list — the banner should disappear.
6. Repeat steps 3–5 in Outlook web (`outlook.office.com` / `outlook.live.com`).
7. Stop the backend and open an email — the banner should show a "couldn't
   analyze this email" state instead of failing silently.
8. Open/construct a phishing-shaped email (spoofed display name + lookalike
   domain + mismatched link text/href, like the example in
   `../backend/README.md`) and confirm it renders as "Likely phishing" with
   the relevant findings listed.

The DOM selectors in `content-scripts/gmail.js` and `content-scripts/outlook.js`
are best-guess starting points — Gmail and Outlook both change their markup
without notice, so if extraction stops working, that's the first place to
check (open DevTools on the page and inspect the open message's markup).
