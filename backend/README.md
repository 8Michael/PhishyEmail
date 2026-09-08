# Phish Checker — local Python backend

Local FastAPI backend for a Chrome-extension phishing checker. All analysis runs on your machine; the only network call is a daily sync of the URLhaus threat feed (works fine offline too — heuristics still run).

## Layout

```
main.py              FastAPI app: /analyze, /health, extension-origin check
models.py            EmailIn / Finding / Verdict schemas (the JS<->Python contract)
scoring.py           Points -> 0-100 score -> ok / suspicious / phishing tier
feeds.py             SQLite threat-feed store + daily URLhaus sync + verdict cache table
analyzers/
  sender.py          Lookalike domains, punycode, brand-vs-freemail, display spoofing
  urls.py            Text/href mismatch, IP URLs, shorteners, bad TLDs, feed hits
  content.py         Urgency language, credential requests, risky attachments
test_engine.py       pytest samples — tune the engine before touching JS
```

## Run it

```bash
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8765
```

Try it without any extension:

```bash
curl -X POST http://127.0.0.1:8765/analyze -H "Content-Type: application/json" -d '{
  "sender_display": "PayPal Support",
  "sender_address": "security@paypa1.com",
  "subject": "Urgent: verify your account",
  "body_text": "Dear Customer, verify your account within 24 hours.",
  "links": [{"href": "http://paypa1.com.login.xyz/verify", "text": "www.paypal.com"}]
}'
```

Tests: `pytest test_engine.py -v`

## Before real use

1. Load your extension in Chrome, copy its ID from `chrome://extensions`, paste it into `ALLOWED_ORIGINS` in `main.py`, set `DEV_MODE = False`.
2. In your extension manifest add `"host_permissions": ["http://127.0.0.1:8765/*"]`.
3. The extension's service worker POSTs the extracted email to `/analyze` and renders `verdict.tier` + `verdict.findings[].message` in the banner.

## Roadmap hooks already in place

- `feeds.py` has a `url_cache` table ready for a Safe Browsing fallback (cache verdicts with TTL).
- PhishTank sync stub is noted in `feeds.py` (needs a free API key).
- Grammar check is stubbed in `analyzers/content.py` (enable `language-tool-python`).
- Brand/domain lists in `sender.py` are constants — move them to a JSON config when they grow.
