"""Local phishing-checker backend.

Run:  uvicorn main:app --host 127.0.0.1 --port 8765
"""
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import feeds
import scoring
from models import EmailIn, Verdict
from analyzers.sender import analyze_sender
from analyzers.urls import analyze_urls
from analyzers.content import analyze_content

# Once your extension is loaded, copy its ID from chrome://extensions
# and set it here so only YOUR extension can call this server.
ALLOWED_ORIGINS = [
    "chrome-extension://gndnbfjkijceddlbkeocdhakmhekhajj",
]
DEV_MODE = False

app = FastAPI(title="Phish Checker (local)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if not DEV_MODE else ["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    feeds.sync_if_stale()


def _check_origin(request: Request) -> None:
    if DEV_MODE:
        return
    origin = request.headers.get("origin", "")
    if origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="forbidden origin")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=Verdict)
def analyze(email: EmailIn, request: Request) -> Verdict:
    _check_origin(request)
    findings = []
    findings += analyze_sender(email)
    findings += analyze_urls(email)
    findings += analyze_content(email)
    return scoring.score(findings)
