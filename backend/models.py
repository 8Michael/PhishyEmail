"""Request/response schemas shared by the API and the analyzers."""
from pydantic import BaseModel, Field


class LinkIn(BaseModel):
    href: str                      # real destination (after unwrapping Gmail redirects, done in JS)
    text: str = ""                 # visible anchor text


class EmailIn(BaseModel):
    sender_display: str = ""       # e.g. "PayPal Support"
    sender_address: str = ""       # e.g. "xk29@random.ru"
    subject: str = ""
    body_text: str = ""
    links: list[LinkIn] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)  # filenames only


class Finding(BaseModel):
    check: str                     # machine id, e.g. "lookalike_domain"
    severity: str                  # "info" | "warn" | "high"
    points: int                    # contribution to the score
    message: str                   # human-readable explanation for the banner


class Verdict(BaseModel):
    score: int                     # 0-100
    tier: str                      # "ok" | "suspicious" | "phishing"
    findings: list[Finding]
