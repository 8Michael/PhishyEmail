"""Run with: pytest test_engine.py -v
Lets you tune the whole engine before writing any extension code.
"""
from models import EmailIn, LinkIn
import scoring
from analyzers.sender import analyze_sender
from analyzers.urls import analyze_urls
from analyzers.content import analyze_content


def run(email: EmailIn):
    findings = analyze_sender(email) + analyze_urls(email) + analyze_content(email)
    return scoring.score(findings)


def test_obvious_phish():
    email = EmailIn(
        sender_display="PayPal Support",
        sender_address="security@paypa1.com",
        subject="Urgent: your account will be suspended",
        body_text="Dear Customer,\nUnusual activity detected. Verify your account "
                  "within 24 hours or your account will be closed. Enter your password here.",
        links=[LinkIn(href="http://paypa1.com.secure-check.xyz/login", text="www.paypal.com")],
    )
    verdict = run(email)
    assert verdict.tier == "phishing"
    checks = {f.check for f in verdict.findings}
    assert "lookalike_domain" in checks
    assert "link_text_mismatch" in checks
    assert "urgency_language" in checks


def test_legit_newsletter():
    email = EmailIn(
        sender_display="GitHub",
        sender_address="noreply@github.com",
        subject="Your weekly digest",
        body_text="Hi Alex, here's what happened in your repositories this week.",
        links=[LinkIn(href="https://github.com/notifications", text="View notifications")],
    )
    verdict = run(email)
    assert verdict.tier == "ok"


def test_high_severity_never_green():
    email = EmailIn(
        sender_address="foo@example.com",
        body_text="hi",
        links=[LinkIn(href="http://192.168.4.20/login", text="login")],
    )
    verdict = run(email)
    assert verdict.tier != "ok"
