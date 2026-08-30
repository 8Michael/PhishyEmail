"""Combine findings into a 0-100 score and a tier."""
from models import Finding, Verdict

SUSPICIOUS_AT = 25
PHISHING_AT = 55


def score(findings: list[Finding]) -> Verdict:
    total = min(sum(f.points for f in findings), 100)

    # Any single 'high' finding should never land in the green tier,
    # even if the numeric total is low.
    has_high = any(f.severity == "high" for f in findings)
    if has_high:
        total = max(total, SUSPICIOUS_AT)

    if total >= PHISHING_AT:
        tier = "phishing"
    elif total >= SUSPICIOUS_AT:
        tier = "suspicious"
    else:
        tier = "ok"

    findings_sorted = sorted(findings, key=lambda f: -f.points)
    return Verdict(score=total, tier=tier, findings=findings_sorted)
