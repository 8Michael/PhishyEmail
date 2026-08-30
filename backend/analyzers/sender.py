"""Sender checks: display-name spoofing, lookalike domains, free-mail brand claims."""
import re
import tldextract
from rapidfuzz.distance import Levenshtein
from models import EmailIn, Finding

# Brands you care about protecting against lookalikes. Extend freely,
# or load from a JSON file so you can edit without touching code.
PROTECTED_DOMAINS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "netflix.com", "facebook.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "dropbox.com", "docusign.com", "usps.com", "fedex.com",
]
BRAND_NAMES = {d.split(".")[0] for d in PROTECTED_DOMAINS}

FREE_PROVIDERS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "aol.com", "proton.me", "protonmail.com", "icloud.com", "mail.com",
}


def _registered_domain(address_or_url: str) -> str:
    ext = tldextract.extract(address_or_url)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()


def analyze_sender(email: EmailIn) -> list[Finding]:
    findings: list[Finding] = []
    addr = email.sender_address.strip().lower()
    if not addr or "@" not in addr:
        return findings

    sender_domain = _registered_domain(addr.split("@", 1)[1])
    display = email.sender_display.strip().lower()

    # 1. Punycode / homoglyph domains
    if sender_domain.startswith("xn--") or "xn--" in addr:
        findings.append(Finding(
            check="punycode_sender", severity="high", points=35,
            message=f"Sender domain uses punycode ({sender_domain}) — often used to fake brand names.",
        ))

    # 2. Lookalike of a protected brand (close but not equal)
    for legit in PROTECTED_DOMAINS:
        if sender_domain == legit:
            break
        dist = Levenshtein.distance(sender_domain, legit)
        if 0 < dist <= 2:
            findings.append(Finding(
                check="lookalike_domain", severity="high", points=40,
                message=f"Sender domain '{sender_domain}' looks like '{legit}' but isn't it.",
            ))
            break

    # 3. Display name claims a brand, address is unrelated / free-mail
    claimed = {b for b in BRAND_NAMES if re.search(rf"\b{re.escape(b)}\b", display)}
    if claimed:
        brand = next(iter(claimed))
        if sender_domain in FREE_PROVIDERS:
            findings.append(Finding(
                check="brand_freemail", severity="high", points=35,
                message=f"Display name mentions '{brand}' but was sent from a free {sender_domain} address.",
            ))
        elif brand not in sender_domain:
            findings.append(Finding(
                check="brand_mismatch", severity="warn", points=20,
                message=f"Display name mentions '{brand}' but the address is @{sender_domain}.",
            ))

    # 4. Display name that itself looks like an email address (classic spoof)
    if "@" in display and display.split("@")[-1] != addr.split("@")[-1]:
        findings.append(Finding(
            check="display_addr_spoof", severity="warn", points=15,
            message="Display name contains a different email address than the real sender.",
        ))

    return findings
