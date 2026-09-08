"""URL checks: text/href mismatch, IP URLs, shorteners, bad TLDs, local threat-feed hits."""
import re
from urllib.parse import urlparse
import tldextract
from models import EmailIn, Finding
import feeds

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "link"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _reg_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()


def analyze_urls(email: EmailIn) -> list[Finding]:
    findings: list[Finding] = []
    seen_checks: set[tuple[str, str]] = set()  # avoid duplicate findings per (check, domain)

    def add(check: str, key: str, severity: str, points: int, message: str, url: str | None = None):
        if (check, key) not in seen_checks:
            seen_checks.add((check, key))
            findings.append(Finding(check=check, severity=severity, points=points, message=message, url=url))

    for link in email.links:
        href = link.href.strip()
        if not href or href.startswith(("mailto:", "tel:", "#")):
            continue
        parsed = urlparse(href if "://" in href else "http://" + href)
        host = (parsed.hostname or "").lower()
        domain = _reg_domain(href)

        # 1. Known-bad URL from local feeds (instant high risk)
        if feeds.is_flagged(href, domain):
            add("known_phish_url", domain, "high", 60,
                f"Link to {domain} appears in a phishing/malware feed.", url=href)
            continue

        # 2. Anchor text shows a different domain than the real destination.
        # Real phishing displays the fake domain AS the link text (e.g. the
        # whole anchor reads "www.paypal.com") -- so only treat this as a
        # domain claim when the match makes up essentially the entire visible
        # text. Without that guard, ordinary prose glued together without a
        # space during DOM text extraction (e.g. from an embedded post:
        # "...what's new.Read more...") produces a coincidental word.word
        # span that happens to resolve to a real, if obscure, gTLD (".read",
        # ".new", ".app", etc. are all real suffixes now) and gets
        # misread as a claimed domain.
        text = link.text.strip().lower()
        text_domain_match = re.search(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", text)
        if text_domain_match and len(text) <= len(text_domain_match.group(0)) + 5:
            text_ext = tldextract.extract(text_domain_match.group(0))
            if text_ext.suffix:
                text_domain = f"{text_ext.domain}.{text_ext.suffix}".lower()
                if text_domain != domain:
                    add("link_text_mismatch", domain, "high", 30,
                        f"Link text says '{text_domain}' but actually goes to '{domain}'.", url=href)

        # 3. Raw IP address URL
        if host and IP_RE.match(host):
            add("ip_url", host, "high", 30, f"Link points to a raw IP address ({host}).", url=href)

        # 4. URL shorteners hide the destination
        if domain in SHORTENERS:
            add("shortener", domain, "warn", 10,
                f"Link uses a URL shortener ({domain}), hiding the real destination.", url=href)

        # 5. Suspicious / heavily-abused TLDs
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            add("suspicious_tld", domain, "warn", 10,
                f"Link uses a frequently abused top-level domain (.{tld}).", url=href)

        # 6. Excessive subdomain nesting (paypal.com.secure-login.example.net)
        if host.count(".") >= 4:
            add("deep_subdomains", host, "warn", 10,
                f"Link has unusually deep subdomains ({host}).", url=href)

        # 7. Credentials embedded in URL (user@host trick)
        if parsed.username:
            add("userinfo_url", host, "high", 25,
                "Link embeds a username before the real domain — a common disguise trick.", url=href)

    return findings
