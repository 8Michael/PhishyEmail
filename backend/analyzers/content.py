"""Body-text checks: urgency language, credential requests, generic greetings, risky attachments."""
import re
from models import EmailIn, Finding

URGENCY_PATTERNS = [
    r"act (now|immediately)", r"urgent(ly)?", r"within \d+ ?(hours?|days?)",
    r"account .{0,20}(suspend|clos|lock|limit|deactivat)",
    r"verify your (account|identity|information)",
    r"unusual (activity|sign.?in|login)", r"final (notice|warning|reminder)",
    r"immediate(ly)? (action|attention)", r"failure to .{0,30}(result|lead)",
]

CREDENTIAL_PATTERNS = [
    r"(confirm|update|enter|provide).{0,30}(password|passcode)",
    r"social security", r"\bssn\b", r"credit card (number|details)",
    r"gift ?cards?", r"wire transfer", r"bank (account|routing)",
    r"one.?time (code|password)", r"\botp\b",
]

GENERIC_GREETINGS = [
    r"^dear (customer|user|member|client|sir|madam|account holder)",
    r"^(hello|hi),?$",
]

RISKY_EXTENSIONS = {".html", ".htm", ".iso", ".img", ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".lnk", ".shtml"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}


def _count_hits(patterns: list[str], text: str) -> list[str]:
    return [p for p in patterns if re.search(p, text, re.IGNORECASE | re.MULTILINE)]


def analyze_content(email: EmailIn) -> list[Finding]:
    findings: list[Finding] = []
    text = f"{email.subject}\n{email.body_text}"

    urgency = _count_hits(URGENCY_PATTERNS, text)
    if urgency:
        pts = min(10 * len(urgency), 25)
        findings.append(Finding(
            check="urgency_language", severity="warn", points=pts,
            message=f"Uses pressure/urgency language ({len(urgency)} pattern(s) matched).",
        ))

    creds = _count_hits(CREDENTIAL_PATTERNS, text)
    if creds:
        pts = min(15 * len(creds), 30)
        findings.append(Finding(
            check="credential_request", severity="high", points=pts,
            message="Asks for sensitive information (passwords, payment, or ID details).",
        ))

    if _count_hits(GENERIC_GREETINGS, email.body_text.strip()):
        findings.append(Finding(
            check="generic_greeting", severity="info", points=5,
            message="Generic greeting instead of your name.",
        ))

    for name in email.attachments:
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in RISKY_EXTENSIONS:
            findings.append(Finding(
                check="risky_attachment", severity="high", points=30,
                message=f"Attachment '{name}' is a file type commonly used to deliver malware.",
            ))
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(Finding(
                check="archive_attachment", severity="warn", points=10,
                message=f"Archive attachment '{name}' — contents can't be inspected.",
            ))

    # Grammar check (optional, weight low — modern phishing is often well-written).
    # Uncomment after installing language-tool-python (downloads a Java-based server on first run):
    #
    # import language_tool_python
    # tool = language_tool_python.LanguageTool("en-US")   # cache this globally, it's slow to start
    # errors = tool.check(email.body_text)
    # if len(errors) >= 8:
    #     findings.append(Finding(check="poor_grammar", severity="info", points=5,
    #                             message=f"Unusually high number of language errors ({len(errors)})."))

    return findings
