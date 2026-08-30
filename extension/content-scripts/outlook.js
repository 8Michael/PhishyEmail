// Outlook web (outlook.live.com / outlook.office.com / outlook.office365.com)
// detection + extraction.
//
// Outlook's Fluent-UI classes are hashed/build-specific, so this prefers
// data-testid / aria-label / role attributes, which tend to survive across
// builds better than class names -- but exact testid values are unverified
// against a live Outlook tab and may differ between "classic" OWA and the
// newer "Monarch" shell. Adjust during real-world testing.
(function () {
  const { unwrapRedirect, fingerprint, debounce } = window.__phishy;
  const { renderBanner, removeBanner } = window.__phishy;

  let lastFingerprint = null;
  let observedPane = null;
  let observer = null;

  function findReadingPane() {
    return (
      document.querySelector('div[aria-label="Reading Pane"]') ||
      document.querySelector('[role="region"][aria-label*="Reading Pane" i]')
    );
  }

  function extractSender(pane) {
    const withTitle = pane.querySelector('[title*="@"]');
    const testIdEl = pane.querySelector('[data-testid*="Sender" i], [data-testid*="From" i]');
    const address = withTitle ? withTitle.getAttribute("title") : "";
    const display = (testIdEl || withTitle) ? (testIdEl || withTitle).textContent.trim() : "";
    return {
      sender_display: display,
      sender_address: address && address.includes("@") ? address : "",
    };
  }

  function extractSubject(pane) {
    const el = pane.querySelector('[role="heading"]') || pane.querySelector('[data-testid*="Subject" i]');
    return el ? el.textContent.trim() : "";
  }

  function findBodyElement(pane) {
    const direct = pane.querySelector('[data-testid*="MessageBody" i], [data-testid*="UniqueBody" i]');
    if (direct && direct.innerText.trim()) return direct;

    const iframe = pane.querySelector('iframe[id*="MessageBody" i], iframe');
    if (iframe) {
      try {
        const doc = iframe.contentDocument;
        if (doc && doc.body) return doc.body;
      } catch {
        // cross-origin iframe -- fall through to graceful degradation
      }
    }
    return direct || null;
  }

  function extractLinks(bodyEl) {
    if (!bodyEl) return [];
    const links = [];
    bodyEl.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href") || "";
      if (!href || /^(mailto:|tel:|#)/i.test(href)) return;
      links.push({ href: unwrapRedirect(href), text: a.textContent.trim() });
    });
    return links;
  }

  function extractAttachments(pane) {
    const names = [];
    pane.querySelectorAll('[data-testid*="Attachment" i]').forEach((el) => {
      const label = el.getAttribute("aria-label") || el.textContent || "";
      const cleaned = label
        .split(",")[0]
        .replace(/\s*\d+(\.\d+)?\s?(KB|MB|GB)\s*$/i, "")
        .trim();
      if (cleaned) names.push(cleaned);
    });
    return names;
  }

  function extractEmail(pane) {
    const bodyEl = findBodyElement(pane);
    return {
      ...extractSender(pane),
      subject: extractSubject(pane),
      body_text: bodyEl ? bodyEl.innerText || "" : "",
      links: extractLinks(bodyEl),
      attachments: extractAttachments(pane),
    };
  }

  function handleResponse(container) {
    return (response) => {
      if (!response) {
        renderBanner(container, { status: "error", message: "No response from extension background." });
        return;
      }
      if (response.ok) {
        renderBanner(container, { status: "ok", verdict: response.verdict });
      } else {
        renderBanner(container, { status: "error", message: response.error || "Unknown error." });
      }
    };
  }

  const check = debounce(() => {
    const pane = findReadingPane();

    if (!pane) {
      if (observedPane) removeBanner(observedPane);
      observedPane = null;
      lastFingerprint = null;
      return;
    }

    if (pane !== observedPane) {
      if (observedPane) removeBanner(observedPane);
      observedPane = pane;
      lastFingerprint = null;
      attachObserver(pane);
    }

    const emailIn = extractEmail(pane);
    const fp = fingerprint(emailIn);
    if (fp === lastFingerprint) return;
    lastFingerprint = fp;

    chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", email: emailIn }, handleResponse(pane));
  }, 400);

  function attachObserver(pane) {
    if (observer) observer.disconnect();
    observer = new MutationObserver(check);
    observer.observe(pane, { childList: true, subtree: true });
  }

  // Route changes can swap the reading pane's own container, so also watch
  // the document body for the pane appearing/disappearing/being replaced.
  new MutationObserver(check).observe(document.body, { childList: true, subtree: true });
  check();
})();
