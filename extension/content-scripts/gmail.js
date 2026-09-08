// Gmail (mail.google.com) detection + extraction.
//
// Selectors below are best-guess starting points based on Gmail's long-
// stable-but-obfuscated class names (div.a3s message bodies, span.gD
// sender chips, h2.hP subject) -- verify and adjust against a live Gmail
// tab, since Gmail changes these without notice.
(function () {
  const { unwrapRedirect, fingerprint, debounce } = window.__phishy;
  const { renderBanner, removeBanner } = window.__phishy;

  let lastFingerprint = null;
  let lastContainer = null;

  function findOpenMessage() {
    // Multiple messages can be expanded in a conversation; take the last
    // one in DOM order as "the" currently-open message.
    const bodies = document.querySelectorAll("div.adn.ads div.a3s");
    if (!bodies.length) return null;
    return bodies[bodies.length - 1];
  }

  function extractSender(messageEl) {
    const header = messageEl.closest("div.adn.ads");
    const senderEl = header ? header.querySelector("span.gD[email]") : null;
    if (!senderEl) return { sender_display: "", sender_address: "" };
    return {
      sender_display: senderEl.getAttribute("name") || senderEl.textContent.trim(),
      sender_address: senderEl.getAttribute("email") || "",
    };
  }

  function extractSubject() {
    const el = document.querySelector('div[role="main"] h2.hP');
    return el ? el.textContent.trim() : "";
  }

  function extractLinks(messageEl) {
    const links = [];
    messageEl.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href") || "";
      if (!href || /^(mailto:|tel:|#)/i.test(href)) return;
      links.push({ href: unwrapRedirect(href), text: a.textContent.trim() });
    });
    return links;
  }

  function extractAttachments(messageEl) {
    const container = messageEl.closest("div.adn.ads");
    if (!container) return [];
    const names = new Set();
    container.querySelectorAll("span.aV3, [data-tooltip]").forEach((el) => {
      const name = el.getAttribute("data-tooltip") || el.textContent.trim();
      if (name && /\.[a-z0-9]{1,5}$/i.test(name)) names.add(name);
    });
    return Array.from(names);
  }

  function extractEmail(messageEl) {
    return {
      ...extractSender(messageEl),
      subject: extractSubject(),
      body_text: messageEl.innerText || "",
      links: extractLinks(messageEl),
      attachments: extractAttachments(messageEl),
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

  // Only analyze received mail -- checking phishing indicators on your own
  // Sent/Drafts messages is pointless (you're the sender) and would also
  // misfire lookalike-domain-style checks against your own address.
  const EXCLUDED_HASH = /^#(sent|drafts)(\/|$)/i;

  function isExcludedFolder() {
    return EXCLUDED_HASH.test(location.hash);
  }

  const check = debounce(() => {
    if (isExcludedFolder()) {
      if (lastContainer) removeBanner(lastContainer);
      lastContainer = null;
      lastFingerprint = null;
      return;
    }

    const messageEl = findOpenMessage();
    if (!messageEl) {
      if (lastContainer) removeBanner(lastContainer);
      lastContainer = null;
      lastFingerprint = null;
      return;
    }

    const container = messageEl.closest("div.adn.ads") || messageEl.parentElement;
    if (lastContainer && lastContainer !== container) {
      removeBanner(lastContainer);
    }
    lastContainer = container;

    const emailIn = extractEmail(messageEl);
    const fp = fingerprint(emailIn);
    if (fp === lastFingerprint) return;
    lastFingerprint = fp;

    chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", email: emailIn }, handleResponse(container));
  }, 400);

  window.addEventListener("hashchange", check);
  new MutationObserver(check).observe(document.body, { childList: true, subtree: true });
  check();
})();
