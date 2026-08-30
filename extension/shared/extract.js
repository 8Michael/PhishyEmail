// Provider-agnostic helpers shared by content-scripts/gmail.js and
// content-scripts/outlook.js. Exposed as window.__phishy since content
// scripts here are plain classic scripts (no bundler, no ES modules).
(function () {
  // Undoes link-wrapping so backend/analyzers/urls.py sees the real
  // destination domain instead of the wrapper's domain (google.com /
  // safelinks.protection.outlook.com), which would otherwise silently
  // defeat lookalike/mismatch/shortener/TLD checks on every wrapped link.
  function unwrapRedirect(href) {
    if (!href) return href;
    try {
      const url = new URL(href, window.location.href);
      const host = url.hostname.toLowerCase();

      // Gmail: https://www.google.com/url?q=<real>&...
      if ((host === "www.google.com" || host === "google.com") && url.pathname === "/url") {
        const real = url.searchParams.get("q");
        if (real) return real;
      }

      // Outlook Safe Links: https://<tenant>.safelinks.protection.outlook.com/?url=<real>&...
      if (host.endsWith(".safelinks.protection.outlook.com")) {
        const real = url.searchParams.get("url");
        if (real) return decodeURIComponent(real);
      }

      return href;
    } catch {
      return href;
    }
  }

  // Cheap key to detect "have we already analyzed this exact email",
  // so we don't re-POST to the backend on every unrelated DOM mutation.
  function fingerprint(emailIn) {
    const linkCount = (emailIn.links || []).length;
    return [
      emailIn.sender_address || "",
      emailIn.subject || "",
      (emailIn.body_text || "").slice(0, 300),
      linkCount,
    ].join("|");
  }

  // Trailing-edge debounce for MutationObserver callbacks.
  function debounce(fn, waitMs) {
    let timer = null;
    return function debounced(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), waitMs);
    };
  }

  window.__phishy = Object.assign(window.__phishy || {}, {
    unwrapRedirect,
    fingerprint,
    debounce,
  });
})();
