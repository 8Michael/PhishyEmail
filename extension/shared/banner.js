// Inline verdict banner, shared by both provider content scripts.
// Uses Shadow DOM (not just a scoped class) because both Gmail and Outlook
// ship aggressive global stylesheets that would otherwise bleed into, or be
// overridden by, a plain same-DOM element.
(function () {
  const HOST_ID = "phishy-banner-host";

  const STYLE = `
    :host { all: initial; }
    .phishy-banner {
      font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      border-radius: 6px;
      padding: 10px 14px;
      margin: 8px 0;
      border: 1px solid transparent;
    }
    .phishy-banner .phishy-title { font-weight: 600; margin-bottom: 4px; }
    .phishy-banner ul { margin: 4px 0 0; padding-left: 18px; }
    .phishy-tier-ok { background: #e6f4ea; border-color: #b7e1c2; color: #1e4620; }
    .phishy-tier-suspicious { background: #fff8e1; border-color: #f2d675; color: #6b5300; }
    .phishy-tier-phishing { background: #fdecea; border-color: #f3b4ac; color: #611a15; }
    .phishy-tier-error { background: #eceff1; border-color: #cfd8dc; color: #37474f; }
  `;

  const TIER_LABEL = {
    ok: "Looks OK",
    suspicious: "Suspicious",
    phishing: "Likely phishing",
  };

  function ensureHost(container) {
    let host = container.querySelector(`:scope > #${HOST_ID}`);
    if (host) return host;
    host = document.createElement("div");
    host.id = HOST_ID;
    host.attachShadow({ mode: "open" });
    container.prepend(host);
    return host;
  }

  function renderBanner(container, state) {
    if (!container) return;
    const host = ensureHost(container);
    const root = host.shadowRoot;
    root.innerHTML = "";

    const style = document.createElement("style");
    style.textContent = STYLE;
    root.appendChild(style);

    const banner = document.createElement("div");

    if (state.status === "error") {
      banner.className = "phishy-banner phishy-tier-error";
      banner.innerHTML = `<div class="phishy-title">Phish Checker: couldn't analyze this email</div><div>${escapeHtml(state.message)}</div>`;
    } else {
      const verdict = state.verdict;
      banner.className = `phishy-banner phishy-tier-${verdict.tier}`;
      const label = TIER_LABEL[verdict.tier] || verdict.tier;
      let html = `<div class="phishy-title">Phish Checker: ${escapeHtml(label)} (score ${verdict.score}/100)</div>`;
      if (verdict.findings && verdict.findings.length) {
        html += "<ul>" + verdict.findings.map((f) => `<li>${escapeHtml(f.message)}</li>`).join("") + "</ul>";
      }
      banner.innerHTML = html;
    }

    root.appendChild(banner);
  }

  function removeBanner(container) {
    if (!container) return;
    const host = container.querySelector(`:scope > #${HOST_ID}`);
    if (host) host.remove();
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = String(str == null ? "" : str);
    return div.innerHTML;
  }

  window.__phishy = Object.assign(window.__phishy || {}, {
    renderBanner,
    removeBanner,
  });
})();
