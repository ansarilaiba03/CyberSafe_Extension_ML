// ============================================================
// content.js — CyberSafe Content Script
// Responsibilities:
//   1. Respond to GET_PAGE_DATA (popup page scan)
//   2. Hover tooltip on links  — ML via background
//   3. Click blocker on links  — ML via background
// No local scoring logic — all predictions come from the ML API.
// ============================================================

if (window.__cybersafeInjected) {
  console.log("[CyberSafe] Already injected — skipping.");
} else {
  window.__cybersafeInjected = true;

  // ── Tooltip state ───────────────────────────────────────────
  let tooltip       = null;
  let hoverTimer    = null;
  let lastHoverUrl  = null;

  // ── Tooltip helpers ─────────────────────────────────────────
  function createTooltip(x, y, result) {
    removeTooltip();

    const el = document.createElement("div");
    el.id = "__cybersafe_tooltip";

    const colorMap = { Low: "#00e676", Medium: "#ffd600", High: "#ff3d3d", Unknown: "#aaa" };
    const color = result.isSafe ? "#00e676" : (colorMap[result.riskLevel] || "#aaa");

    const icon  = result.isSafe ? "✅" : "⚠️";
    const label = result.isSafe
      ? `Safe · Score ${result.riskScore}`
      : `${result.scamType} · Score ${result.riskScore}/100`;

    el.innerHTML = `
      <span style="font-size:13px">${icon}</span>
      <span>${label}</span>
    `;

    Object.assign(el.style, {
      position:       "fixed",
      top:            (y + 14) + "px",
      left:           (x + 14) + "px",
      background:     "#0f1420",
      color:          color,
      border:         `1px solid ${color}44`,
      padding:        "7px 12px",
      borderRadius:   "6px",
      fontSize:       "12px",
      fontFamily:     "monospace",
      display:        "flex",
      gap:            "8px",
      alignItems:     "center",
      zIndex:         "2147483647",
      pointerEvents:  "none",
      boxShadow:      `0 0 12px ${color}33`,
      maxWidth:       "320px",
      whiteSpace:     "nowrap"
    });

    document.body.appendChild(el);
    tooltip = el;
  }

  function removeTooltip() {
    if (tooltip) { tooltip.remove(); tooltip = null; }
  }

  function updateTooltipPosition(x, y) {
    if (!tooltip) return;
    tooltip.style.top  = (y + 14) + "px";
    tooltip.style.left = (x + 14) + "px";
  }

  // ── Hover: show ML-powered tooltip ─────────────────────────
  document.addEventListener("mouseover", (e) => {
    const link = e.target.closest("a[href]");
    if (!link) return;

    const url = link.href;
    if (!url || url === lastHoverUrl) return;
    lastHoverUrl = url;

    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => {
      chrome.runtime.sendMessage({ action: "ML_PREDICT", url }, (resp) => {
        if (chrome.runtime.lastError || !resp?.success) return;
        createTooltip(e.clientX, e.clientY, resp.data);
      });
    }, 350); // 350ms debounce
  });

  document.addEventListener("mousemove", (e) => {
    updateTooltipPosition(e.clientX, e.clientY);
  });

  document.addEventListener("mouseout", (e) => {
    const link = e.target.closest("a[href]");
    if (link) {
      clearTimeout(hoverTimer);
      removeTooltip();
      lastHoverUrl = null;
    }
  });

  // ── Click: block high-risk links ────────────────────────────
  document.addEventListener("click", (e) => {
    const link = e.target.closest("a[href]");
    if (!link) return;

    const url = link.href;
    if (!url || url.startsWith("javascript:")) return;

    // Prevent navigation immediately; restore if ML says it's safe
    e.preventDefault();
    e.stopImmediatePropagation();

    chrome.runtime.sendMessage({ action: "ML_PREDICT", url }, (resp) => {
      if (chrome.runtime.lastError || !resp?.success) {
        // API unreachable — allow navigation (fail open)
        window.location.href = url;
        return;
      }

      const result = resp.data;

      if (!result.isSafe && result.riskLevel === "High") {
        // High risk — show confirmation dialog
        const proceed = window.confirm(
          `⚠️ CyberSafe Warning\n\n` +
          `This link looks dangerous.\n` +
          `Type: ${result.scamType}\n` +
          `Risk Score: ${result.riskScore}/100\n\n` +
          `Do you still want to proceed?`
        );
        if (proceed) window.location.href = url;
      } else {
        // Safe or medium — allow navigation
        window.location.href = url;
      }
    });
  }, true); // capture phase so we intercept before other handlers

  // ── Message listener: GET_PAGE_DATA + PING ──────────────────
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Health check from background.js
    if (request.action === "PING") {
      sendResponse({ success: true });
      return false;
    }

    if (request.action === "GET_PAGE_DATA") {
      try {
        const links = Array.from(document.querySelectorAll("a[href]"))
          .map(a => a.href)
          .filter(href => href && href.startsWith("http"));

        // Basic form signals (used as context, not for local scoring)
        const forms          = document.querySelectorAll("form");
        const passwordFields = document.querySelectorAll("input[type='password']");
        const sensitiveInputs = document.querySelectorAll(
          "input[type='text'][name*='card'], input[name*='cvv'], input[name*='ssn'], input[name*='otp'], input[name*='pin']"
        );

        sendResponse({
          success: true,
          data: {
            url:             window.location.href,
            pageText:        document.body?.innerText || "",
            links,
            formCount:       forms.length,
            passwordFields:  passwordFields.length,
            sensitiveInputs: sensitiveInputs.length
          }
        });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }

      return false; // synchronous response
    }
  });

} // end guard
