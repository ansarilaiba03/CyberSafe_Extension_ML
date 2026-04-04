// ============================================================
// popup.js — CyberSafe Popup UI Controller
// All analysis is delegated to background.js → ML API.
// ============================================================

// ── DOM References ───────────────────────────────────────────
const btnAnalyze     = document.getElementById("btn-analyze");
const stateIdle      = document.getElementById("state-idle");
const stateLoading   = document.getElementById("state-loading");
const stateResult    = document.getElementById("state-result");
const stateError     = document.getElementById("state-error");

const elRiskScore    = document.getElementById("risk-score");
const elRiskLevel    = document.getElementById("risk-level");
const elScamType     = document.getElementById("scam-type");
const elReasonsList  = document.getElementById("reasons-list");
const elScoreBar     = document.getElementById("score-bar-fill");
const elScoreCircle  = document.getElementById("score-circle");
const elErrorMsg     = document.getElementById("error-message");
const elPageUrl      = document.getElementById("page-url");
const elDbgML        = document.getElementById("dbg-ml");
const elDbgPred      = document.getElementById("dbg-pred");
const elBtnRetry     = document.getElementById("btn-retry");
const elBtnReanalyze = document.getElementById("btn-reanalyze");

// ── State switcher ───────────────────────────────────────────
function showState(name) {
  ["idle", "loading", "result", "error"].forEach(s => {
    const el = document.getElementById("state-" + s);
    if (el) el.style.display = "none";
  });
  const target = document.getElementById("state-" + name);
  if (target) target.style.display = "flex";
}

// ── Safe HTML escaping ───────────────────────────────────────
function escapeHTML(str) {
  const d = document.createElement("div");
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}

// ── Render result ────────────────────────────────────────────
function renderResult(result, pageUrl) {
  const { riskScore, riskLevel, scamType, reasons, debug, linkSummary } = result;
  const level = (riskLevel || "low").toLowerCase();

  // URL bar
  if (elPageUrl && pageUrl) {
    const display = pageUrl.length > 55 ? pageUrl.slice(0, 52) + "…" : pageUrl;
    elPageUrl.textContent = display;
    elPageUrl.title = pageUrl;
  }

  // Score circle
  if (elScoreCircle) {
    elScoreCircle.textContent = riskScore;
    elScoreCircle.className = `score-circle score-${level}`;
  }

  // Score bar
  if (elScoreBar) {
    elScoreBar.style.width = "0%";
    requestAnimationFrame(() => setTimeout(() => {
      elScoreBar.style.width = riskScore + "%";
      elScoreBar.className = `score-bar-fill bar-${level}`;
    }, 50));
  }

  if (elRiskScore) elRiskScore.textContent = riskScore + " / 100";

  if (elRiskLevel) {
    elRiskLevel.textContent = riskLevel;
    elRiskLevel.className = `tag tag-${level}`;
  }

  if (elScamType) {
    elScamType.textContent = scamType;
    elScamType.className = "tag tag-type";
  }

  // Detection signals
  if (elReasonsList) {
    elReasonsList.innerHTML = "";
    const items = reasons && reasons.length > 0
      ? reasons.map(r => ({ icon: "⚠", text: r, safe: false }))
      : [{ icon: "✓", text: "No suspicious signals detected", safe: true }];

    items.forEach(({ icon, text, safe }) => {
      const li = document.createElement("li");
      li.className = "reason-item" + (safe ? " reason-safe" : "");
      li.innerHTML = `<span class="reason-icon">${icon}</span> ${escapeHTML(text)}`;
      elReasonsList.appendChild(li);
    });
  }

  // Debug chips
  if (elDbgML)   elDbgML.textContent   = (debug?.mlProbability || 0) + "%";
  if (elDbgPred) elDbgPred.textContent = debug?.prediction || "—";

  // Link summary card
  const existingCard = document.getElementById("link-summary-card");
  if (existingCard) existingCard.remove();

  if (linkSummary && linkSummary.risky > 0) {
    const card = document.createElement("div");
    card.id = "link-summary-card";
    card.className = "reasons-card";

    const label = document.createElement("div");
    label.className = "section-label";
    label.textContent = `Suspicious Links (${linkSummary.risky} of ${linkSummary.total})`;
    card.appendChild(label);

    const list = document.createElement("ul");
    list.style.cssText = "list-style:none;display:flex;flex-direction:column;gap:6px;max-height:110px;overflow-y:auto;";

    (linkSummary.issues || []).forEach(issue => {
      const li = document.createElement("li");
      li.className = "reason-item";
      li.innerHTML = `<span class="reason-icon">🔗</span> ${escapeHTML(issue)}`;
      list.appendChild(li);
    });

    card.appendChild(list);

    const reasonsCard = document.querySelector(".reasons-card");
    if (reasonsCard?.parentNode) {
      reasonsCard.parentNode.insertBefore(card, reasonsCard.nextSibling);
    }
  }

  showState("result");
  animateScore(riskScore);
}

// ── Score counter animation ──────────────────────────────────
function animateScore(target) {
  if (!elScoreCircle) return;
  let current = 0;
  const step = Math.max(1, Math.ceil(target / 30));
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    elScoreCircle.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 30);
}

// ── Run full page scan ───────────────────────────────────────
async function runAnalysis() {
  showState("loading");

  try {
    // Ask background to run the ML scan on the active tab
    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action: "SCAN_PAGE" }, (resp) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(resp);
        }
      });
    });

    if (!response || !response.success) {
      throw new Error(response?.error || "Scan failed.");
    }

    // Format using analyzer.js (pure formatter — no scoring)
    if (!window.CyberSafeAnalyzer) {
      throw new Error("Analyzer module not loaded.");
    }

    const formatted = window.CyberSafeAnalyzer.formatScanResult(response.data);
    renderResult(formatted, response.data.main.url);

  } catch (err) {
    if (elErrorMsg) elErrorMsg.textContent = err.message;
    showState("error");
  }
}

// ── Boot ─────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  showState("idle");
  if (btnAnalyze)     btnAnalyze.addEventListener("click", runAnalysis);
  if (elBtnRetry)     elBtnRetry.addEventListener("click", runAnalysis);
  if (elBtnReanalyze) elBtnReanalyze.addEventListener("click", () => location.reload());
});
