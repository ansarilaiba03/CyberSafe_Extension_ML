// ============================================================
// popup.js — CyberSafe AI Guard (Offline Chatbot Engine)
// Zero API calls. All intelligence built from ML output + rules.
// ============================================================

// ── DOM refs ─────────────────────────────────────────────────
const elWatching        = document.getElementById("watching-state");
const elLinkCard        = document.getElementById("link-card");
const elRiskBadge       = document.getElementById("risk-badge");
const elLinkUrl         = document.getElementById("link-url");
const elLinkType        = document.getElementById("link-type");
const elScoreNum        = document.getElementById("score-num");
const elScoreBar        = document.getElementById("score-bar");
const elChatBox         = document.getElementById("chat-box");
const elIdlePlaceholder = document.getElementById("idle-placeholder");
const elChatInput       = document.getElementById("chat-input");
const elSendBtn         = document.getElementById("send-btn");
const elApiSetup        = document.getElementById("api-setup");

// ── State ─────────────────────────────────────────────────────
let currentLink     = null;
let isThinking      = false;
let lastProcessedTs = 0;

// ── Init ──────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  elApiSetup.classList.remove("visible"); // no API key needed

  const recent = await chrome.storage.local.get(["cybersafe_hovered_link"]);
  if (recent.cybersafe_hovered_link && Date.now() - recent.cybersafe_hovered_link.timestamp < 5000) {
    handleNewLink(recent.cybersafe_hovered_link);
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.cybersafe_hovered_link) {
      const val = changes.cybersafe_hovered_link.newValue;
      if (!val || val.timestamp === lastProcessedTs) return;
      lastProcessedTs = val.timestamp;
      handleNewLink(val);
    }
  });

  elChatInput.addEventListener("input", () => {
    elChatInput.style.height = "auto";
    elChatInput.style.height = Math.min(elChatInput.scrollHeight, 90) + "px";
  });
  elChatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleUserSend(); }
  });
  elSendBtn.addEventListener("click", handleUserSend);
});

// ── Handle new hovered link ───────────────────────────────────
async function handleNewLink(linkData) {
  const isSameUrl = currentLink && currentLink.url === linkData.url;
  currentLink = linkData;
  showLinkCard(linkData);
  elWatching.style.display = "none";

  if (!isSameUrl) {
    clearChat();
    addThinking();
    await sleep(600 + Math.random() * 400);
    removeThinking();
    addMessage("ai", buildBriefing(linkData));
  }
}

// ═══════════════════════════════════════════════════════════════
//  PART 1 — AUTO BRIEFING (fires on every new hover)
//  Generates a human-readable paragraph from ML data alone.
// ═══════════════════════════════════════════════════════════════

function buildBriefing(d) {
  const score  = d.riskScore;
  const level  = (d.riskLevel || "").toLowerCase();
  const type   = d.scamType   || "Unknown";
  const pred   = (d.prediction || "").toLowerCase();
  const conf   = Math.round((d.confidence || 0) * 100);
  const domain = extractDomain(d.url);

  // ── SAFE ──
  if (d.isSafe || score <= 25) {
    return pick([
      `This link looks safe. <strong>${domain}</strong> scored ${score}/100 — well within the safe zone. No phishing patterns, malware signatures, or suspicious redirects were detected. You can proceed with confidence.`,
      `No threats detected on <strong>${domain}</strong> (score: ${score}/100). The ML model found no credential-harvesting patterns, no malware indicators, and no suspicious URL structure. This appears to be a legitimate link.`,
      `<strong>${domain}</strong> checks out clean (${score}/100). URL structure, domain signals, and known threat patterns — all clear. Safe to click.`
    ]);
  }

  // ── RISKY — assemble from building blocks ──
  const opener  = buildOpener(level, type, domain, score);
  const why     = buildWhySection(pred, d.reasons || [], d.url, domain);
  const advice  = buildAdvice(level);
  const confStr = conf >= 80
    ? `The model is <strong>${conf}% confident</strong> in this classification.`
    : conf >= 60
    ? `Confidence is moderate at ${conf}% — treat this link with caution.`
    : `Confidence is ${conf}% — some signals detected but not fully certain. Avoid clicking anyway.`;

  return `${opener}<br><br>${why}<br><br>${advice} ${confStr}`;
}

function buildOpener(level, type, domain, score) {
  if (level === "high") return pick([
    `⚠ <strong>High risk detected</strong> on <strong>${domain}</strong> (score: ${score}/100). Classified as <strong>${type}</strong> — do not click this link.`,
    `🚨 <strong>Danger:</strong> <strong>${domain}</strong> scored ${score}/100 and is flagged as <strong>${type}</strong>. This link is likely malicious.`,
    `This link is <strong>highly suspicious</strong>. <strong>${domain}</strong> matches known <strong>${type}</strong> patterns with a risk score of ${score}/100.`
  ]);
  if (level === "medium") return pick([
    `⚠ <strong>Proceed with caution</strong> — <strong>${domain}</strong> scored ${score}/100 and shows signs of <strong>${type}</strong>.`,
    `This link is <strong>moderately suspicious</strong>. <strong>${domain}</strong> has traits consistent with <strong>${type}</strong> (score: ${score}/100).`,
    `Medium risk on <strong>${domain}</strong> (${score}/100). Patterns associated with <strong>${type}</strong> were detected.`
  ]);
  return `Low-level concern on <strong>${domain}</strong> (score: ${score}/100). Minor signals detected — worth being aware of.`;
}

function buildWhySection(pred, reasons, url, domain) {
  // Use real ML reasons first
  if (reasons.length > 0) {
    const top = reasons.slice(0, 2).join(" and ");
    return `The model flagged: <strong>${top}</strong>.`;
  }

  // Derive from URL structure
  const urlSignals = analyseUrl(url);

  const predMap = {
    phishing:      `Phishing sites mimic real brands to steal your login credentials. The URL structure of <strong>${domain}</strong> matches common phishing patterns — look-alike domains, suspicious subdomains, or misleading paths.`,
    malware:       `Malware distribution sites push harmful files or scripts to your device. <strong>${domain}</strong> has been flagged for distributing malicious content.`,
    spam:          `This looks like a spam link — typically used for ad fraud, fake surveys, or redirect chains. Visiting may track you or expose you to further scams.`,
    lottery:       `Lottery and prize scams claim you've won something to steal personal data or trick you into paying fake fees. <strong>${domain}</strong> matches these patterns.`,
    impersonation: `This site appears to impersonate a legitimate brand. <strong>${domain}</strong> is designed to look like a real company — a classic brand impersonation attack.`,
    scam:          `This link shows patterns of an online scam — fake shops, investment fraud, or deceptive offers. Do not share personal or financial information.`
  };

  const matchedKey = Object.keys(predMap).find(k => pred.includes(k));
  if (matchedKey) return predMap[matchedKey];

  if (urlSignals.length > 0) {
    return `Suspicious URL signals: <strong>${urlSignals.join(", ")}</strong>. These patterns are commonly found in malicious links.`;
  }

  return `The ML model detected anomalous patterns in the URL structure and domain that match known threat signatures.`;
}

function buildAdvice(level) {
  if (level === "high") return pick([
    `<strong>Do not click this link.</strong> If you received it via email or message, report it as phishing and delete it.`,
    `<strong>Avoid this link entirely.</strong> If it arrived unsolicited, it's almost certainly an attack. Block the sender.`,
    `<strong>Do not proceed.</strong> If you've already opened it, close the tab immediately and do not enter any information.`
  ]);
  if (level === "medium") return pick([
    `<strong>Be cautious.</strong> If you must visit, do not enter any passwords or personal information.`,
    `<strong>Think before clicking.</strong> If this came from an unknown source, best to avoid it.`,
    `<strong>Proceed only if you trust the source.</strong> Do not enter any credentials on this page.`
  ]);
  return `<strong>Stay alert.</strong> Risk is low but worth noting.`;
}

// ── URL signal scanner (100% local, no API) ───────────────────
function analyseUrl(url) {
  const signals = [];
  try {
    const u    = new URL(url);
    const host = u.hostname.toLowerCase();
    const path = u.pathname.toLowerCase();
    const full = url.toLowerCase();

    if ((host.match(/-/g) || []).length >= 3)
      signals.push("excessive hyphens in domain");
    if (/\d{4,}/.test(host))
      signals.push("long numeric string in domain");
    if (host.split(".").length > 4)
      signals.push("deeply nested subdomain");
    if (/login|signin|verify|secure|account|update|confirm/.test(host))
      signals.push("sensitive keyword in domain name");
    if (/login|signin|verify|secure|account|update|confirm/.test(path))
      signals.push("sensitive keyword in URL path");
    if (/paypal|google|apple|amazon|microsoft|facebook|netflix/.test(host) &&
        !isOfficialBrand(host))
      signals.push("brand name in unofficial domain");
    if (u.searchParams.toString().length > 200)
      signals.push("unusually long query string");
    if (/\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/.test(host))
      signals.push("free TLD commonly used in scams");
    if (/redirect|click\.php|out\.php|goto/.test(full))
      signals.push("redirect pattern in URL");
    if ((url.match(/%[0-9a-f]{2}/gi) || []).length > 5)
      signals.push("heavy URL encoding — possible obfuscation");
  } catch {}
  return signals;
}

function isOfficialBrand(host) {
  const brands = {
    "paypal.com": true, "google.com": true, "apple.com": true,
    "amazon.com": true, "microsoft.com": true, "facebook.com": true, "netflix.com": true
  };
  const parts = host.split(".");
  const root  = parts.slice(-2).join(".");
  return !!brands[root];
}

// ═══════════════════════════════════════════════════════════════
//  PART 2 — USER QUESTION HANDLER
//  Intent matching → rule-based answer built from ML data.
// ═══════════════════════════════════════════════════════════════

async function handleUserSend() {
  const text = elChatInput.value.trim();
  if (!text || isThinking) return;

  elChatInput.value = "";
  elChatInput.style.height = "auto";
  addMessage("user", text);

  isThinking = true;
  elSendBtn.disabled = true;
  addThinking();

  await sleep(450 + Math.random() * 500);

  const answer = buildResponse(text.toLowerCase(), currentLink);
  removeThinking();
  isThinking = false;
  elSendBtn.disabled = false;

  addMessage("ai", answer);
}

function buildResponse(q, d) {
  // ── No link context yet ──
  if (!d) {
    if (matchesAny(q, ["hello", "hi", "hey", "who are you", "what are you", "what can"])) {
      return "I'm CyberSafe — your AI security assistant. Hover over any link on the page and I'll instantly analyse it for threats, explain the risk, and tell you what to do. No internet connection needed.";
    }
    return "Hover over a link on the page first — then I can answer questions about it.";
  }

  const domain = extractDomain(d.url);
  const level  = (d.riskLevel || "").toLowerCase();
  const score  = d.riskScore;
  const type   = d.scamType  || "Unknown";
  const conf   = Math.round((d.confidence || 0) * 100);

  // ── Is it safe / should I click ──
  if (matchesAny(q, ["safe", "click", "open", "visit", "should i", "can i", "okay", "fine", "trust"])) {
    if (d.isSafe) return `Yes — <strong>${domain}</strong> appears safe (${score}/100). No threat indicators found. You can proceed.`;
    if (level === "high") return `<strong>No — do not click this link.</strong> <strong>${domain}</strong> scored ${score}/100 and is classified as <strong>${type}</strong>. It is very likely malicious.`;
    if (level === "medium") return `Proceed with caution. Score is ${score}/100 — medium risk. If you trust the source, you can visit but <strong>do not enter any passwords or personal information</strong>.`;
    return `Low risk (${score}/100) — you can likely proceed, but stay alert and don't enter sensitive info.`;
  }

  // ── What type of threat ──
  if (matchesAny(q, ["type", "kind", "what is", "classify", "category", "scam", "phishing", "malware", "threat"])) {
    const descriptions = {
      "Credential Phishing":   "a fake login page designed to steal your username and password.",
      "Malware Distribution":  "a site that tries to install harmful software on your device.",
      "Spam":                  "a spam link — used for ad fraud, fake surveys, or redirect chains.",
      "Lottery / Prize Scam":  "a fake lottery or prize claim designed to steal personal info or money.",
      "Brand Impersonation":   "a site impersonating a real brand to trick you into entering credentials.",
      "Scam":                  "a general scam — could be a fake shop, investment fraud, or deceptive offer.",
      "Safe":                  "a safe, legitimate link with no detected threats.",
      "Suspicious":            "a suspicious link that doesn't fit one specific category but has warning signals."
    };
    const desc = descriptions[type] || "an unclassified threat — treat with caution.";
    return `This link is classified as <strong>${type}</strong> — ${desc}`;
  }

  // ── Risk score meaning ──
  if (matchesAny(q, ["score", "number", "mean", "rating", "percentage", "100", "scale"])) {
    return `The risk score is <strong>${score}/100</strong>.<br><br>• 0–25 = Safe<br>• 26–55 = Medium risk<br>• 56–100 = High risk<br><br>This link is <strong>${d.riskLevel}</strong>. The model is ${conf}% confident in this assessment.`;
  }

  // ── Why / reasons / explain ──
  if (matchesAny(q, ["why", "reason", "because", "explain", "how", "detect", "flag", "signal"])) {
    if (d.reasons && d.reasons.length > 0) {
      const list = d.reasons.map(r => `• ${r}`).join("<br>");
      return `The ML model flagged these signals:<br><br>${list}`;
    }
    const urlSignals = analyseUrl(d.url);
    if (urlSignals.length > 0) {
      return `Based on URL analysis, I detected:<br><br>${urlSignals.map(s => `• ${s}`).join("<br>")}`;
    }
    return `The ML model analysed the URL structure, domain patterns, and known threat signatures. The combination of signals places <strong>${domain}</strong> in the <strong>${d.riskLevel}</strong> risk zone.`;
  }

  // ── What to do / precautions ──
  if (matchesAny(q, ["do", "precaution", "protect", "avoid", "action", "advice", "help", "suggest", "recommend", "now"])) {
    if (d.isSafe) return `No action needed — <strong>${domain}</strong> is safe. You can visit it normally.`;
    if (level === "high") return `<strong>Do not click the link.</strong><br><br>• If received via email, mark it as phishing and delete it<br>• If you've already opened it, close the tab immediately<br>• Do not enter any information on the page<br>• Run a malware scan if you downloaded anything`;
    return `<strong>Proceed with caution:</strong><br><br>• Do not enter passwords, card details, or personal info<br>• Verify the site through the official website directly<br>• If it came from an unknown source, avoid it`;
  }

  // ── Domain / URL info ──
  if (matchesAny(q, ["domain", "website", "site", "url", "address", "link"])) {
    return `Domain: <strong>${domain}</strong><br>Full URL: <strong>${truncate(d.url, 58)}</strong><br>ML Prediction: <strong>${d.prediction}</strong> (${conf}% confidence)`;
  }

  // ── Confidence ──
  if (matchesAny(q, ["confident", "confidence", "sure", "certain", "accurate", "correct", "reliable"])) {
    if (conf >= 85) return `The model is <strong>highly confident (${conf}%)</strong>. The threat patterns were strong and clear.`;
    if (conf >= 65) return `The model is <strong>moderately confident (${conf}%)</strong>. Suspicious signals were found but it isn't a textbook case. Still treat it with caution.`;
    return `Confidence is <strong>${conf}%</strong> — relatively low. Some signals were detected but the model isn't certain. I'd still recommend avoiding this link.`;
  }

  // ── How to report ──
  if (matchesAny(q, ["report", "block", "flag", "notify", "report it"])) {
    return `You can report phishing links to:<br><br>• <strong>Google Safe Browsing:</strong> safebrowsing.google.com/safebrowsing/report_phish<br>• <strong>Your email provider</strong> — mark the email as phishing<br>• <strong>CERT-In</strong> (India): incidents@cert-in.org.in<br><br>Blocking the sender also prevents future attacks.`;
  }

  // ── Other links ──
  if (matchesAny(q, ["other", "another", "more links", "rest", "compare"])) {
    return `I analyse links one at a time as you hover over them. Hover another link on the page and I'll instantly analyse that one too.`;
  }

  // ── Greetings ──
  if (matchesAny(q, ["hello", "hi", "hey", "thanks", "thank", "good", "great", "nice"])) {
    return `Happy to help! I'm watching links on this page for you. Ask me anything about the current link — or hover another one to analyse it.`;
  }

  // ── Contextual fallback ──
  return d.isSafe
    ? `<strong>${domain}</strong> is safe (${score}/100). Try asking: "why is it safe?", "what's the score mean?", or hover another link.`
    : pick([
        `I didn't quite catch that — but here's the summary: <strong>${domain}</strong> is <strong>${level}-risk</strong> (${score}/100), classified as <strong>${type}</strong>. Try asking: "why was it flagged?", "is it safe to click?", or "what should I do?"`,
        `Try asking: "why is this flagged?", "is it safe to click?", "what type of threat is this?", or "what should I do?" — I'll give you a clear answer.`
      ]);
}

// ═══════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════

function matchesAny(query, keywords) {
  return keywords.some(k => query.includes(k));
}

function pick(arr) {
  return Array.isArray(arr) ? arr[Math.floor(Math.random() * arr.length)] : arr;
}

function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return url; }
}

function truncate(str, len) {
  return str && str.length > len ? str.slice(0, len - 1) + "…" : (str || "");
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Link card ─────────────────────────────────────────────────
function showLinkCard(data) {
  elLinkCard.classList.add("visible");

  const level = (data.riskLevel || "unknown").toLowerCase();
  const cls   = data.isSafe ? "safe" : (level === "high" ? "high" : level === "medium" ? "medium" : "low");

  elRiskBadge.textContent = data.isSafe ? "SAFE" : data.riskLevel.toUpperCase();
  elRiskBadge.className   = `risk-badge ${cls}`;
  elLinkUrl.textContent   = truncate(data.url, 52);
  elLinkUrl.title         = data.url;
  elLinkType.textContent  = data.scamType || "Unknown";
  elScoreNum.textContent  = data.riskScore;
  elScoreNum.className    = `score-num ${cls}`;
  elScoreBar.style.width  = "0%";
  elScoreBar.className    = `score-bar-fill ${cls}`;
  requestAnimationFrame(() => setTimeout(() => {
    elScoreBar.style.width = data.riskScore + "%";
  }, 30));
}

// ── Chat UI ───────────────────────────────────────────────────
function clearChat() { elChatBox.innerHTML = ""; }

function addMessage(role, html) {
  if (elIdlePlaceholder && elIdlePlaceholder.parentNode) elIdlePlaceholder.remove();

  const wrap   = document.createElement("div");
  wrap.className = "msg fade-in";

  const avatar = document.createElement("div");
  avatar.className  = `msg-avatar ${role}`;
  avatar.textContent = role === "ai" ? "🛡" : "👤";

  const bubble = document.createElement("div");
  bubble.className = `msg-bubble ${role === "ai" ? "ai-bubble" : ""}`;
  bubble.innerHTML = sanitise(html);

  const time = document.createElement("div");
  time.className  = "msg-time";
  time.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  bubble.appendChild(time);

  wrap.appendChild(avatar);
  wrap.appendChild(bubble);
  elChatBox.appendChild(wrap);
  elChatBox.scrollTop = elChatBox.scrollHeight;
}

function addThinking() {
  const wrap = document.createElement("div");
  wrap.className = "msg"; wrap.id = "__thinking";

  const avatar = document.createElement("div");
  avatar.className = "msg-avatar ai"; avatar.textContent = "🛡";

  const bubble = document.createElement("div");
  bubble.className = "msg-bubble ai-bubble thinking";
  bubble.innerHTML  = `<span style="font-size:11px;color:var(--text-muted)">Analysing</span><div class="dot-loader"><span></span><span></span><span></span></div>`;

  wrap.appendChild(avatar); wrap.appendChild(bubble);
  elChatBox.appendChild(wrap);
  elChatBox.scrollTop = elChatBox.scrollHeight;
}

function removeThinking() {
  const el = document.getElementById("__thinking");
  if (el) el.remove();
}

function sanitise(str) {
  const d = document.createElement("div");
  d.textContent = str;
  let s = d.innerHTML;
  s = s.replace(/&lt;br&gt;/gi, "<br>");
  s = s.replace(/&lt;strong&gt;/gi, "<strong>");
  s = s.replace(/&lt;\/strong&gt;/gi, "</strong>");
  return s;
}
