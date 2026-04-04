// ============================================================
// background.js — CyberSafe Service Worker
// Single source of truth: all ML predictions go through here.
// ============================================================

const ML_API = "http://127.0.0.1:8000/predict"; // the address of ML, it tells your extension, whenever you want prediction -> go here. "http://" = talk using internet, "127.0.0.1" = my owm computer, "8000" = port where FastAPI runs, "/predict" = function to call
const ML_BATCH_API = "http://127.0.0.1:8000/predict_batch"; // optional batch endpoint

// ── Prediction cache (survives within the service worker's lifetime) ──
// if i already checked this URL -> dont check again, because without this hover same link 10 times -> 10 API calls with cache: 1 API call -> reuse result
const predCache = new Map(); 

// ── call ML API for a single URL 
async function mlPredict(url) { // check one url
  if (predCache.has(url)) {     // already checked? -> reuse
    return predCache.get(url);
  }

  const res = await fetch(ML_API, { // send request to your FastAPI
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }) // send URL as: {"url": "something.com"}
  });

  if (!res.ok) throw new Error(`ML API error: ${res.status}`); // if API fails -> crash safely
  const data = await res.json(); // get result = ML response comes here

  // Expected API response shape:
  // {
  //   prediction: "benign" | "phishing" | "malware" | ...,
  //   confidence: 0.0–1.0,
  //   risk_score: 0–100,          // optional — we derive it if absent
  //   scam_type: "Phishing" | ... // optional — we derive it if absent
  // }

  const result = normaliseMLResponse(data, url); // convert messy ML output -> clean format
  predCache.set(url, result); // save result for future
  return result;
}

// ── call ML API for multiple URLs ────────────────────
// Falls back to sequential single-URL calls if no batch endpoint.
async function mlPredictBatch(urls) {
  try {
    const res = await fetch(ML_BATCH_API, { // faster (one request for all links)
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls })
    });
    if (!res.ok) throw new Error("batch endpoint unavailable");
    const dataList = await res.json(); // array of same shape as single predict
    return dataList.map((d, i) => normaliseMLResponse(d, urls[i]));
  } catch {
    // Fallback: sequential
    const results = [];
    for (const url of urls) { // ir fails -> fallback, check one by one
      try {
        results.push(await mlPredict(url));
      } catch (e) {
        results.push(errorResult(url, e.message));
      }
    }
    return results;
  }
}

// ── Normalise whatever the ML API returns into a consistent shape ──
function normaliseMLResponse(data, url) {
  const prediction = (data.prediction || "unknown").toLowerCase(); // clean label (phishing -> lowercase)
  const confidence  = typeof data.confidence  === "number" ? data.confidence  : 0.5; // if confidence missing -> assume 50%

  // if API didn't send score: confidence 0.87 -> riskScore 87
  let riskScore = typeof data.risk_score === "number"
    ? data.risk_score
    : Math.round(confidence * 100);

  // Clamp : keep between 0-100
  riskScore = Math.max(0, Math.min(100, riskScore));

  // Risk level: convert number -> human label
  let riskLevel;
  if (riskScore <= 25)      riskLevel = "Low";
  else if (riskScore <= 55) riskLevel = "Medium";
  else                       riskLevel = "High";

  // Scam type label : If API didn't give type -> guess it
  let scamType = data.scam_type || deriveScamType(prediction, riskScore);

  // Human-readable signals — use API's list if provided, else build one
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];

  return {
    url,
    prediction,   // raw ML label
    confidence,
    riskScore,
    riskLevel,
    scamType,
    reasons,
    isSafe: prediction === "benign" || riskScore <= 25
  };
}

function deriveScamType(prediction, riskScore) { 
  if (riskScore <= 25) return "Safe";
  if (riskScore <= 55) return "Suspicious";
  const map = {
    phishing:          "Credential Phishing",
    malware:           "Malware Distribution",
    spam:              "Spam",
    lottery:           "Lottery / Prize Scam",
    impersonation:     "Brand Impersonation",
    scam:              "Scam",
  };
  return map[prediction] || "Phishing";
}

function errorResult(url, msg) { // if ML fails : Prevents crash
  return {
    url,
    prediction: "unknown",
    confidence: 0,
    riskScore: 0,
    riskLevel: "Unknown",
    scamType: "Unknown",
    reasons: [msg || "Analysis failed"],
    isSafe: false,
    error: true
  };
}

// ── Inject content script if not already present ─────────────
async function ensureContentScript(tabId) { //if content.js not available then inject it manually
  try {
    await chrome.tabs.sendMessage(tabId, { action: "PING" });
  } catch {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
  }
}

// ── Message router : this listens to all messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) return false;

  // ── 1. Single URL prediction (hover / click from content.js) ──
  if (message.action === "ML_PREDICT") {
    mlPredict(message.url)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(err  => sendResponse({ success: false, error: err.message }));
    return true; // async
  }

  // ── 2. Full page scan (popup.js) ─────────────────────────────
  if (message.action === "SCAN_PAGE") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => { // get current tab
      if (!tabs || tabs.length === 0) {
        sendResponse({ success: false, error: "No active tab found." });
        return;
      }

      const tab = tabs[0];
      const tabUrl = tab.url || "";

      // Block internal browser pages
      if (/^(chrome|chrome-extension|edge|about):/.test(tabUrl)) {
        sendResponse({ success: false, error: "Cannot analyse browser internal pages." });
        return;
      }

      try {
        await ensureContentScript(tab.id);

        // Ask content script for page data (text, links, form info)
        const pageData = await new Promise((resolve, reject) => {
          chrome.tabs.sendMessage(tab.id, { action: "GET_PAGE_DATA" }, (resp) => { // from content.js gets page text, all links
            if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
            else if (!resp || !resp.success) reject(new Error(resp?.error || "No page data"));
            else resolve(resp.data);
          });
        });

        // 2a. Predict the main page URL
        const mainResult = await mlPredict(pageData.url);

        // 2b. Predict all links on the page (remove duplicates, skip same origin if desired)
        const uniqueLinks = [...new Set((pageData.links || []).filter(Boolean))];
        let linkResults = [];
        if (uniqueLinks.length > 0) {
          linkResults = await mlPredictBatch(uniqueLinks); // predict all links
        }

        // filter risky links
        const riskyLinks = linkResults.filter(r => !r.isSafe);

        // send final response
        sendResponse({
          success: true,
          data: {
            main: mainResult,
            pageText: pageData.pageText,
            linkSummary: {
              total: uniqueLinks.length,
              risky: riskyLinks.length,
              riskyLinks: riskyLinks.map(r => ({
                url: r.url,
                riskScore: r.riskScore,
                scamType: r.scamType
              }))
            }
          }
        });

      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    });

    return true; // async user hover= wait for ML, get result, show popup; withouy async (sync)= user hover link, no waithing, empty result, UI breaks
  }

  // ── 3. Internal ping (used by ensureContentScript) ───────────
  // (content.js handles PING, nothing to do here)

  return false;
});
