// ============================================================
// analyzer.js — CyberSafe Result Formatter
// ============================================================
// This file contains NO scoring or detection logic.
// All predictions come exclusively from the ML API (via background.js).
// This module's only job is to format the raw ML result into a
// consistent shape for popup.js to render.
// ============================================================

window.CyberSafeAnalyzer = { // creates a glogal tool called: CyberSafeAnalyzer

  /**
   * Format the raw scan result from background.js SCAN_PAGE
   * into the shape popup.js expects.
   *
   * @param {object} scanData   — response.data from SCAN_PAGE message
   * @returns {object}          — normalised result for renderResult()
   */
  formatScanResult(scanData) { // input= raw data from background.js/ML and output= clean structured result for UI
    const { main, linkSummary } = scanData; // Breaks the input into 2 parts=> main=overall page result, linkSummary=all links info

    return {
      success:     true,
      riskScore:   main.riskScore, // 0-100 danger
      riskLevel:   main.riskLevel, // low/medium/high
      scamType:    main.scamType, // phishing / malware
      reasons:     main.reasons || [], // why it's suspicious
      confidence:  main.confidence, // ML confidence
      linkSummary: this.formatLinkSummary(linkSummary), // suspicious links
      debug: { // used for display (0.87 -> 87%)
        mlProbability: Math.round((main.confidence || 0) * 100),
        prediction:    main.prediction
      }
    };
  },

  /**
   * Format the link summary into the shape popup.js expects.
   */
  formatLinkSummary(linkSummary = {}) {
    const risky = linkSummary.riskyLinks || []; // gets list of suspicious links
    return {
      total:  linkSummary.total  || 0, //toal links
      risky:  linkSummary.risky  || 0, // how many are dangerous
      issues: risky.map(r => { // loop through each bad link
        const display = r.url.length > 55 ? r.url.slice(0, 52) + "…" : r.url; // if URL is too long -> shorten it, becuase the popup becomes ugly
        return `[${r.scamType} · ${r.riskScore}] ${display}`; // creates a clean string
      })
    };
  }
};
