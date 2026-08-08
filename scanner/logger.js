/* =============================================================
   CyberShield AI  -  scanner/logger.js
   Persistent scan history using localStorage. Every scan is
   recorded with time, file name, size, SHA-256, score, verdict
   and the reasons. Survives page refresh (unlike the old demo).

   Exposes global `CS_LOGGER`.
   ============================================================= */
(function (root) {
  "use strict";

  const KEY = "cybershield.scanHistory.v2";
  const MAX = 100; // keep the most recent 100 scans

  /* Safely read the history array from localStorage. */
  function all() {
    try {
      const raw = root.localStorage ? root.localStorage.getItem(KEY) : null;
      const arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr : [];
    } catch (e) {
      return [];
    }
  }

  /* Persist the array back to localStorage. */
  function save(arr) {
    try {
      if (root.localStorage) root.localStorage.setItem(KEY, JSON.stringify(arr.slice(0, MAX)));
    } catch (e) { /* storage full or unavailable - ignore */ }
  }

  /* Add one scan result. Returns the stored entry (with id). */
  function add(result) {
    const entry = {
      id: "scan_" + Date.now() + "_" + Math.floor(Math.random() * 1e4),
      scannedAt: result.scannedAt || new Date().toISOString(),
      fileName: result.fileName,
      fileSize: result.fileSize,
      fileSizeHuman: result.fileSizeHuman,
      sha256: result.sha256,
      declaredType: result.declaredType,
      trueType: result.trueType,
      mismatch: result.mismatch,
      score: result.score,
      verdict: result.severity ? result.severity.label : "",
      verdictKey: result.severity ? result.severity.key : "",
      recommendation: result.recommendation,
      vt: result.vt ? {
        malicious: result.vt.malicious,
        suspicious: result.vt.suspicious,
        totalEngines: result.vt.totalEngines,
        permalink: result.vt.permalink,
        foundByHash: result.vt.foundByHash
      } : null,
      reasons: (result.reasons || []).map((r) => r.label),
    };
    const arr = all();
    arr.unshift(entry);
    save(arr);
    return entry;
  }

  /* Aggregate stats for the dashboard (from real history). */
  function stats() {
    const arr = all();
    const total = arr.length;
    const counts = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };
    let threats = 0, avg = 0;
    for (const e of arr) {
      if (counts[e.verdictKey] !== undefined) counts[e.verdictKey]++;
      if (e.verdictKey === "medium" || e.verdictKey === "high" || e.verdictKey === "critical") threats++;
      avg += (e.score || 0);
    }
    avg = total ? Math.round(avg / total) : 0;
    return { total, counts, threats, avgScore: avg, clean: counts.safe + counts.low };
  }

  function clear() { save([]); }

  const API = { add, all, stats, clear, KEY };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  root.CS_LOGGER = API;
})(typeof window !== "undefined" ? window : this);
