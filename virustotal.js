/* =============================================================
   CyberShield AI - virustotal.js
   Secure Electron-side VirusTotal API bridge.
   The API key is NEVER exposed to the renderer.
   Set it as an environment variable:
       CYBERSHIELD_VT_API_KEY=<your-key>
   ============================================================= */
"use strict";

const VT_BASE = "https://www.virustotal.com/api/v3";
const MAX_DIRECT_UPLOAD = 32 * 1024 * 1024;

function apiKey() {
  return process.env.CYBERSHIELD_VT_API_KEY || "";
}

function headers() {
  const key = apiKey();
  if (!key) throw new Error("VirusTotal API key is not configured. Set CYBERSHIELD_VT_API_KEY before starting the app.");
  return { "x-apikey": key };
}

async function parseJson(response) {
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (_) {}
  if (!response.ok) {
    const detail = body?.error?.message || body?.error?.code || `${response.status} ${response.statusText}`;
    const err = new Error(`VirusTotal API error: ${detail}`);
    err.status = response.status;
    err.body = body;
    throw err;
  }
  return body;
}

async function getFileReport(sha256) {
  const response = await fetch(`${VT_BASE}/files/${encodeURIComponent(sha256)}`, {
    headers: headers()
  });
  if (response.status === 404) return null;
  return parseJson(response);
}

async function uploadFile(buffer, fileName, mimeType) {
  let url = `${VT_BASE}/files`;
  if (buffer.length > MAX_DIRECT_UPLOAD) {
    const uploadResponse = await fetch(`${VT_BASE}/files/upload_url`, {
      headers: headers()
    });
    const uploadBody = await parseJson(uploadResponse);
    url = uploadBody.data;
  }

  const form = new FormData();
  form.append(
    "file",
    new Blob([buffer], { type: mimeType || "application/octet-stream" }),
    fileName || "unnamed"
  );

  const response = await fetch(url, {
    method: "POST",
    headers: headers(),
    body: form
  });
  return parseJson(response);
}

async function getAnalysis(analysisId) {
  const response = await fetch(`${VT_BASE}/analyses/${encodeURIComponent(analysisId)}`, {
    headers: headers()
  });
  return parseJson(response);
}

async function waitForAnalysis(analysisId, onProgress) {
  const started = Date.now();
  const timeout = 3 * 60 * 1000;

  while (Date.now() - started < timeout) {
    const body = await getAnalysis(analysisId);
    const attrs = body?.data?.attributes || {};
    const status = attrs.status || "queued";

    if (typeof onProgress === "function") {
      const pct = status === "completed" ? 94 : status === "queued" ? 70 : 82;
      onProgress(pct, `VirusTotal analysis: ${status}...`);
    }

    if (status === "completed") return body;
    await new Promise(resolve => setTimeout(resolve, 2500));
  }

  throw new Error("VirusTotal analysis timed out. Try again later.");
}

function statsFromReport(report) {
  return report?.data?.attributes?.last_analysis_stats || {};
}

function totalEngines(stats) {
  return Object.entries(stats)
    .filter(([key]) => key !== "type-unsupported")
    .reduce((sum, [, value]) => sum + (Number(value) || 0), 0);
}

/*
 * Deterministic mapping of VirusTotal engine statistics to the UI's
 * 0-100 risk scale. No randomness is involved.
 */
function classifyVT(stats) {
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const total = totalEngines(stats);

  let score = 0;
  let key = "safe";
  let label = "SAFE";

  if (malicious > 0) {
    score = Math.min(100, 65 + malicious * 5);
    if (malicious >= 10 || (total > 0 && malicious / total >= 0.15)) {
      key = "critical"; label = "CRITICAL";
    } else {
      key = "high"; label = "HIGH RISK";
    }
  } else if (suspicious > 0) {
    score = Math.min(59, 30 + suspicious * 5);
    key = score >= 50 ? "medium" : "low";
    label = key === "medium" ? "MEDIUM RISK" : "LOW RISK";
  }

  return {
    score,
    severity: {
      key,
      label,
      sev: key === "medium" ? "med" : (key === "high" || key === "critical") ? "high" : "low",
      color: key === "safe" ? "success" : key === "low" ? "muted" : key === "medium" ? "warning" : "danger"
    },
    malicious,
    suspicious,
    totalEngines: total
  };
}

function extractTopDetections(report, limit = 8) {
  const results = report?.data?.attributes?.last_analysis_results || {};
  return Object.entries(results)
    .filter(([, r]) => r && (r.category === "malicious" || r.category === "suspicious"))
    .sort((a, b) => String(a[1].category).localeCompare(String(b[1].category)))
    .slice(0, limit)
    .map(([engine, r]) => ({
      engine,
      category: r.category,
      result: r.result || "Detected"
    }));
}

async function scan({ bytes, fileName, mimeType, sha256 }, onProgress) {
  if (!apiKey()) {
    const err = new Error("VirusTotal is not configured. Set CYBERSHIELD_VT_API_KEY.");
    err.code = "VT_NOT_CONFIGURED";
    throw err;
  }

  const buffer = Buffer.from(bytes);
  onProgress?.(58, "Checking SHA-256 on VirusTotal...");

  let report = await getFileReport(sha256);
  let foundByHash = Boolean(report);
  let analysisId = null;

  if (!report) {
    onProgress?.(65, "File not found by hash. Uploading to VirusTotal...");
    const uploaded = await uploadFile(buffer, fileName, mimeType);
    analysisId = uploaded?.data?.id;
    if (!analysisId) throw new Error("VirusTotal did not return an analysis ID.");

    await waitForAnalysis(analysisId, onProgress);

    onProgress?.(96, "Retrieving VirusTotal report...");
    report = await getFileReport(sha256);

    if (!report) {
      throw new Error("VirusTotal analysis completed but the file report is not available yet.");
    }
  }

  const stats = statsFromReport(report);
  const verdict = classifyVT(stats);

  return {
    source: "VirusTotal",
    foundByHash,
    analysisId,
    sha256,
    score: verdict.score,
    severity: verdict.severity,
    stats,
    malicious: verdict.malicious,
    suspicious: verdict.suspicious,
    totalEngines: verdict.totalEngines,
    detections: extractTopDetections(report),
    permalink: `https://www.virustotal.com/gui/file/${sha256}`
  };
}

module.exports = { scan };
