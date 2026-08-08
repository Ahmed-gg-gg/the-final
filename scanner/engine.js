/* =============================================================
   CyberShield AI  -  scanner/engine.js
   THE DETECTION ENGINE (orchestrator).
   Coordinates rules + magic-numbers + hash + analysis to turn a
   real file into a deterministic risk report. No Math.random():
   the SAME file always yields the SAME score and verdict.

   Pipeline:
     metadata -> read bytes -> SHA-256 -> true type (magic) ->
     extension checks -> size checks -> name checks ->
     content inspection -> type-mismatch -> score -> classify.

   Exposes global `CS_ENGINE` with async scanFile(file, onProgress).
   ============================================================= */
(function (root) {
  "use strict";

  const RULES    = root.CS_RULES;
  const MAGIC    = root.CS_MAGIC;
  const HASH     = root.CS_HASH;
  const ANALYSIS = root.CS_ANALYSIS;

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /* ---- filename helpers ---- */
  function getExtension(name) {
    const parts = String(name).toLowerCase().split(".");
    return parts.length > 1 ? parts.pop() : "";
  }
  // All trailing extension-like tokens, e.g. "invoice.pdf.exe" -> ["pdf","exe"]
  function getExtensionChain(name) {
    const parts = String(name).toLowerCase().split(".");
    if (parts.length < 2) return [];
    return parts.slice(1).filter((p) => /^[a-z0-9]{1,5}$/.test(p));
  }
  function baseName(name) { return String(name).toLowerCase().replace(/\.[^.]+$/, ""); }

  /* Human-readable size. */
  function humanSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    const u = ["KB", "MB", "GB", "TB"];
    let i = -1, n = bytes;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n < 10 ? 2 : 1) + " " + u[i];
  }

  /* Read a File/Blob into a Uint8Array (with FileReader fallback). */
  async function readBytes(file) {
    if (typeof file.arrayBuffer === "function") {
      return new Uint8Array(await file.arrayBuffer());
    }
    return await new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(new Uint8Array(fr.result));
      fr.onerror = () => reject(fr.error);
      fr.readAsArrayBuffer(file);
    });
  }

  /* Loose category for a declared extension (for mismatch checks). */
  function categoryForExtension(ext) {
    if (RULES.isExecutableExt(ext)) return "executable";
    if (["pdf","doc","docx","xls","xlsx","ppt","pptx","txt","rtf","csv"].includes(ext)) return "document";
    if (["jpg","jpeg","png","gif","bmp","svg","webp","ico"].includes(ext)) return "image";
    if (["mp3","mp4","avi","mkv","wav","ogg","mov"].includes(ext)) return "media";
    if (["zip","rar","7z","gz","tar"].includes(ext)) return "archive";
    if (["js","vbs","ps1","bat","cmd","sh","py","hta","wsf"].includes(ext)) return "script";
    return "unknown";
  }

  /* =============================================================
     MAIN: scan a single File object.
     onProgress(percent:Number, message:String) is optional.
     ============================================================= */
  async function scanFile(file, onProgress) {
    const report = (typeof onProgress === "function") ? onProgress : () => {};
    const reasons = [];       // scored contributions
    const addReason = (label, score, severity, category) =>
      reasons.push({ label, score: Math.round(score), severity: severity || "med", category: category || "meta" });

    // ---- 1) Metadata ----
    report(6, "Reading file metadata...");
    await sleep(180);
    const name        = file.name || "unnamed";
    const size        = file.size || 0;
    const ext         = getExtension(name);
    const extChain    = getExtensionChain(name);
    const declaredCat = categoryForExtension(ext);
    const declaredType = file.type || (ext ? ext.toUpperCase() + " file" : "unknown");

    // ---- 2) Read bytes ----
    report(20, "Reading file bytes...");
    const bytes = await readBytes(file);
    const header = bytes.subarray(0, 8192);      // enough for signatures
    await sleep(120);

    // ---- 3) SHA-256 ----
    report(38, "Computing SHA-256 hash...");
    const sha256 = await HASH.sha256(bytes);
    await sleep(160);

    // ---- 4) True type via magic numbers ----
    report(52, "Detecting true file type (magic numbers)...");
    const detected = MAGIC.detect(header);
    await sleep(160);

    // ---- 5) Extension analysis ----
    report(64, "Analyzing extension...");
    // Double extension trap: benign inner ext followed by executable outer ext
    if (extChain.length >= 2) {
      const outer = extChain[extChain.length - 1];
      const inner = extChain[extChain.length - 2];
      if (RULES.isExecutableExt(outer) && RULES.DOCUMENT_EXTENSIONS.includes(inner)) {
        addReason(`Double extension "${inner}.${outer}" disguises an executable as a ${inner.toUpperCase()} file`, 45, "high", "extension");
      }
    }
    // Executable / script extension base risk
    if (RULES.isExecutableExt(ext)) {
      const info = RULES.EXECUTABLE_EXTENSIONS[ext];
      addReason(`Executable/code extension .${ext} (${info.note})`, info.score, info.score >= 30 ? "high" : "med", "extension");
    }
    // Macro-enabled Office document
    if (RULES.MACRO_EXTENSIONS.includes(ext)) {
      addReason(`Macro-enabled Office document (.${ext}) can auto-run code`, 18, "med", "extension");
    }
    await sleep(120);

    // ---- 6) Size analysis ----
    report(72, "Analyzing file size...");
    if (size === 0) {
      addReason("File is empty (0 bytes)", 6, "low", "size");
    } else {
      let sizeCat = null;
      if (declaredCat === "executable" || detected.category === "executable") sizeCat = RULES.SIZE_RULES.executable;
      else if (ext === "msi") sizeCat = RULES.SIZE_RULES.installer;
      else if (declaredCat === "document" || detected.category === "document") sizeCat = RULES.SIZE_RULES.document;
      else if (declaredCat === "image" || detected.category === "image") sizeCat = RULES.SIZE_RULES.image;
      if (sizeCat) {
        if (size < sizeCat.min) addReason(`Unusually small for a ${sizeCat.note} (${humanSize(size)}) - possible dropper/stub`, sizeCat.belowScore, "med", "size");
        else if (size > sizeCat.max) addReason(`Unusually large for a ${sizeCat.note} (${humanSize(size)})`, sizeCat.aboveScore, "low", "size");
      }
    }
    await sleep(120);

    // ---- 7) Name analysis ----
    report(80, "Inspecting file name...");
    const lowerBase = baseName(name);
    const lowerName = String(name).toLowerCase();
    const keywordsHit = [];
    for (const kw of RULES.SUSPICIOUS_KEYWORDS) {
      if (lowerName.indexOf(kw.word) !== -1) keywordsHit.push(kw);
    }
    if (keywordsHit.length) {
      // Sum keyword scores but cap the name contribution to avoid runaway totals
      let kwScore = keywordsHit.reduce((s, k) => s + k.score, 0);
      kwScore = Math.min(kwScore, 40);
      addReason(`Suspicious name keyword(s): ${keywordsHit.map((k) => k.word).join(", ")}`, kwScore, kwScore >= 20 ? "high" : "med", "name");
    }
    // System-process impersonation (e.g. a downloaded "svchost.exe")
    for (const proc of RULES.SYSTEM_PROCESS_NAMES) {
      if (lowerBase === proc && (RULES.isExecutableExt(ext) || detected.category === "executable")) {
        addReason(`Impersonates Windows system process "${proc}" outside System32`, 30, "high", "name");
        break;
      }
    }
    await sleep(120);

    // ---- 8) Content inspection ----
    report(90, "Scanning content for malicious patterns...");
    const scanContentCats = ["text", "script", "document", "executable", "unknown"];
    let contentFindings = [];
    if (scanContentCats.includes(detected.category) || declaredCat === "script" || declaredCat === "executable" || declaredCat === "document") {
      const text = ANALYSIS.bytesToText(bytes);
      const res = ANALYSIS.analyzeText(text);
      contentFindings = res.findings;
      let contentScore = 0;
      for (const f of contentFindings) {
        contentScore += f.score;
        addReason("Content: " + f.label, f.score, f.severity, "content");
      }
      // (individual reasons already added; nothing else needed)
    }
    await sleep(140);

    // ---- 9) Type mismatch (the big one) ----
    report(96, "Cross-checking declared vs true type...");
    let mismatch = false;
    if (detected.matched && detected.category === "executable" &&
        ["document", "image", "media", "archive"].includes(declaredCat)) {
      mismatch = true;
      addReason(`Type mismatch: extension claims ${declaredCat.toUpperCase()} (.${ext}) but content is an EXECUTABLE (${detected.type})`, 45, "high", "mismatch");
    } else if (detected.matched && ext && detected.ext && declaredCat !== "unknown" &&
               detected.category !== declaredCat &&
               !(declaredCat === "document" && detected.category === "archive") /* docx is a zip; ignore */) {
      mismatch = true;
      addReason(`Type mismatch: extension .${ext} (${declaredCat}) does not match detected ${detected.type} (${detected.category})`, 14, "med", "mismatch");
    }
    await sleep(120);

    // ---- 10) Aggregate + classify ----
    let total = reasons.reduce((s, r) => s + r.score, 0);
    total = Math.max(0, Math.min(100, total));
    const tier = RULES.classify(total);
    const recommendations = RULES.recommendationsFor(tier.key);

    // A friendly one-line verdict summary
    let summary;
    if (tier.key === "safe") {
      summary = "No malicious indicators found. The file's type, name, size and content look consistent and clean.";
    } else if (tier.key === "low") {
      summary = "Minor indicators found. Likely benign, but review the reasons below before trusting this file.";
    } else if (tier.key === "medium") {
      summary = "Several suspicious indicators found. Treat this file with caution and consider quarantining it.";
    } else if (tier.key === "high") {
      summary = "Strong malicious indicators found. This file is likely dangerous - quarantine or delete it.";
    } else {
      summary = "Critical malicious indicators found. This file is almost certainly malicious - do not open it.";
    }

    report(100, "Finalizing risk assessment...");
    await sleep(120);

    return {
      // file metadata
      fileName: name,
      fileSize: size,
      fileSizeHuman: humanSize(size),
      lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : null,
      declaredExt: ext,
      declaredType,
      declaredCategory: declaredCat,
      // detection
      trueType: detected.type,
      trueCategory: detected.category,
      trueExt: detected.ext,
      typeConfirmed: detected.matched,
      mismatch,
      // integrity
      sha256,
      // verdict
      score: total,
      severity: { key: tier.key, label: tier.label, sev: tier.sev, color: tier.color },
      summary,
      recommendation: recommendations[0],
      recommendations,
      reasons: reasons.sort((a, b) => b.score - a.score),
      contentFindings,
      scannedAt: new Date().toISOString(),
    };
  }

  const API = { scanFile, humanSize, getExtension, getExtensionChain };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  root.CS_ENGINE = API;
})(typeof window !== "undefined" ? window : this);
