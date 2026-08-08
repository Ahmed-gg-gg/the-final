/* =============================================================
   CyberShield AI  -  scanner/rules.js
   The RULE DATABASE for the rule-based detection engine.
   Pure data + tiny helpers. No randomness. Same input => same output.

   Exposes a global `CS_RULES` object (browser) and also supports
   module.exports (Node.js) so the engine can be unit-tested in Node.
   ============================================================= */
(function (root) {
  "use strict";

  /* -------------------------------------------------------------
     1) EXECUTABLE / DANGEROUS EXTENSIONS
     Each carries a base score (0-100 scale contribution) and a note.
     These are the file types that can run code on a system.
  ------------------------------------------------------------- */
  const EXECUTABLE_EXTENSIONS = {
    exe:  { score: 35, note: "Windows executable" },
    scr:  { score: 40, note: "Windows screensaver executable (common malware disguise)" },
    com:  { score: 35, note: "DOS/Windows executable" },
    bat:  { score: 30, note: "Batch script (runs shell commands)" },
    cmd:  { score: 30, note: "Windows command script" },
    ps1:  { score: 32, note: "PowerShell script" },
    vbs:  { score: 32, note: "VBScript (often used by worms)" },
    vbe:  { score: 34, note: "Encoded VBScript" },
    js:   { score: 28, note: "JavaScript (can run via Windows Script Host)" },
    jse:  { score: 30, note: "Encoded JavaScript" },
    wsf:  { score: 30, note: "Windows Script File" },
    hta:  { score: 34, note: "HTML Application (runs with full trust)" },
    msi:  { score: 22, note: "Windows installer package" },
    jar:  { score: 26, note: "Java archive (executable)" },
    apk:  { score: 20, note: "Android package" },
    dll:  { score: 24, note: "Dynamic link library (loadable code)" },
    sys:  { score: 24, note: "System driver" },
    ps2:  { score: 30, note: "PowerShell script variant" },
    reg:  { score: 18, note: "Registry edit file" },
    lnk:  { score: 22, note: "Shortcut (can point to malicious targets)" },
    elf:  { score: 30, note: "Linux/Unix executable" },
    sh:   { score: 22, note: "Unix shell script" },
    py:   { score: 16, note: "Python script" },
  };

  /* Extensions that are generally safe documents/media.
     Used to detect "type mismatch" (e.g. .pdf that is really an .exe). */
  const DOCUMENT_EXTENSIONS = [
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "webp", "mp3", "mp4", "avi",
    "mkv", "wav", "zip", "rar", "7z", "gz", "json", "xml", "html",
  ];

  /* Office documents that can carry macros (extra caution). */
  const MACRO_EXTENSIONS = ["docm", "xlsm", "pptm", "dotm", "xltm"];

  /* -------------------------------------------------------------
     2) SUSPICIOUS NAME KEYWORDS
     Words frequently found in the names of malicious files.
  ------------------------------------------------------------- */
  const SUSPICIOUS_KEYWORDS = [
    { word: "crack",     score: 18, note: "Software crack" },
    { word: "keygen",    score: 18, note: "Key generator" },
    { word: "patch",     score: 10, note: "Unofficial patch" },
    { word: "activator", score: 16, note: "License activator" },
    { word: "loader",    score: 14, note: "Loader (often bundles malware)" },
    { word: "hack",      score: 14, note: "Hacking tool" },
    { word: "cheat",     score: 12, note: "Game cheat (common malware vector)" },
    { word: "nulled",    score: 16, note: "Pirated 'nulled' software" },
    { word: "warez",     score: 16, note: "Pirated software" },
    { word: "torrent",   score: 8,  note: "Torrent-sourced file" },
    { word: "free",      score: 5,  note: "'free' lure keyword" },
    { word: "bitcoin",   score: 14, note: "Cryptocurrency lure/miner" },
    { word: "wallet",    score: 12, note: "Crypto wallet lure" },
    { word: "miner",     score: 16, note: "Crypto miner" },
    { word: "ransom",    score: 22, note: "Ransomware indicator" },
    { word: "decrypt",   score: 16, note: "Decryptor (ransomware indicator)" },
    { word: "invoice",   score: 8,  note: "Invoice lure (phishing)" },
    { word: "receipt",   score: 8,  note: "Receipt lure (phishing)" },
    { word: "payment",   score: 8,  note: "Payment lure (phishing)" },
    { word: "urgent",    score: 6,  note: "Urgency lure (social engineering)" },
    { word: "setup",     score: 6,  note: "Installer keyword" },
    { word: "install",   score: 5,  note: "Installer keyword" },
    { word: "update",    score: 6,  note: "Fake update lure" },
    { word: "flashplayer", score: 14, note: "Fake Flash Player (classic malware)" },
    { word: "codec",     score: 10, note: "Fake codec (classic malware)" },
    { word: "vpn",       score: 6,  note: "Free VPN lure" },
    { word: "generator", score: 10, note: "Generator tool" },
    { word: "spoof",     score: 12, note: "Spoofing tool" },
    { word: "inject",    score: 14, note: "Injector" },
    { word: "trojan",    score: 20, note: "Explicit trojan reference" },
    { word: "backdoor",  score: 20, note: "Explicit backdoor reference" },
    { word: "rootkit",   score: 20, note: "Explicit rootkit reference" },
  ];

  /* -------------------------------------------------------------
     3) SYSTEM-PROCESS IMPERSONATION
     Legit Windows process names. If a downloaded file pretends to be
     one of these (esp. outside System32), that is highly suspicious.
  ------------------------------------------------------------- */
  const SYSTEM_PROCESS_NAMES = [
    "svchost", "csrss", "lsass", "winlogon", "services", "explorer",
    "smss", "wininit", "spoolsv", "taskhost", "dwm", "conhost",
    "rundll32", "regsvr32", "ctfmon",
  ];

  /* -------------------------------------------------------------
     4) SIZE HEURISTICS (bytes) per file category.
     Files far outside the expected range for their claimed type
     are suspicious (e.g. a 2 KB "installer", or a 1 KB "PDF").
  ------------------------------------------------------------- */
  const SIZE_RULES = {
    // category: [minExpected, maxExpected, scoreIfBelowMin, scoreIfAboveMax]
    executable: { min: 10 * 1024,       max: 300 * 1024 * 1024, belowScore: 15, aboveScore: 4,  note: "executable" },
    document:   { min: 1 * 1024,        max: 50 * 1024 * 1024,  belowScore: 8,  aboveScore: 6,  note: "document" },
    image:      { min: 100,             max: 40 * 1024 * 1024,  belowScore: 6,  aboveScore: 4,  note: "image" },
    installer:  { min: 50 * 1024,       max: 2 * 1024 * 1024 * 1024, belowScore: 18, aboveScore: 0, note: "installer" },
  };

  /* -------------------------------------------------------------
     5) RISK CLASSIFICATION TIERS (score => label + severity + color)
  ------------------------------------------------------------- */
  const RISK_TIERS = [
    { max: 20,  key: "safe",     label: "SAFE",          sev: "low",  color: "success" },
    { max: 40,  key: "low",      label: "LOW RISK",      sev: "low",  color: "muted"   },
    { max: 60,  key: "medium",   label: "MEDIUM RISK",   sev: "med",  color: "warning" },
    { max: 80,  key: "high",     label: "HIGH RISK",     sev: "high", color: "danger"  },
    { max: 100, key: "critical", label: "CRITICAL",      sev: "high", color: "danger"  },
  ];

  /* Map a 0-100 score to a risk tier. */
  function classify(score) {
    const s = Math.max(0, Math.min(100, Math.round(score)));
    for (const tier of RISK_TIERS) {
      if (s <= tier.max) return Object.assign({ score: s }, tier);
    }
    return Object.assign({ score: s }, RISK_TIERS[RISK_TIERS.length - 1]);
  }

  /* Map recommendations from a tier key. */
  function recommendationsFor(tierKey) {
    switch (tierKey) {
      case "critical":
      case "high":   return ["Quarantine", "Delete"];
      case "medium": return ["Quarantine", "Ignore"];
      default:        return ["Ignore"];
    }
  }

  /* Helper: is this extension executable/code? */
  function isExecutableExt(ext) {
    return Object.prototype.hasOwnProperty.call(EXECUTABLE_EXTENSIONS, (ext || "").toLowerCase());
  }

  const API = {
    EXECUTABLE_EXTENSIONS,
    DOCUMENT_EXTENSIONS,
    MACRO_EXTENSIONS,
    SUSPICIOUS_KEYWORDS,
    SYSTEM_PROCESS_NAMES,
    SIZE_RULES,
    RISK_TIERS,
    classify,
    recommendationsFor,
    isExecutableExt,
  };

  // Expose to browser (window.CS_RULES) and Node (module.exports)
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  root.CS_RULES = API;
})(typeof window !== "undefined" ? window : this);
