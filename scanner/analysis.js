/* =============================================================
   CyberShield AI  -  scanner/analysis.js
   STATIC CONTENT INSPECTION.
   Decodes the file's bytes to text and looks for known malicious
   patterns: encoded PowerShell, long Base64 blobs, dangerous JS
   (eval/exec), obfuscation, suspicious URLs, ransomware / crypto
   keywords, Office-macro auto-run and Windows shell abuse.

   Exposes global `CS_ANALYSIS` with:
     - bytesToText(bytes, maxLen)
     - analyzeText(text)  => { findings:[...], printableRatio }
   ============================================================= */
(function (root) {
  "use strict";

  /* Decode bytes as ISO-8859-1 so embedded ASCII strings inside
     binaries (e.g. an EXE) are still searchable. Caps the length
     so scanning huge files stays fast. */
  function bytesToText(bytes, maxLen = 512 * 1024) {
    const n = Math.min(bytes.length, maxLen);
    const slice = bytes.subarray(0, n);
    try {
      return new TextDecoder("iso-8859-1").decode(slice);
    } catch (e) {
      // Manual fallback if TextDecoder/label unsupported
      let s = "";
      for (let i = 0; i < n; i++) s += String.fromCharCode(slice[i]);
      return s;
    }
  }

  /* Ratio of printable characters (used to decide text vs binary). */
  function printableRatio(text) {
    if (!text.length) return 0;
    let p = 0;
    const n = Math.min(text.length, 4096);
    for (let i = 0; i < n; i++) {
      const c = text.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) p++;
    }
    return p / n;
  }

  /* Each rule: id, label, score, severity, and a test function
     that returns true / a matched sample when the pattern is found. */
  const RULES = [
    {
      id: "ps_encoded",
      label: "Encoded PowerShell command (-EncodedCommand)",
      score: 28, severity: "high",
      test: (t) => /powershell(\.exe)?[^\n]{0,40}-e(nc|ncodedcommand)?\b/i.test(t) ||
                   /FromBase64String\s*\(/i.test(t),
    },
    {
      id: "ps_download",
      label: "PowerShell remote download (Net.WebClient / DownloadString)",
      score: 26, severity: "high",
      test: (t) => /(New-Object\s+Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|iwr\s)/i.test(t),
    },
    {
      id: "ps_iex",
      label: "PowerShell Invoke-Expression (IEX) execution",
      score: 22, severity: "high",
      test: (t) => /(Invoke-Expression|\bIEX\b)/i.test(t),
    },
    {
      id: "ps_hidden",
      label: "Hidden / no-profile PowerShell window",
      score: 16, severity: "med",
      test: (t) => /-w(indowstyle)?\s+hidden|-nop\b|-noprofile\b|-ep\s+bypass|-executionpolicy\s+bypass/i.test(t),
    },
    {
      id: "eval_exec",
      label: "Dynamic code execution (eval / exec / Function)",
      score: 14, severity: "med",
      test: (t) => /\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|\bexecScript\s*\(/i.test(t),
    },
    {
      id: "js_obf_decode",
      label: "Obfuscated decoding (atob / unescape / fromCharCode)",
      score: 14, severity: "med",
      test: (t) => /\batob\s*\(|\bunescape\s*\(|String\.fromCharCode\s*\(|document\.write\s*\(/i.test(t),
    },
    {
      id: "base64_blob",
      label: "Long Base64 blob (possible embedded payload)",
      score: 12, severity: "med",
      test: (t) => /[A-Za-z0-9+/]{200,}={0,2}/.test(t),
    },
    {
      id: "hex_obfuscation",
      label: "Heavy hex/escape obfuscation",
      score: 15, severity: "med",
      test: (t) => (t.match(/\\x[0-9a-fA-F]{2}/g) || []).length > 40 ||
                   (t.match(/\\u[0-9a-fA-F]{4}/g) || []).length > 40,
    },
    {
      id: "url_exe",
      label: "URL pointing to an executable payload",
      score: 16, severity: "high",
      test: (t) => /https?:\/\/[^\s"'<>]+\.(exe|scr|bat|ps1|vbs|jar|hta|dll|msi)\b/i.test(t),
    },
    {
      id: "url_ip",
      label: "Hard-coded IP-address URL (no domain)",
      score: 10, severity: "med",
      test: (t) => /https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?/i.test(t),
    },
    {
      id: "url_shortener",
      label: "URL shortener (hides real destination)",
      score: 8, severity: "low",
      test: (t) => /https?:\/\/(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cutt\.ly|rb\.gy)\//i.test(t),
    },
    {
      id: "ransom_note",
      label: "Ransomware language (files encrypted / pay ransom)",
      score: 30, severity: "high",
      test: (t) => /(your files have been encrypted|all your files are encrypted|pay(ing)? the ransom|\.onion|decryptor|bitcoin address)/i.test(t),
    },
    {
      id: "crypto_api",
      label: "File-encryption API usage (AES / CryptEncrypt)",
      score: 12, severity: "med",
      test: (t) => /(AES-?256|CryptEncrypt|Rijndael|CryptoStream|vssadmin\s+delete\s+shadows|cipher\s+\/w)/i.test(t),
    },
    {
      id: "office_macro",
      label: "Auto-executing Office macro (Auto_Open / Document_Open)",
      score: 20, severity: "high",
      test: (t) => /(Auto_?Open|Workbook_Open|Document_Open|AutoExec)\b/i.test(t),
    },
    {
      id: "wscript_shell",
      label: "WScript.Shell object creation",
      score: 16, severity: "med",
      test: (t) => /CreateObject\s*\(\s*["']WScript\.Shell["']\s*\)|WScript\.Shell/i.test(t),
    },
    {
      id: "win_persistence",
      label: "Persistence / system tampering (registry, scheduled tasks)",
      score: 14, severity: "med",
      test: (t) => /(reg\s+add|schtasks\s+\/create|New-ItemProperty.*Run|bcdedit|taskkill\s+\/f|netsh\s+firewall)/i.test(t),
    },
    {
      id: "lolbin_download",
      label: "Living-off-the-land download (certutil / bitsadmin / curl)",
      score: 16, severity: "high",
      test: (t) => /(certutil\s+-urlcache|bitsadmin\s+\/transfer|\bcurl\s+-[^\n]*http|\bwget\s+http)/i.test(t),
    },
  ];

  /* Run all content rules against decoded text. */
  function analyzeText(text) {
    const findings = [];
    const ratio = printableRatio(text);
    for (const rule of RULES) {
      let hit = false;
      try { hit = rule.test(text); } catch (e) { hit = false; }
      if (hit) {
        findings.push({ id: rule.id, label: rule.label, score: rule.score, severity: rule.severity });
      }
    }
    return { findings, printableRatio: ratio };
  }

  const API = { bytesToText, analyzeText, printableRatio, RULES };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  root.CS_ANALYSIS = API;
})(typeof window !== "undefined" ? window : this);
