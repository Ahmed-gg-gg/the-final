/* =============================================================
   CyberShield AI  -  scanner/magic-numbers.js
   REAL file-type detection by reading the file's first bytes
   ("magic numbers" / file signatures) instead of trusting the
   extension. This is how real security tools identify a file
   whose extension has been faked (e.g. invoice.pdf.exe).

   Exposes global `CS_MAGIC` with detect(bytes).
   ============================================================= */
(function (root) {
  "use strict";

  /* Each signature:
     - type      : human-readable file type
     - category  : one of executable|document|image|archive|media|database|script|text|unknown
     - ext       : the "true" extension(s) this signature implies
     - offset    : byte offset where the signature starts
     - bytes     : the signature bytes (decimal values)
     - verify    : optional extra check (fn) for container formats (RIFF, etc.)
  */
  const S = (type, category, ext, offset, bytes, verify) =>
    ({ type, category, ext, offset, bytes, verify });

  // Helper used by container verifiers to compare ASCII at an offset
  function asciiAt(b, offset, str) {
    for (let i = 0; i < str.length; i++) {
      if (b[offset + i] !== str.charCodeAt(i)) return false;
    }
    return true;
  }

  const SIGNATURES = [
    // ---- Executables ----
    S("Windows Executable (PE/DOS MZ)", "executable", "exe", 0, [0x4d, 0x5a]),                 // MZ
    S("Linux Executable (ELF)",         "executable", "elf", 0, [0x7f, 0x45, 0x4c, 0x46]),      // .ELF
    S("Java Class / Mach-O binary",     "executable", "class", 0, [0xca, 0xfe, 0xba, 0xbe]),
    S("Mach-O Executable (macOS)",      "executable", "macho", 0, [0xcf, 0xfa, 0xed, 0xfe]),
    S("WebAssembly Module",             "executable", "wasm", 0, [0x00, 0x61, 0x73, 0x6d]),

    // ---- Documents ----
    S("PDF Document",                   "document", "pdf", 0, [0x25, 0x50, 0x44, 0x46]),         // %PDF
    S("MS Office (legacy OLE)",         "document", "doc", 0, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
    S("Rich Text Format",               "document", "rtf", 0, [0x7b, 0x5c, 0x72, 0x74, 0x66]),   // {\rtf

    // ---- Images ----
    S("PNG Image",                      "image", "png", 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    S("JPEG Image",                     "image", "jpg", 0, [0xff, 0xd8, 0xff]),
    S("GIF Image",                      "image", "gif", 0, [0x47, 0x49, 0x46, 0x38]),            // GIF8
    S("BMP Image",                      "image", "bmp", 0, [0x42, 0x4d]),                        // BM
    S("Icon (ICO)",                     "image", "ico", 0, [0x00, 0x00, 0x01, 0x00]),

    // ---- Archives / containers (ZIP also covers docx/xlsx/apk/jar) ----
    S("ZIP Archive (or DOCX/XLSX/APK/JAR)", "archive", "zip", 0, [0x50, 0x4b, 0x03, 0x04]),      // PK..
    S("ZIP Archive (empty/spanned)",    "archive", "zip", 0, [0x50, 0x4b, 0x05, 0x06]),
    S("RAR Archive",                    "archive", "rar", 0, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]),
    S("7-Zip Archive",                  "archive", "7z", 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
    S("GZIP Archive",                   "archive", "gz", 0, [0x1f, 0x8b]),

    // ---- Media ----
    S("MP3 Audio (ID3)",                "media", "mp3", 0, [0x49, 0x44, 0x33]),                  // ID3
    S("OGG Media",                      "media", "ogg", 0, [0x4f, 0x67, 0x67, 0x53]),            // OggS
    // MP4/MOV: 'ftyp' box at offset 4
    S("MP4 / MOV Video",                "media", "mp4", 4, [0x66, 0x74, 0x79, 0x70]),            // ftyp
    // RIFF container: WAV or AVI (verify by subtype at offset 8)
    S("RIFF Media (WAV/AVI)",           "media", "riff", 0, [0x52, 0x49, 0x46, 0x46], (b) =>    // RIFF
        asciiAt(b, 8, "WAVE") ? { type: "WAV Audio", ext: "wav" }
      : asciiAt(b, 8, "AVI ") ? { type: "AVI Video", ext: "avi" }
      : asciiAt(b, 8, "WEBP") ? { type: "WebP Image", ext: "webp", category: "image" }
      : null),

    // ---- Database ----
    S("SQLite Database",                "database", "sqlite", 0,
      [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00]),

    // ---- Scripts / text ----
    S("Shell Script (shebang)",         "script", "sh", 0, [0x23, 0x21]),                        // #!
    S("XML Document",                   "text", "xml", 0, [0x3c, 0x3f, 0x78, 0x6d, 0x6c]),       // <?xml
  ];

  /* Compare a signature's bytes against the file buffer at its offset. */
  function matches(sig, bytes) {
    const start = sig.offset || 0;
    if (bytes.length < start + sig.bytes.length) return false;
    for (let i = 0; i < sig.bytes.length; i++) {
      if (bytes[start + i] !== sig.bytes[i]) return false;
    }
    return true;
  }

  /* Detect the true type from the first bytes of a file.
     `bytes` is a Uint8Array (the file header is enough). */
  function detect(bytes) {
    if (!bytes || bytes.length === 0) {
      return { type: "Empty file", category: "unknown", ext: "", matched: false };
    }
    for (const sig of SIGNATURES) {
      if (matches(sig, bytes)) {
        let type = sig.type, ext = sig.ext, category = sig.category;
        // Container formats resolve their real subtype
        if (typeof sig.verify === "function") {
          const v = sig.verify(bytes);
          if (v) { type = v.type || type; ext = v.ext || ext; category = v.category || category; }
        }
        return { type, category, ext, matched: true };
      }
    }
    // Heuristic: mostly-printable ASCII => plain text
    let printable = 0;
    const n = Math.min(bytes.length, 512);
    for (let i = 0; i < n; i++) {
      const c = bytes[i];
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
    }
    if (n > 0 && printable / n > 0.9) {
      return { type: "Plain text / source", category: "text", ext: "txt", matched: false };
    }
    return { type: "Unknown / binary", category: "unknown", ext: "", matched: false };
  }

  const API = { SIGNATURES, detect };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  root.CS_MAGIC = API;
})(typeof window !== "undefined" ? window : this);
