SAMPLE TEST FILES for the CyberShield AI File Scanner
=====================================================
Drag any of these onto the File Scanner (or use SELECT FILE TO SCAN):

  invoice.pdf.exe  -> CRITICAL  (double extension + real EXE 'MZ' header + tiny size)
  update.ps1       -> CRITICAL  (encoded PowerShell, IEX, Net.WebClient, payload URL)
  photo.png        -> SAFE      (genuine PNG signature, no indicators)
  notes.txt        -> SAFE      (plain text, nothing suspicious)

The verdict is deterministic: the same file always yields the same score.
These are harmless test fixtures (they do nothing if run).
