# =============================================================
#  CyberShield AI  -  serve.ps1
#  A tiny zero-dependency static web server (Windows PowerShell).
#  Serves this folder at http://localhost:8080 so the PWA can be
#  installed and the service worker can run (both need http/localhost,
#  not file://). No Node.js or Python required.
#
#  Run:      powershell -ExecutionPolicy Bypass -File serve.ps1
#  Or just double-click  serve.bat
#  Stop:     press Ctrl+C in this window
# =============================================================
param(
  [int]$Port = 8080,
  [switch]$NoOpen   # pass -NoOpen to avoid auto-launching the browser
)

Add-Type -AssemblyName System.Web | Out-Null

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$prefix = "http://localhost:$Port/"

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)

try {
  $listener.Start()
} catch {
  Write-Host ""
  Write-Host "[!] Could not start the server on $prefix" -ForegroundColor Red
  Write-Host "    Another app may be using port $Port. Try a different port:" -ForegroundColor Yellow
  Write-Host "      powershell -ExecutionPolicy Bypass -File serve.ps1 -Port 8090" -ForegroundColor Yellow
  Write-Host "    If you see 'Access Denied', run PowerShell as Administrator once." -ForegroundColor Yellow
  exit 1
}

Write-Host ""
Write-Host "  CyberShield AI is running" -ForegroundColor Cyan
Write-Host "  ------------------------------------" -ForegroundColor DarkCyan
Write-Host "  URL:  $prefix" -ForegroundColor Green
Write-Host "  Root: $root"
Write-Host "  Stop: press Ctrl+C" -ForegroundColor DarkGray
Write-Host ""

if (-not $NoOpen) { Start-Process $prefix }

# Correct MIME types for the files the PWA needs
function Get-Mime([string]$file) {
  switch ([System.IO.Path]::GetExtension($file).ToLower()) {
    ".html" { return "text/html; charset=utf-8" }
    ".css"  { return "text/css; charset=utf-8" }
    ".js"   { return "application/javascript; charset=utf-8" }
    ".json" { return "application/json; charset=utf-8" }
    ".svg"  { return "image/svg+xml" }
    ".png"  { return "image/png" }
    ".ico"  { return "image/x-icon" }
    ".webmanifest" { return "application/manifest+json" }
    default { return [System.Web.MimeMapping]::GetMimeMapping($file) }
  }
}

try {
  while ($listener.IsListening) {
    $context = $listener.GetContext()          # blocks until a request arrives
    $request = $context.Request
    $response = $context.Response

    try {
      $rel = [System.Uri]::UnescapeDataString($request.Url.AbsolutePath.TrimStart("/"))
      if ([string]::IsNullOrWhiteSpace($rel)) { $rel = "index.html" }

      # Prevent directory traversal, then resolve the file inside root
      $rel = $rel -replace "\.\.", ""
      $path = Join-Path $root ($rel -replace "/", "\")
      if (Test-Path -LiteralPath $path -PathType Container) { $path = Join-Path $path "index.html" }

      if (Test-Path -LiteralPath $path -PathType Leaf) {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $response.ContentType = Get-Mime $path
        $response.Headers.Add("Cache-Control", "no-cache")
        $response.ContentLength64 = $bytes.Length
        $response.OutputStream.Write($bytes, 0, $bytes.Length)
        Write-Host ("  200  {0}" -f $rel) -ForegroundColor DarkGray
      } else {
        $response.StatusCode = 404
        $msg = [System.Text.Encoding]::UTF8.GetBytes("404 Not Found: $rel")
        $response.OutputStream.Write($msg, 0, $msg.Length)
        Write-Host ("  404  {0}" -f $rel) -ForegroundColor DarkYellow
      }
    } catch {
      $response.StatusCode = 500
    } finally {
      $response.OutputStream.Close()
    }
  }
} finally {
  $listener.Stop()
}
