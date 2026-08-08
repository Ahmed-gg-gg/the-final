
## Startup mode selection

CyberShield now starts with a choice between the existing CyberShield AI and the existing CyberShield Academy. The original scanner project is preserved; Academy opens `academy.html`.

# CyberShield AI

**Predict Before You Get Hacked** — a futuristic, AI-themed cybersecurity dashboard.

> University final project prototype. This is **NOT** a real antivirus. All threats, scans, and metrics are simulated by a fake AI engine for demonstration purposes.

Available as a **web app**, **desktop app** (installable PWA + Electron), and **mobile app** (installable PWA + native APK).

---

## Features

- **Login screen** with AI typing effect, animated scan line, and fade transition into the dashboard.
- **Dashboard** with animated circular gauges (Threat Level, System Health), live count-ups (Protected Files, Network Status), and rolling **CPU / RAM** sparklines and bars.
- **AI Scanner** with a glowing shield, rotating scan sweep, animated progress bar, and live status messages (`Analyzing processes...`, `Checking USB...`, etc.).
- **Deterministic local scanner**: the same file always produces the same local result (SHA-256, magic-number type detection, extension/name/size/content rules).
- **VirusTotal integration (desktop/Electron)**: when `CYBERSHIELD_VT_API_KEY` is configured, VirusTotal multi-engine results become the final verdict. No random scan verdicts are generated.
- **Quarantine animation** — "Threat isolated successfully."
- **Threats** table with live status (active / quarantined / removed).
- **Network** page with an animated world map, connection nodes, firewall status ring, rolling traffic graph, and live packet counters.
- **Logs** timeline of security events.
- **Settings** with working toggles (Notifications, Auto Scan, Cloud AI, Language).
- **About** page with version and project info.
- **Bonus effects:** animated matrix background, floating connected particles, mouse-follow glow, neon buttons, live toast notifications, and fake live monitoring.

## Tech Stack

- **Frontend:** HTML5 + CSS3 + Vanilla JavaScript (no frameworks).
- **Desktop:** Electron (builds to `.exe` installer + portable).
- **Mobile:** Progressive Web App (installable on Android/iOS) + optional Capacitor APK.
- **Server:** Zero-dependency PowerShell static server (`serve.ps1`) for local PWA installation.
- **Charts:** Hand-drawn on `<canvas>` (no libraries).
- Fully responsive, dark cyber theme, works offline after first load.

## Project Structure

```
CyberShield-AI/
├── index.html               # Login + 6 pages
├── style.css                # Dark cyber theme, animations
├── script.js                # AI engine, charts, interactions
├── pwa.js                   # PWA install button + service worker registration
├── service-worker.js        # Offline caching
├── manifest.json            # PWA metadata (name, icons, theme)
├── main.js                  # Electron main process
├── preload.js               # Electron preload (secure context bridge)
├── package.json             # Electron build config
├── capacitor.config.json    # Native mobile config (Android)
├── serve.ps1 / serve.bat    # Zero-install local server
├── assets/
│   ├── favicon.svg          # Browser icon
│   ├── icon-192.png         # PWA icon (Android)
│   ├── icon-512.png         # PWA icon (desktop + Android)
│   ├── icon-maskable-512.png # Adaptive icon (Android)
│   └── apple-touch-icon.png # iOS home screen icon
├── build/
│   └── icon.png             # Electron app icon
├── DESKTOP-APP-GUIDE.md     # Desktop installation (Arabic)
├── MOBILE-APP-GUIDE.md      # Mobile installation (Arabic)
└── README.md
```

---

## 🌐 Quick Start (Web — open in browser)

**Option 1: Direct (file://)** — double-click `index.html`. Works immediately but PWA install requires a server.

**Option 2: Local server (http://)** — enables PWA installation and offline mode:
1. Double-click **`serve.bat`** (or run `powershell -ExecutionPolicy Bypass -File serve.ps1`).
2. Browser opens at `http://localhost:8080` → log in and use the app.
3. Look for an **Install** button in the browser address bar (Chrome/Edge) or inside the app navbar.

---

## 🖥️ Desktop App (Computer)

You have **two paths**. For quick presentations use PWA install; for a distributable `.exe` use Electron.

### Path A: Install as Desktop App (PWA — instant, no tools)
1. Run **`serve.bat`** → opens `http://localhost:8080`.
2. In **Chrome/Edge**, click the **Install** icon in the address bar (monitor with down arrow).
3. The app installs like a native program (Start menu + desktop icon), runs in its own window, works offline.

### Path B: Build a real `.exe` (Electron — requires Node.js)
1. Install [Node.js LTS](https://nodejs.org).
2. Open PowerShell in this folder:
   ```powershell
   npm install        # once: download Electron
   npm start          # dev: opens the app window
   npm run dist       # build: creates installer in dist/
   ```
3. Find `CyberShield AI Setup 1.0.0.exe` in `dist/` → distribute or install.

📘 **Full guide:** see [DESKTOP-APP-GUIDE.md](DESKTOP-APP-GUIDE.md) (Arabic).

---

## 📱 Mobile App (Phone)

### Path A: Install PWA on Phone (instant, recommended for demos)
1. **Deploy online (free):** Drag the entire `CyberShield-AI` folder to [Netlify Drop](https://app.netlify.com/drop) → get an HTTPS link like `https://cybershield-xyz.netlify.app`.
2. **Open on phone:** Visit that link in Chrome (Android) or Safari (iOS).
3. **Install:** Tap the browser prompt "Add to Home screen" / "Install app" → app icon appears on your home screen, opens fullscreen like a native app.

### Path B: Build a native APK (Android — requires Android Studio)
1. Install [Node.js](https://nodejs.org) + [Android Studio](https://developer.android.com/studio).
2. Run:
   ```powershell
   npm init -y
   npm install @capacitor/core @capacitor/cli @capacitor/android
   npx cap init "CyberShield AI" "com.cybershield.ai" --web-dir="."
   npx cap add android
   npx cap copy
   npx cap open android
   ```
3. In Android Studio: **Build → Build APK** → install the `.apk` on your phone.

📘 **Full guide:** see [MOBILE-APP-GUIDE.md](MOBILE-APP-GUIDE.md) (Arabic).

---

## VirusTotal Integration

The Electron desktop build can use the official VirusTotal API v3. The API key stays in the Electron main process and is **not exposed to the web renderer**.

1. Create/get a VirusTotal API key from your VirusTotal account.
2. Open PowerShell in the project folder.
3. Set the key for the current terminal:
   ```powershell
   $env:CYBERSHIELD_VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
   npm start
   ```
4. Scan a file from **File Scanner**.
5. The app first calculates the SHA-256 locally. It then checks VirusTotal by hash; if the hash is not known, the file is uploaded and the analysis is polled until completion.
6. The result card shows the number of **malicious / suspicious / total engines** and the final risk score is derived deterministically from those VirusTotal statistics.

**Important:** files uploaded to the standard/public VirusTotal API are subject to VirusTotal's handling and privacy terms. Do not upload confidential files without understanding those terms. For private scanning, VirusTotal documents a separate Private Scanning service with additional licensing requirements.

The browser/PWA version continues to use the deterministic local scanner because putting a VirusTotal API key directly into frontend JavaScript would expose the key.

## Presentation Tips

- **Web/PWA demo:** Run `serve.bat`, install to desktop live, show the icon and standalone window.
- **AI Scanner:** Run 2–3 scans back-to-back to prove results are randomized.
- **Quarantine:** Click "Quarantine" on a detected threat → watch the isolation animation.
- **Network:** Show the animated world map and live traffic graph.
- **Auto Scan:** Enable it in Settings to demonstrate "live monitoring" background toasts.

---

## Deployment Options Summary

| Target | Method | Output | Best For |
|--------|--------|--------|----------|
| **Web** | Open `index.html` | Runs in browser | Quick local demo |
| **Web (served)** | `serve.bat` | `http://localhost` | PWA installation |
| **Desktop (PWA)** | Install from browser | Desktop icon + window | Fast presentation |
| **Desktop (Electron)** | `npm run dist` | `.exe` installer | Submission file |
| **Mobile (PWA)** | Deploy to Netlify/GitHub Pages | Installable from browser | Demo on phone |
| **Mobile (APK)** | Capacitor + Android Studio | `.apk` file | Submission file |

---

Built for a Cyber Security final project. Prototype / demo only.
