/* =============================================================
   CyberShield AI  -  pwa.js
   Progressive Web App glue (loads AFTER script.js):
     1) Registers the service worker (enables offline + install).
     2) Adds an "Install App" button to the navbar when the browser
        offers installation (Chrome/Edge/Android).
     3) Handles the ?page= deep-link (app shortcut).
   Safe to run even when opened from file:// - it simply no-ops.
   ============================================================= */
(function () {
  "use strict";

  /* ---- 1) Register the service worker ---- */
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker
        .register("service-worker.js")
        .then(() => console.log("[PWA] Service worker registered."))
        .catch((err) => console.warn("[PWA] SW registration failed (need http/localhost):", err.message));
    });
  }

  /* ---- 2) Custom install flow ---- */
  let deferredPrompt = null;

  // Detect if already running as an installed app
  const isStandalone =
    window.matchMedia("(display-mode: standalone)").matches ||
    window.navigator.standalone === true;

  // Create the navbar install button (hidden until installable)
  function ensureInstallButton() {
    if (document.getElementById("installBtn")) return document.getElementById("installBtn");
    const navRight = document.querySelector(".nav-right");
    if (!navRight) return null;

    const btn = document.createElement("button");
    btn.id = "installBtn";
    btn.className = "icon-btn";
    btn.title = "Install CyberShield AI";
    btn.setAttribute("aria-label", "Install app");
    btn.style.display = "none";
    btn.innerHTML =
      '<svg viewBox="0 0 24 24"><path d="M5 20h14v-2H5v2ZM12 2v10.2l3.6-3.6L17 10l-5 5-5-5 1.4-1.4L12 12.2V2h0Z"/></svg>';
    // insert before the logout button so layout stays tidy
    const logout = document.getElementById("logoutBtn");
    navRight.insertBefore(btn, logout || null);

    btn.addEventListener("click", async () => {
      if (!deferredPrompt) return;
      deferredPrompt.prompt();
      const choice = await deferredPrompt.userChoice;
      deferredPrompt = null;
      btn.style.display = "none";
      if (typeof toast === "function") {
        choice && choice.outcome === "accepted"
          ? toast("Installing", "CyberShield AI is being added to your device.", "success")
          : toast("Install dismissed", "You can install later from the top bar.", "warning");
      }
    });
    return btn;
  }

  // Browser signals the app can be installed
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();          // stop the mini-infobar
    deferredPrompt = e;          // save for our custom button
    const btn = ensureInstallButton();
    if (btn && !isStandalone) {
      btn.style.display = "grid";
      if (typeof toast === "function") {
        toast("Install available", "Tap the download icon to install this app.", "accent");
      }
    }
  });

  // Confirmed installed
  window.addEventListener("appinstalled", () => {
    deferredPrompt = null;
    const btn = document.getElementById("installBtn");
    if (btn) btn.style.display = "none";
    if (typeof toast === "function") {
      toast("Installed", "CyberShield AI added successfully. Launch it like any app.", "success");
    }
  });

  /* ---- 3) App shortcut deep-link: ?page=scanner ---- */
  window.addEventListener("load", () => {
    const params = new URLSearchParams(location.search);
    const page = params.get("page");
    if (!page) return;
    // Wait until the user is inside the app shell, then navigate.
    const tryNav = () => {
      const shell = document.getElementById("appShell");
      if (shell && !shell.hidden && typeof switchPage === "function") {
        switchPage(page);
      } else {
        setTimeout(tryNav, 600);
      }
    };
    tryNav();
  });
})();
