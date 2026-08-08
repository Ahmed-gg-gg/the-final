/* =============================================================
   CyberShield AI  -  main.js  (Electron main process)
   Creates the desktop application window and loads the same
   web app (index.html) used by the browser + PWA versions.
   Run in dev:   npm start
   Build .exe:   npm run dist        (output in ./dist)
   ============================================================= */

const { app, BrowserWindow, Menu, shell, ipcMain } = require("electron");
const { scan: scanWithVirusTotal } = require("./virustotal");
const path = require("path");
const fs = require("fs/promises");

let mainWindow;

/* -------------------------------------------------------------
   VirusTotal bridge
   The renderer never receives the API key. Files are sent through
   Electron IPC to the main process, which talks to VirusTotal.
------------------------------------------------------------- */
ipcMain.handle("virustotal:configured", () => Boolean(process.env.CYBERSHIELD_VT_API_KEY));

ipcMain.handle("file:delete", async (_event, filePath) => {
  if (!filePath || typeof filePath !== "string") throw new Error("Invalid file path.");
  // Only allow deletion of an existing regular file selected by the user.
  const info = await fs.stat(filePath);
  if (!info.isFile()) throw new Error("The selected path is not a file.");
  await fs.unlink(filePath);
  return { success: true };
});

ipcMain.handle("virustotal:scan", async (_event, payload) => {
  if (!payload || !payload.bytes || !payload.sha256) {
    throw new Error("Invalid file payload.");
  }

  return scanWithVirusTotal({
    bytes: payload.bytes,
    fileName: payload.fileName,
    mimeType: payload.mimeType,
    sha256: payload.sha256
  }, (pct, message) => {
    // Progress events are intentionally not sent back here because
    // the current renderer uses a single Promise. The result remains
    // deterministic and the renderer can show a VT status phase.
  });
});


function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 640,
    backgroundColor: "#07111f",       // matches the cyber theme (no white flash)
    show: false,                        // show only when ready (smooth startup)
    autoHideMenuBar: true,              // hide the default menu bar
    title: "CyberShield AI",
    icon: path.join(__dirname, "build", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,           // security best practice
      nodeIntegration: false,           // do not expose Node to the page
      sandbox: true
    }
  });

  // Load the existing web app
  mainWindow.loadFile("index.html");

  // Show the window once the content has painted
  mainWindow.once("ready-to-show", () => mainWindow.show());

  // Open any external links (e.g. docs) in the system browser, not in-app
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http")) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  mainWindow.on("closed", () => (mainWindow = null));
}

/* Minimal application menu (keeps a clean, app-like feel) */
function buildMenu() {
  const template = [
    {
      label: "File",
      submenu: [{ role: "quit", label: "Exit" }]
    },
    {
      label: "View",
      submenu: [
        { role: "reload" },
        { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" }
      ]
    },
    {
      label: "Help",
      submenu: [
        {
          label: "About CyberShield AI",
          click: () => {
            if (mainWindow) mainWindow.webContents.executeJavaScript(
              "if (typeof switchPage==='function') switchPage('about');"
            );
          }
        }
      ]
    }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(() => {
  buildMenu();
  createWindow();

  // macOS: re-open a window when the dock icon is clicked
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Quit when all windows are closed (except on macOS)
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
