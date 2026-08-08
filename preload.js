/* =============================================================
   CyberShield AI  -  preload.js  (Electron preload script)
   Runs in an isolated context before the page loads. We expose
   a tiny, safe read-only API so the web app can tell it is
   running as a desktop app. No Node.js access is leaked to the page.
   ============================================================= */

const { contextBridge, ipcRenderer, webUtils } = require("electron");

contextBridge.exposeInMainWorld("cybershield", {
  isDesktop: true,
  getFilePath: (file) => webUtils.getPathForFile(file),
  deleteFile: (filePath) => ipcRenderer.invoke("file:delete", filePath),
  platform: process.platform,        // 'win32' | 'darwin' | 'linux'
  virusTotal: {
    isConfigured: () => ipcRenderer.invoke("virustotal:configured"),
    scan: (payload) => ipcRenderer.invoke("virustotal:scan", payload)
  },
  versions: {
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node
  }
});
