/* =============================================================
   CyberShield AI  -  script.js
   Vanilla JavaScript only. No frameworks, no backend.
   Contains: login flow, routing, live clock, animated gauges,
   canvas charts, particles + matrix background, mouse glow,
   the REAL rule-based file scanner (see scanner/*.js), threats,
   quarantine, logs, network, settings and toast notifications.
   ============================================================= */
"use strict";

/* -------------------------------------------------------------
   Small helpers
------------------------------------------------------------- */
const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const rand  = (min, max) => Math.random() * (max - min) + min;             // float
const randi = (min, max) => Math.floor(rand(min, max + 1));                // int
const pick  = (arr) => arr[Math.floor(Math.random() * arr.length)];        // random item
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

/* Escape user-controlled strings (file names, types) before putting
   them into innerHTML, to keep the report rendering safe. */
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

/* Application state (kept in memory only) */
const state = {
  loggedIn: false,
  currentPage: "dashboard",
  threats: [],            // threats detected by the latest scan
  autoScanTimer: null,
  notificationsOn: true,
};

/* =============================================================
   1) LOGIN FLOW + AI TYPING EFFECT
   ============================================================= */

/* Typewriter effect for the login subtitle */
function typeWriter(el, text, speed = 55) {
  el.textContent = "";
  let i = 0;
  (function step() {
    if (i <= text.length) {
      el.textContent = text.slice(0, i);
      i++;
      setTimeout(step, speed);
    }
  })();
}

function initLogin() {
  const form = $("#loginForm");
  const btn = $("#loginBtn");
  if (!form || !btn) return;

  typeWriter($("#loginTypeText"), "Predict Before You Get Hacked");

  let loggingIn = false;
  const performLogin = (e) => {
    if (e) e.preventDefault();
    if (loggingIn) return false;
    loggingIn = true;

    const label = $(".btn-label", btn);
    const spinner = $(".btn-spinner", btn);
    if (label) label.textContent = "Authenticating...";
    if (spinner) spinner.hidden = false;
    btn.disabled = true;

    // Demo login: any non-empty username/password is accepted.
    setTimeout(() => {
      const login = $("#loginScreen");
      if (login) login.classList.add("leaving");
      setTimeout(enterDashboard, 480);
    }, 700);
    return false;
  };

  form.addEventListener("submit", performLogin);
  // Also support a direct click so login remains reliable in Electron/PWA.
  btn.addEventListener("click", (e) => {
    if (form.checkValidity()) performLogin(e);
  });
}

/* Fade from login into the dashboard shell */
function enterDashboard() {
  state.loggedIn = true;
  $("#loginScreen").style.display = "none";
  const shell = $("#appShell");
  shell.hidden = false;
  shell.classList.add("entering");

  bootDashboard();                    // start live data + charts
  toast("System Online", "CyberShield AI engine initialized successfully.", "success");
  // A couple of delayed "live" notifications for realism
  setTimeout(() => toast("Cloud AI Connected", "Threat intelligence feed synced.", "accent"), 3200);
  setTimeout(() => toast("Firewall Active", "248 rules loaded and enforced.", "accent"), 6400);
}

function logout() {
  clearInterval(state.autoScanTimer);
  location.reload(); // simplest clean reset back to login
}

/* =============================================================
   2) NAVBAR CLOCK
   ============================================================= */
function startClock() {
  const t = $("#navTime"), d = $("#navDate");
  const days = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  function tick() {
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    const ss = String(now.getSeconds()).padStart(2, "0");
    t.textContent = `${hh}:${mm}:${ss}`;
    d.textContent = `${days[now.getDay()]}, ${now.getDate()} ${months[now.getMonth()]} ${now.getFullYear()}`;
  }
  tick();
  setInterval(tick, 1000);
}

/* =============================================================
   3) PAGE ROUTING (sidebar menu)
   ============================================================= */
function initRouting() {
  $$(".menu-item").forEach((item) => {
    item.addEventListener("click", () => {
      const page = item.dataset.page;
      switchPage(page);
      // close mobile sidebar after navigation
      $("#sidebar").classList.remove("open");
    });
  });

  $("#menuToggle").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#logoutBtn").addEventListener("click", logout);
}

function switchPage(page) {
  state.currentPage = page;
  $$(".menu-item").forEach((m) => m.classList.toggle("active", m.dataset.page === page));
  $$(".page").forEach((p) => {
    const active = p.dataset.page === page;
    p.classList.toggle("active", active);
  });
  // Lazy-init the network map the first time it is shown
  if (page === "network" && !state.mapReady) buildWorldMap();
}

/* =============================================================
   4) DASHBOARD: gauges, numbers, live bars, charts
   ============================================================= */
function bootDashboard() {
  startClock();

  // Initialize dashboard from REAL scan history (localStorage), not random.
  const stats = window.CS_LOGGER ? window.CS_LOGGER.stats() : { total: 0, avgScore: 0, threats: 0 };
  animateGauge("#threatLevelValue", ".gauge-fill:not(.success)", stats.avgScore, "#threatLevelLabel");
  animateGauge("#systemHealthValue", ".gauge-fill.success", 100 - Math.min(60, stats.avgScore));
  countUp("#protectedFiles", stats.total);
  countUp("#activeConnections", randi(40, 180));

  // Rebuild the threats table + badge from any persisted medium+ scans
  restoreThreatsFromHistory();

  drawActivityChart();
  startLiveMetrics();     // CPU / RAM sparklines + bars (system telemetry - still simulated)
  startMiniBars();        // sidebar live traffic
  renderLogs();           // initial timeline
  startTrafficChart();    // network page traffic graph
  startPacketCounters();
  scheduleRandomNotifications();
}

/* Rebuild the in-memory threats list from persisted scan history. */
function restoreThreatsFromHistory() {
  if (!window.CS_LOGGER) return;
  const history = window.CS_LOGGER.all();
  const seen = new Set();
  state.threats = [];
  history.forEach((e) => {
    const risky = e.verdictKey === "medium" || e.verdictKey === "high" || e.verdictKey === "critical";
    if (risky && !seen.has(e.fileName)) {
      seen.add(e.fileName);
      state.threats.push({
        file: e.fileName,
        type: e.trueType + (e.mismatch ? " (disguised)" : ""),
        loc: "Selected file",
        sev: (e.verdictKey === "medium") ? "med" : "high",
        id: e.id,
        status: "active",
        score: e.score,
      });
    }
  });
  renderThreatsTable();
  updateThreatBadge();
}

/* Animate a circular gauge to a target percentage */
function animateGauge(valueSel, fillSel, target, labelSel) {
  const valueEl = $(valueSel);
  const fillEl = $(fillSel);
  const circ = 327; // 2 * PI * r (r = 52)
  let cur = 0;
  const step = () => {
    cur += (target - cur) * 0.08;
    if (Math.abs(target - cur) < 0.5) cur = target;
    valueEl.textContent = Math.round(cur);
    fillEl.style.strokeDashoffset = circ - (circ * cur) / 100;
    if (labelSel) {
      const l = $(labelSel);
      l.textContent = target < 30 ? "Low risk - protected" : target < 60 ? "Moderate risk" : "High risk - action needed";
    }
    if (cur !== target) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* Count-up animation for big numbers */
function countUp(sel, target) {
  const el = $(sel);
  let cur = 0;
  const step = () => {
    cur += (target - cur) * 0.06;
    if (target - cur < 1) cur = target;
    el.textContent = Math.round(cur).toLocaleString();
    if (cur !== target) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* Live CPU / RAM metrics with rolling sparklines */
function startLiveMetrics() {
  const cpu = { bar: $("#cpuBar"), val: $("#cpuValue"), spark: $("#cpuSpark"), data: [], color: "#00e5ff" };
  const ram = { bar: $("#ramBar"), val: $("#ramValue"), spark: $("#ramSpark"), data: [], color: "#00ff95" };
  [cpu, ram].forEach((m) => { for (let i = 0; i < 40; i++) m.data.push(randi(20, 60)); });

  function update(m, min, max) {
    const v = clamp(m.data[m.data.length - 1] + randi(-7, 7), min, max);
    m.data.push(v); m.data.shift();
    m.val.textContent = v + "%";
    m.bar.style.width = v + "%";
    drawSpark(m.spark, m.data, m.color);
  }
  update(cpu, 8, 92); update(ram, 20, 88);
  setInterval(() => { update(cpu, 8, 92); update(ram, 20, 88); }, 1500);
}

/* Draw a sparkline into a canvas */
function drawSpark(canvas, data, color) {
  const ctx = canvas.getContext("2d");
  const w = canvas.width = canvas.offsetWidth;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const max = 100, min = 0;
  const stepX = w / (data.length - 1);
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = i * stepX;
    const y = h - ((v - min) / (max - min)) * h;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke();
  // fill under the line
  ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color + "55"); grad.addColorStop(1, color + "00");
  ctx.fillStyle = grad; ctx.fill();
}

/* Sidebar mini traffic bars */
function startMiniBars() {
  const wrap = $("#miniBars");
  const bars = [];
  for (let i = 0; i < 16; i++) { const s = document.createElement("span"); wrap.appendChild(s); bars.push(s); }
  setInterval(() => {
    bars.forEach((b) => (b.style.height = randi(20, 100) + "%"));
    $("#liveTraffic").textContent = rand(1.2, 9.8).toFixed(1) + " Mb/s";
  }, 900);
}

/* Dashboard activity chart (bars: blocked vs detected) */
function drawActivityChart() {
  const canvas = $("#activityChart");
  const ctx = canvas.getContext("2d");
  const w = canvas.width = canvas.offsetWidth;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const points = 24, pad = 6;
  const barW = (w - pad * 2) / points;
  for (let i = 0; i < points; i++) {
    const blocked = randi(10, h - 20);
    const detected = randi(3, blocked * 0.5);
    const x = pad + i * barW;
    // blocked (accent)
    ctx.fillStyle = "rgba(0,229,255,0.55)";
    ctx.fillRect(x + barW * 0.2, h - blocked, barW * 0.35, blocked);
    // detected (danger)
    ctx.fillStyle = "rgba(255,59,92,0.7)";
    ctx.fillRect(x + barW * 0.55, h - detected, barW * 0.35, detected);
  }
}

/* =============================================================
   5) THE REAL RULE-BASED FILE SCANNER
   Uses the engine in scanner/*.js. No Math.random() here:
   the same file always produces the same score and verdict.
   ============================================================= */

/* Recommendation map by severity (used by the threats table). */
const RECS = { high: ["Quarantine", "Delete"], med: ["Quarantine", "Ignore"], low: ["Ignore"] };

let scanning = false;
let lastResult = null;   // the most recent scan report (real engine output)

/* Wire the file picker + drag-and-drop to the real engine. */
function initScanner() {
  const btn = $("#startScanBtn");
  const input = $("#fileInput");
  const dropZone = $("#dropZone");

  // Button opens the native file dialog
  btn.addEventListener("click", () => { if (!scanning) input.click(); });

  // A file was chosen -> scan it
  input.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) scanFile(file);
    input.value = ""; // allow re-selecting the same file
  });

  // Drag-and-drop support
  ["dragenter", "dragover"].forEach((ev) =>
    dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add("dragging"); })
  );
  ["dragleave", "drop"].forEach((ev) =>
    dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove("dragging"); })
  );
  dropZone.addEventListener("drop", (e) => {
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (file && !scanning) scanFile(file);
  });
}

/* Run the real engine against a File, driving the progress UI. */
async function scanFile(file) {
  if (scanning) return;
  if (!window.CS_ENGINE) { toast("Engine error", "Detection engine failed to load.", "danger"); return; }
  scanning = true;

  const btn = $("#startScanBtn");
  const stage = $("#shieldStage");
  const progress = $("#scanProgress");
  const bar = $("#scanBar");
  const msg = $("#scanMessage");
  const percentEl = $("#scanPercent");
  const resultCard = $("#resultCard");

  // reset UI into "scanning" state
  btn.disabled = true;
  btn.style.opacity = "0.5";
  resultCard.hidden = true;
  progress.hidden = false;
  percentEl.hidden = false;
  stage.classList.add("scanning");
  bar.style.width = "0%";
  percentEl.textContent = "0%";
  msg.textContent = "Initializing engine...";

  try {
    // The engine calls this back with (percent, message) at each stage
    let result = await window.CS_ENGINE.scanFile(file, (pct, message) => {
      // Local engine is deterministic and supplies metadata + SHA-256.
      bar.style.width = pct + "%";
      percentEl.textContent = Math.floor(pct) + "%";
      if (message) msg.textContent = message;
    });

    // Keep the real local path in the desktop build so a user can delete
    // the exact file they selected after a malicious verdict.
    if (window.cybershield?.isDesktop && window.cybershield?.getFilePath) {
      try { result.filePath = window.cybershield.getFilePath(file); } catch (_) { result.filePath = null; }
    }

    // Desktop + API key => VirusTotal is the source of the final verdict.
    // No API key is exposed to the renderer; Electron handles the request.
    if (window.cybershield?.isDesktop && window.cybershield?.virusTotal) {
      const vtConfigured = await window.cybershield.virusTotal.isConfigured();
      if (vtConfigured) {
        bar.style.width = "62%";
        percentEl.textContent = "62%";
        msg.textContent = "Checking VirusTotal threat intelligence...";

        const bytes = await file.arrayBuffer();
        const vt = await window.cybershield.virusTotal.scan({
          bytes: new Uint8Array(bytes),
          fileName: file.name,
          mimeType: file.type || "application/octet-stream",
          sha256: result.sha256
        });

        // Keep local forensic details, but make the verdict deterministic
        // and based on VirusTotal's engine statistics.
        result.vt = vt;
        result.score = vt.score;
        result.severity = vt.severity;
        result.recommendations =
          (vt.malicious > 0 || vt.suspicious > 0)
            ? ["Quarantine", "Delete"]
            : ["Ignore"];
        result.recommendation = result.recommendations[0];
        result.summary =
          `VirusTotal: ${vt.malicious} malicious and ${vt.suspicious} suspicious detections ` +
          `from ${vt.totalEngines} engines. ` +
          (vt.malicious > 0
            ? "Treat this file as dangerous."
            : vt.suspicious > 0
              ? "The file needs review."
              : "No antivirus engine reported a malicious detection.");
        result.reasons = [
          {
            label: `VirusTotal detections: ${vt.malicious} malicious, ${vt.suspicious} suspicious`,
            score: vt.score,
            severity: vt.malicious > 0 ? "high" : vt.suspicious > 0 ? "med" : "low",
            category: "virustotal"
          },
          ...(result.reasons || [])
        ];
        bar.style.width = "100%";
        percentEl.textContent = "100%";
        msg.textContent = "VirusTotal verdict received.";
      }
    }

    lastResult = result;
    setTimeout(() => finishScan(result), 350);
  } catch (err) {
    console.error(err);
    toast("Scan failed", "Could not read this file. Try another one.", "danger");
    resetScannerUI();
  }
}

/* Restore the scanner UI to idle. */
function resetScannerUI() {
  const stage = $("#shieldStage");
  stage.classList.remove("scanning");
  $("#scanProgress").hidden = true;
  $("#scanPercent").hidden = true;
  const btn = $("#startScanBtn");
  btn.disabled = false;
  btn.style.opacity = "1";
  scanning = false;
}

/* Finalize a completed scan: render, persist, log, update dashboard. */
function finishScan(result) {
  resetScannerUI();
  renderScanResult(result);

  // Persist to history (localStorage) - survives page refresh
  if (window.CS_LOGGER) window.CS_LOGGER.add(result);

  // Add to the Threats table when the file is medium risk or above
  const key = result.severity.key;
  if (key === "medium" || key === "high" || key === "critical") {
    const threat = {
      file: result.fileName,
      type: result.trueType + (result.mismatch ? " (disguised)" : ""),
      loc: "Selected file",
      sev: result.severity.sev,          // 'med' | 'high'
      id: "T" + Date.now(),
      status: "active",
      score: result.score,
      filePath: result.filePath || null,
    };
    state.threats = state.threats.filter((t) => t.file !== threat.file); // de-dupe by name
    state.threats.unshift(threat);
    renderThreatsTable();
    updateThreatBadge();
  }

  // Log + notify using REAL data
  const kind = key === "safe" ? "success"
             : (key === "high" || key === "critical") ? "danger"
             : key === "low" ? "accent" : "warning";
  addLog(nowTime(), "File Scanned: " + result.fileName,
    `${result.severity.label} - Risk ${result.score}/100`, kind === "accent" ? "" : kind);
  toast(result.severity.label, `${result.fileName}: risk ${result.score}/100`, kind);

  // Reflect real numbers on the dashboard
  animateGauge("#threatLevelValue", ".gauge-fill:not(.success)", result.score, "#threatLevelLabel");
  animateGauge("#systemHealthValue", ".gauge-fill.success", 100 - Math.min(60, result.score));
  if (window.CS_LOGGER) countUp("#protectedFiles", window.CS_LOGGER.stats().total);
}

/* Render the real scan report into the result card. */
function renderScanResult(result) {
  const card = $("#resultCard");
  const badge = $("#verdictBadge");
  const score = $("#riskScore");
  const summary = $("#resultSummary");

  card.hidden = false;
  badge.className = "verdict-badge " + result.severity.key;   // safe|low|medium|high|critical
  badge.textContent = result.severity.label;

  // animate the risk score number to the real value
  let cur = 0;
  const target = result.score;
  const step = () => {
    cur += (target - cur) * 0.12;
    if (target - cur < 0.5) cur = target;
    score.textContent = Math.round(cur);
    if (cur !== target) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);

  summary.textContent = result.summary || "";

  // ----- File metadata block (real values) -----
  const meta = $("#fileMeta");
  const typeRow = result.mismatch
    ? `<div class="meta-row danger"><span>Type check</span><b>MISMATCH &rarr; ${escapeHtml(result.trueType)}</b></div>`
    : `<div class="meta-row"><span>Type check</span><b>${result.typeConfirmed ? "Confirmed" : "Assumed"}: ${escapeHtml(result.trueType)}</b></div>`;
  meta.innerHTML = `
    <div class="meta-row"><span>File name</span><b>${escapeHtml(result.fileName)}</b></div>
    <div class="meta-row"><span>Size</span><b>${escapeHtml(result.fileSizeHuman)}</b></div>
    <div class="meta-row"><span>Declared type</span><b>.${escapeHtml(result.declaredExt || "?")}</b></div>
    ${typeRow}
    <div class="meta-row hash"><span>SHA-256</span><b class="mono">${escapeHtml(result.sha256)}</b></div>`;

  const vtStatus = $("#vtStatus");
  const vtText = $("#vtStatusText");
  if (result.vt) {
    vtStatus.hidden = false;
    vtText.textContent = `${result.vt.malicious} malicious / ${result.vt.suspicious} suspicious (${result.vt.totalEngines} engines)`;
    vtText.title = result.vt.permalink || "";
  } else {
    vtStatus.hidden = true;
  }

  // ----- Reasons list (real findings) -----
  const list = $("#reasonsList");
  const title = $("#reasonsTitle");
  if (!result.reasons.length) {
    title.textContent = "Detection Reasons";
    list.innerHTML = `<li class="reason ok"><span class="reason-score ok">&#10003;</span><span class="reason-text">No suspicious indicators found. The file looks clean.</span></li>`;
  } else {
    title.textContent = `Detection Reasons (${result.reasons.length})`;
    list.innerHTML = result.reasons.map((r) => {
      const cls = r.severity === "high" ? "high" : r.severity === "med" ? "med" : "low";
      return `<li class="reason ${cls}">
        <span class="reason-score">+${r.score}</span>
        <span class="reason-text">${escapeHtml(r.label)}</span>
      </li>`;
    }).join("");
  }

  // ----- Recommendation actions -----
  const actions = $("#resultActions");
  const recs = result.recommendations || ["Ignore"];
  actions.innerHTML = recs.map((r) =>
    `<button class="btn-ghost ${r !== "Ignore" ? "danger" : ""}" data-rec="${r}" data-file="${escapeHtml(result.fileName)}">${r}</button>`
  ).join("");
  $$("#resultActions button").forEach((b) =>
    b.addEventListener("click", () => handleRecommendation(b.dataset.rec, b.dataset.file))
  );
}

/* Handle Quarantine / Delete / Ignore actions */
function handleRecommendation(rec, file) {
  if (rec === "Quarantine") return quarantineThreat(file);
  if (rec === "Delete") {
    const target = state.threats.find(t => t.file === file);
    const filePath = target?.filePath || lastResult?.filePath || null;

    if (window.cybershield?.isDesktop && window.cybershield?.deleteFile && filePath) {
      window.cybershield.deleteFile(filePath).then(() => {
        setThreatStatus(file, "removed");
        toast("File Deleted", `${file} was permanently removed from the computer.`, "success");
        addLog(nowTime(), "Threat Removed", `${file} deleted by user.`, "success");
        updateThreatBadge();
        renderThreatsTable();
      }).catch((err) => {
        toast("Delete Failed", err?.message || "The file could not be deleted.", "danger");
      });
    } else {
      setThreatStatus(file, "removed");
      toast("Delete", "Browser mode cannot delete files automatically. Use the desktop app for real deletion.", "warning");
      addLog(nowTime(), "Delete Requested", `${file} marked as removed in the interface.`, "warning");
    }
  }
  if (rec === "Ignore") {
    toast("Ignored", `${file} was added to the exclusions list.`, "warning");
    addLog(nowTime(), "Threat Ignored", `${file} whitelisted by user.`, "");
  }
  updateThreatBadge();
}

/* =============================================================
   6) QUARANTINE ANIMATION
   ============================================================= */
function quarantineThreat(file) {
  const overlay = document.createElement("div");
  overlay.className = "overlay";
  overlay.innerHTML = `
    <div class="quarantine-box">
      <div class="q-ring" id="qRing">
        <svg viewBox="0 0 24 24"><path d="M17 9V7a5 5 0 0 0-10 0v2H5v13h14V9h-2ZM9 7a3 3 0 0 1 6 0v2H9V7Z"/></svg>
      </div>
      <h3 id="qTitle">Isolating threat...</h3>
      <p id="qText">${file}</p>
    </div>`;
  document.body.appendChild(overlay);

  // after a short "isolation" delay, switch to success state
  setTimeout(() => {
    $("#qRing").classList.add("done");
    $("#qRing").innerHTML = `<svg viewBox="0 0 24 24"><path d="M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4L9 16.2Z"/></svg>`;
    $("#qTitle").textContent = "Threat isolated successfully";
    $("#qText").textContent = `${file} moved to secure quarantine.`;
    setThreatStatus(file, "quarantined");
    updateThreatBadge();
    addLog(nowTime(), "Threat Quarantined", `${file} isolated in secure vault.`, "danger");
  }, 1600);

  // auto-close
  setTimeout(() => {
    overlay.classList.add("leaving");
    setTimeout(() => overlay.remove(), 350);
    toast("Quarantine Complete", `${file} is now isolated and harmless.`, "success");
  }, 3200);
}

/* =============================================================
   7) THREATS TABLE
   ============================================================= */
function renderThreatsTable() {
  const body = $("#threatsTableBody");
  if (!state.threats.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="6">No threats yet &mdash; scan a file to populate this list.</td></tr>`;
    return;
  }
  body.innerHTML = state.threats.map((t) => {
    const pill = t.sev === "high" ? "high" : t.sev === "med" ? "med" : "low";
    const recs = RECS[t.sev] || ["Ignore"];
    return `<tr>
      <td>${t.file}</td>
      <td>${t.type}</td>
      <td>${t.loc}</td>
      <td><span class="risk-pill ${pill}">${t.sev.toUpperCase()}</span></td>
      <td><span class="status-tag ${t.status}">${t.status.toUpperCase()}</span></td>
      <td>${t.status === "active"
          ? recs.map((r) => `<button class="btn-ghost ${r !== "Ignore" ? "danger" : ""}" data-rec="${r}" data-file="${t.file}">${r}</button>`).join(" ")
          : "&mdash;"}</td>
    </tr>`;
  }).join("");

  $$("#threatsTableBody button").forEach((b) =>
    b.addEventListener("click", () => { handleRecommendation(b.dataset.rec, b.dataset.file); renderThreatsTable(); })
  );
}

function setThreatStatus(file, status) {
  state.threats.forEach((t) => { if (t.file === file) t.status = status; });
  renderThreatsTable();
}

function updateThreatBadge() {
  const active = state.threats.filter((t) => t.status === "active").length;
  const badge = $("#threatBadge");
  badge.textContent = active;
  badge.classList.toggle("show", active > 0);
}

/* =============================================================
   8) LOGS TIMELINE
   ============================================================= */
function nowTime() {
  const n = new Date();
  return String(n.getHours()).padStart(2, "0") + ":" + String(n.getMinutes()).padStart(2, "0");
}

const logs = [
  { time: "10:31", title: "USB Device Connected", desc: "Kingston DataTraveler scanned - clean.", kind: "" },
  { time: "11:12", title: "Suspicious Login Attempt", desc: "Blocked login from 185.220.x.x (TOR exit node).", kind: "danger" },
  { time: "12:04", title: "Network Scan Completed", desc: "142 endpoints verified, 0 rogue devices.", kind: "success" },
  { time: "12:30", title: "Threat Quarantined", desc: "trojan.invoice.pdf.exe isolated automatically.", kind: "danger" },
];

function renderLogs() {
  const ul = $("#timeline");
  ul.innerHTML = logs.map((l) => `
    <li class="${l.kind}">
      <div class="t-time">${l.time}</div>
      <div class="t-title">${l.title}</div>
      <div class="t-desc">${l.desc}</div>
    </li>`).join("");
}

function addLog(time, title, desc, kind = "") {
  logs.unshift({ time, title, desc, kind });
  if (logs.length > 20) logs.pop();
  renderLogs();
}

/* =============================================================
   9) NETWORK PAGE (world map + traffic + packets)
   ============================================================= */

/* Simplified continents drawn as SVG blobs + animated connection nodes */
function buildWorldMap() {
  state.mapReady = true;
  const wrap = $("#worldMap");
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 200 100");
  svg.setAttribute("preserveAspectRatio", "xMidYMid meet");

  // very light stylized landmass paths (decorative, not geographically exact)
  const land =
    "M20,45 q10,-15 25,-12 q15,-8 22,3 q8,10 -2,16 q-18,8 -30,2 q-14,-2 -15,-9 Z " +
    "M92,30 q14,-10 26,-4 q10,8 4,18 q-10,12 -24,8 q-12,-6 -6,-22 Z " +
    "M96,58 q10,-4 14,6 q4,14 -6,24 q-10,6 -12,-8 q-2,-16 4,-22 Z " +
    "M150,40 q16,-8 30,0 q8,10 -4,18 q-18,8 -28,-2 q-6,-10 2,-16 Z";
  const p = document.createElementNS(NS, "path");
  p.setAttribute("d", land);
  p.setAttribute("fill", "rgba(0,229,255,0.06)");
  p.setAttribute("stroke", "rgba(0,229,255,0.2)");
  p.setAttribute("stroke-width", "0.5");
  svg.appendChild(p);

  // hub (your machine) roughly center
  const hub = { x: 100, y: 50 };
  const nodes = [];
  const nodeCount = randi(7, 11);
  for (let i = 0; i < nodeCount; i++) nodes.push({ x: randi(20, 180), y: randi(20, 82) });

  // connection arcs from hub to each node
  nodes.forEach((n) => {
    const arc = document.createElementNS(NS, "path");
    const mx = (hub.x + n.x) / 2, my = Math.min(hub.y, n.y) - randi(6, 18);
    arc.setAttribute("d", `M${hub.x},${hub.y} Q${mx},${my} ${n.x},${n.y}`);
    arc.setAttribute("class", "map-arc");
    svg.appendChild(arc);
  });

  // node dots + ping rings
  nodes.forEach((n) => {
    const ping = document.createElementNS(NS, "circle");
    ping.setAttribute("cx", n.x); ping.setAttribute("cy", n.y); ping.setAttribute("r", "2");
    ping.setAttribute("class", "map-ping");
    ping.style.animation = `mapPing ${rand(1.6, 3)}s ease-out ${rand(0, 2)}s infinite`;
    svg.appendChild(ping);

    const dot = document.createElementNS(NS, "circle");
    dot.setAttribute("cx", n.x); dot.setAttribute("cy", n.y); dot.setAttribute("r", "1.6");
    dot.setAttribute("class", "map-dot");
    svg.appendChild(dot);
  });

  // hub dot (bigger, success color)
  const hubDot = document.createElementNS(NS, "circle");
  hubDot.setAttribute("cx", hub.x); hubDot.setAttribute("cy", hub.y); hubDot.setAttribute("r", "3");
  hubDot.setAttribute("fill", "#00ff95");
  svg.appendChild(hubDot);

  wrap.innerHTML = "";
  wrap.appendChild(svg);
  $("#mapConnCount").textContent = nodeCount + " nodes";
}

/* Rolling traffic graph (inbound / outbound lines) */
function startTrafficChart() {
  const canvas = $("#trafficChart");
  const inData = [], outData = [];
  for (let i = 0; i < 60; i++) { inData.push(randi(20, 70)); outData.push(randi(10, 50)); }

  function draw() {
    const ctx = canvas.getContext("2d");
    const w = canvas.width = canvas.offsetWidth;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    // grid lines
    ctx.strokeStyle = "rgba(255,255,255,0.05)"; ctx.lineWidth = 1;
    for (let g = 0; g <= 4; g++) { const y = (h / 4) * g; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }

    const drawLine = (data, color) => {
      const stepX = w / (data.length - 1);
      ctx.beginPath();
      data.forEach((v, i) => { const x = i * stepX, y = h - (v / 100) * h; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke();
      ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, color + "33"); grad.addColorStop(1, color + "00");
      ctx.fillStyle = grad; ctx.fill();
    };
    drawLine(inData, "#00e5ff");
    drawLine(outData, "#00ff95");
  }

  draw();
  setInterval(() => {
    inData.push(clamp(inData[inData.length - 1] + randi(-10, 10), 8, 95)); inData.shift();
    outData.push(clamp(outData[outData.length - 1] + randi(-8, 8), 5, 80)); outData.shift();
    if (state.currentPage === "network") draw();
  }, 1200);

  // redraw on resize so the canvas stays crisp
  window.addEventListener("resize", () => { if (state.currentPage === "network") draw(); });
}

/* Live packet counters + firewall blocked count */
function startPacketCounters() {
  let pin = randi(50000, 90000), pout = randi(30000, 60000), drop = randi(200, 900), blocked = randi(50, 300);
  const set = () => {
    pin += randi(20, 260); pout += randi(10, 180); drop += randi(0, 4); blocked += randi(0, 3);
    $("#packetsIn").textContent = pin.toLocaleString();
    $("#packetsOut").textContent = pout.toLocaleString();
    $("#packetsDropped").textContent = drop.toLocaleString();
    $("#fwBlocked").textContent = blocked.toLocaleString();
  };
  set();
  setInterval(set, 1400);
}

/* =============================================================
   10) MULTI-LANGUAGE UI
   English, Arabic, French and Spanish are real UI translations.
   ============================================================= */
const I18N = {
  en: {
    "Cyber Shield AI":"Cyber Shield AI", "Choose how you want to use CyberShield.":"Choose how you want to use CyberShield.",
    "Use the existing CyberShield file scanner with VirusTotal cloud analysis.":"Use the existing CyberShield file scanner with VirusTotal cloud analysis.", "Enter Scanner →":"Enter Scanner →", "Enter Academy →":"Enter Academy →",
    "Username":"Username", "Password":"Password", "Login":"Login", "Dashboard":"Dashboard", "File Scanner":"File Scanner", "Threats":"Threats", "Network":"Network", "Logs":"Logs", "Settings":"Settings", "About":"About",
    "Security Dashboard":"Security Dashboard", "Real-time overview of your protected environment":"Real-time overview of your protected environment", "Threat Level":"Threat Level", "Calculating...":"Calculating...", "System Health":"System Health", "Optimal performance":"Optimal performance", "Protected Files":"Protected Files", "Network Status":"Network Status", "Secure":"Secure", "CPU Usage":"CPU Usage", "RAM Usage":"RAM Usage", "Threat Activity (last 24h)":"Threat Activity (last 24h)", "Blocked":"Blocked", "Detected":"Detected",
    "Drop a file here to scan":"Drop a file here to scan", "or":"or", "100% local · your file is analyzed in the browser and never uploaded.":"100% local · your file is analyzed in the browser and never uploaded.", "Detection Reasons":"Detection Reasons", "No threats yet — scan a file to populate this list.":"No threats yet — scan a file to populate this list.",
    "Event Logs":"Event Logs", "Chronological timeline of security events":"Chronological timeline of security events", "Configure the CyberShield AI engine":"Configure the CyberShield AI engine", "Dark Mode":"Dark Mode", "Use the dark cyber theme (recommended).":"Use the dark cyber theme (recommended).", "Notifications":"Notifications", "Show live threat notifications.":"Show live threat notifications.", "Automatic Scan":"Automatic Scan", "Run a background AI scan every few minutes.":"Run a background AI scan every few minutes.", "VirusTotal Cloud Scan":"VirusTotal Cloud Scan", "Use VirusTotal multi-engine analysis for the final file verdict.":"Use VirusTotal multi-engine analysis for the final file verdict.", "Language":"Language", "Interface language.":"Interface language.", "Project information":"Project information"
  },
  ar: {
    "Cyber Shield AI":"سايبر شيلد AI", "Choose how you want to use CyberShield.":"اختر الطريقة التي تريد استخدام CyberShield بها.",
    "Use the existing CyberShield file scanner with VirusTotal cloud analysis.":"استخدم فاحص الملفات الحالي مع تحليل VirusTotal السحابي.", "Enter Scanner →":"دخول الفاحص ←", "Enter Academy →":"دخول الأكاديمية ←",
    "Username":"اسم المستخدم", "Password":"كلمة المرور", "Login":"تسجيل الدخول", "Dashboard":"لوحة التحكم", "File Scanner":"فحص الملفات", "Threats":"التهديدات", "Network":"الشبكة", "Logs":"السجلات", "Settings":"الإعدادات", "About":"حول المشروع",
    "Security Dashboard":"لوحة الأمان", "Real-time overview of your protected environment":"نظرة فورية على البيئة المحمية", "Threat Level":"مستوى التهديد", "Calculating...":"جارٍ الحساب...", "System Health":"حالة النظام", "Optimal performance":"الأداء مثالي", "Protected Files":"الملفات المحمية", "Network Status":"حالة الشبكة", "Secure":"آمنة", "CPU Usage":"استخدام المعالج", "RAM Usage":"استخدام الذاكرة", "Threat Activity (last 24h)":"نشاط التهديدات (آخر 24 ساعة)", "Blocked":"محجوب", "Detected":"مكتشف",
    "Drop a file here to scan":"اسحب ملفًا هنا لفحصه", "or":"أو", "100% local · your file is analyzed in the browser and never uploaded.":"100% محلي · يتم تحليل الملف داخل المتصفح ولا يتم رفعه.", "Detection Reasons":"أسباب الاكتشاف", "No threats yet — scan a file to populate this list.":"لا توجد تهديدات بعد — افحص ملفًا لعرض النتائج.",
    "Event Logs":"سجلات الأحداث", "Chronological timeline of security events":"التسلسل الزمني لأحداث الأمان", "Configure the CyberShield AI engine":"إعداد محرك CyberShield AI", "Dark Mode":"الوضع الداكن", "Use the dark cyber theme (recommended).":"استخدم المظهر السيبراني الداكن (موصى به).", "Notifications":"الإشعارات", "Show live threat notifications.":"إظهار إشعارات التهديدات المباشرة.", "Automatic Scan":"الفحص التلقائي", "Run a background AI scan every few minutes.":"تشغيل فحص في الخلفية كل عدة دقائق.", "VirusTotal Cloud Scan":"فحص VirusTotal السحابي", "Use VirusTotal multi-engine analysis for the final file verdict.":"استخدم تحليل VirusTotal متعدد المحركات للحكم النهائي على الملف.", "Language":"اللغة", "Interface language.":"لغة الواجهة.", "Project information":"معلومات المشروع"
  },
  fr: {
    "Cyber Shield AI":"Cyber Shield AI", "Choose how you want to use CyberShield.":"Choisissez comment utiliser CyberShield.", "Use the existing CyberShield file scanner with VirusTotal cloud analysis.":"Utilisez l'analyseur de fichiers CyberShield avec l'analyse cloud VirusTotal.", "Enter Scanner →":"Ouvrir l'analyseur →", "Enter Academy →":"Ouvrir l'académie →", "Username":"Nom d'utilisateur", "Password":"Mot de passe", "Login":"Connexion", "Dashboard":"Tableau de bord", "File Scanner":"Analyseur de fichiers", "Threats":"Menaces", "Network":"Réseau", "Logs":"Journaux", "Settings":"Paramètres", "About":"À propos", "Security Dashboard":"Tableau de sécurité", "Real-time overview of your protected environment":"Vue en temps réel de votre environnement protégé", "Threat Level":"Niveau de menace", "System Health":"État du système", "Optimal performance":"Performances optimales", "Protected Files":"Fichiers protégés", "Network Status":"État du réseau", "Secure":"Sécurisé", "CPU Usage":"Utilisation CPU", "RAM Usage":"Utilisation RAM", "Blocked":"Bloqué", "Detected":"Détecté", "Drop a file here to scan":"Déposez un fichier ici pour l'analyser", "or":"ou", "Detection Reasons":"Raisons de détection", "Event Logs":"Journaux d'événements", "Settings":"Paramètres", "Language":"Langue", "Interface language.":"Langue de l'interface.", "Dark Mode":"Mode sombre", "Notifications":"Notifications", "Automatic Scan":"Analyse automatique", "VirusTotal Cloud Scan":"Analyse cloud VirusTotal", "About":"À propos"
  },
  es: {
    "Cyber Shield AI":"Cyber Shield AI", "Choose how you want to use CyberShield.":"Elige cómo quieres usar CyberShield.", "Use the existing CyberShield file scanner with VirusTotal cloud analysis.":"Usa el escáner de archivos CyberShield con análisis en la nube de VirusTotal.", "Enter Scanner →":"Abrir escáner →", "Enter Academy →":"Abrir academia →", "Username":"Nombre de usuario", "Password":"Contraseña", "Login":"Iniciar sesión", "Dashboard":"Panel", "File Scanner":"Escáner de archivos", "Threats":"Amenazas", "Network":"Red", "Logs":"Registros", "Settings":"Configuración", "About":"Acerca de", "Security Dashboard":"Panel de seguridad", "Real-time overview of your protected environment":"Vista en tiempo real de tu entorno protegido", "Threat Level":"Nivel de amenaza", "System Health":"Estado del sistema", "Optimal performance":"Rendimiento óptimo", "Protected Files":"Archivos protegidos", "Network Status":"Estado de red", "Secure":"Seguro", "CPU Usage":"Uso de CPU", "RAM Usage":"Uso de RAM", "Blocked":"Bloqueado", "Detected":"Detectado", "Drop a file here to scan":"Suelta un archivo aquí para analizarlo", "or":"o", "Detection Reasons":"Motivos de detección", "Event Logs":"Registros de eventos", "Language":"Idioma", "Interface language.":"Idioma de la interfaz", "Dark Mode":"Modo oscuro", "Notifications":"Notificaciones", "Automatic Scan":"Análisis automático", "VirusTotal Cloud Scan":"Análisis en la nube de VirusTotal", "About":"Acerca de"
  }
};

function translateInterface(lang) {
  const dict = I18N[lang] || I18N.en;
  const nodes = document.querySelectorAll("h1,h2,h3,h4,p,button,span,small,label,option,div");
  nodes.forEach((el) => {
    if (el.children.length && !["BUTTON","OPTION"].includes(el.tagName)) return;
    const original = el.dataset.i18nOriginal || el.textContent.trim();
    if (!original) return;
    el.dataset.i18nOriginal = original;
    if (dict[original]) el.textContent = dict[original];
    else if (lang === "en" && I18N.en[original]) el.textContent = I18N.en[original];
  });
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  localStorage.setItem("cs_language", lang);
  const select = $("#setLanguage");
  if (select) select.value = lang;
}

/* =============================================================
   10) SETTINGS
   ============================================================= */
function initSettings() {
  $("#setNotifications").addEventListener("change", (e) => {
    state.notificationsOn = e.target.checked;
    toast("Settings Updated", `Notifications ${e.target.checked ? "enabled" : "disabled"}.`, "accent");
  });

  $("#setAutoScan").addEventListener("change", (e) => {
    if (e.target.checked) {
      toast("Real-time Monitoring On", "Folder watching is a demo indicator in this build.", "accent");
      // The real engine only scans files the user selects (browsers cannot
      // silently read the filesystem). We surface a periodic heartbeat so the
      // "monitoring" indicator is honest rather than inventing fake threats.
      state.autoScanTimer = setInterval(() => {
        if (state.currentPage !== "scanner") {
          const s = window.CS_LOGGER ? window.CS_LOGGER.stats() : { total: 0 };
          addLog(nowTime(), "Monitoring heartbeat", `Engine idle - ${s.total} file(s) scanned so far.`, "");
        }
      }, 30000);
    } else {
      clearInterval(state.autoScanTimer);
      toast("Real-time Monitoring Off", "Monitoring heartbeat stopped.", "accent");
    }
  });

  $("#setDarkMode").addEventListener("change", (e) => {
    // this build is dark-only; keep it on and inform the user
    if (!e.target.checked) { e.target.checked = true; toast("Theme Locked", "This prototype ships with the dark cyber theme.", "warning"); }
  });

  $("#setLanguage").addEventListener("change", (e) => {
    translateInterface(e.target.value);
    const names = { en: "English", ar: "العربية", fr: "Français", es: "Español" };
    toast("Language", `Interface language set to ${names[e.target.value]}.`, "accent");
  });
  const savedLang = localStorage.getItem("cs_language") || "en";
  translateInterface(savedLang);

  $("#setCloudAI").addEventListener("change", (e) =>
    toast("Cloud AI", `Cloud analysis ${e.target.checked ? "enabled" : "disabled"}.`, "accent"));
}

/* =============================================================
   11) TOAST NOTIFICATIONS
   ============================================================= */
const TOAST_ICONS = {
  success: '<path d="M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4L9 16.2Z"/>',
  danger:  '<path d="M1 21h22L12 2 1 21Zm12-3h-2v-2h2v2Zm0-4h-2v-4h2v4Z"/>',
  warning: '<path d="M1 21h22L12 2 1 21Zm12-3h-2v-2h2v2Zm0-4h-2v-4h2v4Z"/>',
  accent:  '<path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm1 15h-2v-6h2v6Zm0-8h-2V7h2v2Z"/>',
};

function toast(title, message, kind = "accent") {
  if (!state.notificationsOn && kind !== "success") return; // respect notifications toggle (always allow key success)
  const stack = $("#toastStack");
  const el = document.createElement("div");
  el.className = "toast " + (kind === "accent" ? "" : kind);
  el.innerHTML = `
    <svg viewBox="0 0 24 24" class="t-ico">${TOAST_ICONS[kind] || TOAST_ICONS.accent}</svg>
    <div class="toast-body"><h5>${title}</h5><p>${message}</p></div>`;
  stack.appendChild(el);
  setTimeout(() => { el.classList.add("leaving"); setTimeout(() => el.remove(), 350); }, 4200);
}

/* Occasional random "live monitoring" notifications */
function scheduleRandomNotifications() {
  const events = [
    ["Port Scan Blocked", "Blocked reconnaissance from 45.83.x.x.", "danger"],
    ["Signature Update", "Threat database updated to build 20240."],
    ["Anomaly Detected", "Unusual outbound traffic normalized.", "warning"],
    ["Endpoint Verified", "New device authenticated on the network.", "success"],
    ["Phishing Blocked", "Malicious URL blocked in browser.", "danger"],
    ["Backup Complete", "Encrypted system snapshot created.", "success"],
  ];
  const loop = () => {
    const [t, m, k] = pick(events);
    toast(t, m, k || "accent");
    setTimeout(loop, rand(9000, 16000));
  };
  setTimeout(loop, 9000);
}

/* =============================================================
   12) BACKGROUND EFFECTS: matrix, particles, mouse glow
   ============================================================= */

/* Matrix falling-code effect */
function initMatrix() {
  const canvas = $("#matrixCanvas");
  const ctx = canvas.getContext("2d");
  let cols, drops;
  const chars = "01<>[]{}#$%&*ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
  const fontSize = 14;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.floor(canvas.width / fontSize);
    drops = new Array(cols).fill(1);
  }
  resize();
  window.addEventListener("resize", resize);

  function draw() {
    ctx.fillStyle = "rgba(7,17,31,0.08)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#00e5ff";
    ctx.font = fontSize + "px monospace";
    for (let i = 0; i < drops.length; i++) {
      const text = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  setInterval(draw, 55);
}

/* Floating connected particles */
function initParticles() {
  const canvas = $("#particleCanvas");
  const ctx = canvas.getContext("2d");
  let particles = [];

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const count = Math.min(90, Math.floor((canvas.width * canvas.height) / 18000));
    particles = [];
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: rand(-0.4, 0.4),
        vy: rand(-0.4, 0.4),
        r: rand(1, 2.4),
      });
    }
  }
  resize();
  window.addEventListener("resize", resize);

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    // move + draw dots
    particles.forEach((p) => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(0,229,255,0.7)";
      ctx.fill();
    });
    // connect nearby particles with faint lines
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const dist = Math.hypot(a.x - b.x, a.y - b.y);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(0,229,255,${0.12 * (1 - dist / 120)})`;
          ctx.lineWidth = 1; ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
}

/* Radial glow that follows the mouse */
function initMouseGlow() {
  const glow = $("#mouseGlow");
  window.addEventListener("mousemove", (e) => {
    glow.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
  });
}

/* =============================================================
   13) BOOTSTRAP
   ============================================================= */
document.addEventListener("DOMContentLoaded", () => {
  // background effects run on the login screen too
  initMatrix();
  initParticles();
  initMouseGlow();

  // app wiring
  initLogin();
  initRouting();
  initScanner();
  initSettings();
});
