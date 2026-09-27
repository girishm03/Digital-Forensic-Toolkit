// Aegis Forensics Command Center - Frontend Logic
let currentCase = null;
let activeCasesList = [];
let audioEnabled = false;
let audioCtx = null;
let radarAnimationId = null;

document.addEventListener("DOMContentLoaded", () => {
  initAudio();
  initNavigation();
  initModals();
  initRadarCanvas();
  initScanlinesToggle();
  loadCases();
  loadLiveHostSummary();
  loadSampleDemos();

  // Clock
  updateClock();
  setInterval(updateClock, 1000);
});

// ==================== TACTICAL AUDIO SYNTHESIZER ====================
function initAudio() {
  const soundToggleBtn = document.getElementById("toggle-sound-btn");
  if (!soundToggleBtn) return;

  soundToggleBtn.addEventListener("click", () => {
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    audioEnabled = !audioEnabled;
    soundToggleBtn.classList.toggle("active", audioEnabled);
    soundToggleBtn.innerHTML = audioEnabled ? "🔊 AUDIO ON" : "🔇 AUDIO OFF";
    if (audioEnabled) {
      playTone(587.33, 0.08, "sine"); // D5 chirp
    }
  });
}

function playTone(freq, duration = 0.08, type = "sine", gainVal = 0.08) {
  if (!audioEnabled || !audioCtx) return;
  try {
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(gainVal, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch (e) {
    // Ignore audio errors
  }
}

function playAlertSound() {
  if (!audioEnabled || !audioCtx) return;
  // Warning sequence
  playTone(880, 0.15, "sawtooth", 0.12);
  setTimeout(() => playTone(440, 0.25, "sawtooth", 0.12), 160);
}

// ==================== ANIMATED RADAR CANVAS ====================
function initRadarCanvas() {
  const canvas = document.getElementById("radar-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  let angle = 0;
  
  // Blip simulation
  const blips = [
    { r: 35, a: 0.8, life: 1 },
    { r: 48, a: 2.4, life: 1 },
    { r: 20, a: 4.1, life: 1 }
  ];

  function drawRadar() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    const maxR = cx - 4;

    // Draw concentric circles
    ctx.strokeStyle = "rgba(0, 255, 200, 0.25)";
    ctx.lineWidth = 1;
    [0.33, 0.66, 1].forEach(frac => {
      ctx.beginPath();
      ctx.arc(cx, cy, maxR * frac, 0, Math.PI * 2);
      ctx.stroke();
    });

    // Crosshairs
    ctx.beginPath();
    ctx.moveTo(cx, 0); ctx.lineTo(cx, canvas.height);
    ctx.moveTo(0, cy); ctx.lineTo(canvas.width, cy);
    ctx.stroke();

    // Radar beam sweep
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(angle);
    const grad = ctx.createRadialGradient(0, 0, 0, 0, 0, maxR);
    grad.addColorStop(0, "rgba(0, 255, 200, 0)");
    grad.addColorStop(1, "rgba(0, 255, 200, 0.4)");
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, maxR, -0.4, 0);
    ctx.lineTo(0, 0);
    ctx.fill();
    ctx.restore();

    // Draw blips
    blips.forEach(b => {
      const bx = cx + Math.cos(b.a) * b.r;
      const by = cy + Math.sin(b.a) * b.r;
      ctx.fillStyle = "rgba(244, 63, 94, 0.85)";
      ctx.beginPath();
      ctx.arc(bx, by, 2.5, 0, Math.PI * 2);
      ctx.fill();
    });

    angle += 0.035;
    radarAnimationId = requestAnimationFrame(drawRadar);
  }

  drawRadar();
}

// ==================== SCANLINE TOGGLE ====================
function initScanlinesToggle() {
  const btn = document.getElementById("toggle-scanlines-btn");
  const overlay = document.getElementById("scanlines-overlay");
  if (!btn || !overlay) return;

  btn.addEventListener("click", () => {
    overlay.classList.toggle("disabled");
    const isOff = overlay.classList.contains("disabled");
    btn.classList.toggle("active", !isOff);
    playTone(659.25, 0.05); // E5
  });
}

function updateClock() {
  const el = document.getElementById("utc-clock");
  if (el) {
    const now = new Date();
    el.innerText = now.toUTCString().replace("GMT", "UTC");
  }
}

// Animated Counter Utility
function animateValue(elemId, start, end, duration = 800) {
  const obj = document.getElementById(elemId);
  if (!obj) return;
  const startNum = parseInt(start) || 0;
  const endNum = parseInt(end) || 0;
  if (isNaN(endNum)) { obj.innerText = end; return; }
  
  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    obj.innerText = Math.floor(progress * (endNum - startNum) + startNum);
    if (progress < 1) {
      window.requestAnimationFrame(step);
    } else {
      obj.innerText = endNum;
    }
  };
  window.requestAnimationFrame(step);
}

// Navigation between tabs
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item[data-tab]");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetTab = item.getAttribute("data-tab");
      playTone(440, 0.04); // A4 click
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(el => el.classList.remove("active"));

  const targetNav = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
  const targetPanel = document.getElementById(`tab-${tabId}`);

  if (targetNav) targetNav.classList.add("active");
  if (targetPanel) targetPanel.classList.add("active");

  // Lazy loaders
  if (tabId === "triage") refreshLiveTriage();
  if (tabId === "timeline") refreshTimeline();
  if (tabId === "browser") loadLiveBrowsers();
  if (tabId === "mitre") refreshMITREMatrix();
}

// Modal handling
function initModals() {
  const newCaseBtn = document.getElementById("btn-new-case");
  const modalNewCase = document.getElementById("modal-new-case");
  const closeModals = document.querySelectorAll(".btn-close-modal");

  if (newCaseBtn && modalNewCase) {
    newCaseBtn.addEventListener("click", () => {
      playTone(523.25, 0.05);
      modalNewCase.classList.add("open");
    });
  }

  closeModals.forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("open"));
    });
  });

  // Create Case Form Submit
  const formCreateCase = document.getElementById("form-create-case");
  if (formCreateCase) {
    formCreateCase.addEventListener("submit", async (e) => {
      e.preventDefault();
      const formData = new FormData(formCreateCase);
      try {
        const res = await fetch("/api/cases", { method: "POST", body: formData });
        const caseObj = await res.json();
        showToast(`Case '${caseObj.case_id}' established!`);
        modalNewCase.classList.remove("open");
        formCreateCase.reset();
        await loadCases();
        selectCase(caseObj.case_id);
      } catch (err) {
        showToast("Error creating case: " + err, "error");
      }
    });
  }
}

function showToast(msg, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const t = document.createElement("div");
  t.className = `toast toast-${type}`;
  t.innerText = msg;
  container.appendChild(t);
  if (type === "error") {
    playAlertSound();
  }
  setTimeout(() => t.remove(), 4000);
}

// Load Cases
async function loadCases() {
  try {
    const res = await fetch("/api/cases");
    activeCasesList = await res.json();
    const selectEl = document.getElementById("select-active-case");
    const tableBody = document.getElementById("table-cases-body");

    if (selectEl) {
      selectEl.innerHTML = '<option value="">-- Select Investigation Case --</option>';
      activeCasesList.forEach(c => {
        const opt = document.createElement("option");
        opt.value = c.case_id;
        opt.innerText = `[${c.case_id}] ${c.title}`;
        selectEl.appendChild(opt);
      });
      selectEl.addEventListener("change", (e) => selectCase(e.target.value));
    }

    if (tableBody) {
      if (activeCasesList.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-dim);">No cases registered yet. Create one to begin.</td></tr>';
      } else {
        tableBody.innerHTML = activeCasesList.map(c => `
          <tr>
            <td><code>${c.case_id}</code></td>
            <td><strong>${c.title}</strong></td>
            <td>${c.investigator}</td>
            <td>${c.evidence_count || 0} items</td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="selectCase('${c.case_id}')">Open Case</button>
            </td>
          </tr>
        `).join("");
      }
    }

    if (!currentCase && activeCasesList.length > 0) {
      selectCase(activeCasesList[0].case_id);
    }
  } catch (err) {
    console.error("Failed to load cases:", err);
  }
}

async function selectCase(caseId) {
  if (!caseId) return;
  try {
    const res = await fetch(`/api/cases/${caseId}`);
    currentCase = await res.json();
    
    // Update UI headers
    const badgeVal = document.getElementById("active-case-name");
    if (badgeVal) badgeVal.innerText = `[${currentCase.case_id}] ${currentCase.title}`;
    
    const selEl = document.getElementById("select-active-case");
    if (selEl) selEl.value = currentCase.case_id;

    // Render Evidence Vault Table
    renderCaseEvidence();
    renderChainOfCustody();
  } catch (err) {
    showToast("Error opening case: " + err, "error");
  }
}

function renderCaseEvidence() {
  const table = document.getElementById("table-evidence-body");
  if (!table || !currentCase) return;

  const items = currentCase.evidence_items || [];
  animateValue("stat-evidence-count", 0, items.length);

  if (items.length === 0) {
    table.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-dim);">No evidence items ingested yet. Use the upload box below.</td></tr>';
    return;
  }

  table.innerHTML = items.map(ev => `
    <tr>
      <td><code>${ev.evidence_id}</code></td>
      <td><strong>${ev.label}</strong><br><small style="color:var(--text-dim);">${ev.original_filename}</small></td>
      <td>${ev.size_human}</td>
      <td><code style="font-size:10px; color:#38bdf8;">${ev.sha256}</code></td>
      <td><span class="tag tag-success">${ev.status}</span></td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="runIntegrityAudit()">Audit</button>
      </td>
    </tr>
  `).join("");
}

function renderChainOfCustody() {
  const table = document.getElementById("table-coc-body");
  if (!table || !currentCase) return;

  const logs = currentCase.chain_of_custody || [];
  if (logs.length === 0) {
    table.innerHTML = '<tr><td colspan="4" style="text-align:center;">No audit records.</td></tr>';
    return;
  }

  table.innerHTML = logs.map(l => `
    <tr>
      <td><small style="font-family:var(--font-mono);">${l.timestamp.replace("T", " ").slice(0, 19)} UTC</small></td>
      <td><strong>${l.investigator}</strong></td>
      <td><span class="tag tag-info">${l.action}</span></td>
      <td><small>${l.details}</small></td>
    </tr>
  `).join("");
}

// 1-Click Integrity Audit
async function runIntegrityAudit() {
  if (!currentCase) {
    showToast("Please select a case first.", "error");
    return;
  }
  showToast("Running cryptographic SHA-256 integrity verification across vault...", "info");
  try {
    const res = await fetch(`/api/cases/${currentCase.case_id}/verify?investigator=${encodeURIComponent(currentCase.investigator)}`, { method: "POST" });
    const auditResults = await res.json();
    
    let allValid = true;
    auditResults.forEach(r => {
      if (!r.is_intact) allValid = false;
    });

    if (allValid) {
      showToast("INTEGRITY VERIFIED: All evidence items match baseline hashes perfectly!", "info");
      playTone(880, 0.1, "sine");
    } else {
      showToast("WARNING: Integrity mismatch or missing file detected in evidence vault!", "error");
      playAlertSound();
    }

    await selectCase(currentCase.case_id);
  } catch (err) {
    showToast("Audit failed: " + err, "error");
  }
}

// Export Reports
function exportReport(format) {
  if (!currentCase) {
    showToast("Please open a case to export its report.", "error");
    return;
  }
  window.open(`/api/cases/${currentCase.case_id}/report/${format}`, "_blank");
}

// File Ingestion to Vault
async function uploadEvidenceToVault() {
  if (!currentCase) {
    showToast("Please select or create an active case before ingesting evidence.", "error");
    return;
  }

  const fileInput = document.getElementById("vault-file-input");
  const labelInput = document.getElementById("vault-evidence-label");
  const notesInput = document.getElementById("vault-evidence-notes");

  if (!fileInput.files.length) {
    showToast("Select a file to ingest.", "error");
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  formData.append("label", labelInput.value || fileInput.files[0].name);
  formData.append("investigator", currentCase.investigator);
  formData.append("notes", notesInput.value || "");

  showToast("Calculating cryptographic hashes and copying to Evidence Vault...", "info");
  try {
    const res = await fetch(`/api/cases/${currentCase.case_id}/evidence`, { method: "POST", body: formData });
    const ev = await res.json();
    showToast(`Evidence '${ev.label}' successfully ingested! Baseline SHA-256 recorded.`, "info");
    fileInput.value = "";
    labelInput.value = "";
    notesInput.value = "";
    await selectCase(currentCase.case_id);
  } catch (err) {
    showToast("Ingestion error: " + err, "error");
  }
}

// ==================== FILE & MEDIA FORENSICS ====================

async function analyzeFileUpload(file) {
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);

  showToast(`Examining magic bytes, entropy, EXIF, and strings for '${file.name}'...`, "info");
  try {
    const res = await fetch("/api/analyze/file", { method: "POST", body: formData });
    const data = await res.json();
    renderFileAnalysisResults(data);
  } catch (err) {
    showToast("Analysis error: " + err, "error");
  }
}

function renderFileAnalysisResults(data) {
  const container = document.getElementById("file-analysis-results");
  if (!container) return;
  container.style.display = "block";

  const { hashes, header, exif, strings_and_iocs, hex_preview, entropy_profile } = data;

  // Hashes
  document.getElementById("fa-filename").innerText = hashes.file_name;
  document.getElementById("fa-size").innerText = `${hashes.size_human} (${hashes.size_bytes} bytes)`;
  document.getElementById("fa-md5").innerText = hashes.md5;
  document.getElementById("fa-sha1").innerText = hashes.sha1;
  document.getElementById("fa-sha256").innerText = hashes.sha256;
  document.getElementById("fa-entropy").innerText = `${hashes.entropy} / 8.0000 (${hashes.entropy_assessment})`;

  // Magic Bytes & Spoof Alert
  const spoofBanner = document.getElementById("fa-spoof-alert");
  if (header.is_spoofed) {
    spoofBanner.style.display = "block";
    spoofBanner.innerHTML = `<strong>CRITICAL SPOOFING WARNING:</strong> File has extension '${header.extension}', but magic bytes identify it as <strong>${header.detected_type}</strong>! This file is likely a disguised executable or payload.`;
    playAlertSound();
    setThreatCondition("RED", "EXTENSION SPOOF DETECTED");
  } else {
    spoofBanner.style.display = "none";
  }

  document.getElementById("fa-magic-hex").innerText = header.magic_hex;
  document.getElementById("fa-magic-type").innerText = `${header.detected_type} (${header.description})`;

  // EXIF
  const exifBox = document.getElementById("fa-exif-data");
  if (exif && exif.has_exif) {
    let exifHtml = '<table class="dfir-table">';
    for (const [k, v] of Object.entries(exif.metadata)) {
      exifHtml += `<tr><td><strong>${k}</strong></td><td>${v}</td></tr>`;
    }
    if (exif.gps) {
      exifHtml += `<tr><td><strong style="color:var(--accent-cyan);">GPS Coordinates</strong></td><td>${exif.gps.latitude}, ${exif.gps.longitude} <a href="${exif.gps.maps_url}" target="_blank" style="color:var(--accent-blue); margin-left:10px;">View on Google Maps</a></td></tr>`;
    }
    exifHtml += '</table>';
    exifBox.innerHTML = exifHtml;
  } else {
    exifBox.innerHTML = '<span style="color:var(--text-dim);">No EXIF / Camera metadata detected in this file format.</span>';
  }

  // Hex Viewer
  const hexContainer = document.getElementById("fa-hex-viewer");
  if (hex_preview && hexContainer) {
    hexContainer.innerHTML = hex_preview.map(row => `
      <div class="hex-row">
        <span class="hex-offset">${row.offset}</span>
        <span class="hex-bytes">${row.hex_str}</span>
        <span class="hex-ascii">${escapeHtml(row.ascii)}</span>
      </div>
    `).join("");
  }

  // IOCs
  const iocBox = document.getElementById("fa-iocs-list");
  const iocs = strings_and_iocs.iocs;
  let iocHtml = `<p>Found <strong>${strings_and_iocs.total_strings_found}</strong> readable strings.</p>`;
  
  if (iocs.ips.length > 0) {
    iocHtml += `<div style="margin-top:10px;"><strong>Detected IPv4 Addresses (${iocs.ips.length}):</strong><br>` +
      iocs.ips.map(ip => `<button class="btn btn-secondary btn-sm" style="margin:2px;" onclick="quickLookupIntel('${ip}')">${ip} 🔎</button>`).join(" ") + '</div>';
  }
  if (iocs.urls.length > 0) {
    iocHtml += `<div style="margin-top:10px;"><strong>Extracted URLs (${iocs.urls.length}):</strong><br>` +
      iocs.urls.map(u => `<div style="color:var(--accent-blue); font-family:var(--font-mono); font-size:11px; margin:2px 0;">${escapeHtml(u)}</div>`).join("") + '</div>';
  }
  if (iocs.emails.length > 0) {
    iocHtml += `<div style="margin-top:10px;"><strong>Email Addresses:</strong> ` + iocs.emails.join(", ") + '</div>';
  }
  iocBox.innerHTML = iocHtml;

  // Entropy Chart
  renderEntropyBars(entropy_profile);
}

function renderEntropyBars(profile) {
  const container = document.getElementById("fa-entropy-chart");
  if (!container || !profile) return;
  container.innerHTML = profile.map(chunk => {
    const heightPercent = Math.min(100, Math.round((chunk.entropy / 8.0) * 100));
    const color = chunk.entropy > 7.1 ? "var(--accent-magenta)" : chunk.entropy > 5.0 ? "var(--accent-cyan)" : "var(--accent-blue)";
    return `
      <div style="flex:1; height:60px; display:flex; flex-direction:column; justify-content:flex-end; align-items:center;" title="Chunk ${chunk.chunk_index} (${chunk.offset_hex}): Entropy ${chunk.entropy}">
        <div style="width:80%; height:${heightPercent}%; background:${color}; border-radius:2px 2px 0 0; transition:height 0.4s ease;"></div>
      </div>
    `;
  }).join("");
}

// ==================== PE EXECUTABLE FORENSICS ====================

async function analyzePEUpload(file) {
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);

  showToast(`Parsing PE headers, sections, imports, and threats for '${file.name}'...`, "info");
  try {
    const res = await fetch("/api/analyze/pe", { method: "POST", body: formData });
    const data = await res.json();
    renderPEResults(data);
  } catch (err) {
    showToast("PE Analysis error: " + err, "error");
  }
}

function renderPEResults(data) {
  const container = document.getElementById("pe-analysis-results");
  if (!container) return;
  container.style.display = "block";

  if (!data.is_pe) {
    container.innerHTML = `<div class="card" style="border-color:var(--accent-magenta);"><p style="color:var(--accent-magenta);">${data.error}</p></div>`;
    return;
  }

  document.getElementById("pe-arch").innerText = data.architecture;
  document.getElementById("pe-compile-time").innerText = data.compile_timestamp;
  document.getElementById("pe-entry").innerText = data.entry_point;
  document.getElementById("pe-subsystem").innerText = data.subsystem;

  // Threat Score Meter
  const meterFill = document.getElementById("pe-threat-fill");
  const meterScore = document.getElementById("pe-threat-score");
  meterScore.innerText = `${data.threat_score} / 100 (${data.assessment})`;
  meterFill.style.width = `${data.threat_score}%`;
  meterFill.style.background = data.threat_score > 60 ? "var(--accent-magenta)" : data.threat_score > 30 ? "var(--accent-amber)" : "var(--accent-emerald)";

  if (data.threat_score > 60) {
    setThreatCondition("RED", "HIGH-RISK PE BINARY");
    playAlertSound();
  }

  // Sections Table
  const secTable = document.getElementById("pe-sections-body");
  secTable.innerHTML = data.sections.map(s => `
    <tr>
      <td><strong>${s.name}</strong></td>
      <td><code>${s.virtual_address}</code></td>
      <td>${s.virtual_size} bytes</td>
      <td>${s.raw_size} bytes</td>
      <td><span class="tag ${s.entropy > 7.1 ? 'tag-danger' : 'tag-info'}">${s.entropy}</span></td>
      <td>${s.is_packed ? '<span class="tag tag-danger">PACKED / SUSPICIOUS</span>' : '<span class="tag tag-success">Normal</span>'}</td>
    </tr>
  `).join("");

  // Suspicious APIs
  const apisBox = document.getElementById("pe-suspicious-apis");
  if (data.suspicious_apis && data.suspicious_apis.length > 0) {
    apisBox.innerHTML = data.suspicious_apis.map(sa => `
      <div style="margin-bottom:6px; display:flex; align-items:center; gap:8px;">
        <span class="tag tag-danger">${sa.category}</span>
        <code>${sa.api}</code>
        <small style="color:var(--text-dim);">from ${sa.dll}</small>
      </div>
    `).join("");
  } else {
    apisBox.innerHTML = '<span style="color:var(--accent-emerald);">No high-risk / injection APIs found in import directory.</span>';
  }
}

// ==================== EVTX EVENT LOG FORENSICS ====================

async function analyzeEVTXUpload(file) {
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);

  showToast(`Parsing Windows Event Log (.evtx): '${file.name}'...`, "info");
  try {
    const res = await fetch("/api/analyze/evtx", { method: "POST", body: formData });
    const data = await res.json();
    renderEVTXResults(data);
  } catch (err) {
    showToast("EVTX parsing error: " + err, "error");
  }
}

function renderEVTXResults(data) {
  const container = document.getElementById("evtx-results");
  if (!container) return;
  container.style.display = "block";

  if (data.error) {
    showToast(data.error, "error");
    return;
  }

  animateValue("evtx-total-records", 0, data.total_records_analyzed);
  animateValue("evtx-failed-logons", 0, data.failed_logons_count);
  animateValue("evtx-suspicious-events", 0, data.suspicious_events_count);

  // Log Clear Tamper Alert
  const alertBox = document.getElementById("evtx-tamper-alert");
  if (data.log_cleared_tamper_alerts && data.log_cleared_tamper_alerts.length > 0) {
    alertBox.style.display = "block";
    alertBox.innerHTML = `<strong>CRITICAL SECURITY ALERT:</strong> Security audit log was purged (${data.log_cleared_tamper_alerts.length} instances)! Event ID 1102 / 104 indicates potential adversary covering tracks.`;
    playAlertSound();
    setThreatCondition("RED", "AUDIT LOG PURGE DETECTED");
  } else {
    alertBox.style.display = "none";
  }

  // Failed Logons
  const failTable = document.getElementById("evtx-failed-logons-body");
  if (data.failed_logons.length > 0) {
    failTable.innerHTML = data.failed_logons.map(f => `
      <tr>
        <td>${f.timestamp.replace("T", " ").slice(0, 19)}</td>
        <td><strong>${f.user}</strong></td>
        <td>${f.domain}</td>
        <td><code>${f.source_ip}</code></td>
        <td><span class="tag tag-danger">${f.status || 'Logon Failure'}</span></td>
      </tr>
    `).join("");
  } else {
    failTable.innerHTML = '<tr><td colspan="5" style="text-align:center;">No failed logons recorded.</td></tr>';
  }

  // Critical Events Sample
  const eventsTable = document.getElementById("evtx-events-body");
  eventsTable.innerHTML = data.records_sample.slice(0, 50).map(r => `
    <tr>
      <td><code>${r.event_id}</code></td>
      <td><strong>${r.event_name}</strong></td>
      <td>${r.timestamp.replace("T", " ").slice(0, 19)}</td>
      <td><span class="tag tag-${r.severity.toLowerCase()}">${r.severity}</span></td>
      <td>${r.computer}</td>
    </tr>
  `).join("");
}

// ==================== BROWSER FORENSICS ====================

async function loadLiveBrowsers() {
  try {
    const res = await fetch("/api/analyze/browser/live");
    const browsers = await res.json();
    const liveContainer = document.getElementById("browser-live-profiles");
    if (!liveContainer) return;

    if (browsers.length === 0) {
      liveContainer.innerHTML = '<p style="color:var(--text-dim);">No active browser history databases discovered in default user paths.</p>';
      return;
    }

    liveContainer.innerHTML = browsers.map(b => `
      <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-input); padding:10px 14px; border-radius:6px; margin-bottom:8px;">
        <div>
          <strong>${b.browser}</strong><br>
          <small style="color:var(--text-dim); font-family:var(--font-mono);">${b.history_path}</small>
        </div>
        <button class="btn btn-primary btn-sm" onclick="parseBrowserPath('${encodeURIComponent(b.history_path)}')">Analyze Live History</button>
      </div>
    `).join("");
  } catch (err) {
    console.error("Live browser load error:", err);
  }
}

async function parseBrowserPath(encodedPath) {
  const path = decodeURIComponent(encodedPath);
  const formData = new FormData();
  formData.append("db_path", path);

  showToast(`Parsing live browser database: ${path}...`, "info");
  try {
    const res = await fetch("/api/analyze/browser/parse_path", { method: "POST", body: formData });
    const data = await res.json();
    renderBrowserResults(data);
  } catch (err) {
    showToast("Browser parsing error: " + err, "error");
  }
}

async function analyzeBrowserUpload(file) {
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);

  showToast(`Parsing uploaded browser SQLite database: ${file.name}...`, "info");
  try {
    const res = await fetch("/api/analyze/browser", { method: "POST", body: formData });
    const data = await res.json();
    renderBrowserResults(data);
  } catch (err) {
    showToast("Browser upload error: " + err, "error");
  }
}

function renderBrowserResults(data) {
  const container = document.getElementById("browser-results");
  if (!container) return;
  container.style.display = "block";

  document.getElementById("browser-family-tag").innerText = data.browser_family;
  animateValue("browser-history-count", 0, data.total_history_count);
  animateValue("browser-downloads-count", 0, data.total_downloads_count);

  // History Table
  const histTable = document.getElementById("browser-history-body");
  histTable.innerHTML = (data.history || []).slice(0, 50).map(h => `
    <tr>
      <td>${h.last_visit_time ? h.last_visit_time.replace("T", " ").slice(0, 19) : 'N/A'}</td>
      <td><strong>${escapeHtml(h.title)}</strong></td>
      <td><a href="${h.url}" target="_blank" style="color:var(--accent-blue); font-family:var(--font-mono); font-size:11px;">${escapeHtml(h.url.slice(0, 70))}...</a></td>
      <td>${h.visit_count}</td>
    </tr>
  `).join("");

  // Downloads Table
  const dlTable = document.getElementById("browser-downloads-body");
  if (data.downloads && data.downloads.length > 0) {
    dlTable.innerHTML = data.downloads.map(d => `
      <tr>
        <td><strong>${escapeHtml(d.filename)}</strong></td>
        <td><code>${d.path}</code></td>
        <td>${Math.round(d.total_bytes / 1024)} KB</td>
        <td>${d.start_time ? d.start_time.replace("T", " ").slice(0, 19) : ''}</td>
      </tr>
    `).join("");
  } else {
    dlTable.innerHTML = '<tr><td colspan="4" style="text-align:center;">No downloads recorded in this database.</td></tr>';
  }
}

// ==================== LIVE SYSTEM TRIAGE ====================

async function loadLiveHostSummary() {
  try {
    const res = await fetch("/api/triage/system");
    const data = await res.json();
    
    const hostEl = document.getElementById("host-stat-name");
    const cpuEl = document.getElementById("host-stat-cpu");
    const memEl = document.getElementById("host-stat-mem");

    if (hostEl) hostEl.innerText = `${data.hostname} (${data.platform})`;
    if (cpuEl) cpuEl.innerText = `${data.cpu_count} Cores`;
    if (memEl) memEl.innerText = `${data.memory_used_percent}% used (${data.memory_total_gb} GB)`;
  } catch (err) {
    console.error("Host summary error:", err);
  }
}

async function refreshLiveTriage() {
  showToast("Scanning live processes, open sockets, and persistence mechanisms...", "info");
  
  // Processes
  try {
    const res = await fetch("/api/triage/processes");
    const procs = await res.json();
    const table = document.getElementById("triage-proc-body");
    
    table.innerHTML = procs.slice(0, 100).map(p => `
      <tr style="${p.is_suspicious ? 'background:rgba(244,63,94,0.08);' : ''}">
        <td><code>${p.pid}</code></td>
        <td><strong>${p.name}</strong></td>
        <td><small style="color:var(--text-dim);">${escapeHtml(p.exe)}</small></td>
        <td>${p.username}</td>
        <td>${p.memory_percent}%</td>
        <td>
          ${p.is_suspicious 
            ? `<span class="tag tag-danger" title="${p.reasons.join('; ')}">SUSPICIOUS: ${p.reasons[0]}</span>` 
            : '<span class="tag tag-success">Normal</span>'}
        </td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Process triage error:", err);
  }

  // Network Sockets
  try {
    const res = await fetch("/api/triage/network");
    const conns = await res.json();
    const netTable = document.getElementById("triage-net-body");
    
    netTable.innerHTML = conns.slice(0, 60).map(c => `
      <tr>
        <td><span class="tag tag-info">${c.proto}</span></td>
        <td><code>${c.local_address}</code></td>
        <td><code>${c.remote_address || 'LISTENING'}</code></td>
        <td>${c.status}</td>
        <td><strong>${c.process_name}</strong> (PID ${c.pid || '?'})</td>
        <td>${c.is_suspicious ? '<span class="tag tag-danger">THREAT PORT</span>' : '<span class="tag tag-success">OK</span>'}</td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Network triage error:", err);
  }

  // Persistence
  try {
    const res = await fetch("/api/triage/persistence");
    const persist = await res.json();
    const runTable = document.getElementById("triage-runkeys-body");
    
    runTable.innerHTML = (persist.registry_run_keys || []).map(r => `
      <tr>
        <td><span class="tag tag-info">${r.location}</span></td>
        <td><strong>${r.name}</strong></td>
        <td><small style="font-family:var(--font-mono);">${escapeHtml(r.command)}</small></td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Persistence triage error:", err);
  }
}

// ==================== NETWORK FORENSICS (PCAP) ====================

async function analyzePCAPUpload(file) {
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);

  showToast(`Parsing PCAP network packets, protocols, and flows for '${file.name}'...`, "info");
  try {
    const res = await fetch("/api/analyze/pcap", { method: "POST", body: formData });
    const data = await res.json();
    renderPCAPResults(data);
  } catch (err) {
    showToast("PCAP parsing error: " + err, "error");
  }
}

function renderPCAPResults(data) {
  const container = document.getElementById("pcap-results");
  if (!container) return;
  container.style.display = "block";

  animateValue("pcap-total-pkts", 0, data.total_packets);
  document.getElementById("pcap-total-bytes").innerText = `${Math.round(data.total_bytes / 1024)} KB`;

  // Protocol Breakdown
  const protoBox = document.getElementById("pcap-protocol-tags");
  protoBox.innerHTML = Object.entries(data.protocol_breakdown || {}).map(([k, v]) => `
    <span class="tag tag-info" style="margin-right:6px;">${k}: ${v}</span>
  `).join("");

  // Conversations
  const flowTable = document.getElementById("pcap-flows-body");
  flowTable.innerHTML = (data.top_conversations || []).slice(0, 30).map(f => `
    <tr>
      <td><code>${f.flow}</code></td>
      <td><span class="tag tag-info">${f.proto}</span></td>
      <td>${f.packets}</td>
      <td>${Math.round(f.bytes / 1024)} KB</td>
    </tr>
  `).join("");

  // DNS Queries
  const dnsTable = document.getElementById("pcap-dns-body");
  dnsTable.innerHTML = (data.dns_queries || []).map(d => `
    <tr style="${d.is_dga_suspicious ? 'background:rgba(244,63,94,0.1);' : ''}">
      <td>${d.timestamp ? d.timestamp.replace("T", " ").slice(0, 19) : ''}</td>
      <td><code>${d.src_ip}</code></td>
      <td><strong>${escapeHtml(d.domain)}</strong></td>
      <td><span class="tag ${d.is_dga_suspicious ? 'tag-danger' : 'tag-info'}">Entropy: ${d.entropy}</span></td>
      <td>${d.is_dga_suspicious ? '<span class="tag tag-danger">DGA / TUNNEL SUSPICION</span>' : '<span class="tag tag-success">Benign</span>'}</td>
    </tr>
  `).join("");

  // HTTP Requests
  const httpTable = document.getElementById("pcap-http-body");
  httpTable.innerHTML = (data.http_requests || []).map(h => `
    <tr>
      <td>${h.timestamp ? h.timestamp.replace("T", " ").slice(0, 19) : ''}</td>
      <td><span class="tag tag-info">${h.method}</span></td>
      <td>${h.host}</td>
      <td><code>${escapeHtml(h.uri)}</code></td>
    </tr>
  `).join("");
}

// ==================== SUPERTIMELINE ====================

async function refreshTimeline() {
  try {
    const res = await fetch("/api/timeline");
    const data = await res.json();
    renderTimelineStream(data);
  } catch (err) {
    console.error("Timeline error:", err);
  }
}

function renderTimelineStream(data) {
  const container = document.getElementById("timeline-stream-container");
  const alertContainer = document.getElementById("timeline-anomalies");
  if (!container) return;

  if (alertContainer && data.anomalies_detected && data.anomalies_detected.length > 0) {
    alertContainer.innerHTML = data.anomalies_detected.map(a => `
      <div style="background:rgba(244,63,94,0.15); border:1px solid var(--accent-magenta); padding:12px 16px; border-radius:8px; margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between;">
          <strong style="color:var(--accent-magenta);">[${a.severity}] ${a.threat_type}</strong>
          <small style="color:var(--text-dim);">${a.timestamp ? a.timestamp.replace('T', ' ').slice(0,19) : ''}</small>
        </div>
        <p style="margin:4px 0 0 0; font-size:13px;">${a.details}</p>
      </div>
    `).join("");
    setThreatCondition("RED", `${data.anomalies_detected.length} ANOMALIES DETECTED`);
  } else if (alertContainer) {
    alertContainer.innerHTML = '<p style="color:var(--text-dim);">No correlated threat anomalies detected in active timeline stream.</p>';
  }

  const events = data.timeline || [];
  if (events.length === 0) {
    container.innerHTML = '<p style="color:var(--text-dim); text-align:center; padding:30px;">Timeline is empty. Ingest evidence files, analyze EVTX logs, or run network captures to generate timeline events.</p>';
    return;
  }

  container.innerHTML = events.map(ev => {
    const sev = (ev.severity || "info").toLowerCase();
    return `
      <div class="timeline-entry sev-${sev}">
        <div class="timeline-time">${ev.timestamp ? ev.timestamp.replace("T", " ").slice(0, 19) + " UTC" : "Timestamp N/A"}</div>
        <div class="timeline-content">
          <div class="timeline-header-row">
            <span class="tag tag-info">${ev.source}</span>
            <span class="tag tag-${sev}">${ev.event_type}</span>
          </div>
          <p style="font-size:13px; margin:0;">${escapeHtml(ev.description)}</p>
        </div>
      </div>
    `;
  }).join("");
}

async function clearTimeline() {
  await fetch("/api/timeline/clear", { method: "POST" });
  showToast("Active investigation timeline cleared.", "info");
  refreshTimeline();
}

// ==================== NEW FEATURE: FILE CARVER ====================

async function startFileCarving(file) {
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);

  showToast(`Initiating deep byte carving on '${file.name}' for hidden/embedded files...`, "info");
  try {
    const res = await fetch("/api/carve", { method: "POST", body: formData });
    const data = await res.json();
    renderCarvedResults(data);
  } catch (err) {
    showToast("File carving error: " + err, "error");
  }
}

function renderCarvedResults(data) {
  const container = document.getElementById("carver-results");
  if (!container) return;
  container.style.display = "block";

  document.getElementById("carver-total-found").innerText = data.carved_count;
  const grid = document.getElementById("carver-grid");

  if (!data.carved_files || data.carved_files.length === 0) {
    grid.innerHTML = '<p style="color:var(--text-dim); grid-column:1/-1;">No embedded headers matching known file types (JPEG, PNG, PDF, ZIP) were carved.</p>';
    return;
  }

  grid.innerHTML = data.carved_files.map(cf => `
    <div class="carved-card">
      ${cf.preview_b64 ? `<img src="data:image/${cf.extension};base64,${cf.preview_b64}" class="carved-preview-img" alt="Carved Image">` : `<div class="carved-preview-img" style="display:flex; align-items:center; justify-content:center; color:var(--accent-blue); font-size:28px;">📄</div>`}
      <div>
        <strong>${cf.id}: ${cf.type}</strong>
        <div style="font-size:11px; color:var(--text-dim); margin-top:4px;">
          Offset: <code>${cf.start_offset_hex}</code> | Size: ${cf.size_human}
        </div>
        <div style="font-size:10px; font-family:var(--font-mono); color:var(--accent-blue); margin-top:4px; word-break:break-all;">
          SHA256: ${cf.sha256.slice(0, 24)}...
        </div>
      </div>
      ${cf.preview_b64 ? `<a href="data:image/${cf.extension};base64,${cf.preview_b64}" download="${cf.id}.${cf.extension}" class="btn btn-secondary btn-sm">Download Carved ${cf.extension.toUpperCase()}</a>` : ''}
    </div>
  `).join("");
}

// ==================== NEW FEATURE: MITRE ATT&CK MATRIX ====================

async function refreshMITREMatrix() {
  const techContainer = document.getElementById("mitre-techniques-list");
  if (techContainer) {
    techContainer.innerHTML = '<p style="color:var(--text-dim); padding:16px;">Correlating enterprise TTPs across artifacts...</p>';
  }
  try {
    const res = await fetch("/api/mitre");
    if (!res.ok) {
      throw new Error(`Server returned status ${res.status}`);
    }
    const data = await res.json();
    renderMITREMatrix(data);
  } catch (err) {
    console.error("MITRE load error:", err);
    if (techContainer) {
      techContainer.innerHTML = `<div class="card" style="border-color:var(--accent-magenta);"><p style="color:var(--accent-magenta);">Error loading MITRE Matrix: ${escapeHtml(err.message)}</p></div>`;
    }
    showToast("Error loading MITRE ATT&CK Matrix: " + err.message, "error");
  }
}

function renderMITREMatrix(data) {
  const tacticsBar = document.getElementById("mitre-tactics-bar");
  const techContainer = document.getElementById("mitre-techniques-list");
  if (!tacticsBar || !techContainer) return;

  // Tactics Bar
  tacticsBar.innerHTML = Object.entries(data.tactics_summary || {}).map(([tactic, count]) => `
    <div class="tactic-box ${count > 0 ? 'active' : ''}">
      <div class="tactic-name">${tactic}</div>
      <div class="tactic-count" style="${count > 0 ? 'color:var(--accent-magenta);' : ''}">${count}</div>
    </div>
  `).join("");

  // Techniques List
  if (!data.techniques || data.techniques.length === 0) {
    techContainer.innerHTML = '<p style="color:var(--text-dim); padding:20px; text-align:center;">No techniques mapped yet. Ingest artifacts to populate threat TTPs.</p>';
    return;
  }

  techContainer.innerHTML = data.techniques.map(t => `
    <div class="mitre-technique-card">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span class="tag tag-danger">${t.id}</span>
          <strong style="margin-left:8px; font-size:14px;">${escapeHtml(t.name)}</strong>
          <span class="tag tag-info" style="margin-left:8px;">${escapeHtml(t.tactic)}</span>
        </div>
        <a href="${t.url}" target="_blank" class="btn btn-secondary btn-sm">MITRE ATT&CK &nearr;</a>
      </div>
      <p style="font-size:12px; color:var(--text-muted); margin:8px 0 6px 0;">${escapeHtml(t.description)}</p>
      <div style="font-size:11px; color:var(--accent-cyan); font-family:var(--font-mono);">
        Forensic Signal (${t.detection_count}): ${t.evidence_samples && t.evidence_samples[0] ? escapeHtml(String(t.evidence_samples[0]).slice(0, 100)) : 'Artifact Detected'}...
      </div>
    </div>
  `).join("");
}

// ==================== NEW FEATURE: THREAT INTEL LOOKUP ====================

async function executeIntelLookup() {
  const input = document.getElementById("intel-ioc-input");
  if (!input || !input.value.trim()) {
    showToast("Enter an IOC (Hash, IP, or Domain) to lookup.", "error");
    return;
  }

  showToast(`Looking up IOC reputation for '${input.value.trim()}'...`, "info");
  const formData = new FormData();
  formData.append("indicator", input.value.trim());

  try {
    const res = await fetch("/api/intel/lookup", { method: "POST", body: formData });
    const data = await res.json();
    renderIntelResults(data);
  } catch (err) {
    showToast("Intel lookup error: " + err, "error");
  }
}

function quickLookupIntel(ioc) {
  switchTab("intel");
  const input = document.getElementById("intel-ioc-input");
  if (input) {
    input.value = ioc;
    executeIntelLookup();
  }
}

function renderIntelResults(data) {
  const container = document.getElementById("intel-results");
  if (!container) return;
  container.style.display = "block";

  const isThreat = data.is_known_threat;
  container.innerHTML = `
    <div class="card" style="border-left: 5px solid ${isThreat ? 'var(--accent-magenta)' : 'var(--accent-emerald)'};">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <div>
          <span class="tag ${isThreat ? 'tag-danger' : 'tag-success'}">${data.classification}</span>
          <span class="tag tag-info" style="margin-left:6px;">${data.type}</span>
          <h3 style="font-family:var(--font-mono); margin-top:8px; font-size:16px;">${escapeHtml(data.ioc)}</h3>
        </div>
        <div style="text-align:right;">
          <div style="font-size:11px; color:var(--text-dim);">THREAT CONFIDENCE</div>
          <div style="font-size:24px; font-weight:700; font-family:var(--font-mono); color:${isThreat ? 'var(--accent-magenta)' : 'var(--accent-emerald)'};">${data.confidence_score}%</div>
        </div>
      </div>
      <table class="dfir-table">
        <tr><td style="width:160px;"><strong>Threat Family</strong></td><td>${data.threat_family}</td></tr>
        <tr><td><strong>Actor / Attribution</strong></td><td>${data.actor_attribution}</td></tr>
        <tr><td><strong>Intelligence Verdict</strong></td><td>${data.details}</td></tr>
      </table>
    </div>
  `;
}

// Dynamic Threat Level setter
function setThreatCondition(level, message) {
  const ticker = document.getElementById("threat-condition-ticker");
  const dot = document.getElementById("threat-condition-dot");
  if (!ticker || !dot) return;

  if (level === "RED") {
    dot.className = "threat-dot critical";
    ticker.innerHTML = `<span class="threat-dot critical"></span><span style="color:var(--accent-magenta); font-weight:700;">DEFCON 1: ${message}</span>`;
  } else if (level === "AMBER") {
    dot.className = "threat-dot";
    dot.style.background = "var(--accent-amber)";
    ticker.innerHTML = `<span class="threat-dot" style="background:var(--accent-amber);"></span><span style="color:var(--accent-amber); font-weight:700;">DEFCON 3: ${message}</span>`;
  }
}

// ==================== SAMPLE DEMOS ====================

async function loadSampleDemos() {
  try {
    const res = await fetch("/api/samples");
    const samples = await res.json();
    const list = document.getElementById("samples-quick-load");
    if (!list) return;

    list.innerHTML = samples.map(s => `
      <button class="btn btn-secondary btn-sm" onclick="loadSampleFile('${s.name}')">
        Load Sample: ${s.name} (${Math.round(s.size_bytes / 1024)} KB)
      </button>
    `).join("");
  } catch (err) {
    console.error("Samples load error:", err);
  }
}

async function loadSampleFile(sampleName) {
  showToast(`Loading sample forensic file: ${sampleName}...`, "info");
  if (sampleName.endsWith(".png") || sampleName.endsWith(".exe")) {
    switchTab("file-analysis");
    const resp = await fetch(`/static/../../aegis_forensics/samples/${sampleName}`);
    const blob = await resp.blob();
    const file = new File([blob], sampleName);
    analyzeFileUpload(file);
  } else if (sampleName.endsWith(".pcap")) {
    switchTab("pcap");
    const resp = await fetch(`/static/../../aegis_forensics/samples/${sampleName}`);
    const blob = await resp.blob();
    const file = new File([blob], sampleName);
    analyzePCAPUpload(file);
  } else if (sampleName.endsWith(".raw")) {
    switchTab("carver");
    const resp = await fetch(`/static/../../aegis_forensics/samples/${sampleName}`);
    const blob = await resp.blob();
    const file = new File([blob], sampleName);
    startFileCarving(file);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
