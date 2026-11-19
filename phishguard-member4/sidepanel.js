/**
 * PhishTriage Side Panel Logic
 * Real-time SSE multi-agent investigation trace, explainable AI, Link Shield,
 * consequence simulator, quarantine governance, and analyst co-pilot chat.
 */

// Global State
let backendUrl = "http://localhost:8000";
let activeCaseId = null;
let activeCaseData = null;
let activeEventSource = null;
let selectedFile = null;

// DOM Elements
const toggleConfigBtn = document.getElementById("toggleConfigBtn");
const openOptionsBtn = document.getElementById("openOptionsBtn");
const configDrawer = document.getElementById("configDrawer");
const backendUrlInput = document.getElementById("backendUrlInput");
const saveConfigBtn = document.getElementById("saveConfigBtn");
const connectionStatus = document.getElementById("connectionStatus");

const analyzeGmailBtn = document.getElementById("analyzeGmailBtn");
const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");
const rawEmailText = document.getElementById("rawEmailText");
const analyzeBtn = document.getElementById("analyzeBtn");

const stepperSection = document.getElementById("stepperSection");
const pipelineStatusBadge = document.getElementById("pipelineStatusBadge");
const traceLog = document.getElementById("traceLog");
const stepPlan = document.getElementById("step-plan");
const stepForensic = document.getElementById("step-forensic");
const stepVision = document.getElementById("step-vision");
const stepCritic = document.getElementById("step-critic");
const stepScoring = document.getElementById("step-scoring");

const resultsSection = document.getElementById("resultsSection");
const verdictBanner = document.getElementById("verdictBanner");
const verdictBadge = document.getElementById("verdictBadge");
const criticAdjustedBadge = document.getElementById("criticAdjustedBadge");
const scoreDisplay = document.getElementById("scoreDisplay");
const summaryText = document.getElementById("summaryText");
const limitationsBox = document.getElementById("limitationsBox");
const limitationsText = document.getElementById("limitationsText");
const defangedLinksList = document.getElementById("defangedLinksList");
const indicatorCount = document.getElementById("indicatorCount");
const indicatorsList = document.getElementById("indicatorsList");
const whatIfList = document.getElementById("whatIfList");

const quarantineCard = document.getElementById("quarantineCard");
const quarantineDetails = document.getElementById("quarantineDetails");
const analystIdInput = document.getElementById("analystIdInput");
const approveQuarantineBtn = document.getElementById("approveQuarantineBtn");
const rejectQuarantineBtn = document.getElementById("rejectQuarantineBtn");
const quarantineStatusFeedback = document.getElementById("quarantineStatusFeedback");

const replyDraftText = document.getElementById("replyDraftText");
const copyReplyBtn = document.getElementById("copyReplyBtn");
const openMailtoBtn = document.getElementById("openMailtoBtn");
const toast = document.getElementById("toast");

const chatBox = document.getElementById("chatBox");
const chatInput = document.getElementById("chatInput");
const sendChatBtn = document.getElementById("sendChatBtn");

// =============================================================================
// Initialization & Configuration
// =============================================================================

document.addEventListener("DOMContentLoaded", () => {
  // Restore configured backend URL
  chrome.storage?.local?.get(["backendUrl"], (res) => {
    if (res?.backendUrl) {
      backendUrl = res.backendUrl;
      backendUrlInput.value = backendUrl;
    }
    checkHealth();
  });

  // Check for any email payload ingested from background/Gmail
  chrome.storage?.local?.get(["pendingEmailPayload"], (res) => {
    if (res?.pendingEmailPayload) {
      rawEmailText.value = res.pendingEmailPayload;
      // Clear pending payload
      chrome.storage.local.remove(["pendingEmailPayload"]);
      showToast("Ingested email from Gmail!");
    }
  });
});

toggleConfigBtn.addEventListener("click", () => {
  configDrawer.style.display = configDrawer.style.display === "block" ? "none" : "block";
});

saveConfigBtn.addEventListener("click", () => {
  const url = backendUrlInput.value.trim().replace(/\/+$/, "");
  if (!url) return;
  backendUrl = url;
  chrome.storage?.local?.set({ backendUrl: url }, () => {
    checkHealth();
    showToast("Backend URL updated");
  });
});

openOptionsBtn.addEventListener("click", () => {
  chrome.runtime.openOptionsPage?.() || window.open("options.html", "_blank");
});

async function checkHealth() {
  connectionStatus.textContent = "Status: Connecting...";
  connectionStatus.style.color = "#94a3b8";
  try {
    const res = await fetch(`${backendUrl}/health`, { method: "GET" });
    if (res.ok) {
      connectionStatus.textContent = "Status: Connected to Backend (Healthy)";
      connectionStatus.style.color = "#10b981";
    } else {
      connectionStatus.textContent = `Status: Unhealthy (HTTP ${res.status})`;
      connectionStatus.style.color = "#f59e0b";
    }
  } catch (err) {
    connectionStatus.textContent = "Status: Backend Unreachable";
    connectionStatus.style.color = "#ef4444";
  }
}

// =============================================================================
// File Ingestion & Drag-and-Drop
// =============================================================================

dropZone.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", (e) => {
  if (e.target.files && e.target.files[0]) {
    handleFileSelected(e.target.files[0]);
  }
});

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("dragover");
});

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
    handleFileSelected(e.dataTransfer.files[0]);
  }
});

function handleFileSelected(file) {
  selectedFile = file;
  dropZone.querySelector(".dropzone-text").innerHTML = `Selected: <strong>${file.name}</strong> (${(file.size / 1024).toFixed(1)} KB)`;
  
  const reader = new FileReader();
  reader.onload = () => {
    rawEmailText.value = reader.result;
    showToast(`Loaded ${file.name}`);
  };
  reader.readAsText(file);
}

// =============================================================================
// Gmail One-Click Extraction
// =============================================================================

analyzeGmailBtn.addEventListener("click", async () => {
  logTrace("SYS", "Querying active browser tab for Gmail DOM...");
  try {
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!activeTab?.id) {
      throw new Error("No active browser tab found.");
    }

    const response = await chrome.tabs.sendMessage(activeTab.id, {
      type: "PHISHTRIAGE_EXTRACT_OPEN_EMAIL",
    });

    if (!response?.ok) {
      throw new Error(response?.error || "Open an email message in Gmail before scanning.");
    }

    rawEmailText.value = response.email;
    selectedFile = null;
    dropZone.querySelector(".dropzone-text").innerHTML = `Ingested from active Gmail thread`;
    showToast("Extracted email from Gmail!");
    
    // Auto-trigger analysis
    startAnalysis();
  } catch (err) {
    alert("Gmail Scan: " + err.message);
    logTrace("ERR", "Gmail extraction failed: " + err.message);
  }
});

// =============================================================================
// Trigger Analysis (POST /analyze)
// =============================================================================

analyzeBtn.addEventListener("click", startAnalysis);

async function startAnalysis() {
  const content = rawEmailText.value.trim();
  if (!content && !selectedFile) {
    alert("Please upload a .eml file or paste email content before analyzing.");
    return;
  }

  // Reset UI
  resetInvestigationUI();
  stepperSection.style.display = "block";
  pipelineStatusBadge.textContent = "INITIALIZING";
  logTrace("SYS", "Submitting email to backend /analyze endpoint...");

  try {
    const formData = new FormData();
    if (selectedFile) {
      formData.append("file", selectedFile, selectedFile.name);
    } else {
      formData.append("raw_eml", content);
    }

    const res = await fetch(`${backendUrl}/analyze`, {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      throw new Error(`Server returned HTTP ${res.status}: ${res.statusText}`);
    }

    const data = await res.json();
    if (!data.case_id) {
      throw new Error("Backend response missing case_id.");
    }

    activeCaseId = data.case_id;
    logTrace("SYS", `Case initialized: ${activeCaseId}`);
    
    // Connect to SSE stream
    connectSSEStream(activeCaseId);
  } catch (err) {
    logTrace("ERR", `Analysis request failed: ${err.message}`);
    pipelineStatusBadge.textContent = "FAILED";
    alert("Could not start analysis: " + err.message + "\nEnsure backend is running at " + backendUrl);
  }
}

// =============================================================================
// Live SSE Stream Listener (GET /analyze/{case_id}/stream)
// =============================================================================

function connectSSEStream(caseId) {
  if (activeEventSource) {
    activeEventSource.close();
  }

  logTrace("SSE", `Connecting to event stream: /analyze/${caseId}/stream`);
  pipelineStatusBadge.textContent = "PROCESSING";

  const streamUrl = `${backendUrl}/analyze/${caseId}/stream`;
  activeEventSource = new EventSource(streamUrl);

  activeEventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleSSEEvent(data);
    } catch (err) {
      logTrace("WARN", `Failed to parse SSE line: ${event.data}`);
    }
  };

  activeEventSource.onerror = (err) => {
    logTrace("WARN", "SSE connection closed or interrupted. Fetching final state...");
    activeEventSource.close();
    // Fetch case details as reliable fallback
    fetchCaseDetails(caseId);
  };
}

function handleSSEEvent(evt) {
  const eventType = evt.event;
  const payload = evt.payload || {};

  logTrace(eventType, payload.message || JSON.stringify(payload));

  switch (eventType) {
    case "PLAN_CREATED":
      stepPlan.className = "step-item active";
      setTimeout(() => { stepPlan.className = "step-item done"; }, 400);
      break;

    case "AGENT_PROGRESS":
      if (payload.agent === "Forensic") {
        stepForensic.className = "step-item active";
        if (payload.status === "complete") stepForensic.className = "step-item done";
      } else if (payload.agent === "Vision") {
        stepForensic.className = "step-item done";
        stepVision.className = "step-item active";
        if (payload.status === "complete") stepVision.className = "step-item done";
      }
      break;

    case "CRITIC_REVIEW":
      stepVision.className = "step-item done";
      stepCritic.className = "step-item active";
      if (payload.status === "complete") stepCritic.className = "step-item done";
      break;

    case "SCORING_COMPLETE":
      stepCritic.className = "step-item done";
      stepScoring.className = "step-item active";
      break;

    case "DONE":
      stepScoring.className = "step-item done";
      pipelineStatusBadge.textContent = "COMPLETE";
      pipelineStatusBadge.style.color = "#10b981";
      logTrace("DONE", `Case triage finalized (Score: ${payload.total_score || "N/A"})`);
      if (activeEventSource) activeEventSource.close();
      
      // Fetch full case details
      fetchCaseDetails(evt.case_id || activeCaseId);
      break;
  }
}

// =============================================================================
// Fetch & Display Case Details (GET /cases/{case_id})
// =============================================================================

async function fetchCaseDetails(caseId) {
  try {
    const res = await fetch(`${backendUrl}/cases/${caseId}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch case details (HTTP ${res.status})`);
    }

    const data = await res.json();
    activeCaseData = data;
    renderCaseDetails(data);
  } catch (err) {
    logTrace("ERR", `Error loading case details: ${err.message}`);
  }
}

function renderCaseDetails(caseData) {
  const verdict = caseData.verdict || {};
  const risk = (verdict.risk_level || "SAFE").toUpperCase();
  const score = verdict.total_score ?? 0;

  // 1. Verdict Banner
  verdictBanner.className = `verdict-banner ${risk.toLowerCase()}`;
  verdictBadge.textContent = risk;
  scoreDisplay.textContent = `${score} / 100`;

  if (verdict.critic_adjusted) {
    criticAdjustedBadge.style.display = "inline-block";
  } else {
    criticAdjustedBadge.style.display = "none";
  }

  summaryText.textContent = verdict.summary || "No executive summary generated.";

  // Limitations
  if (caseData.limitations && caseData.limitations.length > 0) {
    limitationsBox.style.display = "block";
    limitationsText.textContent = caseData.limitations.join(" ");
  } else {
    limitationsBox.style.display = "none";
  }

  // 2. Link Shield (Defanged URLs)
  defangedLinksList.innerHTML = "";
  const urls = caseData.defanged_urls || [];
  if (urls.length > 0) {
    urls.forEach((url) => {
      const div = document.createElement("div");
      div.className = "defanged-link";
      div.textContent = `🛡️ ${url}`;
      div.title = "Neutralized Link (Safe to inspect / non-navigable)";
      defangedLinksList.appendChild(div);
    });
  } else {
    defangedLinksList.innerHTML = `<div style="color:#64748b; font-size:12px;">No external links extracted.</div>`;
  }

  // 3. Explainable AI Indicators
  indicatorsList.innerHTML = "";
  const indicators = verdict.primary_indicators || [];
  indicatorCount.textContent = `${indicators.length} signals`;

  if (indicators.length > 0) {
    indicators.forEach((ind) => {
      const card = document.createElement("div");
      card.className = "indicator-card";

      const weightClass = ind.weight >= 0 ? "pos" : "neg";
      const sign = ind.weight > 0 ? "+" : "";

      card.innerHTML = `
        <div class="indicator-head">
          <span class="indicator-title">${escapeHtml(ind.title || ind.id)}</span>
          <span class="weight-pill ${weightClass}">${sign}${ind.weight}</span>
        </div>
        <div style="font-size:11px; color:#64748b; margin-bottom:4px;">Module: <strong>${escapeHtml(ind.agent || "Core")}</strong></div>
        <div style="font-size:12px; color:#cbd5e1; margin-bottom:4px;">${escapeHtml(ind.evidence || "")}</div>
        <div class="indicator-explanation">${escapeHtml(explainIndicator(ind))}</div>
      `;
      indicatorsList.appendChild(card);
    });
  } else {
    indicatorsList.innerHTML = `<div style="color:#64748b; font-size:12px;">No risk indicators triggered.</div>`;
  }

  // 4. What-If Consequence Simulator
  whatIfList.innerHTML = "";
  const steps = caseData.what_if_simulation || [];
  if (steps.length > 0) {
    steps.forEach((step, idx) => {
      const item = document.createElement("div");
      item.className = "sim-step";
      item.innerHTML = `
        <div class="sim-num">${idx + 1}</div>
        <div style="color:#e2e8f0;">${escapeHtml(step)}</div>
      `;
      whatIfList.appendChild(item);
    });
  } else {
    whatIfList.innerHTML = `<div style="color:#64748b; font-size:12px;">No simulation steps available.</div>`;
  }

  // 5. Reporter Reply Draft
  replyDraftText.value = caseData.reporter_reply_draft || "";

  // 6. Quarantine Proposal Governance
  if (caseData.quarantine_proposal && caseData.quarantine_proposal.status === "PENDING") {
    quarantineCard.style.display = "block";
    const qp = caseData.quarantine_proposal;
    quarantineDetails.innerHTML = `
      <strong>Proposal ID:</strong> ${qp.proposal_id}<br>
      <strong>Sender:</strong> ${escapeHtml(qp.target_sender)}<br>
      <strong>Subject:</strong> ${escapeHtml(qp.target_subject)}<br>
      <strong>Action:</strong> ${escapeHtml(qp.recommended_action)}
    `;
    quarantineStatusFeedback.textContent = "";
  } else if (caseData.quarantine_proposal && caseData.quarantine_proposal.status !== "PENDING") {
    quarantineCard.style.display = "block";
    quarantineDetails.innerHTML = `Action Status: <strong>${caseData.quarantine_proposal.status}</strong> by ${escapeHtml(caseData.quarantine_proposal.approved_by || "Analyst")}`;
    approveQuarantineBtn.style.display = "none";
    rejectQuarantineBtn.style.display = "none";
  } else {
    quarantineCard.style.display = "none";
  }

  // Display results section smoothly
  resultsSection.style.display = "block";
  resultsSection.scrollIntoView({ behavior: "smooth" });
}

// =============================================================================
// Quarantine Approval Actions (POST /queue/{id}/approve & reject)
// =============================================================================

approveQuarantineBtn.addEventListener("click", async () => {
  if (!activeCaseData?.quarantine_proposal) return;
  const proposalId = activeCaseData.quarantine_proposal.proposal_id;
  const analystId = analystIdInput.value.trim() || "SOC-Analyst-1";

  quarantineStatusFeedback.textContent = "Submitting approval...";
  quarantineStatusFeedback.style.color = "#3b82f6";

  try {
    const res = await fetch(`${backendUrl}/queue/${proposalId}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_id: analystId }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const updated = await res.json();
    quarantineStatusFeedback.textContent = `✅ Approved! Mailbox quarantine executed by ${analystId}.`;
    quarantineStatusFeedback.style.color = "#10b981";
    approveQuarantineBtn.style.display = "none";
    rejectQuarantineBtn.style.display = "none";
    showToast("Quarantine Approved");
  } catch (err) {
    quarantineStatusFeedback.textContent = `❌ Approval failed: ${err.message}`;
    quarantineStatusFeedback.style.color = "#ef4444";
  }
});

rejectQuarantineBtn.addEventListener("click", async () => {
  if (!activeCaseData?.quarantine_proposal) return;
  const proposalId = activeCaseData.quarantine_proposal.proposal_id;
  const analystId = analystIdInput.value.trim() || "SOC-Analyst-1";

  quarantineStatusFeedback.textContent = "Rejecting proposal...";
  try {
    const res = await fetch(`${backendUrl}/queue/${proposalId}/reject`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_id: analystId }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    quarantineStatusFeedback.textContent = `Proposal closed (Rejected by ${analystId}).`;
    quarantineStatusFeedback.style.color = "#94a3b8";
    approveQuarantineBtn.style.display = "none";
    rejectQuarantineBtn.style.display = "none";
    showToast("Quarantine Rejected");
  } catch (err) {
    quarantineStatusFeedback.textContent = `Error: ${err.message}`;
    quarantineStatusFeedback.style.color = "#ef4444";
  }
});

// =============================================================================
// Copy & mailto Actions
// =============================================================================

copyReplyBtn.addEventListener("click", () => {
  if (!replyDraftText.value) return;
  navigator.clipboard.writeText(replyDraftText.value).then(() => {
    showToast("Copied reply draft to clipboard!");
  });
});

openMailtoBtn.addEventListener("click", () => {
  const body = replyDraftText.value || "";
  const subject = activeCaseData?.verdict?.summary ? `Re: PhishTriage Security Report` : "Security Notice";
  const mailtoUrl = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  window.open(mailtoUrl, "_blank");
});

// =============================================================================
// SOC Analyst Co-Pilot Chat (POST /cases/{case_id}/chat)
// =============================================================================

sendChatBtn.addEventListener("click", handleChatSubmit);
chatInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter") handleChatSubmit();
});

async function handleChatSubmit() {
  const query = chatInput.value.trim();
  if (!query || !activeCaseId) return;

  chatInput.value = "";
  appendChatMessage("user", query);

  try {
    const res = await fetch(`${backendUrl}/cases/${activeCaseId}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: query }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    appendChatMessage("bot", data.response || "No response generated.");
  } catch (err) {
    appendChatMessage("bot", `Co-Pilot query error: ${err.message}`);
  }
}

function appendChatMessage(sender, text) {
  const msg = document.createElement("div");
  msg.className = `chat-msg ${sender}`;
  msg.textContent = text;
  chatBox.appendChild(msg);
  chatBox.scrollTop = chatBox.scrollHeight;
}

// =============================================================================
// Helper Functions
// =============================================================================

function logTrace(tag, message) {
  const entry = document.createElement("div");
  entry.className = "trace-entry";
  const now = new Date().toTimeString().split(" ")[0];
  entry.innerHTML = `<span class="time">[${now}] [${escapeHtml(tag)}]</span> ${escapeHtml(message)}`;
  traceLog.appendChild(entry);
  traceLog.scrollTop = traceLog.scrollHeight;
}

function resetInvestigationUI() {
  stepPlan.className = "step-item";
  stepForensic.className = "step-item";
  stepVision.className = "step-item";
  stepCritic.className = "step-item";
  stepScoring.className = "step-item";
  traceLog.innerHTML = "";
  resultsSection.style.display = "none";
}

function showToast(msg) {
  toast.textContent = msg;
  toast.style.display = "block";
  setTimeout(() => { toast.style.display = "none"; }, 2500);
}

function escapeHtml(str) {
  return (str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function explainIndicator(ind) {
  const dict = {
    lookalike_domain: "The sending domain visually mimics a trusted brand with subtle spelling variations.",
    reply_to_mismatch: "Replies will silently redirect to an external address different from the visible sender.",
    vision_brand_mismatch: "The email displays brand logos, but sender domain headers do not belong to that organization.",
    vision_login_form: "Visual inspection revealed a fake credential harvesting sign-in interface.",
    vision_urgency_language: "Psychological coercion or urgent suspension countdowns were detected in the message.",
    prompt_injection_attempt: "The email payload contained instructions attempting to manipulate automated security tools.",
    double_extension: "The attachment uses a disguised double extension (e.g., .pdf.exe) concealing executable code.",
    aligned_auth_pass: "Cryptographic SPF, DKIM, and DMARC checks passed and aligned successfully for the genuine domain.",
  };
  return dict[ind.id] || "Security anomaly detected during multi-agent forensic inspection.";
}
