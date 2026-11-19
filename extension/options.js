/**
 * SOC Analyst Console Options Page Logic
 * Manages quarantine approval queue, active campaign clusters, and backend config.
 */

let backendUrl = "http://localhost:8000";

const optionsBackendUrl = document.getElementById("optionsBackendUrl");
const saveBackendUrlBtn = document.getElementById("saveBackendUrlBtn");
const backendStatus = document.getElementById("backendStatus");
const queueTableBody = document.getElementById("queueTableBody");
const campaignsTableBody = document.getElementById("campaignsTableBody");
const refreshQueueBtn = document.getElementById("refreshQueueBtn");
const refreshCampaignsBtn = document.getElementById("refreshCampaignsBtn");

document.addEventListener("DOMContentLoaded", () => {
  chrome.storage?.local?.get(["backendUrl"], (res) => {
    if (res?.backendUrl) {
      backendUrl = res.backendUrl;
      optionsBackendUrl.value = backendUrl;
    }
    loadData();
  });
});

saveBackendUrlBtn.addEventListener("click", () => {
  const url = optionsBackendUrl.value.trim().replace(/\/+$/, "");
  if (!url) return;
  backendUrl = url;
  chrome.storage?.local?.set({ backendUrl: url }, () => {
    loadData();
  });
});

refreshQueueBtn.addEventListener("click", loadQueue);
refreshCampaignsBtn.addEventListener("click", loadCampaigns);

async function loadData() {
  await checkHealth();
  await Promise.all([loadQueue(), loadCampaigns()]);
}

async function checkHealth() {
  try {
    const res = await fetch(`${backendUrl}/health`);
    if (res.ok) {
      backendStatus.textContent = "Backend: Connected (Healthy)";
      backendStatus.style.color = "#10b981";
    } else {
      backendStatus.textContent = `Backend: Error (${res.status})`;
      backendStatus.style.color = "#f59e0b";
    }
  } catch (err) {
    backendStatus.textContent = "Backend: Offline / Unreachable";
    backendStatus.style.color = "#ef4444";
  }
}

async function loadQueue() {
  queueTableBody.innerHTML = `<tr><td colspan="7" style="color:#94a3b8; text-align:center;">Loading proposals...</td></tr>`;
  try {
    const res = await fetch(`${backendUrl}/queue`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const items = await res.json();

    if (!items || items.length === 0) {
      queueTableBody.innerHTML = `<tr><td colspan="7" style="color:#64748b; text-align:center;">No pending quarantine proposals.</td></tr>`;
      return;
    }

    queueTableBody.innerHTML = items.map((p) => {
      const badgeClass = p.status === "APPROVED" ? "badge-approved" : p.status === "REJECTED" ? "badge-rejected" : "badge-pending";
      const actionHtml = p.status === "PENDING"
        ? `<div style="display:flex; gap:6px;">
             <button class="btn-primary" style="padding:4px 8px; font-size:11px;" onclick="approveProposal('${p.proposal_id}')">Approve</button>
             <button class="btn-danger" style="padding:4px 8px; font-size:11px;" onclick="rejectProposal('${p.proposal_id}')">Reject</button>
           </div>`
        : `<span style="font-size:11px; color:#94a3b8;">${escapeHtml(p.approved_by || "Completed")}</span>`;

      return `
        <tr>
          <td><strong style="color:#38bdf8;">${escapeHtml(p.proposal_id)}</strong></td>
          <td><code style="font-size:11px;">${escapeHtml(p.case_id)}</code></td>
          <td>${escapeHtml(p.target_sender)}</td>
          <td>${escapeHtml(p.target_subject)}</td>
          <td>${escapeHtml(p.recommended_action)}</td>
          <td><span class="badge ${badgeClass}">${escapeHtml(p.status)}</span></td>
          <td>${actionHtml}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    queueTableBody.innerHTML = `<tr><td colspan="7" style="color:#ef4444; text-align:center;">Failed to load queue: ${err.message}</td></tr>`;
  }
}

async function loadCampaigns() {
  campaignsTableBody.innerHTML = `<tr><td colspan="6" style="color:#94a3b8; text-align:center;">Loading campaigns...</td></tr>`;
  try {
    const res = await fetch(`${backendUrl}/campaigns`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const campaigns = await res.json();

    if (!campaigns || campaigns.length === 0) {
      campaignsTableBody.innerHTML = `<tr><td colspan="6" style="color:#64748b; text-align:center;">No active campaigns indexed.</td></tr>`;
      return;
    }

    campaignsTableBody.innerHTML = campaigns.map((c) => {
      return `
        <tr>
          <td><strong style="color:#a855f7;">${escapeHtml(c.campaign_id)}</strong></td>
          <td><strong>${escapeHtml(c.name)}</strong></td>
          <td>${escapeHtml(c.threat_actor || "Unknown")}</td>
          <td><span class="badge badge-active">${escapeHtml(c.target_brand || "General")}</span></td>
          <td><strong>${c.case_count || 1}</strong></td>
          <td><span class="badge badge-pending">${escapeHtml(c.status || "ACTIVE")}</span></td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    campaignsTableBody.innerHTML = `<tr><td colspan="6" style="color:#ef4444; text-align:center;">Failed to load campaigns: ${err.message}</td></tr>`;
  }
}

window.approveProposal = async function(proposalId) {
  const analystId = prompt("Enter Analyst Identifier for audit log:", "SOC-Analyst-Lead") || "SOC-Analyst-Lead";
  try {
    const res = await fetch(`${backendUrl}/queue/${proposalId}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_id: analystId }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    await loadQueue();
  } catch (err) {
    alert("Approval error: " + err.message);
  }
};

window.rejectProposal = async function(proposalId) {
  const analystId = prompt("Enter Analyst Identifier for audit log:", "SOC-Analyst-Lead") || "SOC-Analyst-Lead";
  try {
    const res = await fetch(`${backendUrl}/queue/${proposalId}/reject`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_id: analystId }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    await loadQueue();
  } catch (err) {
    alert("Rejection error: " + err.message);
  }
};

function escapeHtml(str) {
  return (str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
