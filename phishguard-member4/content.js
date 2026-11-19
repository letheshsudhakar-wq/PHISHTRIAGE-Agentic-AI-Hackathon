/**
 * PhishTriage Content Script (Gmail Integration & Link Shield)
 * Extracts RFC 822 email metadata from the active Gmail DOM and provides Link Shield protection.
 */

function getText(element) {
  return element?.innerText?.trim() || element?.textContent?.trim() || "";
}

function getHeaderValue(value) {
  return (value || "").replace(/[\r\n]+/g, " ").trim();
}

/**
 * Extracts the currently opened email in Gmail as formatted RFC 822 text.
 */
function extractOpenedEmail() {
  const bodyElement = Array.from(document.querySelectorAll("div.a3s.aiL"))
    .filter((element) => element.getClientRects().length > 0)
    .pop();

  const body = getText(bodyElement);
  if (!body) {
    return {
      ok: false,
      error: "Open an email message in Gmail before analyzing it.",
    };
  }

  const messageElement = bodyElement.closest(".adn") || bodyElement.parentElement;
  const subject = getHeaderValue(getText(document.querySelector("h2.hP")));
  const senderElement = messageElement?.querySelector(".gD[email]");
  const senderEmail = senderElement?.getAttribute("email") || "";
  const senderName = getHeaderValue(
    senderElement?.getAttribute("name") || getText(senderElement)
  );
  const sender = senderEmail && senderName && senderName !== senderEmail
    ? `"${senderName}" <${senderEmail}>`
    : senderEmail || senderName || "unknown-sender@gmail.com";

  const recipientElements = Array.from(
    messageElement?.querySelectorAll(".g2[email]") || []
  );
  const recipients = recipientElements
    .map((element) => getHeaderValue(element.getAttribute("email") || ""))
    .filter(Boolean);

  const dateElement = messageElement?.querySelector(".g3[title], .g3");
  const date = getHeaderValue(
    dateElement?.getAttribute("title") || getText(dateElement) || new Date().toUTCString()
  );

  const headers = [];
  if (subject) headers.push(`Subject: ${subject}`);
  if (sender) headers.push(`From: ${sender}`);
  if (recipients.length) headers.push(`To: ${recipients.join(", ")}`);
  if (date) headers.push(`Date: ${date}`);
  headers.push("MIME-Version: 1.0");
  headers.push("Content-Type: text/plain; charset=UTF-8");

  const rawRfc822 = `${headers.join("\r\n")}\r\n\r\n${body}`;

  return {
    ok: true,
    email: rawRfc822,
    metadata: {
      subject,
      sender,
      recipients,
      date,
    },
  };
}

/**
 * Injects PhishTriage toolbar action button in Gmail email header if not present.
 */
function injectToolbarButton() {
  if (document.getElementById("phishtriage-toolbar-btn")) return;

  const targetToolbar = document.querySelector(".G-Ni.J-J5-Ji, .adn .gH");
  if (!targetToolbar) return;

  const btn = document.createElement("button");
  btn.id = "phishtriage-toolbar-btn";
  btn.type = "button";
  btn.innerHTML = `<span style="font-weight:700; color:#3b82f6;">🛡️ Scan with PhishTriage</span>`;
  btn.style.cssText = `
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin: 4px 8px;
    padding: 6px 12px;
    background: #0f172a;
    border: 1px solid #3b82f6;
    border-radius: 6px;
    color: #e2e8f0;
    font-size: 12px;
    cursor: pointer;
    z-index: 1000;
  `;

  btn.addEventListener("click", async () => {
    const extracted = extractOpenedEmail();
    if (extracted.ok) {
      chrome.runtime.sendMessage({
        type: "PHISHTRIAGE_EMAIL_INGESTED",
        payload: extracted.email,
      });
      chrome.runtime.sendMessage({ type: "PHISHTRIAGE_OPEN_SIDEPANEL" });
    } else {
      alert(extracted.error);
    }
  });

  targetToolbar.appendChild(btn);
}

// Observe Gmail DOM updates for dynamic email navigation
const observer = new MutationObserver(() => {
  injectToolbarButton();
});
observer.observe(document.body, { childList: true, subtree: true });

// Listen for direct queries from Side Panel
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (
    message?.type === "PHISHTRIAGE_EXTRACT_OPEN_EMAIL" ||
    message?.type === "PHISHGUARD_EXTRACT_OPEN_EMAIL"
  ) {
    sendResponse(extractOpenedEmail());
  }
});
