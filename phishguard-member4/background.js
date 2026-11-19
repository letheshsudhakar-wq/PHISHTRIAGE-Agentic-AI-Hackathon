/**
 * PhishTriage Background Service Worker (Manifest V3)
 * Manages side panel behavior, extension lifecycle, and tab communications.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishTriage] Service worker initialized.");
  chrome.sidePanel.setPanelBehavior({
    openPanelOnActionClick: true,
  }).catch((err) => console.warn("[PhishTriage] setPanelBehavior error:", err));
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PHISHTRIAGE_OPEN_SIDEPANEL") {
    if (sender.tab?.id) {
      chrome.sidePanel.open({ tabId: sender.tab.id })
        .then(() => sendResponse({ ok: true }))
        .catch((err) => sendResponse({ ok: false, error: err.message }));
      return true; // Keep message channel open for async response
    }
  }

  if (message?.type === "PHISHTRIAGE_EMAIL_INGESTED") {
    // Cache the latest ingested email payload in chrome.storage.local for side panel retrieval
    chrome.storage.local.set({ pendingEmailPayload: message.payload }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }
});
