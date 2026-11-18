
chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishGuard installed!");
});

chrome.sidePanel.setPanelBehavior({
    openPanelOnActionClick: true
});
