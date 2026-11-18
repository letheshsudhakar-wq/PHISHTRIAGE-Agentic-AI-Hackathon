function getText(element) {
    return element?.innerText?.trim() || element?.textContent?.trim() || "";
}

function getHeaderValue(value) {
    return value.replace(/[\r\n]+/g, " ").trim();
}

function extractOpenedEmail() {
    const bodyElement = Array.from(
        document.querySelectorAll("div.a3s.aiL")
    ).filter(element => element.getClientRects().length > 0)
        .pop();

    const body = getText(bodyElement);
    if (!body) {
        return {
            ok: false,
            error: "Open an email message in Gmail before analyzing it."
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
        ? `${senderName} <${senderEmail}>`
        : senderEmail || senderName;

    const recipientElements = Array.from(
        messageElement?.querySelectorAll(".g2[email]") || []
    );
    const recipients = recipientElements
        .map(element => getHeaderValue(element.getAttribute("email") || ""))
        .filter(Boolean);

    const dateElement = messageElement?.querySelector(".g3[title], .g3");
    const date = getHeaderValue(
        dateElement?.getAttribute("title") || getText(dateElement)
    );

    const headers = [];
    if (subject) headers.push(`Subject: ${subject}`);
    if (sender) headers.push(`From: ${sender}`);
    if (recipients.length) headers.push(`To: ${recipients.join(", ")}`);
    if (date) headers.push(`Date: ${date}`);

    return {
        ok: true,
        email: `${headers.join("\r\n")}\r\n\r\n${body}`
    };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== "PHISHGUARD_EXTRACT_OPEN_EMAIL") {
        return;
    }

    sendResponse(extractOpenedEmail());
});