
const fileInput = document.getElementById("emailFile");
const emailText = document.getElementById("emailText");
const analyzeBtn = document.getElementById("analyzeBtn");
const analyzeGmailBtn = document.getElementById("analyzeGmailBtn");
const result = document.getElementById("result");

function displayVerdict(verdict) {
    const riskClass = {
        PHISHING: "risk-phishing",
        SUSPICIOUS: "risk-suspicious",
        SAFE: "risk-safe"
    }[verdict.risk_level] || "risk-unknown";

    const badge = document.createElement("span");
    badge.className = `risk-badge ${riskClass}`;
    badge.textContent = verdict.risk_level;

    const score = document.createElement("p");
    score.className = "result-score";
    score.textContent = `Risk score: ${verdict.total_score} / 100`;

    const summaryHeading = document.createElement("h4");
    summaryHeading.className = "summary-heading";
    summaryHeading.textContent = "Investigation Summary";

    const summary = document.createElement("p");
    summary.className = "summary-text";
    summary.textContent = verdict.summary;

    result.replaceChildren(badge, score, summaryHeading, summary);
}

// When user selects an email file
fileInput.addEventListener("change", function () {
    const file = fileInput.files[0];

    if (file) {
        const reader = new FileReader();

        reader.onload = function () {
            emailText.value = reader.result;
            result.textContent = "Email loaded successfully!";
        };

        reader.onerror = function () {
            result.textContent = "Could not read the selected .eml file.";
        };

        reader.readAsText(file);
    }
});

async function analyzeEmail(email) {
    const emailContent = email.trim();
    if (emailContent === "") {
        result.textContent = "Please upload or paste an email first!";
        return;
    }

    result.textContent = "Analysing email...";

    try {
        const formData = new FormData();
        formData.append("raw_eml", emailContent);

        let response;
        try {
            response = await fetch("http://127.0.0.1:8000/analyze", {
                method: "POST",
                body: formData
            });
        } catch (error) {
            throw new Error(
                "Cannot connect to the local backend at http://127.0.0.1:8000. " +
                error.message
            );
        }

        if (!response.ok) {
            if ([400, 413, 415, 422].includes(response.status)) {
                throw new Error(
                    `The backend rejected this email as invalid (HTTP ${response.status}).`
                );
            }
            throw new Error(
                `The backend could not start the analysis (HTTP ${response.status}).`
            );
        }

        let data;
        try {
            data = await response.json();
        } catch {
            throw new Error("The backend returned an invalid analysis response.");
        }

        if (typeof data?.case_id !== "string" || !data.case_id) {
            throw new Error("The backend response did not include a case ID.");
        }

        result.textContent = "Fetching investigation results...";

        let caseResponse;
        for (let i = 0; i < 15; i++) {
            await new Promise(resolve => setTimeout(resolve, 1000));

            try {
                caseResponse = await fetch(
                    `http://127.0.0.1:8000/cases/${data.case_id}`
                );
            } catch (error) {
                throw new Error(
                    "Lost connection to the backend while waiting for results. " +
                    error.message
                );
            }

            if (caseResponse.ok) {
                break;
            }

            if (caseResponse.status !== 404) {
                throw new Error(
                    `The backend could not return investigation results (HTTP ${caseResponse.status}).`
                );
            }
        }

        if (!caseResponse || !caseResponse.ok) {
            throw new Error("Analysis is taking too long. Please try again.");
        }

        let caseData;
        try {
            caseData = await caseResponse.json();
        } catch {
            throw new Error("The backend returned invalid investigation results.");
        }

        const verdict = caseData?.verdict;
        if (
            !verdict ||
            !["PHISHING", "SUSPICIOUS", "SAFE"].includes(verdict.risk_level) ||
            !Number.isInteger(verdict.total_score) ||
            verdict.total_score < 0 ||
            verdict.total_score > 100 ||
            typeof verdict.summary !== "string"
        ) {
            throw new Error("The backend returned incomplete investigation results.");
        }

        displayVerdict(verdict);
    } catch (error) {
        result.textContent = error.message || "An unexpected analysis error occurred.";
    }
}

analyzeBtn.addEventListener("click", function () {
    analyzeEmail(emailText.value);
});

analyzeGmailBtn.addEventListener("click", async function () {
    result.textContent = "Reading the open Gmail email...";

    try {
        const [activeTab] = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

        if (!activeTab?.id) {
            throw new Error("No active browser tab was found.");
        }

        const response = await chrome.tabs.sendMessage(activeTab.id, {
            type: "PHISHGUARD_EXTRACT_OPEN_EMAIL"
        });

        if (!response?.ok) {
            result.textContent = response?.error ||
                "Open an email message in Gmail before analyzing it.";
            return;
        }

        emailText.value = response.email;
        await analyzeEmail(response.email);
    } catch (error) {
        result.textContent = "Could not read Gmail: " + error.message +
            ". Open Gmail, refresh the page after installing or updating PhishGuard, and try again.";
    }
});