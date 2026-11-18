"""Unit tests for deterministic scoring engine, URL defanging, governance rules, and Member 1 API endpoints."""

import asyncio
import io
import json
import pytest
from fastapi.testclient import TestClient

from app.core.scoring import calculate_verdict, defang_url
from app.models.schemas import Indicator, QuarantineProposal, RiskLevel
from app.api.routes import approve_quarantine, PROPOSAL_STORE, CASE_STORE, CAMPAIGN_STORE, _run_analysis_pipeline
from app.api.sse import sse_event_generator
from app.main import app


@pytest.fixture
def client():
    """TestClient fixture for FastAPI endpoints."""
    return TestClient(app)


def test_safe_email_clamping():
    """Verify aligned authentication mitigation clamps score to 0 and evaluates to SAFE."""
    indicators = [
        Indicator(
            id="aligned_auth_pass",
            agent="Forensic",
            weight=-25,
            title="SPF and DKIM Aligned",
            evidence="Domain authentication passed with strict alignment.",
        )
    ]
    verdict = calculate_verdict("case-safe-01", indicators)

    assert verdict.total_score == 0
    assert verdict.risk_level == RiskLevel.SAFE
    assert verdict.case_id == "case-safe-01"


def test_suspicious_email_threshold():
    """Verify an indicator with weight 45 lands in SUSPICIOUS band (35 - 69)."""
    indicators = [
        Indicator(
            id="suspicious_reply_to",
            agent="Forensic",
            weight=45,
            title="Reply-To Mismatch",
            evidence="Reply-To domain differs significantly from envelope sender.",
        )
    ]
    verdict = calculate_verdict("case-suspicious-01", indicators)

    assert verdict.total_score == 45
    assert verdict.risk_level == RiskLevel.SUSPICIOUS


def test_multi_agent_phishing():
    """Verify multi-agent corroboration (+35 Forensic, +40 Vision -> 75) yields PHISHING."""
    indicators = [
        Indicator(
            id="lookalike_domain",
            agent="Forensic",
            weight=35,
            title="Typosquatting Domain",
            evidence="Registered yesterday, similarity 0.94 to target brand.",
        ),
        Indicator(
            id="vision_brand_mismatch",
            agent="Vision",
            weight=40,
            title="Logo Impersonation",
            evidence="Detected Microsoft login banner on untrusted domain.",
        ),
    ]
    verdict = calculate_verdict("case-phish-01", indicators)

    assert verdict.total_score == 75
    assert verdict.risk_level == RiskLevel.PHISHING
    assert len(verdict.primary_indicators) == 2


def test_single_indicator_corroboration_cap():
    """Verify a single positive indicator with weight 75 cannot trigger PHISHING alone.

    Corroboration rule caps score at 69 and downgrades risk_level to SUSPICIOUS.
    """
    indicators = [
        Indicator(
            id="critical_credential_harvesting",
            agent="Forensic",
            weight=75,
            title="Known Phishing URL Match",
            evidence="Direct match in local threat intelligence feed.",
        )
    ]
    verdict = calculate_verdict("case-single-high-01", indicators)

    assert verdict.total_score == 69
    assert verdict.risk_level == RiskLevel.SUSPICIOUS
    assert "capped at 69" in verdict.summary


def test_single_agent_multiple_indicators_corroboration_cap():
    """Verify multiple positive indicators from the SAME agent still trigger corroboration cap."""
    indicators = [
        Indicator(
            id="lookalike_domain",
            agent="Forensic",
            weight=40,
            title="Typosquatting",
            evidence="Lookalike domain.",
        ),
        Indicator(
            id="spf_fail",
            agent="Forensic",
            weight=40,
            title="SPF Hard Fail",
            evidence="SPF failed.",
        ),
    ]
    verdict = calculate_verdict("case-same-agent-01", indicators)

    # 40 + 40 = 80, but only 1 distinct agent ("Forensic") -> must cap at 69
    assert verdict.total_score == 69
    assert verdict.risk_level == RiskLevel.SUSPICIOUS


def test_defang_url():
    """Verify URL defanging rules: http -> hxxp, https -> hxxps, and dot replacement in hostname."""
    test_url = "https://micros0ft.com/login"
    expected = "hxxps://micros0ft[.]com/login"
    assert defang_url(test_url) == expected

    http_url = "http://bad-domain.co.uk/steal"
    assert defang_url(http_url) == "hxxp://bad-domain[.]co[.]uk/steal"


def test_quarantine_approval_guard():
    """Verify approve_quarantine enforces non-empty analyst_id."""
    proposal = QuarantineProposal(
        proposal_id="QP-12345",
        case_id="case-12345",
        target_sender="phisher@evil.com",
        target_subject="Invoice Notice",
        affected_user="victim@corp.com",
        recommended_action="Quarantine",
    )

    # Empty analyst_id must raise ValueError
    with pytest.raises(ValueError, match="analyst_id cannot be empty"):
        approve_quarantine(proposal, "")

    with pytest.raises(ValueError, match="analyst_id cannot be empty"):
        approve_quarantine(proposal, "   ")

    # Valid analyst_id succeeds
    approved = approve_quarantine(proposal, "SOC-Analyst-42")
    assert approved.status == "APPROVED"
    assert approved.approved_by == "SOC-Analyst-42"


# =============================================================================
# API Endpoint Integration Tests (Member 1)
# =============================================================================

def test_analyze_and_get_case_details(client: TestClient):
    """POST /analyze -> GET /cases/{case_id} returns valid CaseDetails."""
    raw_email = (
        "From: alerts@paypal-verification-center.com\n"
        "To: victim@company.com\n"
        "Subject: Urgent: Verify Suspicious PayPal Activity\n\n"
        "Please visit https://paypal-verification-center.com/login to restore access."
    )
    res = client.post("/analyze", data={"raw_eml": raw_email})
    assert res.status_code == 200
    data = res.json()
    assert "case_id" in data
    case_id = data["case_id"]

    # Retrieve case details
    case_res = client.get(f"/cases/{case_id}")
    assert case_res.status_code == 200
    case_data = case_res.json()

    assert case_data["case_id"] == case_id
    assert "verdict" in case_data
    assert case_data["verdict"]["risk_level"] in ["SAFE", "SUSPICIOUS", "PHISHING"]
    assert 0 <= case_data["verdict"]["total_score"] <= 100
    assert len(case_data["agent_results"]) >= 2
    assert isinstance(case_data["defanged_urls"], list)
    assert any("[.]" in u for u in case_data["defanged_urls"])
    assert "reporter_reply_draft" in case_data
    assert len(case_data["reporter_reply_draft"]) > 0
    assert isinstance(case_data["what_if_simulation"], list)
    assert len(case_data["what_if_simulation"]) > 0


def test_analyze_with_eml_file_upload(client: TestClient):
    """POST /analyze with uploaded .eml file correctly extracts and processes email."""
    file_bytes = (
        b"From: security-alert@micros0ft-support.com\r\n"
        b"To: victim@target.com\r\n"
        b"Subject: Action Required: Password Expiry\r\n\r\n"
        b"Log in at http://fake-login-update.net/auth to keep access."
    )
    files = {"file": ("alert.eml", io.BytesIO(file_bytes), "message/rfc822")}
    res = client.post("/analyze", files=files)
    assert res.status_code == 200
    data = res.json()
    assert "case_id" in data

    case_res = client.get(f"/cases/{data['case_id']}")
    assert case_res.status_code == 200
    assert case_res.json()["case_id"] == data["case_id"]


def test_high_risk_phishing_stages_pending_proposal_in_queue(client: TestClient):
    """High-risk PHISHING verdict automatically stages a PENDING proposal in GET /queue."""
    res = client.post(
        "/analyze",
        data={"raw_eml": "From: security-alert@micros0ft-support.com\nSubject: Account Verification Required\n\nClick here"},
    )
    assert res.status_code == 200
    case_id = res.json()["case_id"]

    case_res = client.get(f"/cases/{case_id}")
    assert case_res.status_code == 200
    case_data = case_res.json()

    # Default fallback pipeline yields 35 + 40 = 75 (PHISHING)
    assert case_data["verdict"]["risk_level"] == "PHISHING"
    assert case_data["quarantine_proposal"] is not None

    proposal = case_data["quarantine_proposal"]
    prop_id = proposal["proposal_id"]
    assert proposal["status"] == "PENDING"
    assert proposal["case_id"] == case_id

    # Verify staged proposal exists in /queue
    queue_res = client.get("/queue")
    assert queue_res.status_code == 200
    queue_items = queue_res.json()
    matching = [p for p in queue_items if p["proposal_id"] == prop_id]
    assert len(matching) == 1
    assert matching[0]["status"] == "PENDING"

    # Verify status filtering in /queue
    pending_only = client.get("/queue?status=PENDING").json()
    assert any(p["proposal_id"] == prop_id for p in pending_only)

    approved_only = client.get("/queue?status=APPROVED").json()
    assert not any(p["proposal_id"] == prop_id for p in approved_only)


def test_queue_approval_validation_and_success(client: TestClient):
    """POST /queue/{proposal_id}/approve fails with 400 when analyst_id is blank and succeeds with APPROVED."""
    # Create a proposal via analysis
    res = client.post("/analyze", data={"raw_eml": "Subject: Test Phish\n\nLogin now"})
    case_id = res.json()["case_id"]
    case_data = client.get(f"/cases/{case_id}").json()
    prop_id = case_data["quarantine_proposal"]["proposal_id"]

    # Fails with 400 when analyst_id is empty or whitespace
    bad_res1 = client.post(f"/queue/{prop_id}/approve", json={"analyst_id": ""})
    assert bad_res1.status_code == 400
    assert "analyst_id cannot be empty" in bad_res1.json()["detail"]

    bad_res2 = client.post(f"/queue/{prop_id}/approve", json={"analyst_id": "   "})
    assert bad_res2.status_code == 400

    # Non-existent proposal returns 404
    missing_res = client.post("/queue/QP-DOESNOTEXIST/approve", json={"analyst_id": "analyst-01"})
    assert missing_res.status_code == 404

    # Succeeds with APPROVED when valid analyst_id is provided
    ok_res = client.post(f"/queue/{prop_id}/approve", json={"analyst_id": "SOC-Analyst-Alice"})
    assert ok_res.status_code == 200
    approved_prop = ok_res.json()
    assert approved_prop["status"] == "APPROVED"
    assert approved_prop["approved_by"] == "SOC-Analyst-Alice"

    # Case details reflects updated status
    refreshed_case = client.get(f"/cases/{case_id}").json()
    assert refreshed_case["quarantine_proposal"]["status"] == "APPROVED"
    assert refreshed_case["quarantine_proposal"]["approved_by"] == "SOC-Analyst-Alice"


def test_queue_rejection_validation_and_success(client: TestClient):
    """POST /queue/{proposal_id}/reject fails with 400 when blank and succeeds with REJECTED."""
    res = client.post("/analyze", data={"raw_eml": "Subject: Reject Test\n\nVerify"})
    case_id = res.json()["case_id"]
    case_data = client.get(f"/cases/{case_id}").json()
    prop_id = case_data["quarantine_proposal"]["proposal_id"]

    # Empty analyst_id fails with 400
    bad_res = client.post(f"/queue/{prop_id}/reject", json={"analyst_id": ""})
    assert bad_res.status_code == 400

    # Valid analyst_id rejects proposal
    ok_res = client.post(f"/queue/{prop_id}/reject", json={"analyst_id": "SOC-Analyst-Bob"})
    assert ok_res.status_code == 200
    rejected_prop = ok_res.json()
    assert rejected_prop["status"] == "REJECTED"
    assert rejected_prop["approved_by"] == "SOC-Analyst-Bob"

    # Case details reflects REJECTED status
    refreshed_case = client.get(f"/cases/{case_id}").json()
    assert refreshed_case["quarantine_proposal"]["status"] == "REJECTED"


def test_cases_chat_copilot_grounded_response(client: TestClient):
    """POST /cases/{case_id}/chat returns grounded responses strictly from case details."""
    res = client.post("/analyze", data={"raw_eml": "Subject: Urgent Wire Transfer\n\nLogin here"})
    case_id = res.json()["case_id"]

    # 1. Ask about suspicious links / URLs
    chat_url_res = client.post(
        f"/cases/{case_id}/chat",
        json={"message": "What URLs and links were observed in this email?"},
    )
    assert chat_url_res.status_code == 200
    url_data = chat_url_res.json()
    assert url_data["case_id"] == case_id
    assert "response" in url_data
    assert "hxxp" in url_data["response"] or "[.]" in url_data["response"]
    assert "grounding" in url_data
    assert "defanged_urls" in url_data["grounding"]

    # 2. Ask about indicators / evidence
    chat_ind_res = client.post(
        f"/cases/{case_id}/chat",
        json={"message": "Why was this flagged? Explain the indicators and evidence."},
    )
    assert chat_ind_res.status_code == 200
    ind_data = chat_ind_res.json()
    assert "PHISHING" in ind_data["response"] or "score" in ind_data["response"].lower()
    assert len(ind_data["grounding"]["primary_indicators"]) >= 2

    # 3. Ask about what-if simulations
    chat_sim_res = client.post(
        f"/cases/{case_id}/chat",
        json={"message": "What-if simulation counterfactuals"},
    )
    assert chat_sim_res.status_code == 200
    sim_data = chat_sim_res.json()
    assert "What-If" in sim_data["response"] or "DKIM" in sim_data["response"]

    # 4. 404 for non-existent case
    missing_chat = client.post("/cases/non-existent-case-id/chat", json={"message": "Hello"})
    assert missing_chat.status_code == 404

    # 5. 400 for empty message
    empty_chat = client.post(f"/cases/{case_id}/chat", json={"message": "   "})
    assert empty_chat.status_code == 400


def test_campaigns_endpoint(client: TestClient):
    """GET /campaigns returns campaign summaries for Analyst Console."""
    res = client.get("/campaigns")
    assert res.status_code == 200
    campaigns = res.json()
    assert isinstance(campaigns, list)
    assert len(campaigns) >= 1
    assert "campaign_id" in campaigns[0]
    assert "target_brand" in campaigns[0]
    assert "status" in campaigns[0]


@pytest.mark.asyncio
async def test_sse_streaming_trace_stages():
    """Verify SSE streaming emits complete stage sequence in order."""
    case_id = "test-sse-trace-stage-verify"
    task = asyncio.create_task(
        _run_analysis_pipeline(case_id, "From: user@corp.com\nSubject: Test\n\nMsg")
    )

    events = []
    gen = sse_event_generator(case_id)
    async for line in gen:
        if line.startswith("data: "):
            payload = json.loads(line[6:].strip())
            events.append(payload["event"])
            if payload["event"] == "DONE":
                break

    await task
    expected_sequence = ["PLAN_CREATED", "AGENT_PROGRESS", "AGENT_PROGRESS", "CRITIC_REVIEW", "SCORING_COMPLETE", "DONE"]
    assert events == expected_sequence
