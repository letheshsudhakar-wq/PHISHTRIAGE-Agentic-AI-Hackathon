import os
import tempfile
import pytest
import sqlite3

from app.models.schemas import (
    CaseDetails,
    Verdict,
    Indicator,
    RiskLevel,
    QuarantineProposal,
    AgentResult,
)
from app.core.database import (
    init_db,
    create_case,
    get_case,
    list_cases,
    create_campaign,
    associate_case_to_campaign,
    list_cases_for_campaign,
    create_proposal,
    get_proposal,
    list_proposals,
    approve_proposal,
    reject_proposal,
    list_audit_events,
    sanitize_text,
    get_connection,
)
from app.utils.osint import OSINTCache, OSINTResult, ReputationStatus


@pytest.fixture
def temp_db():
    """Provides a fresh isolated temporary database path for each test."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


def make_sample_case(case_id: str = "CASE-001", score: int = 75, risk: RiskLevel = RiskLevel.PHISHING) -> CaseDetails:
    verdict = Verdict(
        case_id=case_id,
        total_score=score,
        risk_level=risk,
        primary_indicators=[
            Indicator(
                id="lookalike_domain",
                agent="Forensic",
                weight=35,
                title="Lookalike Domain Detected",
                evidence="Sender domain mimics paypal.com with password=secret_pw123",
            ),
            Indicator(
                id="vision_brand_mismatch",
                agent="Vision",
                weight=40,
                title="Visual Impersonation",
                evidence="PayPal login screen with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token",
            ),
        ],
        summary="High confidence phishing targeting financial credentials.",
    )
    proposal = None
    if risk == RiskLevel.PHISHING:
        proposal = QuarantineProposal(
            proposal_id=f"QP-{case_id}",
            case_id=case_id,
            target_sender="phish@evil-site.com",
            target_subject="Urgent Security Alert",
            affected_user="victim@corp.net",
            recommended_action="Quarantine across organization",
            status="PENDING",
        )

    return CaseDetails(
        case_id=case_id,
        verdict=verdict,
        agent_results=[
            AgentResult(
                agent_name="Forensic",
                execution_time_ms=25,
                indicators=verdict.primary_indicators[:1],
                raw_notes="Evaluated DNS and headers safely.",
            )
        ],
        defanged_urls=["hxxps://evil-site[.]com/login"],
        reporter_reply_draft="Thank you for reporting this phishing email.",
        what_if_simulation=["If domain was legitimate, score drops to 0."],
        quarantine_proposal=proposal,
        limitations=["Zero-day attachments require sandbox."],
    )


# =============================================================================
# 1. DATABASE INITIALIZATION & FOREIGN KEYS
# =============================================================================

def test_database_initialization_and_foreign_keys(temp_db):
    conn = get_connection(temp_db)
    cursor = conn.cursor()

    # Verify tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r["name"] for r in cursor.fetchall()}
    assert "cases" in tables
    assert "campaigns" in tables
    assert "campaign_cases" in tables
    assert "quarantine_proposals" in tables
    assert "audit_log" in tables

    # Verify foreign keys are enabled
    cursor.execute("PRAGMA foreign_keys")
    fk_enabled = cursor.fetchone()[0]
    assert fk_enabled == 1
    conn.close()


# =============================================================================
# 2. CASE PERSISTENCE & SENSITIVE DATA REDACTION
# =============================================================================

def test_case_creation_and_retrieval(temp_db):
    sample = make_sample_case("CASE-101")
    created = create_case(sample, db_path=temp_db)
    assert created.case_id == "CASE-101"

    retrieved = get_case("CASE-101", db_path=temp_db)
    assert retrieved is not None
    assert retrieved.case_id == "CASE-101"
    assert retrieved.verdict.total_score == 75
    assert retrieved.verdict.risk_level == RiskLevel.PHISHING
    assert len(retrieved.verdict.primary_indicators) == 2
    assert retrieved.quarantine_proposal is not None
    assert retrieved.quarantine_proposal.proposal_id == "QP-CASE-101"


def test_case_listing_and_filtering(temp_db):
    create_case(make_sample_case("C-01", score=10, risk=RiskLevel.SAFE), db_path=temp_db)
    create_case(make_sample_case("C-02", score=50, risk=RiskLevel.SUSPICIOUS), db_path=temp_db)
    create_case(make_sample_case("C-03", score=85, risk=RiskLevel.PHISHING), db_path=temp_db)

    all_cases = list_cases(db_path=temp_db)
    assert len(all_cases) == 3

    phishing_only = list_cases(risk_level="PHISHING", db_path=temp_db)
    assert len(phishing_only) == 1
    assert phishing_only[0].case_id == "C-03"


def test_sensitive_content_redaction(temp_db):
    # Ensure raw tokens, passwords, credit cards, or SSNs are redacted on save
    sample = make_sample_case("CASE-REDACT")
    create_case(sample, db_path=temp_db)

    retrieved = get_case("CASE-REDACT", db_path=temp_db)
    evidence_1 = retrieved.verdict.primary_indicators[0].evidence
    evidence_2 = retrieved.verdict.primary_indicators[1].evidence

    assert "secret_pw123" not in evidence_1
    assert "[REDACTED_PASSWORD]" in evidence_1
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in evidence_2
    assert "[REDACTED_TOKEN]" in evidence_2


# =============================================================================
# 3. CAMPAIGN CREATION & ASSOCIATIONS
# =============================================================================

def test_campaign_creation_and_case_association(temp_db):
    create_case(make_sample_case("CASE-CAMP-1"), db_path=temp_db)
    create_case(make_sample_case("CASE-CAMP-2"), db_path=temp_db)

    camp = create_campaign(
        name="PayPal Credential Harvesting",
        threat_actor="FIN-7 Variant",
        target_brand="PayPal",
        threat_level="HIGH",
        indicators=["lookalike_domain", "vision_brand_mismatch"],
        db_path=temp_db,
    )
    cid = camp["campaign_id"]

    assert associate_case_to_campaign(cid, "CASE-CAMP-1", db_path=temp_db) is True
    assert associate_case_to_campaign(cid, "CASE-CAMP-2", db_path=temp_db) is True

    camp_cases = list_cases_for_campaign(cid, db_path=temp_db)
    assert len(camp_cases) == 2
    case_ids = {c.case_id for c in camp_cases}
    assert case_ids == {"CASE-CAMP-1", "CASE-CAMP-2"}


# =============================================================================
# 4. QUARANTINE PROPOSAL GOVERNANCE & APPROVAL
# =============================================================================

def test_quarantine_proposal_lifecycle_and_approval(temp_db):
    create_case(make_sample_case("CASE-QP-1"), db_path=temp_db)

    prop = get_proposal("QP-CASE-QP-1", db_path=temp_db)
    assert prop is not None
    assert prop.status == "PENDING"
    assert prop.approved_by is None

    # Valid approval
    approved = approve_proposal(prop.proposal_id, analyst_id="SOC-Analyst-Alice", db_path=temp_db)
    assert approved.status == "APPROVED"
    assert approved.approved_by == "SOC-Analyst-Alice"

    # Refetched reflects updated state
    refreshed = get_proposal(prop.proposal_id, db_path=temp_db)
    assert refreshed.status == "APPROVED"
    assert refreshed.approved_by == "SOC-Analyst-Alice"


def test_quarantine_proposal_rejection(temp_db):
    create_case(make_sample_case("CASE-QP-2"), db_path=temp_db)

    rejected = reject_proposal("QP-CASE-QP-2", analyst_id="SOC-Analyst-Bob", db_path=temp_db)
    assert rejected.status == "REJECTED"
    assert rejected.approved_by == "SOC-Analyst-Bob"


def test_quarantine_blank_analyst_rejected(temp_db):
    create_case(make_sample_case("CASE-QP-BLANK"), db_path=temp_db)

    with pytest.raises(ValueError, match="analyst_id cannot be empty"):
        approve_proposal("QP-CASE-QP-BLANK", analyst_id="", db_path=temp_db)

    with pytest.raises(ValueError, match="analyst_id cannot be empty"):
        reject_proposal("QP-CASE-QP-BLANK", analyst_id="   ", db_path=temp_db)


def test_invalid_proposal_status_transitions(temp_db):
    create_case(make_sample_case("CASE-QP-TRANS"), db_path=temp_db)
    approve_proposal("QP-CASE-QP-TRANS", analyst_id="Analyst-1", db_path=temp_db)

    # Cannot re-approve an already APPROVED proposal
    with pytest.raises(ValueError, match="Invalid status transition"):
        approve_proposal("QP-CASE-QP-TRANS", analyst_id="Analyst-2", db_path=temp_db)

    # Cannot reject an already APPROVED proposal
    with pytest.raises(ValueError, match="Invalid status transition"):
        reject_proposal("QP-CASE-QP-TRANS", analyst_id="Analyst-2", db_path=temp_db)


# =============================================================================
# 5. AUDIT LOGGING & APPEND-ONLY BEHAVIOR
# =============================================================================

def test_audit_logging_and_append_only(temp_db):
    create_case(make_sample_case("CASE-AUDIT-1"), db_path=temp_db)
    approve_proposal("QP-CASE-AUDIT-1", analyst_id="Alice", db_path=temp_db)

    events = list_audit_events(db_path=temp_db)
    assert len(events) >= 2

    actions = [e["action"] for e in events]
    assert "CREATE_CASE" in actions
    assert "APPROVE_QUARANTINE" in actions

    # Verify event fields
    approval_evt = next(e for e in events if e["action"] == "APPROVE_QUARANTINE")
    assert approval_evt["analyst_id"] == "Alice"
    assert approval_evt["resource_id"] == "QP-CASE-AUDIT-1"
    assert approval_evt["timestamp"] > 0


# =============================================================================
# 6. TRANSACTION ROLLBACK & OSINT COMPATIBILITY
# =============================================================================

def test_transaction_rollback_on_error(temp_db):
    # Attempting to insert duplicate primary key must rollback cleanly
    sample = make_sample_case("CASE-DUP")
    create_case(sample, db_path=temp_db)

    with pytest.raises(sqlite3.IntegrityError):
        # Direct SQL duplicate insertion
        conn = get_connection(temp_db)
        with conn:
            conn.execute("INSERT INTO cases (case_id, created_at, risk_level, total_score, summary, critic_adjusted, primary_indicators, defanged_urls) VALUES ('CASE-DUP', 0, 'SAFE', 0, '', 0, '[]', '[]')")

    # Verify DB remains consistent
    cases = list_cases(db_path=temp_db)
    assert len(cases) == 1


def test_osint_cache_compatibility(temp_db):
    # The OSINT cache can share the same database file without colliding tables
    cache = OSINTCache(db_path=temp_db)

    osint_item = OSINTResult(
        domain="phish-bank.com",
        registered_domain="phish-bank.com",
        domain_age_days=3,
        reputation=ReputationStatus.MALICIOUS,
        source="test",
    )
    cache.set(osint_item, ttl_seconds=3600)

    cached_res = cache.get("phish-bank.com")
    assert cached_res is not None
    assert cached_res.reputation == ReputationStatus.MALICIOUS
    assert cached_res.domain_age_days == 3

    # Verify cases table is still intact and operable
    sample = make_sample_case("CASE-COEXIST")
    create_case(sample, db_path=temp_db)
    assert get_case("CASE-COEXIST", db_path=temp_db) is not None

