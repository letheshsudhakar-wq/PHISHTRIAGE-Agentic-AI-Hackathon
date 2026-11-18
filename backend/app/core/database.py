"""SQLite Database and Persistence Module for PhishTriage AI.

Member 2 — Static Forensics, Parser & Persistence.
Stores cases, quarantine proposals, campaigns, and audit events securely.
Explicitly avoids storing raw emails, message bodies, HTML, attachments,
or unredacted sensitive secrets.
"""

from datetime import datetime, timezone
import json
import os
import re
import sqlite3
import uuid
from typing import Any, Dict, List, Optional, Tuple

from app.models.schemas import (
    CaseDetails,
    Indicator,
    QuarantineProposal,
    RiskLevel,
    Verdict,
    AgentResult,
)


_DEFAULT_DB_FILE = os.environ.get("PHISHTRIAGE_DB_PATH", "phishtriage.db")


# -----------------------------------------------------------------------------
# Redaction & Sanitization Helpers
# -----------------------------------------------------------------------------

_REDACT_PATTERNS = [
    (re.compile(r"(bearer\s+)[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(password\s*[:=]\s*)[^\s,;]+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"(apikey\s*[:=]\s*)[a-zA-Z0-9_\-]{15,}", re.IGNORECASE), r"\1[REDACTED_KEY]"),
    (re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"), "[REDACTED_CCN]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
]


def sanitize_text(text: Optional[str]) -> str:
    """Sanitizes strings to strip accidental tokens, passwords, or PII."""
    if not text:
        return ""
    sanitized = text
    for pattern, repl in _REDACT_PATTERNS:
        sanitized = pattern.sub(repl, sanitized)
    return sanitized.strip()


def sanitize_indicator(ind: Indicator) -> Dict[str, Any]:
    """Sanitizes an indicator before serialization."""
    return {
        "id": ind.id,
        "agent": ind.agent,
        "weight": ind.weight,
        "title": sanitize_text(ind.title),
        "evidence": sanitize_text(ind.evidence),
    }


# -----------------------------------------------------------------------------
# Database Connection & Initialization
# -----------------------------------------------------------------------------

def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Returns a new sqlite3 connection with WAL mode and foreign keys enabled."""
    path = db_path or os.environ.get("PHISHTRIAGE_DB_PATH", _DEFAULT_DB_FILE)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Optional[str] = None):
    """Initializes all database tables and indexes."""
    conn = get_connection(db_path)
    try:
        with conn:
            # 1. Cases Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    total_score INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    critic_adjusted INTEGER NOT NULL DEFAULT 0,
                    primary_indicators TEXT NOT NULL,
                    defanged_urls TEXT NOT NULL,
                    reporter_reply_draft TEXT,
                    what_if_simulation TEXT,
                    limitations TEXT,
                    agent_results TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases (created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_risk_level ON cases (risk_level)")

            # 2. Campaigns Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    threat_actor TEXT,
                    target_brand TEXT,
                    threat_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    indicators TEXT
                )
            """)

            # 3. Campaign Case Associations
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaign_cases (
                    campaign_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    associated_at REAL NOT NULL,
                    PRIMARY KEY (campaign_id, case_id),
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign_cases_case ON campaign_cases (case_id)")

            # 4. Quarantine Proposals Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_proposals (
                    proposal_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    target_sender TEXT NOT NULL,
                    target_subject TEXT NOT NULL,
                    affected_user TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approved_by TEXT,
                    created_at REAL NOT NULL,
                    decided_at REAL,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_proposals_status ON quarantine_proposals (status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_proposals_case ON quarantine_proposals (case_id)")

            # 5. Audit Events (Append-Only)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    analyst_id TEXT,
                    details TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp)")
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Case Persistence Functions
# -----------------------------------------------------------------------------

def create_case(case: CaseDetails, db_path: Optional[str] = None) -> CaseDetails:
    """
    Persists a CaseDetails record into SQLite.
    Redacts sensitive evidence and serializes metadata.
    """
    now = datetime.now(timezone.utc).timestamp()
    sanitized_indicators = [
        sanitize_indicator(i) for i in case.verdict.primary_indicators
    ]

    agent_results_summary = []
    for ar in case.agent_results:
        agent_results_summary.append({
            "agent_name": ar.agent_name,
            "execution_time_ms": ar.execution_time_ms,
            "indicators": [sanitize_indicator(i) for i in ar.indicators],
            "raw_notes": sanitize_text(ar.raw_notes),
            "confidence_score": ar.confidence_score,
        })

    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO cases (
                    case_id, created_at, risk_level, total_score, summary,
                    critic_adjusted, primary_indicators, defanged_urls,
                    reporter_reply_draft, what_if_simulation, limitations, agent_results
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case.case_id,
                    now,
                    case.verdict.risk_level.value,
                    case.verdict.total_score,
                    sanitize_text(case.verdict.summary),
                    1 if case.verdict.critic_adjusted else 0,
                    json.dumps(sanitized_indicators),
                    json.dumps(case.defanged_urls),
                    sanitize_text(case.reporter_reply_draft),
                    json.dumps(case.what_if_simulation),
                    json.dumps(case.limitations),
                    json.dumps(agent_results_summary),
                ),
            )

            # If case contains a quarantine proposal, persist it too
            if case.quarantine_proposal:
                qp = case.quarantine_proposal
                conn.execute(
                    """
                    INSERT INTO quarantine_proposals (
                        proposal_id, case_id, target_sender, target_subject,
                        affected_user, recommended_action, status, approved_by,
                        created_at, decided_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        qp.proposal_id,
                        case.case_id,
                        sanitize_text(qp.target_sender),
                        sanitize_text(qp.target_subject),
                        sanitize_text(qp.affected_user),
                        sanitize_text(qp.recommended_action),
                        qp.status,
                        qp.approved_by,
                        now,
                        None,
                    ),
                )

            # Audit event for case creation
            _append_audit_event_tx(
                conn,
                action="CREATE_CASE",
                resource_type="CASE",
                resource_id=case.case_id,
                analyst_id="SYSTEM",
                details={"risk_level": case.verdict.risk_level.value, "total_score": case.verdict.total_score},
            )

        return case
    finally:
        conn.close()


def get_case(case_id: str, db_path: Optional[str] = None) -> Optional[CaseDetails]:
    """Retrieves a CaseDetails by case_id, or None if not found."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        if not row:
            return None

        primary_indicators_data = json.loads(row["primary_indicators"])
        primary_indicators = [
            Indicator(**i) for i in primary_indicators_data
        ]

        verdict = Verdict(
            case_id=row["case_id"],
            total_score=row["total_score"],
            risk_level=RiskLevel(row["risk_level"]),
            primary_indicators=primary_indicators,
            summary=row["summary"],
            critic_adjusted=bool(row["critic_adjusted"]),
        )

        agent_results_data = json.loads(row["agent_results"]) if row["agent_results"] else []
        agent_results = []
        for ar in agent_results_data:
            inds = [Indicator(**i) for i in ar.get("indicators", [])]
            agent_results.append(
                AgentResult(
                    agent_name=ar["agent_name"],
                    execution_time_ms=ar["execution_time_ms"],
                    indicators=inds,
                    raw_notes=ar.get("raw_notes"),
                    confidence_score=ar.get("confidence_score", 1.0),
                )
            )

        # Retrieve attached quarantine proposal if one exists
        cursor.execute("SELECT * FROM quarantine_proposals WHERE case_id = ?", (case_id,))
        p_row = cursor.fetchone()
        proposal = None
        if p_row:
            proposal = QuarantineProposal(
                proposal_id=p_row["proposal_id"],
                case_id=p_row["case_id"],
                target_sender=p_row["target_sender"],
                target_subject=p_row["target_subject"],
                affected_user=p_row["affected_user"],
                recommended_action=p_row["recommended_action"],
                status=p_row["status"],
                approved_by=p_row["approved_by"],
            )

        return CaseDetails(
            case_id=row["case_id"],
            verdict=verdict,
            agent_results=agent_results,
            defanged_urls=json.loads(row["defanged_urls"]),
            reporter_reply_draft=row["reporter_reply_draft"] or "",
            what_if_simulation=json.loads(row["what_if_simulation"]) if row["what_if_simulation"] else [],
            quarantine_proposal=proposal,
            limitations=json.loads(row["limitations"]) if row["limitations"] else [],
        )
    finally:
        conn.close()


def list_cases(
    limit: int = 50,
    offset: int = 0,
    risk_level: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[CaseDetails]:
    """Lists cases with optional risk_level filter and pagination."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if risk_level:
            cursor.execute(
                """
                SELECT case_id FROM cases
                WHERE risk_level = ?
                ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
                (risk_level.upper(), limit, offset),
            )
        else:
            cursor.execute(
                """
                SELECT case_id FROM cases
                ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
        case_ids = [r["case_id"] for r in cursor.fetchall()]
        return [c for cid in case_ids if (c := get_case(cid, db_path=db_path))]
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Campaign Tracking Functions
# -----------------------------------------------------------------------------

def create_campaign(
    name: str,
    threat_actor: Optional[str] = None,
    target_brand: Optional[str] = None,
    threat_level: str = "MEDIUM",
    status: str = "ACTIVE",
    indicators: Optional[List[str]] = None,
    campaign_id: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates a distinct campaign record with explicit non-sensitive fingerprints."""
    cid = campaign_id or f"CAMP-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.now(timezone.utc).timestamp()
    ind_json = json.dumps(indicators or [])

    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO campaigns (
                    campaign_id, name, threat_actor, target_brand,
                    threat_level, status, created_at, updated_at, indicators
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cid,
                    sanitize_text(name),
                    sanitize_text(threat_actor),
                    sanitize_text(target_brand),
                    threat_level.upper(),
                    status.upper(),
                    now,
                    now,
                    ind_json,
                ),
            )
            _append_audit_event_tx(
                conn,
                action="CREATE_CAMPAIGN",
                resource_type="CAMPAIGN",
                resource_id=cid,
                analyst_id="SYSTEM",
                details={"name": name, "threat_level": threat_level},
            )

        return {
            "campaign_id": cid,
            "name": name,
            "threat_actor": threat_actor,
            "target_brand": target_brand,
            "threat_level": threat_level,
            "status": status,
            "created_at": now,
            "indicators": indicators or [],
        }
    finally:
        conn.close()


def associate_case_to_campaign(
    campaign_id: str,
    case_id: str,
    db_path: Optional[str] = None,
) -> bool:
    """Associates a case to an existing campaign."""
    now = datetime.now(timezone.utc).timestamp()
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO campaign_cases (campaign_id, case_id, associated_at)
                VALUES (?, ?, ?)
                """,
                (campaign_id, case_id, now),
            )
            conn.execute(
                "UPDATE campaigns SET updated_at = ? WHERE campaign_id = ?",
                (now, campaign_id),
            )
            _append_audit_event_tx(
                conn,
                action="ASSOCIATE_CASE_CAMPAIGN",
                resource_type="CAMPAIGN",
                resource_id=campaign_id,
                analyst_id="SYSTEM",
                details={"case_id": case_id},
            )
        return True
    finally:
        conn.close()


def list_cases_for_campaign(
    campaign_id: str,
    db_path: Optional[str] = None,
) -> List[CaseDetails]:
    """Returns all cases associated with a given campaign."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT case_id FROM campaign_cases
            WHERE campaign_id = ?
            ORDER BY associated_at DESC
            """,
            (campaign_id,),
        )
        case_ids = [r["case_id"] for r in cursor.fetchall()]
        return [c for cid in case_ids if (c := get_case(cid, db_path=db_path))]
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Quarantine Proposal Governance Functions
# -----------------------------------------------------------------------------

def create_proposal(
    proposal: QuarantineProposal,
    db_path: Optional[str] = None,
) -> QuarantineProposal:
    """Inserts a quarantine proposal in PENDING status."""
    now = datetime.now(timezone.utc).timestamp()
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO quarantine_proposals (
                    proposal_id, case_id, target_sender, target_subject,
                    affected_user, recommended_action, status, approved_by,
                    created_at, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal.proposal_id,
                    proposal.case_id,
                    sanitize_text(proposal.target_sender),
                    sanitize_text(proposal.target_subject),
                    sanitize_text(proposal.affected_user),
                    sanitize_text(proposal.recommended_action),
                    "PENDING",
                    None,
                    now,
                    None,
                ),
            )
            _append_audit_event_tx(
                conn,
                action="CREATE_PROPOSAL",
                resource_type="PROPOSAL",
                resource_id=proposal.proposal_id,
                analyst_id="SYSTEM",
                details={"case_id": proposal.case_id, "status": "PENDING"},
            )
        proposal.status = "PENDING"
        proposal.approved_by = None
        return proposal
    finally:
        conn.close()


def get_proposal(
    proposal_id: str,
    db_path: Optional[str] = None,
) -> Optional[QuarantineProposal]:
    """Fetches a quarantine proposal by proposal_id."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM quarantine_proposals WHERE proposal_id = ?",
            (proposal_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return QuarantineProposal(
            proposal_id=row["proposal_id"],
            case_id=row["case_id"],
            target_sender=row["target_sender"],
            target_subject=row["target_subject"],
            affected_user=row["affected_user"],
            recommended_action=row["recommended_action"],
            status=row["status"],
            approved_by=row["approved_by"],
        )
    finally:
        conn.close()


def list_proposals(
    status: Optional[str] = None,
    limit: int = 50,
    db_path: Optional[str] = None,
) -> List[QuarantineProposal]:
    """Lists proposals, optionally filtered by status (PENDING, APPROVED, REJECTED)."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if status:
            cursor.execute(
                """
                SELECT * FROM quarantine_proposals
                WHERE status = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (status.upper(), limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM quarantine_proposals
                ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            )
        rows = cursor.fetchall()
        return [
            QuarantineProposal(
                proposal_id=r["proposal_id"],
                case_id=r["case_id"],
                target_sender=r["target_sender"],
                target_subject=r["target_subject"],
                affected_user=r["affected_user"],
                recommended_action=r["recommended_action"],
                status=r["status"],
                approved_by=r["approved_by"],
            )
            for r in rows
        ]
    finally:
        conn.close()


def approve_proposal(
    proposal_id: str,
    analyst_id: str,
    db_path: Optional[str] = None,
) -> QuarantineProposal:
    """
    Approves a PENDING quarantine proposal.
    Rejects blank analyst_id. Prevents double approval via transactional guard.
    Updates DB state only (does not execute real quarantine).
    """
    if not analyst_id or not analyst_id.strip():
        raise ValueError("analyst_id cannot be empty or whitespace")

    clean_analyst = analyst_id.strip()
    now = datetime.now(timezone.utc).timestamp()
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM quarantine_proposals WHERE proposal_id = ?",
                (proposal_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Proposal '{proposal_id}' not found")
            if row["status"] != "PENDING":
                raise ValueError(
                    f"Invalid status transition: proposal '{proposal_id}' is already {row['status']}"
                )

            # Atomic conditional update
            cursor.execute(
                """
                UPDATE quarantine_proposals
                SET status = 'APPROVED', approved_by = ?, decided_at = ?
                WHERE proposal_id = ? AND status = 'PENDING'
                """,
                (clean_analyst, now, proposal_id),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Proposal '{proposal_id}' was concurrently modified")

            _append_audit_event_tx(
                conn,
                action="APPROVE_QUARANTINE",
                resource_type="PROPOSAL",
                resource_id=proposal_id,
                analyst_id=clean_analyst,
                details={"case_id": row["case_id"], "status": "APPROVED"},
            )

        return get_proposal(proposal_id, db_path=db_path)  # type: ignore
    finally:
        conn.close()


def reject_proposal(
    proposal_id: str,
    analyst_id: str,
    db_path: Optional[str] = None,
) -> QuarantineProposal:
    """
    Rejects a PENDING quarantine proposal.
    Rejects blank analyst_id. Prevents double rejection/approval via transactional guard.
    """
    if not analyst_id or not analyst_id.strip():
        raise ValueError("analyst_id cannot be empty or whitespace")

    clean_analyst = analyst_id.strip()
    now = datetime.now(timezone.utc).timestamp()
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM quarantine_proposals WHERE proposal_id = ?",
                (proposal_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Proposal '{proposal_id}' not found")
            if row["status"] != "PENDING":
                raise ValueError(
                    f"Invalid status transition: proposal '{proposal_id}' is already {row['status']}"
                )

            cursor.execute(
                """
                UPDATE quarantine_proposals
                SET status = 'REJECTED', approved_by = ?, decided_at = ?
                WHERE proposal_id = ? AND status = 'PENDING'
                """,
                (clean_analyst, now, proposal_id),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Proposal '{proposal_id}' was concurrently modified")

            _append_audit_event_tx(
                conn,
                action="REJECT_QUARANTINE",
                resource_type="PROPOSAL",
                resource_id=proposal_id,
                analyst_id=clean_analyst,
                details={"case_id": row["case_id"], "status": "REJECTED"},
            )

        return get_proposal(proposal_id, db_path=db_path)  # type: ignore
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Append-Only Audit Logging
# -----------------------------------------------------------------------------

def _append_audit_event_tx(
    conn: sqlite3.Connection,
    action: str,
    resource_type: str,
    resource_id: str,
    analyst_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
):
    """Internal helper to insert an audit event inside an existing transaction."""
    event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(timezone.utc).timestamp()
    details_str = json.dumps(details) if details else None

    conn.execute(
        """
        INSERT INTO audit_log (
            event_id, timestamp, action, resource_type,
            resource_id, analyst_id, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            now,
            action,
            resource_type,
            resource_id,
            analyst_id,
            details_str,
        ),
    )


def list_audit_events(
    resource_id: Optional[str] = None,
    limit: int = 100,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Returns append-only audit events, ordered chronologically."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if resource_id:
            cursor.execute(
                """
                SELECT * FROM audit_log
                WHERE resource_id = ?
                ORDER BY timestamp ASC LIMIT ?
                """,
                (resource_id, limit),
            )
        else:
            cursor.execute(
                "SELECT * FROM audit_log ORDER BY timestamp ASC LIMIT ?",
                (limit,),
            )
        rows = cursor.fetchall()
        return [
            {
                "event_id": r["event_id"],
                "timestamp": r["timestamp"],
                "action": r["action"],
                "resource_type": r["resource_type"],
                "resource_id": r["resource_id"],
                "analyst_id": r["analyst_id"],
                "details": json.loads(r["details"]) if r["details"] else None,
            }
            for r in rows
        ]
    finally:
        conn.close()

