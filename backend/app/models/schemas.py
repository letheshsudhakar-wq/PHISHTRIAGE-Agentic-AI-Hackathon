"""Pydantic schemas and contracts for PhishTriage.

Locked JSON contracts shared across all multi-agent triage modules.
"""

from enum import Enum
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


class Indicator(BaseModel):
    id: str
    agent: str
    weight: int
    title: str
    evidence: str


class AgentResult(BaseModel):
    agent_name: str
    execution_time_ms: int
    indicators: list[Indicator]
    raw_notes: str | None = None
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)


class ParsedEmail(BaseModel):
    message_id: str | None = None
    sender: str
    reply_to: str | None = None
    return_path: str | None = None
    subject: str
    headers_raw: str
    body_text: str
    links: list[dict[str, str]] = []
    attachments: list[dict[str, str]] = []
    inline_images: list[dict[str, str]] = []


class Verdict(BaseModel):
    case_id: str
    total_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    primary_indicators: list[Indicator]
    summary: str
    critic_adjusted: bool = False


class QuarantineProposal(BaseModel):
    proposal_id: str
    case_id: str
    target_sender: str
    target_subject: str
    affected_user: str
    recommended_action: str
    status: str = Field(default="PENDING")
    approved_by: str | None = None


class CaseDetails(BaseModel):
    case_id: str
    verdict: Verdict
    agent_results: list[AgentResult]
    defanged_urls: list[str]
    reporter_reply_draft: str
    what_if_simulation: list[str]
    quarantine_proposal: QuarantineProposal | None = None
    limitations: list[str] = []


class AnalyzeResponse(BaseModel):
    case_id: str


class QuarantineApprovalRequest(BaseModel):
    analyst_id: str

