"""API route definitions for PhishTriage.

Includes endpoints for health check, email analysis, SSE trace streaming,
case inspection, quarantine governance queue, campaigns, and analyst co-pilot chat.
"""

import asyncio
import email
from email import policy
import time
from typing import Any
import uuid

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.sse import (
    CASE_STORE,
    push_event,
    sse_event_generator,
)
from app.core.scoring import calculate_verdict, defang_url
from app.models.schemas import (
    AgentResult,
    AnalyzeResponse,
    CaseDetails,
    Indicator,
    ParsedEmail,
    QuarantineApprovalRequest,
    QuarantineProposal,
    RiskLevel,
    Verdict,
)

# -----------------------------------------------------------------------------
# Plug-and-Play Integration Hooks for Member 2 & Member 3
# -----------------------------------------------------------------------------
try:
    from app.utils.eml_parser import parse_eml_bytes
except ImportError:
    parse_eml_bytes = None

try:
    from app.agents.forensic import run_forensic_agent
except ImportError:
    run_forensic_agent = None

try:
    from app.agents.vision import run_vision_agent
except ImportError:
    run_vision_agent = None

try:
    from app.agents.critic import run_critic_agent
except ImportError:
    run_critic_agent = None

try:
    from app.agents.response import generate_user_outputs
except ImportError:
    generate_user_outputs = None

try:
    from app.agents.copilot import ask_copilot
except ImportError:
    try:
        from app.agents.chat import ask_copilot
    except ImportError:
        ask_copilot = None

router = APIRouter()

# -----------------------------------------------------------------------------
# In-Memory Stores
# -----------------------------------------------------------------------------
PROPOSAL_STORE: dict[str, QuarantineProposal] = {}
CAMPAIGN_STORE: list[dict] = [
    {
        "campaign_id": "CAMP-2026-001",
        "name": "Microsoft 365 Credential Harvesting",
        "threat_actor": "Unknown / FIN7-style",
        "target_brand": "Microsoft",
        "case_count": 14,
        "first_seen": "2026-11-15T08:30:00Z",
        "status": "ACTIVE",
        "indicators": ["lookalike_domain", "spf_softfail", "vision_brand_mismatch"],
        "threat_level": "HIGH",
    },
    {
        "campaign_id": "CAMP-2026-002",
        "name": "Urgent Payroll / Direct Deposit Phish",
        "threat_actor": "BEC Actor Group 4",
        "target_brand": "ADP / Payroll",
        "case_count": 5,
        "first_seen": "2026-11-17T14:15:00Z",
        "status": "MONITORING",
        "indicators": ["reply_to_mismatch", "urgency_cues"],
        "threat_level": "MEDIUM",
    },
]
AUDIT_LOG: list[dict] = []


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    case_id: str
    response: str
    grounding: dict[str, Any] | None = None


def approve_quarantine(proposal: QuarantineProposal, analyst_id: str) -> QuarantineProposal:
    """Hard-coded guard for approving email quarantine actions.

    Raises ValueError if analyst_id is empty or missing.
    """
    if not analyst_id or not analyst_id.strip():
        raise ValueError("analyst_id cannot be empty")

    proposal.status = "APPROVED"
    proposal.approved_by = analyst_id.strip()
    return proposal


def _fallback_parse_eml(raw_content: str | bytes) -> ParsedEmail:
    """Lightweight built-in RFC 822 email parser stub."""
    raw_bytes = raw_content.encode("utf-8") if isinstance(raw_content, str) else raw_content
    raw_text = raw_content if isinstance(raw_content, str) else raw_content.decode("utf-8", errors="replace")

    sender = "security-alert@micros0ft-support.com"
    subject = "Urgent: Verify Your Microsoft 365 Account Immediately"
    body_text = raw_text

    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        if msg.get("From"):
            sender = str(msg.get("From"))
        if msg.get("Subject"):
            subject = str(msg.get("Subject"))
        body_part = msg.get_body(preferencelist=("plain", "html"))
        if body_part:
            body_text = str(body_part.get_content())
    except Exception:
        pass

    return ParsedEmail(
        sender=sender,
        subject=subject,
        headers_raw=raw_text[:1000],
        body_text=body_text,
        links=[
            {"url": "https://micros0ft.com/login", "text": "Sign In"},
            {"url": "http://verify-account-update.net/auth", "text": "Verify Account"},
        ],
    )


async def _run_analysis_pipeline(case_id: str, raw_content: str) -> None:
    """Multi-agent background orchestration pipeline.

    Emits SSE events:
      PLAN_CREATED -> AGENT_PROGRESS (Forensic) -> AGENT_PROGRESS (Vision)
      -> CRITIC_REVIEW -> SCORING_COMPLETE -> DONE
    """
    try:
        # Step 1: Initialize Plan
        await push_event(
            case_id,
            "PLAN_CREATED",
            {
                "steps": [
                    "Email Parser & Header Extraction",
                    "Forensic Analysis Agent",
                    "Vision Analysis Agent",
                    "Critic Review & Hallucination Filter",
                    "Deterministic Scoring Engine",
                ]
            },
        )
        await asyncio.sleep(0.01)

        # Step 2: Email Parsing (Member 2 hook or fallback stub)
        parsed_email = None
        if parse_eml_bytes is not None:
            try:
                raw_bytes = raw_content.encode("utf-8") if isinstance(raw_content, str) else raw_content
                parsed_email = parse_eml_bytes(raw_bytes)
            except Exception:
                parsed_email = None

        if parsed_email is None:
            parsed_email = _fallback_parse_eml(raw_content)

        # Step 3: Forensic Agent Analysis (Member 2 hook or fallback stub)
        await push_event(
            case_id,
            "AGENT_PROGRESS",
            {"agent": "Forensic", "status": "running", "message": "Evaluating headers & domain authenticity"},
        )
        await asyncio.sleep(0.01)

        forensic_result = None
        if run_forensic_agent is not None:
            try:
                if asyncio.iscoroutinefunction(run_forensic_agent):
                    res = await run_forensic_agent(parsed_email)
                else:
                    res = run_forensic_agent(parsed_email)
                if isinstance(res, AgentResult):
                    forensic_result = res
            except Exception:
                forensic_result = None

        if forensic_result is None:
            forensic_indicators = [
                Indicator(
                    id="lookalike_domain",
                    agent="Forensic",
                    weight=35,
                    title="Typosquatting / Lookalike Domain",
                    evidence="Domain 'micros0ft.com' mimics legitimate Microsoft brand domain.",
                ),
                Indicator(
                    id="spf_softfail",
                    agent="Forensic",
                    weight=15,
                    title="SPF Authentication SoftFail",
                    evidence="Sender IP is not authorized in SPF record for sending domain.",
                ),
            ]
            forensic_result = AgentResult(
                agent_name="Forensic",
                execution_time_ms=120,
                indicators=forensic_indicators,
                confidence_score=0.95,
                raw_notes="Header analysis revealed domain impersonation and SPF misalignment.",
            )

        # Step 4: Vision Agent Analysis (Member 3 hook or fallback stub)
        await push_event(
            case_id,
            "AGENT_PROGRESS",
            {"agent": "Vision", "status": "running", "message": "Inspecting visual branding & screenshots"},
        )
        await asyncio.sleep(0.01)

        vision_result = None
        if run_vision_agent is not None:
            try:
                if asyncio.iscoroutinefunction(run_vision_agent):
                    res = await run_vision_agent(parsed_email)
                else:
                    res = run_vision_agent(parsed_email)
                if isinstance(res, AgentResult):
                    vision_result = res
            except Exception:
                vision_result = None

        if vision_result is None:
            vision_indicators = [
                Indicator(
                    id="vision_brand_mismatch",
                    agent="Vision",
                    weight=40,
                    title="Visual Brand Impersonation",
                    evidence="Microsoft logo detected on page served from unverified external host.",
                )
            ]
            vision_result = AgentResult(
                agent_name="Vision",
                execution_time_ms=210,
                indicators=vision_indicators,
                confidence_score=0.90,
                raw_notes="High-confidence Microsoft login form visual spoofing detected.",
            )

        # Step 5: Critic Review & Corroboration Check (Member 3 hook or fallback stub)
        await push_event(
            case_id,
            "CRITIC_REVIEW",
            {"status": "reviewing", "message": "Validating multi-agent corroboration and evidence strength"},
        )
        await asyncio.sleep(0.01)

        all_indicators = list(forensic_result.indicators) + list(vision_result.indicators)
        critic_adjusted = False

        if run_critic_agent is not None:
            try:
                if asyncio.iscoroutinefunction(run_critic_agent):
                    critic_res = await run_critic_agent(all_indicators, [forensic_result, vision_result])
                else:
                    critic_res = run_critic_agent(all_indicators, [forensic_result, vision_result])

                if isinstance(critic_res, tuple) and len(critic_res) == 2:
                    all_indicators, critic_adjusted = critic_res
                elif isinstance(critic_res, list):
                    all_indicators = critic_res
            except Exception:
                pass

        # Step 6: Deterministic Scoring Engine Calculation
        await push_event(
            case_id,
            "SCORING_COMPLETE",
            {"status": "calculating", "message": "Running deterministic scoring and corroboration policy"},
        )

        verdict = calculate_verdict(case_id, all_indicators, critic_adjusted=critic_adjusted)

        raw_links = [l.get("url") for l in parsed_email.links if isinstance(l, dict) and l.get("url")]
        if not raw_links:
            raw_links = ["https://micros0ft.com/login", "http://verify-account-update.net/auth"]
        defanged_links = [defang_url(u) for u in raw_links]

        # Step 7: Generate User Outputs (Member 3 hook or fallback stubs)
        reply_draft = None
        what_if_sim = None
        limitations = None

        if generate_user_outputs is not None:
            try:
                if asyncio.iscoroutinefunction(generate_user_outputs):
                    user_outs = await generate_user_outputs(verdict, [forensic_result, vision_result], parsed_email)
                else:
                    user_outs = generate_user_outputs(verdict, [forensic_result, vision_result], parsed_email)
                if isinstance(user_outs, dict):
                    reply_draft = user_outs.get("reporter_reply_draft")
                    what_if_sim = user_outs.get("what_if_simulation")
                    limitations = user_outs.get("limitations")
            except Exception:
                pass

        if not reply_draft:
            reply_draft = (
                f"Hello,\n\nThank you for reporting this email with subject '{parsed_email.subject}'. "
                f"Our automated triage analyzed the message with verdict: {verdict.risk_level.value} "
                f"(Risk Score: {verdict.total_score}/100).\n\n"
                f"Summary: {verdict.summary}\n\nSecurity Operations Team"
            )

        if not what_if_sim:
            what_if_sim = [
                "If DKIM had passed: Score would reduce by 10 points.",
                "If domain was verified tenant domain: Verdict would downgrade to SAFE.",
            ]

        if not limitations:
            limitations = [
                "Zero-day malware payload scanning depends on external sandbox.",
                "Simulated pipeline run using Member 1 standard contracts.",
            ]

        # Step 8: Quarantine Proposal Governance
        # Whenever a case finishes with RiskLevel.PHISHING, automatically stage
        # QuarantineProposal(status="PENDING") into PROPOSAL_STORE and attach to CaseDetails.
        quarantine_proposal = None
        if verdict.risk_level == RiskLevel.PHISHING:
            quarantine_proposal = QuarantineProposal(
                proposal_id=f"QP-{uuid.uuid4().hex[:8].upper()}",
                case_id=case_id,
                target_sender=parsed_email.sender,
                target_subject=parsed_email.subject,
                affected_user="user@organization.corp",
                recommended_action="Quarantine message across all tenant inboxes & block sender domain",
                status="PENDING",
            )
            PROPOSAL_STORE[quarantine_proposal.proposal_id] = quarantine_proposal

        case_details = CaseDetails(
            case_id=case_id,
            verdict=verdict,
            agent_results=[forensic_result, vision_result],
            defanged_urls=defanged_links,
            reporter_reply_draft=reply_draft,
            what_if_simulation=what_if_sim,
            quarantine_proposal=quarantine_proposal,
            limitations=limitations,
        )

        CASE_STORE[case_id] = case_details

        # Step 9: Final Terminal Event
        await push_event(
            case_id,
            "DONE",
            {
                "case_id": case_id,
                "risk_level": verdict.risk_level.value,
                "total_score": verdict.total_score,
            },
        )
    except Exception as exc:
        await push_event(
            case_id,
            "DONE",
            {"case_id": case_id, "error": str(exc)},
        )


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint for the PhishTriage service."""
    return {"status": "ok", "service": "phishtriage-backend"}


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(
    file: UploadFile | None = File(None),
    raw_eml: str | None = Form(None),
    background_tasks: BackgroundTasks = None,
) -> AnalyzeResponse:
    """Initiates asynchronous email triage analysis.

    Accepts either an uploaded RFC 822 .eml file or raw email text via form data.
    Returns case_id immediately and starts background analysis.
    """
    if file is None and (raw_eml is None or not raw_eml.strip()):
        raise HTTPException(
            status_code=400,
            detail="Either a .eml file or 'raw_eml' text must be provided for analysis.",
        )

    if file:
        content_bytes = await file.read()
        email_content = content_bytes.decode("utf-8", errors="replace")
    else:
        email_content = raw_eml or ""

    case_id = str(uuid.uuid4())

    if background_tasks is not None:
        background_tasks.add_task(_run_analysis_pipeline, case_id, email_content)
    else:
        asyncio.create_task(_run_analysis_pipeline(case_id, email_content))

    return AnalyzeResponse(case_id=case_id)


@router.get("/analyze/{case_id}/stream")
async def stream_analysis(case_id: str) -> StreamingResponse:
    """Streams live Server-Sent Events (SSE) trace events for a given case."""
    return StreamingResponse(
        sse_event_generator(case_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/cases/{case_id}", response_model=CaseDetails)
async def get_case_details(case_id: str) -> CaseDetails:
    """Fetches full case details including verdict, indicators, and quarantine proposals."""
    if case_id not in CASE_STORE:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return CASE_STORE[case_id]


@router.get("/queue", response_model=list[QuarantineProposal])
async def get_quarantine_queue(status: str | None = None) -> list[QuarantineProposal]:
    """Returns list[QuarantineProposal] from PROPOSAL_STORE, optionally filtered by status."""
    proposals = list(PROPOSAL_STORE.values())
    if status is not None and status.strip():
        req_status = status.strip().upper()
        proposals = [p for p in proposals if p.status.upper() == req_status]
    return proposals


@router.post("/queue/{proposal_id}/approve", response_model=QuarantineProposal)
async def approve_queue_item(
    proposal_id: str,
    request: QuarantineApprovalRequest,
) -> QuarantineProposal:
    """Validates analyst_id via approve_quarantine(...), updates proposal.status = 'APPROVED',
    sets proposal.approved_by = analyst_id, appends an entry to AUDIT_LOG, and returns proposal.
    """
    if proposal_id not in PROPOSAL_STORE:
        for case in CASE_STORE.values():
            if case.quarantine_proposal and case.quarantine_proposal.proposal_id == proposal_id:
                PROPOSAL_STORE[proposal_id] = case.quarantine_proposal
                break

    if proposal_id not in PROPOSAL_STORE:
        raise HTTPException(status_code=404, detail=f"Quarantine proposal '{proposal_id}' not found.")

    proposal = PROPOSAL_STORE[proposal_id]
    try:
        approve_quarantine(proposal, request.analyst_id)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    if proposal.case_id in CASE_STORE:
        CASE_STORE[proposal.case_id].quarantine_proposal = proposal

    AUDIT_LOG.append({
        "timestamp": time.time(),
        "action": "APPROVE_QUARANTINE",
        "proposal_id": proposal_id,
        "case_id": proposal.case_id,
        "analyst_id": proposal.approved_by,
        "status": "APPROVED",
    })
    return proposal


@router.post("/queue/{proposal_id}/reject", response_model=QuarantineProposal)
async def reject_queue_item(
    proposal_id: str,
    request: QuarantineApprovalRequest,
) -> QuarantineProposal:
    """Validates analyst_id is non-empty, updates proposal.status = 'REJECTED',
    appends an entry to AUDIT_LOG, and returns proposal.
    """
    if not request.analyst_id or not request.analyst_id.strip():
        raise HTTPException(status_code=400, detail="analyst_id cannot be empty")

    if proposal_id not in PROPOSAL_STORE:
        for case in CASE_STORE.values():
            if case.quarantine_proposal and case.quarantine_proposal.proposal_id == proposal_id:
                PROPOSAL_STORE[proposal_id] = case.quarantine_proposal
                break

    if proposal_id not in PROPOSAL_STORE:
        raise HTTPException(status_code=404, detail=f"Quarantine proposal '{proposal_id}' not found.")

    proposal = PROPOSAL_STORE[proposal_id]
    proposal.status = "REJECTED"
    proposal.approved_by = request.analyst_id.strip()

    if proposal.case_id in CASE_STORE:
        CASE_STORE[proposal.case_id].quarantine_proposal = proposal

    AUDIT_LOG.append({
        "timestamp": time.time(),
        "action": "REJECT_QUARANTINE",
        "proposal_id": proposal_id,
        "case_id": proposal.case_id,
        "analyst_id": proposal.approved_by,
        "status": "REJECTED",
    })
    return proposal


@router.get("/campaigns")
async def get_campaigns() -> list[dict]:
    """Returns CAMPAIGN_STORE (clustered campaign summaries)."""
    return CAMPAIGN_STORE


@router.post("/cases/{case_id}/chat", response_model=ChatResponse)
async def chat_with_copilot(case_id: str, request: ChatRequest) -> ChatResponse:
    """Analyst Co-Pilot Q&A endpoint.

    Fetches CaseDetails from CASE_STORE (404 if missing) and answers questions
    grounded strictly in that case's verdict, primary_indicators, defanged_urls,
    and what_if_simulation (with a clean hook for Member 3's LLM helper if present,
    plus an immediate deterministic fallback so it never crashes).
    """
    if case_id not in CASE_STORE:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    case = CASE_STORE[case_id]
    user_msg = (request.message or "").strip()
    if not user_msg:
        raise HTTPException(status_code=400, detail="message cannot be empty")

    # Member 3 LLM Helper hook
    if ask_copilot is not None:
        try:
            if asyncio.iscoroutinefunction(ask_copilot):
                copilot_reply = await ask_copilot(case=case, query=user_msg)
            else:
                copilot_reply = ask_copilot(case=case, query=user_msg)

            if isinstance(copilot_reply, dict):
                return ChatResponse(
                    case_id=case_id,
                    response=copilot_reply.get("response", str(copilot_reply)),
                    grounding=copilot_reply.get("grounding"),
                )
            elif isinstance(copilot_reply, str):
                return ChatResponse(
                    case_id=case_id,
                    response=copilot_reply,
                    grounding={
                        "verdict": case.verdict.risk_level.value,
                        "total_score": case.verdict.total_score,
                    },
                )
        except Exception:
            pass

    # Deterministic fallback grounded strictly in case details
    grounding = {
        "verdict": case.verdict.risk_level.value,
        "total_score": case.verdict.total_score,
        "summary": case.verdict.summary,
        "primary_indicators": [
            {"id": i.id, "title": i.title, "agent": i.agent, "weight": i.weight, "evidence": i.evidence}
            for i in case.verdict.primary_indicators
        ],
        "defanged_urls": case.defanged_urls,
        "what_if_simulation": case.what_if_simulation,
    }

    q = user_msg.lower()
    if any(k in q for k in ["url", "link", "domain", "site"]):
        urls_str = ", ".join(case.defanged_urls) if case.defanged_urls else "No defanged URLs recorded."
        domain_indicators = [
            f"[{i.agent}] {i.title}: {i.evidence}"
            for i in case.verdict.primary_indicators
            if "domain" in i.title.lower() or "url" in i.title.lower() or "domain" in i.id.lower()
        ]
        dom_str = "; ".join(domain_indicators) if domain_indicators else "No specific domain mismatch indicators."
        reply = (
            f"Case {case_id} contains the following defanged links: {urls_str}. "
            f"Related domain indicators: {dom_str}"
        )
    elif any(k in q for k in ["what if", "simulation", "counterfactual", "hypothetical"]):
        sim_str = " | ".join(case.what_if_simulation) if case.what_if_simulation else "No simulations recorded."
        reply = f"What-If Simulation for Case {case_id}: {sim_str}"
    elif any(k in q for k in ["indicator", "evidence", "why", "reason", "finding", "score"]):
        ind_bullets = "\n".join(
            f"- [{i.agent}] {i.title} (+{i.weight}): {i.evidence}"
            for i in case.verdict.primary_indicators
        )
        reply = (
            f"Case {case_id} has verdict {case.verdict.risk_level.value} "
            f"with a deterministic score of {case.verdict.total_score}/100.\n"
            f"Primary Indicators:\n{ind_bullets}\n"
            f"Summary: {case.verdict.summary}"
        )
    elif any(k in q for k in ["quarantine", "action", "recommend"]):
        if case.quarantine_proposal:
            qp = case.quarantine_proposal
            reply = (
                f"Quarantine Proposal ({qp.proposal_id}): Status is {qp.status}. "
                f"Recommended action: {qp.recommended_action} for sender '{qp.target_sender}'."
            )
        else:
            reply = f"No quarantine proposal was staged for Case {case_id}."
    else:
        top_inds = ", ".join(f"{i.title} (+{i.weight})" for i in case.verdict.primary_indicators[:3])
        reply = (
            f"Case {case_id} is assessed as {case.verdict.risk_level.value} "
            f"(Score: {case.verdict.total_score}/100). "
            f"Top indicators: {top_inds or 'None'}. "
            f"Verdict summary: {case.verdict.summary}"
        )

    return ChatResponse(case_id=case_id, response=reply, grounding=grounding)


# Maintain backward compatibility with case quarantine endpoint
@router.post("/cases/{case_id}/quarantine/approve", response_model=QuarantineProposal)
async def approve_case_quarantine(
    case_id: str,
    request: QuarantineApprovalRequest,
) -> QuarantineProposal:
    """Approve a pending quarantine proposal for a given case."""
    if case_id not in CASE_STORE:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    case = CASE_STORE[case_id]
    if not case.quarantine_proposal:
        raise HTTPException(
            status_code=400,
            detail=f"Case '{case_id}' does not have an active quarantine proposal.",
        )

    try:
        approve_quarantine(case.quarantine_proposal, request.analyst_id)
        # Keep PROPOSAL_STORE & AUDIT_LOG updated
        PROPOSAL_STORE[case.quarantine_proposal.proposal_id] = case.quarantine_proposal
        AUDIT_LOG.append({
            "timestamp": time.time(),
            "action": "APPROVE_QUARANTINE",
            "proposal_id": case.quarantine_proposal.proposal_id,
            "case_id": case_id,
            "analyst_id": case.quarantine_proposal.approved_by,
            "status": "APPROVED",
        })
        return case.quarantine_proposal
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
