"""Critic Agent: Adversarial Reflection & Threat Calibration Engine.

Audits Forensic and Vision outputs, detects prompt injection attempts,
resolves cross-modal contradictions, and calibrates indicator weights
prior to deterministic scoring.
"""

import re
import time
from typing import List, Tuple

from app.models.schemas import AgentResult, Indicator

# Adversarial prompt-injection attack signatures
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous\s+|prior\s+)?(?:instructions|rules|prompts|directives)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous\s+|prior\s+)?(?:instructions|rules|security|guidelines)", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"mark\s+(?:this\s+email\s+as\s+)?safe", re.IGNORECASE),
    re.compile(r"verdict\s*:\s*safe", re.IGNORECASE),
    re.compile(r"score\s*:\s*0\b", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"###\s*SYSTEM", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"override\s+(?:all\s+)?(?:security\s+)?rules", re.IGNORECASE),
    re.compile(r"report\s+as\s+safe", re.IGNORECASE),
    re.compile(r"do\s+not\s+flag", re.IGNORECASE),
    re.compile(r"bypass\s+security\s+check", re.IGNORECASE),
]


async def run_critic(
    raw_email_data: dict,
    forensic_indicators: List[Indicator],
    vision_result: AgentResult,
) -> Tuple[AgentResult, List[Indicator], bool, List[str], str]:
    """Audit agent findings, neutralize adversarial attacks, and calibrate indicator weights.

    Args:
        raw_email_data: Dictionary containing email subject, body, html, headers, etc.
        forensic_indicators: Indicators extracted by the Forensic Analyst Agent.
        vision_result: AgentResult output from the Visual & Social Engineering Agent.

    Returns:
        Tuple of:
            - critic_agent_result: AgentResult representing the Critic's own findings.
            - calibrated_indicators: Full list of calibrated indicators (Forensic + Vision + Critic).
            - critic_adjusted: Boolean flag indicating if any adjustments/rules fired.
            - tags: List of triage tags (e.g. 'prompt_injection', 'agent_disagreement').
            - sanitized_body: Body text with prompt-injection control strings neutralized.
    """
    start_time = time.perf_counter()
    critic_adjusted = False
    tags: List[str] = []
    critic_indicators: List[Indicator] = []
    critic_notes: List[str] = []

    # Extract all text representations to scan
    subject = str(raw_email_data.get("subject", "") or "")
    body = str(raw_email_data.get("body") or raw_email_data.get("body_text", "") or "")
    html = str(raw_email_data.get("html", "") or "")
    vision_notes = str(vision_result.raw_notes or "")

    combined_text = f"{subject}\n{body}\n{html}\n{vision_notes}"
    sanitized_body = body

    # -------------------------------------------------------------------------
    # RULE 5 (Run First): Prompt-Injection Intercept & Isolation
    # -------------------------------------------------------------------------
    detected_injections: List[str] = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        match = pattern.search(combined_text)
        if match:
            matched_snippet = match.group(0)
            detected_injections.append(matched_snippet)
            # Neutralize in sanitized body
            sanitized_body = pattern.sub("[NEUTRALIZED_INJECTION_PAYLOAD]", sanitized_body)

    if detected_injections:
        critic_adjusted = True
        tags.append("prompt_injection")
        snippet_summary = ", ".join(f"'{s}'" for s in detected_injections[:3])
        critic_indicators.append(
            Indicator(
                id="prompt_injection_attempt",
                agent="Critic",
                weight=50,
                title="Adversarial Prompt Injection Attempt Detected",
                evidence=f"Adversarial prompt injection pattern detected: {snippet_summary}",
            )
        )
        critic_notes.append(f"Prompt injection detected ({len(detected_injections)} occurrences); payload neutralized.")

    # -------------------------------------------------------------------------
    # RULE 1: Brand Domain Mismatch Escalation
    # Condition: vision_brand_mismatch present AND aligned_auth_pass NOT present
    # -------------------------------------------------------------------------
    has_vision_brand_mismatch = any(i.id == "vision_brand_mismatch" for i in vision_result.indicators)
    has_aligned_auth_pass = any(i.id == "aligned_auth_pass" for i in forensic_indicators)

    if has_vision_brand_mismatch and not has_aligned_auth_pass:
        critic_adjusted = True
        tags.append("brand_domain_mismatch_escalation")
        critic_notes.append("Brand domain mismatch without aligned auth: severity elevated to override benign interpretation.")

    # -------------------------------------------------------------------------
    # RULE 2: Auth Pass on Look-Alike Domain Neutralization
    # Condition: aligned_auth_pass present AND (lookalike_domain OR homoglyph_or_punycode) present
    # Action: Neutralize aligned_auth_pass (-25 -> 0)
    # -------------------------------------------------------------------------
    has_lookalike = any(i.id in ("lookalike_domain", "homoglyph_or_punycode") for i in forensic_indicators)
    calibrated_forensics: List[Indicator] = []

    for ind in forensic_indicators:
        if ind.id == "aligned_auth_pass" and has_lookalike:
            critic_adjusted = True
            tags.append("auth_pass_neutralized")
            calibrated_forensics.append(
                Indicator(
                    id="aligned_auth_pass",
                    agent=ind.agent,
                    weight=0,
                    title="Neutralized Aligned Auth Pass",
                    evidence=f"{ind.evidence} (Neutralized by Critic: valid auth on spoofed look-alike infrastructure)",
                )
            )
            critic_notes.append("Neutralized aligned_auth_pass (-25 -> 0) due to authentic auth on lookalike domain.")
        else:
            calibrated_forensics.append(ind)

    # -------------------------------------------------------------------------
    # RULE 3: Agent Disagreement Flag
    # Condition: Forensic positive score < 20 AND Vision score > 60
    # -------------------------------------------------------------------------
    forensic_positive_score = sum(i.weight for i in forensic_indicators if i.weight > 0)
    vision_score = sum(i.weight for i in vision_result.indicators)

    if forensic_positive_score < 20 and vision_score > 60:
        tags.append("agent_disagreement")
        critic_notes.append("Agent disagreement: low forensic score (<20) with high vision score (>60), indicating image-only phish.")

    # -------------------------------------------------------------------------
    # RULE 4: Low Vision Confidence Calibration
    # Condition: Vision score > 40 AND vision_result.confidence_score < 0.60
    # Action: Halve the weight of every Vision indicator
    # -------------------------------------------------------------------------
    calibrated_vision: List[Indicator] = []
    if vision_score > 40 and vision_result.confidence_score < 0.60:
        critic_adjusted = True
        tags.append("low_vision_confidence_calibrated")
        for ind in vision_result.indicators:
            calibrated_weight = int(round(ind.weight * 0.5))
            calibrated_vision.append(
                Indicator(
                    id=ind.id,
                    agent=ind.agent,
                    weight=calibrated_weight,
                    title=ind.title,
                    evidence=f"{ind.evidence} (halved due to low vision confidence)",
                )
            )
        critic_notes.append("Vision indicators halved due to low confidence (<0.60).")
    else:
        calibrated_vision = list(vision_result.indicators)

    # Combine all calibrated indicators
    calibrated_indicators: List[Indicator] = calibrated_forensics + calibrated_vision + critic_indicators

    elapsed_ms = int((time.perf_counter() - start_time) * 1000)
    raw_notes_str = "; ".join(critic_notes) if critic_notes else "Critic audit complete: no contradictions or overrides detected."

    critic_agent_result = AgentResult(
        agent_name="Critic",
        execution_time_ms=elapsed_ms,
        indicators=critic_indicators,
        raw_notes=raw_notes_str,
        confidence_score=1.0,
    )

    return (
        critic_agent_result,
        calibrated_indicators,
        critic_adjusted,
        tags,
        sanitized_body,
    )


async def run_critic_agent(
    all_indicators: List[Indicator],
    agent_results: List[AgentResult],
    raw_email_data: object = None,
) -> Tuple[List[Indicator], bool]:
    """Adapter for orchestrator and API routes calling run_critic_agent(all_indicators, agent_results)."""
    forensic_res = next((r for r in agent_results if getattr(r, "agent_name", "") == "Forensic"), None)
    vision_res = next((r for r in agent_results if getattr(r, "agent_name", "") == "Vision"), None) or AgentResult(
        agent_name="Vision", execution_time_ms=0, indicators=[], confidence_score=1.0
    )

    forensic_indicators = forensic_res.indicators if forensic_res else [i for i in all_indicators if getattr(i, "agent", "") == "Forensic"]

    email_data = raw_email_data if isinstance(raw_email_data, dict) else {
        "subject": "",
        "body": " ".join(getattr(i, "evidence", "") for i in all_indicators),
        "html": "",
    }

    _, calibrated_indicators, critic_adjusted, _, _ = await run_critic(
        raw_email_data=email_data,
        forensic_indicators=forensic_indicators,
        vision_result=vision_res,
    )
    return calibrated_indicators, critic_adjusted

