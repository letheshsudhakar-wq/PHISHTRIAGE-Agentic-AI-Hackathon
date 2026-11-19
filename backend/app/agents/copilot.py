"""SOC Analyst Co-Pilot Assistant module for PhishTriage."""

from typing import Any, Dict
from app.agents.response import answer_case_question


async def ask_copilot(case: Any, query: str) -> Dict[str, Any]:
    """Answers analyst follow-up questions grounded strictly in CaseDetails telemetry."""
    case_dict = case.model_dump() if hasattr(case, "model_dump") else dict(case)
    ans = await answer_case_question(case_data=case_dict, user_message=query)

    verdict = case_dict.get("verdict", {})
    return {
        "case_id": case_dict.get("case_id", ""),
        "response": ans,
        "grounding": {
            "verdict": verdict.get("risk_level", "UNKNOWN") if isinstance(verdict, dict) else getattr(verdict, "risk_level", "UNKNOWN"),
            "total_score": verdict.get("total_score", 0) if isinstance(verdict, dict) else getattr(verdict, "total_score", 0),
            "primary_indicators": verdict.get("primary_indicators", []) if isinstance(verdict, dict) else getattr(verdict, "primary_indicators", []),
            "defanged_urls": case_dict.get("defanged_urls", []),
        },
    }
