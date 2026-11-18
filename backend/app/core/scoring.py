"""Deterministic scoring engine for PhishTriage.

Evaluates indicators using strict scoring bands and multi-agent corroboration policy rules.
"""

from urllib.parse import urlsplit, urlunsplit
from app.models.schemas import Indicator, RiskLevel, Verdict


def defang_url(url: str) -> str:
    """Defang a URL for safe display and logging.

    Converts http:// -> hxxp://, https:// -> hxxps://,
    and replaces '.' in the hostname with '[.]'.
    """
    if not url:
        return ""

    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()

    if scheme in ("http", "https"):
        defanged_scheme = "hxxps" if scheme == "https" else "hxxp"
        # Defang dots only in netloc/hostname, keeping path/query intact
        hostname = parsed.hostname or ""
        defanged_host = hostname.replace(".", "[.]")

        # Reconstruct netloc with port and user credentials if present
        userinfo = ""
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            userinfo += "@"

        port_str = f":{parsed.port}" if parsed.port else ""
        defanged_netloc = f"{userinfo}{defanged_host}{port_str}"

        return urlunsplit((
            defanged_scheme,
            defanged_netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        ))

    # If scheme was not http/https or is a naked domain
    if "://" in url:
        prefix, rest = url.split("://", 1)
        prefix_defanged = prefix.replace("http", "hxxp")
        if "/" in rest:
            domain, path = rest.split("/", 1)
            return f"{prefix_defanged}://{domain.replace('.', '[.]')}/{path}"
        return f"{prefix_defanged}://{rest.replace('.', '[.]')}"

    # Plain domain or string
    if "/" in url:
        domain, path = url.split("/", 1)
        return f"{domain.replace('.', '[.]')}/{path}"
    return url.replace(".", "[.]")


def calculate_verdict(
    case_id: str,
    indicators: list[Indicator],
    critic_adjusted: bool = False,
) -> Verdict:
    """Calculate deterministic risk verdict from list of indicators.

    Rules:
    1. Sum all indicator weights, clamped strictly between 0 and 100.
    2. Thresholds:
       - 0 to 34: SAFE
       - 35 to 69: SUSPICIOUS
       - 70 to 100: PHISHING
    3. Corroboration Policy: A single positive indicator alone CANNOT produce
       RiskLevel.PHISHING. If total_score >= 70 but there are fewer than 2 distinct
       positive indicators or fewer than 2 distinct agent sources among positive
       indicators, cap total_score at 69 and downgrade to RiskLevel.SUSPICIOUS.
    """
    raw_score = sum(ind.weight for ind in indicators)
    total_score = max(0, min(100, raw_score))

    # Initial threshold mapping
    if total_score >= 70:
        risk_level = RiskLevel.PHISHING
    elif total_score >= 35:
        risk_level = RiskLevel.SUSPICIOUS
    else:
        risk_level = RiskLevel.SAFE

    # Corroboration Policy Rule check
    positive_indicators = [ind for ind in indicators if ind.weight > 0]
    distinct_agents = {ind.agent for ind in positive_indicators}

    corroboration_capped = False
    if total_score >= 70:
        if len(positive_indicators) < 2 or len(distinct_agents) < 2:
            total_score = 69
            risk_level = RiskLevel.SUSPICIOUS
            corroboration_capped = True

    # Order primary indicators by weight descending
    primary_indicators = sorted(indicators, key=lambda i: i.weight, reverse=True)

    # Informative summary
    if risk_level == RiskLevel.PHISHING:
        summary = (
            f"Phishing confirmed (Score: {total_score}/100). "
            f"Corroborated across {len(distinct_agents)} distinct agent sources "
            f"with {len(positive_indicators)} positive risk indicators."
        )
    elif corroboration_capped:
        summary = (
            f"Suspicious email (Score capped at 69/100). "
            f"High-weight indicator observed but single-source. "
            f"Down-scoped to SUSPICIOUS pending multi-agent corroboration."
        )
    elif risk_level == RiskLevel.SUSPICIOUS:
        summary = (
            f"Suspicious email detected (Score: {total_score}/100) "
            f"based on {len(positive_indicators)} risk indicators."
        )
    else:
        summary = (
            f"Assessed as Safe (Score: {total_score}/100). "
            f"No corroborating phishing indicators detected."
        )

    if critic_adjusted:
        summary += " [Critic Adjusted]"

    return Verdict(
        case_id=case_id,
        total_score=total_score,
        risk_level=risk_level,
        primary_indicators=primary_indicators,
        summary=summary,
        critic_adjusted=critic_adjusted,
    )

