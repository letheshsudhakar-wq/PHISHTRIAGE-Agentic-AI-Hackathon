from datetime import datetime, timezone, timedelta
import json
import pytest
import requests
from unittest.mock import MagicMock

from app.utils.osint import (
    ReputationStatus,
    OSINTResult,
    OSINTCache,
    extract_and_validate_domain,
    query_rdap_registration,
    query_reputation_provider,
    lookup_domain_osint,
)


# =============================================================================
# 1. DOMAIN EXTRACTION & VALIDATION TESTS
# =============================================================================

def test_domain_normalization_and_registered_domain():
    # Full URL with scheme and path
    res = extract_and_validate_domain("https://sub.portal.paypal.com/signin?ref=1")
    assert res is not None
    host, reg_d = res
    assert host == "sub.portal.paypal.com"
    assert reg_d == "paypal.com"

    # Bare domain with trailing slash
    res2 = extract_and_validate_domain("evil-phish.co.uk/")
    assert res2 is not None
    host2, reg_d2 = res2
    assert host2 == "evil-phish.co.uk"
    assert reg_d2 == "evil-phish.co.uk"


def test_invalid_domains_and_safety_rejections():
    # Empty or whitespace
    assert extract_and_validate_domain("") is None
    assert extract_and_validate_domain("   ") is None
    assert extract_and_validate_domain(None) is None

    # Localhost and single labels
    assert extract_and_validate_domain("localhost") is None
    assert extract_and_validate_domain("http://localhost:8000") is None
    assert extract_and_validate_domain("internal_host") is None

    # IP literals (should be rejected from domain-specific lookup)
    assert extract_and_validate_domain("127.0.0.1") is None
    assert extract_and_validate_domain("http://192.168.1.1/login") is None
    assert extract_and_validate_domain("http://[::1]/") is None


# =============================================================================
# 2. RDAP REGISTRATION INTELLIGENCE (MOCKED)
# =============================================================================

def test_rdap_registration_newly_registered_domain():
    # Domain registered 10 days ago
    ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "events": [
            {"eventAction": "registration", "eventDate": ten_days_ago}
        ]
    }
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response

    date_str, age_days, err = query_rdap_registration(
        "new-phish-domain.com", session=mock_session
    )
    assert err is None
    assert date_str == ten_days_ago
    assert age_days == 10


def test_rdap_registration_older_domain():
    # Domain registered 1000 days ago
    thousand_days_ago = (datetime.now(timezone.utc) - timedelta(days=1000)).isoformat()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "events": [
            {"eventAction": "created", "eventDate": thousand_days_ago}
        ]
    }
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response

    date_str, age_days, err = query_rdap_registration(
        "established-brand.com", session=mock_session
    )
    assert err is None
    assert age_days == 1000


def test_rdap_registration_unknown_date_or_missing_event():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"}
        ]
    }
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response

    date_str, age_days, err = query_rdap_registration("private-whois.org", session=mock_session)
    assert date_str is None
    assert age_days is None
    assert "not present in RDAP response" in err


def test_rdap_timeout_handling():
    mock_session = MagicMock()
    mock_session.get.side_effect = requests.exceptions.Timeout("Connection timed out")

    date_str, age_days, err = query_rdap_registration("timeout-domain.com", session=mock_session)
    assert date_str is None
    assert age_days is None
    assert "timed out" in err


# =============================================================================
# 3. REPUTATION PROVIDER LOOKUPS (MOCKED)
# =============================================================================

def test_reputation_malicious_response():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 1,
                    "harmless": 2,
                    "undetected": 60,
                }
            }
        }
    }
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response

    status, details, err = query_reputation_provider(
        "evil-credential-stealer.com", api_key="test-api-key", session=mock_session
    )
    assert err is None
    assert status == ReputationStatus.MALICIOUS
    assert details["malicious"] == 8


def test_reputation_clean_response():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 75,
                    "undetected": 5,
                }
            }
        }
    }
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response

    status, details, err = query_reputation_provider(
        "legit-service.com", api_key="test-api-key", session=mock_session
    )
    assert err is None
    assert status == ReputationStatus.CLEAN
    assert details["harmless"] == 75


def test_reputation_missing_api_key():
    # Pass api_key=None and ensure env is cleared
    status, details, err = query_reputation_provider(
        "target.com", api_key="", session=MagicMock()
    )
    assert status == ReputationStatus.UNAVAILABLE
    assert details is None
    assert "missing" in err.lower() or "no reputation api key" in err.lower()


def test_reputation_provider_http_error():
    mock_response = MagicMock()
    mock_response.status_code = 503
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response

    status, details, err = query_reputation_provider(
        "target.com", api_key="test-key", session=mock_session
    )
    assert status == ReputationStatus.UNAVAILABLE
    assert "HTTP error 503" in err


# =============================================================================
# 4. SQLITE CACHE TESTS
# =============================================================================

def test_cache_miss_and_hit():
    cache = OSINTCache(db_path=":memory:")

    # Initial miss
    assert cache.get("test.com") is None

    # Populate cache
    res = OSINTResult(
        domain="test.com",
        registered_domain="test.com",
        domain_age_days=150,
        registration_date="2024-01-01T00:00:00Z",
        reputation=ReputationStatus.CLEAN,
        reputation_details={"harmless": 20},
        source="test",
    )
    cache.set(res, ttl_seconds=3600)

    # Cache hit
    cached = cache.get("test.com")
    assert cached is not None
    assert cached.cache_hit is True
    assert cached.domain == "test.com"
    assert cached.domain_age_days == 150
    assert cached.reputation == ReputationStatus.CLEAN
    assert cached.reputation_details["harmless"] == 20


def test_cache_expiration():
    cache = OSINTCache(db_path=":memory:")

    res = OSINTResult(
        domain="expired.com",
        registered_domain="expired.com",
        domain_age_days=5,
        reputation=ReputationStatus.UNKNOWN,
    )
    # TTL of -10 seconds (already expired)
    cache.set(res, ttl_seconds=-10)

    assert cache.get("expired.com") is None


# =============================================================================
# 5. HIGH-LEVEL ENTRY POINT & ZERO NETWORK TESTS
# =============================================================================

def test_lookup_domain_osint_offline_default():
    """Default lookup with enable_network=False must never call out and return UNAVAILABLE/UNKNOWN."""
    cache = OSINTCache(db_path=":memory:")

    res = lookup_domain_osint("suspicious-login-update.com", cache=cache, enable_network=False)
    assert res is not None
    assert res.domain == "suspicious-login-update.com"
    assert res.registered_domain == "suspicious-login-update.com"
    assert res.domain_age_days is None
    assert res.reputation == ReputationStatus.UNAVAILABLE
    assert res.cache_hit is False
    assert any("offline mode" in e for e in res.errors)

    # Verify cached on second call
    cached = lookup_domain_osint("suspicious-login-update.com", cache=cache, enable_network=False)
    assert cached is not None
    assert cached.cache_hit is True


def test_lookup_domain_osint_mocked_network():
    cache = OSINTCache(db_path=":memory:")

    # Mock both RDAP and VT
    session = MagicMock()
    # RDAP response
    rdap_resp = MagicMock()
    rdap_resp.status_code = 200
    rdap_resp.json.return_value = {
        "events": [{"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}]
    }

    # VT response
    vt_resp = MagicMock()
    vt_resp.status_code = 200
    vt_resp.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 12, "harmless": 0}}}
    }

    session.get.side_effect = [rdap_resp, vt_resp]

    res = lookup_domain_osint(
        "https://phish.attacker.com/login",
        cache=cache,
        enable_network=True,
        api_key="mock-key",
        session=session,
    )

    assert res is not None
    assert res.domain == "phish.attacker.com"
    assert res.registered_domain == "attacker.com"
    assert res.registration_date == "2026-11-01T00:00:00Z"
    assert res.reputation == ReputationStatus.MALICIOUS
    assert res.cache_hit is False

    # Second call hits cache
    cached = lookup_domain_osint(
        "phish.attacker.com",
        cache=cache,
        enable_network=True,
        api_key="mock-key",
        session=session,
    )
    assert cached is not None
    assert cached.cache_hit is True

