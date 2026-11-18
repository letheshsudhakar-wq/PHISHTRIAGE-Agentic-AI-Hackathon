"""Safe, passive OSINT enrichment and SQLite-based caching for PhishTriage AI.

Member 2 - Static Forensics, Parser & Persistence.
Strictly passive: Never visits, resolves, or directly contacts submitted domains.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
import os
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import tldextract


class ReputationStatus(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class OSINTResult:
    domain: str
    registered_domain: str
    domain_age_days: Optional[int] = None
    registration_date: Optional[str] = None
    reputation: ReputationStatus = ReputationStatus.UNKNOWN
    reputation_details: Optional[Dict[str, Any]] = None
    source: str = "offline"
    cache_hit: bool = False
    errors: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["reputation"] = self.reputation.value
        return d


# Initialize offline tldextract
_extractor = tldextract.TLDExtract(suffix_list_urls=())

# Blocked IP networks for network safety (prevent SSRF)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),     # Private RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),    # Private RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
]


def extract_and_validate_domain(target: str) -> Optional[Tuple[str, str]]:
    """
    Safely extracts and validates (hostname, registered_domain).
    Rejects malformed inputs, IP addresses, localhost, and loopback.
    Never fetches or visits the submitted URL.
    """
    if not target or not isinstance(target, str):
        return None

    raw = target.strip()
    if not raw:
        return None

    # Strip scheme if present, but do not request
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        try:
            parsed = urlparse(raw)
            host = parsed.hostname
        except Exception:
            return None
    else:
        # Might be a domain or path like 'example.com/path'
        host = raw.split("/")[0].split(":")[0]

    if not host:
        return None

    host = host.strip(".").lower()

    # Reject localhost or single label domains
    if host == "localhost" or "." not in host:
        return None

    # Check if host is an IP address
    clean_ip_host = host.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_ip_host)
        # It's an IP literal, not a domain name
        return None
    except ValueError:
        pass

    # Extract registered domain using offline suffix list
    ext = _extractor(host)
    reg_domain = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else getattr(ext, "registered_domain", None)
    if not reg_domain or not ext.suffix:
        return None

    reg_domain = reg_domain.lower()
    return host, reg_domain


class OSINTCache:
    """
    Isolated SQLite cache for OSINT domain queries.
    Stores parameterized records with expiration TTLs.
    """
    def __init__(self, db_path: str = ":memory:", default_ttl_hours: int = 24):
        self.db_path = db_path
        self.default_ttl_hours = default_ttl_hours
        self._shared_conn = None
        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:")
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS osint_cache (
                domain TEXT PRIMARY KEY,
                registered_domain TEXT NOT NULL,
                domain_age_days INTEGER,
                registration_date TEXT,
                reputation TEXT NOT NULL,
                reputation_details TEXT,
                source TEXT NOT NULL,
                retrieval_timestamp REAL NOT NULL,
                expiration_timestamp REAL NOT NULL,
                errors TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_osint_expiration ON osint_cache (expiration_timestamp)")
        conn.commit()
        if self._shared_conn is None:
            conn.close()

    def get(self, domain: str) -> Optional[OSINTResult]:
        domain = domain.lower()
        now = time.time()
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM osint_cache WHERE domain = ? AND expiration_timestamp > ?",
                (domain, now),
            )
            row = cursor.fetchone()
            if not row:
                return None

            errors = json.loads(row["errors"]) if row["errors"] else None
            details = json.loads(row["reputation_details"]) if row["reputation_details"] else None
            rep_str = row["reputation"]
            try:
                reputation = ReputationStatus(rep_str)
            except Exception:
                reputation = ReputationStatus.UNKNOWN

            return OSINTResult(
                domain=row["domain"],
                registered_domain=row["registered_domain"],
                domain_age_days=row["domain_age_days"],
                registration_date=row["registration_date"],
                reputation=reputation,
                reputation_details=details,
                source=row["source"],
                cache_hit=True,
                errors=errors,
            )
        except Exception:
            return None
        finally:
            if self._shared_conn is None:
                conn.close()

    def set(
        self,
        result: OSINTResult,
        ttl_seconds: Optional[int] = None,
    ):
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else (self.default_ttl_hours * 3600)
        exp = now + ttl

        errors_json = json.dumps(result.errors) if result.errors else None
        details_json = json.dumps(result.reputation_details) if result.reputation_details else None

        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO osint_cache (
                    domain, registered_domain, domain_age_days,
                    registration_date, reputation, reputation_details,
                    source, retrieval_timestamp, expiration_timestamp, errors
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.domain.lower(),
                    result.registered_domain.lower(),
                    result.domain_age_days,
                    result.registration_date,
                    result.reputation.value,
                    details_json,
                    result.source,
                    now,
                    exp,
                    errors_json,
                ),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            if self._shared_conn is None:
                conn.close()


def _is_safe_endpoint(url: str) -> bool:
    """Verifies that an external service endpoint is not resolving to private/loopback space."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block literal private IPs
        clean_host = hostname.strip("[]")
        try:
            ip = ipaddress.ip_address(clean_host)
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    return False
        except ValueError:
            pass
        if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
            return False
        return True
    except Exception:
        return False


def query_rdap_registration(
    registered_domain: str,
    timeout: float = 2.0,
    session: Optional[requests.Session] = None,
) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Passive RDAP registration date lookup via ICANN/RDAP.
    Returns (iso_date_string, age_days, error_message).
    Never visits or contacts the registered_domain itself.
    """
    # Standard RDAP bootstrap endpoint for domains
    rdap_url = f"https://rdap.org/domain/{registered_domain}"
    if not _is_safe_endpoint(rdap_url):
        return None, None, "Unsafe RDAP endpoint"

    req_session = session or requests.Session()
    headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "PhishTriage-OSINT/1.0"}

    try:
        resp = req_session.get(
            rdap_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )
        if resp.status_code == 404:
            return None, None, "Domain registration not found (RDAP 404)"
        if resp.status_code != 200:
            return None, None, f"RDAP provider returned status {resp.status_code}"

        data = resp.json()
        events = data.get("events", [])
        registration_date_str = None
        for ev in events:
            action = ev.get("eventAction", "").lower()
            if action in ("registration", "created"):
                registration_date_str = ev.get("eventDate")
                break

        if not registration_date_str:
            return None, None, "Registration event date not present in RDAP response"

        # Parse ISO date
        # Example format: 2023-01-15T12:00:00Z
        clean_date_str = registration_date_str.replace("Z", "+00:00")
        try:
            created_dt = datetime.fromisoformat(clean_date_str)
            now_dt = datetime.now(timezone.utc)
            # Ensure timezone awareness
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            age_days = max(0, (now_dt - created_dt).days)
            return registration_date_str, age_days, None
        except Exception as e:
            return registration_date_str, None, f"Failed parsing date '{registration_date_str}': {str(e)}"

    except requests.exceptions.Timeout:
        return None, None, f"RDAP lookup timed out (> {timeout}s)"
    except Exception as e:
        return None, None, f"RDAP query error: {str(e)}"


def query_reputation_provider(
    domain: str,
    api_key: Optional[str] = None,
    timeout: float = 2.0,
    session: Optional[requests.Session] = None,
) -> Tuple[ReputationStatus, Optional[Dict[str, Any]], Optional[str]]:
    """
    Passive reputation query using VirusTotal v3 Domain API if VIRUSTOTAL_API_KEY is configured.
    Returns (status, details, error_message).
    Never transmits email bodies, headers or attachments.
    Never requests the domain itself.
    """
    key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return ReputationStatus.UNAVAILABLE, None, "No reputation API key configured (VIRUSTOTAL_API_KEY missing)"

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    if not _is_safe_endpoint(url):
        return ReputationStatus.UNAVAILABLE, None, "Unsafe provider endpoint"

    req_session = session or requests.Session()
    headers = {"x-apikey": key, "Accept": "application/json"}

    try:
        resp = req_session.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )
        if resp.status_code == 404:
            return ReputationStatus.UNKNOWN, {"status_code": 404}, "Domain not found in reputation database"
        if resp.status_code == 401 or resp.status_code == 403:
            return ReputationStatus.UNAVAILABLE, None, f"Reputation API authentication failed ({resp.status_code})"
        if resp.status_code != 200:
            return ReputationStatus.UNAVAILABLE, None, f"Reputation provider HTTP error {resp.status_code}"

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        details = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        }

        if malicious >= 2:
            status = ReputationStatus.MALICIOUS
        elif malicious == 1 or suspicious >= 2:
            status = ReputationStatus.SUSPICIOUS
        elif harmless > 0 and (malicious + suspicious == 0):
            status = ReputationStatus.CLEAN
        else:
            status = ReputationStatus.UNKNOWN

        return status, details, None

    except requests.exceptions.Timeout:
        return ReputationStatus.UNAVAILABLE, None, f"Reputation query timed out (> {timeout}s)"
    except Exception as e:
        return ReputationStatus.UNAVAILABLE, None, f"Reputation query error: {str(e)}"


# Global default cache instance (uses file or memory)
_DEFAULT_DB_PATH = os.environ.get("PHISHTRIAGE_OSINT_DB", "osint_cache.db")
_default_cache: Optional[OSINTCache] = None


def get_default_cache() -> OSINTCache:
    global _default_cache
    if _default_cache is None:
        _default_cache = OSINTCache(db_path=_DEFAULT_DB_PATH)
    return _default_cache


def lookup_domain_osint(
    target: str,
    cache: Optional[OSINTCache] = None,
    enable_network: bool = False,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
    timeout: float = 2.0,
) -> Optional[OSINTResult]:
    """
    Public OSINT Entry Point.
    Accepts domain or URL, extracts registered domain, checks SQLite cache,
    and optionally executes bounded passive lookups if enable_network=True.

    Parameters:
    - target: Domain or URL to enrich.
    - cache: Optional OSINTCache instance (defaults to global cache).
    - enable_network: If False, does not make any live network requests (returns cached or offline UNKNOWN).
    - api_key: Optional provider API key.
    - session: Optional requests.Session for mocking.
    - timeout: Network timeout in seconds (default 2.0s).

    Returns:
    - OSINTResult or None if target is malformed/invalid.
    """
    extracted = extract_and_validate_domain(target)
    if not extracted:
        return None

    host, reg_domain = extracted
    active_cache = cache if cache is not None else get_default_cache()

    # 1. Check cache first
    cached_res = active_cache.get(host)
    if cached_res is not None:
        return cached_res

    errors: List[str] = []
    source = "offline"
    reg_date: Optional[str] = None
    age_days: Optional[int] = None
    reputation = ReputationStatus.UNKNOWN
    rep_details: Optional[Dict[str, Any]] = None

    if enable_network:
        source = "passive_rdap_reputation"
        # 2. RDAP Domain Registration query
        r_date, r_age, r_err = query_rdap_registration(reg_domain, timeout=timeout, session=session)
        reg_date = r_date
        age_days = r_age
        if r_err:
            errors.append(r_err)

        # 3. Reputation lookup
        rep_stat, rep_det, rep_err = query_reputation_provider(
            reg_domain, api_key=api_key, timeout=timeout, session=session
        )
        reputation = rep_stat
        rep_details = rep_det
        if rep_err:
            errors.append(rep_err)
    else:
        errors.append("Live network lookups disabled (offline mode)")
        reputation = ReputationStatus.UNAVAILABLE

    result = OSINTResult(
        domain=host,
        registered_domain=reg_domain,
        domain_age_days=age_days,
        registration_date=reg_date,
        reputation=reputation,
        reputation_details=rep_details,
        source=source,
        cache_hit=False,
        errors=errors if errors else None,
    )

    # Cache result (TTL 24 hours for successful/clean/malicious, 1 hour for failures/offline)
    ttl = 86400 if enable_network and not errors else 3600
    active_cache.set(result, ttl_seconds=ttl)

    return result
