# PhishTriage AI — Member 2 Handoff & Integration Guide

**Role:** Member 2 (Static Forensics, Parser & Persistence)  
**Branch:** `feature/member2-forensics`  
**Test Suite Status:** 60/60 Member 2 Tests Passing (100% Pass Rate)

---

## 1. Summary of Completed Modules

Member 2 owns all deterministic email parsing, static forensic indicators, passive OSINT enrichment, and SQLite persistence:

1. **`app.utils.eml_parser`**:
   - RFC 822 `.eml` parser using `BytesParser(policy=policy.default)` and `BeautifulSoup`.
   - Never crashes on missing headers or malformed MIME.
   - Extracts sender, recipients, reply-to, return-path, subject, complete raw headers, bodies, links (`href` & `visible_text`), attachment metadata with SHA-256 digests, and inline images (Base64).
   - Zero execution or opening of untrusted files.

2. **`app.agents.forensic`**:
   - 17 deterministic forensic indicators across 3 batches:
     - **Batch 1 (Headers & Authentication):** `spf_fail` (+15), `dkim_fail` (+10), `dmarc_fail` (+15), `reply_to_mismatch` (+20), `return_path_mismatch` (+15).
     - **Batch 2 (Domain & URL Analysis):** `lookalike_domain` (+35), `homoglyph_or_punycode` (+30), `brand_keyword_stuffing` (+15), `anchor_href_mismatch` (+25), `ip_url` (+20), `at_sign_url` (+15), `url_shortener` (+10), `excessive_subdomains` (+15), `risky_tld` (+15).
     - **Batch 3 (Attachment Analysis):** `double_extension` (+35), `macro_attachment` (+30), `mime_extension_mismatch` (+25).
   - Fully offline via `tldextract.TLDExtract(suffix_list_urls=())`.
   - Never hallucinates indicators; missing or passing checks are noted in `raw_notes`.

3. **`app.utils.osint`**:
   - Passive domain registration (RDAP) and reputation lookups (VirusTotal v3).
   - Isolated SQLite cache (`OSINTCache`) with configurable TTLs.
   - Anti-SSRF protection: rejects private, loopback, and multicast IP ranges.
   - 2.0-second timeout, `allow_redirects=False`.
   - Defaults to safe offline mode (`enable_network=False`), making 0 external network requests during standard operation.

4. **`app.core.database`**:
   - SQLite persistence layer for `CaseDetails`, `QuarantineProposal`, `Campaign`, and `audit_log`.
   - Explicit sanitization/redaction of sensitive tokens, passwords, credit card numbers, and SSNs.
   - Zero storage of raw email bodies, attachment bytes, or unparsed raw messages.
   - Atomic quarantine governance transitions (`PENDING` -> `APPROVED` / `REJECTED`) with blank-analyst guards.
   - Append-only audit trail.

---

## 2. Files Owned by Member 2

* `backend/app/utils/eml_parser.py`
* `backend/app/agents/forensic.py`
* `backend/app/utils/osint.py`
* `backend/app/core/database.py`
* `backend/tests/test_eml_parser.py`
* `backend/tests/test_forensic.py`
* `backend/tests/test_osint.py`
* `backend/tests/test_database.py`
* `backend/MEMBER2_HANDOFF.md`

---

## 3. Public Function Signatures

### `app.utils.eml_parser`
```python
def parse_eml(raw: bytes) -> ParsedEmail: ...
def parse_eml_bytes(raw: bytes) -> ParsedEmail: ... # Member 1 API hook alias
```

### `app.agents.forensic`
```python
def analyze(parsed: ParsedEmail) -> AgentResult: ...
def run_forensic_agent(parsed: ParsedEmail) -> AgentResult: ... # Member 1 API hook alias
```

### `app.utils.osint`
```python
def extract_and_validate_domain(target: str) -> Optional[Tuple[str, str]]: ...
def lookup_domain_osint(
    target: str,
    cache: Optional[OSINTCache] = None,
    enable_network: bool = False,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
    timeout: float = 2.0,
) -> Optional[OSINTResult]: ...
```

### `app.core.database`
```python
def init_db(db_path: Optional[str] = None) -> None: ...
def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection: ...

# Case CRUD
def create_case(case: CaseDetails, db_path: Optional[str] = None) -> CaseDetails: ...
def get_case(case_id: str, db_path: Optional[str] = None) -> Optional[CaseDetails]: ...
def list_cases(limit: int = 50, offset: int = 0, risk_level: Optional[str] = None, db_path: Optional[str] = None) -> List[CaseDetails]: ...

# Campaigns
def create_campaign(name: str, threat_actor: Optional[str] = None, target_brand: Optional[str] = None, threat_level: str = "MEDIUM", status: str = "ACTIVE", indicators: Optional[List[str]] = None, campaign_id: Optional[str] = None, db_path: Optional[str] = None) -> Dict[str, Any]: ...
def associate_case_to_campaign(campaign_id: str, case_id: str, db_path: Optional[str] = None) -> bool: ...
def list_cases_for_campaign(campaign_id: str, db_path: Optional[str] = None) -> List[CaseDetails]: ...

# Quarantine Governance
def create_proposal(proposal: QuarantineProposal, db_path: Optional[str] = None) -> QuarantineProposal: ...
def get_proposal(proposal_id: str, db_path: Optional[str] = None) -> Optional[QuarantineProposal]: ...
def list_proposals(status: Optional[str] = None, limit: int = 50, db_path: Optional[str] = None) -> List[QuarantineProposal]: ...
def approve_proposal(proposal_id: str, analyst_id: str, db_path: Optional[str] = None) -> QuarantineProposal: ...
def reject_proposal(proposal_id: str, analyst_id: str, db_path: Optional[str] = None) -> QuarantineProposal: ...

# Audit Trail
def list_audit_events(resource_id: Optional[str] = None, limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]: ...
```

---

## 4. Required Dependencies

All required dependencies are compatible with Python 3.10+:
* `beautifulsoup4>=4.12.0`
* `tldextract>=5.0.0`
* `rapidfuzz>=3.0.0`
* `requests>=2.28.0`
* `pydantic>=2.0.0`
* `pytest>=8.0.0`

---

## 5. Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PHISHTRIAGE_DB_PATH` | `phishtriage.db` | File path for SQLite database. |
| `PHISHTRIAGE_OSINT_DB` | `osint_cache.db` | File path for dedicated OSINT cache. |
| `VIRUSTOTAL_API_KEY` | *(None)* | Optional API key for live reputation checks. |

---

## 6. Member 1 Integration Instructions

Member 1 can connect Member 2's persistence and parsing directly into `app/api/routes.py`:

### Step 1: Initialize DB on Startup
In `app/main.py`:
```python
from app.core.database import init_db

@app.on_event("startup")
def on_startup():
    init_db()
```

### Step 2: Persist Analyzed Cases
In `app/api/routes.py` inside `_run_analysis_pipeline`:
```python
from app.core.database import create_case

# Replace CASE_STORE[case_id] = case_details with:
CASE_STORE[case_id] = case_details  # (or keep as memory cache)
create_case(case_details)           # Persists case + proposal + audit event
```

### Step 3: Fetch Cases from SQLite
In `GET /cases/{case_id}`:
```python
from app.core.database import get_case

case = get_case(case_id) or CASE_STORE.get(case_id)
if not case:
    raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
return case
```

### Step 4: Quarantine Governance Endpoints
In `GET /queue`, `POST /queue/{proposal_id}/approve`, and `POST /queue/{proposal_id}/reject`:
```python
from app.core.database import list_proposals, approve_proposal, reject_proposal

# In /queue:
return list_proposals(status=status)

# In approve:
proposal = approve_proposal(proposal_id, request.analyst_id)
return proposal

# In reject:
proposal = reject_proposal(proposal_id, request.analyst_id)
return proposal
```

---

## 7. Example Investigation Flow

```python
from app.utils.eml_parser import parse_eml
from app.agents.forensic import analyze
from app.core.database import create_case, get_case
from app.models.schemas import CaseDetails, Verdict, RiskLevel

# 1. Parse incoming raw email bytes
parsed = parse_eml(raw_eml_bytes)

# 2. Run static forensic agent
forensic_result = analyze(parsed)

# 3. Create case details (with scoring from core.scoring)
case = CaseDetails(
    case_id="CASE-2026-001",
    verdict=Verdict(
        case_id="CASE-2026-001",
        total_score=75,
        risk_level=RiskLevel.PHISHING,
        primary_indicators=forensic_result.indicators,
        summary="Phishing attempt detected.",
    ),
    agent_results=[forensic_result],
    defanged_urls=["hxxps://micros0ft[.]com/login"],
    reporter_reply_draft="Thank you for reporting.",
)

# 4. Persist to SQLite
create_case(case)

# 5. Fetch from SQLite
saved = get_case("CASE-2026-001")
assert saved.verdict.risk_level == RiskLevel.PHISHING
```

---

## 8. Test Commands & Verification Results

### Run Member 2 Tests (60 tests)
```bash
python -m pytest tests/test_eml_parser.py tests/test_forensic.py tests/test_osint.py tests/test_database.py -v
```
**Result:** 60 passed in 1.84s (100% pass rate).

### Full Team Test Suite
```bash
python -m pytest -v
```
**Result:** 71 passed, 4 failed.
* All 60 Member 2 tests **pass**.
* 11 Member 1 scoring/defang tests **pass**.
* 4 test failures reside exclusively in Member 1's `test_scoring.py`:
  1. `test_queue_approval_validation_and_success`: Test input lacks phishing indicators, so score is 40 (`SUSPICIOUS`), resulting in `quarantine_proposal` being `None` (proposals are only generated on `PHISHING`).
  2. `test_queue_rejection_validation_and_success`: Same fixture issue.
  3. `test_cases_chat_copilot_grounded_response`: Plain text input has no headers/links, yielding only 1 indicator (vision) instead of $\ge 2$.
  4. `test_sse_streaming_trace_stages`: Test is marked `@pytest.mark.asyncio` but `pytest-asyncio` plugin is not registered.

---

## 9. Security & Privacy Highlights

* **100% Deterministic:** Zero LLM calls in Member 2 modules.
* **Network Isolation:** No external requests during static forensic analysis; offline TLD extraction.
* **Passive Only:** Target URLs/domains are never fetched, visited, or resolved.
* **Anti-Malware:** Attachments are hashed with SHA-256; never executed or written to disk.
* **Data Sanitization:** Passwords, API keys, Bearer tokens, and credit card numbers are stripped before saving to SQLite.
* **Append-Only Auditing:** Immutable audit records for every governance event.

