import email.utils
import ipaddress
import re
import time
import unicodedata
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Set, Tuple
import tldextract
from rapidfuzz.distance import Levenshtein

from app.models.schemas import Indicator, AgentResult, ParsedEmail

# Initialize tldextract with suffix_list_urls=() for 100% offline analysis
_extractor = tldextract.TLDExtract(suffix_list_urls=())

# Small configurable demo list of trusted brand domains (not comprehensive)
TRUSTED_BRAND_DOMAINS = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "netflix.com",
    "facebook.com",
]

# Brand names derived for keyword stuffing checks
TRUSTED_BRAND_NAMES = {
    brand_domain.split(".")[0] for brand_domain in TRUSTED_BRAND_DOMAINS
}

# Known URL shorteners list (demo list)
KNOWN_URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorte.st",
}

# Risky/suspicious TLDs (heuristic demo list, not proof of phishing)
RISKY_TLDS = {
    "zip",
    "mov",
    "top",
    "work",
    "country",
    "gq",
    "cf",
    "tk",
    "ml",
    "buzz",
}

# Attachment Analysis Constants
DANGEROUS_FINAL_EXTENSIONS = {
    "exe", "scr", "js", "vbs", "vbe", "bat", "cmd", "ps1", "hta", "wsf", "pif", "cpl", "jar"
}

DECOY_INNER_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "rtf", "mp3", "mp4"
}

BENIGN_COMPOUND_EXTENSIONS = {
    "tar.gz", "tar.bz2", "tar.xz", "tar.z", "user.js"
}

MACRO_OFFICE_EXTENSIONS = {
    "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "ppsm", "potm"
}

EXTENSION_MIME_MAP: Dict[str, Set[str]] = {
    "pdf": {"application/pdf", "application/x-pdf"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    "doc": {"application/msword"},
    "xls": {"application/vnd.ms-excel"},
    "ppt": {"application/vnd.ms-powerpoint"},
    "docm": {"application/vnd.ms-word.document.macroenabled.12"},
    "xlsm": {"application/vnd.ms-excel.sheet.macroenabled.12"},
    "pptm": {"application/vnd.ms-powerpoint.presentation.macroenabled.12"},
    "jpg": {"image/jpeg"},
    "jpeg": {"image/jpeg"},
    "png": {"image/png"},
    "gif": {"image/gif"},
    "txt": {"text/plain"},
    "html": {"text/html"},
    "htm": {"text/html"},
    "csv": {"text/csv", "application/csv", "text/plain"},
    "zip": {"application/zip", "application/x-zip-compressed"},
    "tar": {"application/x-tar", "application/tar"},
    "gz": {"application/gzip", "application/x-gzip"},
    "7z": {"application/x-7z-compressed"},
    "exe": {"application/x-msdownload", "application/x-dosexec", "application/exe"},
}


def _extract_domain(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    _, addr = email.utils.parseaddr(header_value)
    if "@" in addr:
        domain = addr.split("@")[-1].strip().lower()
        return domain if domain else None
    return None


def _get_registered_domain(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    ext = _extractor(domain)
    reg_domain = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else getattr(ext, "registered_domain", None)
    return reg_domain.lower() if reg_domain else None


def _get_tld(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    ext = _extractor(domain)
    return ext.suffix.lower() if ext.suffix else None


def _extract_hostname_and_info(url: str) -> Tuple[Optional[str], bool]:
    if not url:
        return None, False
    trimmed = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", trimmed):
        trimmed = "http://" + trimmed

    try:
        parsed = urlparse(trimmed)
        hostname = parsed.hostname.lower() if parsed.hostname else None
        has_at = False
        if parsed.netloc and "@" in parsed.netloc:
            has_at = True
        return hostname, has_at
    except Exception:
        return None, False


def _is_ip_literal(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    clean_host = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def _is_suspicious_homoglyph(domain: str) -> Tuple[bool, str]:
    if not domain:
        return False, ""

    labels = domain.split(".")
    for label in labels:
        decoded_label = label
        is_punycode = False
        if label.startswith("xn--"):
            is_punycode = True
            try:
                decoded_label = label.encode("ascii").decode("idna")
            except Exception:
                return True, f"Malformed punycode label: {label}"

        scripts = set()
        for char in decoded_label:
            if not char.isalnum():
                continue
            name = unicodedata.name(char, "")
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
            elif "HEBREW" in name:
                scripts.add("HEBREW")
            elif "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name:
                scripts.add("EAST_ASIAN")
            else:
                scripts.add("OTHER")

        if len(scripts) > 1 and "LATIN" in scripts:
            return True, f"Mixed-script homoglyphs detected in '{label}' ({', '.join(sorted(scripts))})"

        if is_punycode and ("CYRILLIC" in scripts or "GREEK" in scripts):
            return True, f"Suspicious punycode brand spoofing in '{label}'"

    return False, ""


def _extract_header_from_raw(headers_raw: str, header_name: str) -> Optional[str]:
    """
    Safely searches for a header line inside headers_raw.
    """
    if not headers_raw:
        return None
    pattern = rf"(?im)^{re.escape(header_name)}\s*:\s*(.*(?:\r?\n\s+.*)*)"
    match = re.search(pattern, headers_raw)
    if match:
        raw_val = match.group(1)
        # Unfold multiline header
        unfolded = re.sub(r"\r?\n\s+", " ", raw_val)
        return unfolded.strip()
    return None


def analyze(parsed: ParsedEmail) -> AgentResult:
    """
    Performs deterministic static forensic checks on a parsed email.
    """
    start_time = time.perf_counter()
    indicators: List[Indicator] = []
    raw_notes_list: List[str] = []
    seen_indicator_keys: Set[str] = set()

    def add_indicator(ind_id: str, weight: int, title: str, evidence: str, dedup_key: Optional[str] = None):
        key = dedup_key or f"{ind_id}:{evidence}"
        if key not in seen_indicator_keys:
            seen_indicator_keys.add(key)
            indicators.append(
                Indicator(
                    id=ind_id,
                    agent="Forensic",
                    weight=weight,
                    title=title,
                    evidence=evidence,
                )
            )

    headers_raw = parsed.headers_raw or ""
    auth_results_header = _extract_header_from_raw(headers_raw, "Authentication-Results")

    # 1. SPF Check
    if auth_results_header:
        spf_match = re.search(r"\bspf\s*=\s*([a-zA-Z0-9_\-]+)", auth_results_header, re.IGNORECASE)
        if spf_match:
            spf_val = spf_match.group(1).lower()
            if spf_val in ("fail", "softfail"):
                add_indicator(
                    ind_id="spf_fail",
                    weight=15,
                    title="SPF Authentication Failed",
                    evidence=f"Authentication-Results: {auth_results_header.strip()}",
                )
            else:
                raw_notes_list.append(f"SPF check inconclusive or passed: '{spf_val}'")
        else:
            raw_notes_list.append("Authentication-Results header present but SPF result not found")
    else:
        raw_notes_list.append("Authentication-Results header missing: SPF check skipped")

    # 2. DKIM Check
    if auth_results_header:
        dkim_match = re.search(r"\bdkim\s*=\s*([a-zA-Z0-9_\-]+)", auth_results_header, re.IGNORECASE)
        if dkim_match:
            dkim_val = dkim_match.group(1).lower()
            if dkim_val == "fail":
                add_indicator(
                    ind_id="dkim_fail",
                    weight=10,
                    title="DKIM Authentication Failed",
                    evidence=f"Authentication-Results: {auth_results_header.strip()}",
                )
            else:
                raw_notes_list.append(f"DKIM check inconclusive or passed: '{dkim_val}'")
        else:
            raw_notes_list.append("Authentication-Results header present but DKIM result not found")
    else:
        raw_notes_list.append("Authentication-Results header missing: DKIM check skipped")

    # 3. DMARC Check
    if auth_results_header:
        dmarc_match = re.search(r"\bdmarc\s*=\s*([a-zA-Z0-9_\-]+)", auth_results_header, re.IGNORECASE)
        if dmarc_match:
            dmarc_val = dmarc_match.group(1).lower()
            if dmarc_val == "fail":
                add_indicator(
                    ind_id="dmarc_fail",
                    weight=15,
                    title="DMARC Authentication Failed",
                    evidence=f"Authentication-Results: {auth_results_header.strip()}",
                )
            else:
                raw_notes_list.append(f"DMARC check inconclusive or passed: '{dmarc_val}'")
        else:
            raw_notes_list.append("Authentication-Results header present but DMARC result not found")
    else:
        raw_notes_list.append("Authentication-Results header missing: DMARC check skipped")

    # From Domain Reference
    from_raw = parsed.sender or _extract_header_from_raw(headers_raw, "From")
    from_domain = _extract_domain(from_raw)
    from_reg_domain = _get_registered_domain(from_domain)

    # 4. Reply-To Mismatch Check
    reply_to_raw = parsed.reply_to or _extract_header_from_raw(headers_raw, "Reply-To")
    if reply_to_raw and from_reg_domain:
        reply_to_domain = _extract_domain(reply_to_raw)
        reply_to_reg_domain = _get_registered_domain(reply_to_domain)
        if reply_to_reg_domain:
            if reply_to_reg_domain != from_reg_domain:
                add_indicator(
                    ind_id="reply_to_mismatch",
                    weight=20,
                    title="Reply-To Domain Mismatch",
                    evidence=f"From: '{from_raw}' vs Reply-To: '{reply_to_raw}'",
                )
            else:
                raw_notes_list.append(f"Reply-To registered domain matches From: '{reply_to_reg_domain}'")
        else:
            raw_notes_list.append(f"Could not extract registered domain from Reply-To: '{reply_to_raw}'")
    else:
        if not reply_to_raw:
            raw_notes_list.append("Reply-To header missing: reply_to_mismatch check skipped")
        if not from_reg_domain:
            raw_notes_list.append("From header missing or invalid: reply_to_mismatch check skipped")

    # 5. Return-Path Mismatch Check
    return_path_raw = parsed.return_path or _extract_header_from_raw(headers_raw, "Return-Path")
    if return_path_raw and from_reg_domain:
        return_path_domain = _extract_domain(return_path_raw)
        return_path_reg_domain = _get_registered_domain(return_path_domain)
        if return_path_reg_domain:
            if return_path_reg_domain != from_reg_domain:
                add_indicator(
                    ind_id="return_path_mismatch",
                    weight=15,
                    title="Return-Path Domain Mismatch",
                    evidence=f"From: '{from_raw}' vs Return-Path: '{return_path_raw}'",
                )
            else:
                raw_notes_list.append(f"Return-Path registered domain matches From: '{return_path_reg_domain}'")
        else:
            raw_notes_list.append(f"Could not extract registered domain from Return-Path: '{return_path_raw}'")
    else:
        if not return_path_raw:
            raw_notes_list.append("Return-Path header missing: return_path_mismatch check skipped")
        if not from_reg_domain:
            raw_notes_list.append("From header missing or invalid: return_path_mismatch check skipped")

    # ==========================================
    # BATCH 2 CHECKS: DOMAIN & URL ANALYSIS
    # ==========================================
    domains_to_check: Set[Tuple[str, str]] = set()
    if from_domain:
        domains_to_check.add((from_domain, f"From header: {from_raw}"))

    # Convert links from dict representations
    parsed_links = parsed.links or []
    for item in parsed_links:
        href = item.get("href") or item.get("url") or ""
        host, _ = _extract_hostname_and_info(href)
        if host and not _is_ip_literal(host):
            domains_to_check.add((host, f"URL href: {href}"))

    # 6. lookalike_domain (+35)
    checked_reg_domains: Set[str] = set()
    for d, source in domains_to_check:
        reg_d = _get_registered_domain(d)
        if not reg_d or reg_d in checked_reg_domains:
            continue
        checked_reg_domains.add(reg_d)

        for trusted in TRUSTED_BRAND_DOMAINS:
            if reg_d == trusted:
                continue

            reg_name = reg_d.split(".")[0]
            trusted_name = trusted.split(".")[0]

            dist_full = Levenshtein.distance(reg_d, trusted)
            dist_name = Levenshtein.distance(reg_name, trusted_name)

            if (dist_full <= 2 or dist_name <= 2) and min(len(reg_name), len(trusted_name)) >= 4:
                add_indicator(
                    ind_id="lookalike_domain",
                    weight=35,
                    title="Lookalike Domain Detected",
                    evidence=f"Domain '{reg_d}' ({source}) is visually close to trusted brand '{trusted}'",
                    dedup_key=f"lookalike:{reg_d}:{trusted}",
                )
                break

    # 7. homoglyph_or_punycode (+30)
    for d, source in domains_to_check:
        is_homo, reason = _is_suspicious_homoglyph(d)
        if is_homo:
            add_indicator(
                ind_id="homoglyph_or_punycode",
                weight=30,
                title="Suspicious Homoglyph or Punycode Domain",
                evidence=f"{reason} in '{d}' ({source})",
                dedup_key=f"homoglyph:{d}",
            )

    # URL-Specific Checks
    for item in parsed_links:
        visible_text = item.get("visible_text") or item.get("text") or ""
        href = item.get("href") or item.get("url") or ""
        hostname, has_at = _extract_hostname_and_info(href)
        if not hostname:
            continue

        # 8. brand_keyword_stuffing (+15)
        reg_domain = _get_registered_domain(hostname)
        if reg_domain:
            ext = _extractor(hostname)
            subdomain_str = ext.subdomain.lower() if ext.subdomain else ""
            if subdomain_str:
                sub_labels = subdomain_str.split(".")
                for brand in TRUSTED_BRAND_NAMES:
                    if any(brand in lbl for lbl in sub_labels):
                        if reg_domain not in TRUSTED_BRAND_DOMAINS:
                            add_indicator(
                                ind_id="brand_keyword_stuffing",
                                weight=15,
                                title="Brand Keyword Stuffing in Hostname",
                                evidence=f"Brand '{brand}' found in subdomains of '{hostname}' (Registered domain: '{reg_domain}')",
                                dedup_key=f"keyword_stuffing:{hostname}:{brand}",
                            )
                            break

        # 9. anchor_href_mismatch (+25)
        v_text = visible_text.strip()
        v_host, _ = _extract_hostname_and_info(v_text)
        if v_host or ("." in v_text and not " " in v_text):
            target_v_host = v_host or v_text.lower()
            v_reg = _get_registered_domain(target_v_host)
            href_reg = _get_registered_domain(hostname)
            if v_reg and href_reg and v_reg != href_reg:
                add_indicator(
                    ind_id="anchor_href_mismatch",
                    weight=25,
                    title="Anchor Text and Destination Link Mismatch",
                    evidence=f"Visible anchor domain '{v_reg}' does not match destination registered domain '{href_reg}' (href='{href}')",
                    dedup_key=f"anchor_mismatch:{v_reg}:{href_reg}",
                )

        # 10. ip_url (+20)
        if _is_ip_literal(hostname):
            add_indicator(
                ind_id="ip_url",
                weight=20,
                title="IP Address Used in URL Hostname",
                evidence=f"URL uses IP address literal: '{href}'",
                dedup_key=f"ip_url:{hostname}",
            )

        # 11. at_sign_url (+15)
        if has_at:
            add_indicator(
                ind_id="at_sign_url",
                weight=15,
                title="URL Contains Userinfo '@' Sign",
                evidence=f"URL contains '@' symbol in netloc: '{href}'",
                dedup_key=f"at_sign:{href}",
            )

        # 12. url_shortener (+10)
        if hostname in KNOWN_URL_SHORTENERS or (reg_domain and reg_domain in KNOWN_URL_SHORTENERS):
            add_indicator(
                ind_id="url_shortener",
                weight=10,
                title="Known URL Shortener Service Used",
                evidence=f"URL uses shortener service '{hostname}': '{href}'",
                dedup_key=f"shortener:{hostname}",
            )

        # 13. excessive_subdomains (+15)
        ext = _extractor(hostname)
        if ext.subdomain:
            sub_labels = [l for l in ext.subdomain.split(".") if l]
            if len(sub_labels) >= 4:
                add_indicator(
                    ind_id="excessive_subdomains",
                    weight=15,
                    title="Excessive Subdomains Detected",
                    evidence=f"Hostname '{hostname}' has {len(sub_labels)} subdomains before registered domain: '{ext.subdomain}'",
                    dedup_key=f"subdomains:{hostname}",
                )

        # 14. risky_tld (+15)
        tld = _get_tld(hostname)
        if tld and tld in RISKY_TLDS:
            add_indicator(
                ind_id="risky_tld",
                weight=15,
                title="Suspicious or High-Risk TLD",
                evidence=f"URL hostname '{hostname}' uses risky TLD '.{tld}' (Note: heuristic, not definitive proof)",
                dedup_key=f"risky_tld:{hostname}",
            )

    # ==========================================
    # BATCH 3 CHECKS: ATTACHMENT ANALYSIS
    # ==========================================
    for att in parsed.attachments:
        filename = (att.get("filename") or "").strip()
        content_type = (att.get("content_type") or "").strip().lower()
        sha256 = att.get("sha256") or ""

        if not filename:
            raw_notes_list.append(f"Attachment missing filename (size: {att.get('size', '0')}, sha256: {sha256})")
            continue

        filename_lower = filename.lower()
        parts = [p for p in filename_lower.split(".") if p]

        # 15. double_extension (+35)
        if len(parts) >= 3:
            is_benign_compound = any(filename_lower.endswith("." + comp) for comp in BENIGN_COMPOUND_EXTENSIONS)
            if not is_benign_compound:
                final_ext = parts[-1]
                inner_ext = parts[-2]
                if final_ext in DANGEROUS_FINAL_EXTENSIONS and inner_ext in DECOY_INNER_EXTENSIONS:
                    add_indicator(
                        ind_id="double_extension",
                        weight=35,
                        title="Deceptive Double File Extension",
                        evidence=f"Attachment '{filename}' uses deceptive double extension (decoy: '.{inner_ext}', actual: '.{final_ext}')",
                        dedup_key=f"double_ext:{filename}:{sha256}",
                    )

        # 16. macro_attachment (+30)
        if len(parts) >= 2:
            final_ext = parts[-1]
            if final_ext in MACRO_OFFICE_EXTENSIONS:
                add_indicator(
                    ind_id="macro_attachment",
                    weight=30,
                    title="Macro-Enabled Office Document Attachment",
                    evidence=f"Attachment '{filename}' has macro-enabled Office extension '.{final_ext}'",
                    dedup_key=f"macro_att:{filename}:{sha256}",
                )

        # 17. mime_extension_mismatch (+25)
        if len(parts) >= 2 and content_type:
            final_ext = parts[-1]
            clean_mime = content_type.split(";")[0].strip().lower()
            if clean_mime and clean_mime != "application/octet-stream":
                if final_ext in EXTENSION_MIME_MAP:
                    expected_mimes = EXTENSION_MIME_MAP[final_ext]
                    if clean_mime not in expected_mimes:
                        add_indicator(
                            ind_id="mime_extension_mismatch",
                            weight=25,
                            title="Attachment MIME Type and Extension Mismatch",
                            evidence=f"Attachment '{filename}' (extension '.{final_ext}') declared mismatched MIME type '{clean_mime}' (expected: {', '.join(sorted(expected_mimes))})",
                            dedup_key=f"mime_mismatch:{filename}:{sha256}",
                        )

    execution_time_ms = int(round((time.perf_counter() - start_time) * 1000.0))
    raw_notes_str = "\n".join(raw_notes_list) if raw_notes_list else None

    return AgentResult(
        agent_name="Forensic",
        execution_time_ms=execution_time_ms,
        indicators=indicators,
        raw_notes=raw_notes_str,
        confidence_score=1.0,
    )


# Alias for Member 1 API route integration
run_forensic_agent = analyze
