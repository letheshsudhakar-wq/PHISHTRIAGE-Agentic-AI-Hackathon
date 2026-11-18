import pytest
from app.models.schemas import ParsedEmail, Indicator, AgentResult
from app.agents.forensic import analyze


def make_parsed_email(
    sender: str = "",
    reply_to: str = None,
    return_path: str = None,
    headers_raw: str = "",
    links: list = None,
    attachments: list = None,
) -> ParsedEmail:
    return ParsedEmail(
        message_id=None,
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        subject="Test Subject",
        headers_raw=headers_raw,
        body_text="Test Body",
        links=links or [],
        attachments=attachments or [],
        inline_images=[],
    )


# ==========================================
# BATCH 1 TESTS
# ==========================================

def test_spf_fail_and_softfail():
    # SPF Fail
    email_fail = make_parsed_email(
        headers_raw="Authentication-Results: mx.google.com; spf=fail (google.com: domain does not designate IP) smtp.mailfrom=attacker.com\r\n"
    )
    result_fail = analyze(email_fail)
    spf_ind = next((i for i in result_fail.indicators if i.id == "spf_fail"), None)
    assert spf_ind is not None
    assert spf_ind.weight == 15
    assert spf_ind.agent == "Forensic"
    assert "spf=fail" in spf_ind.evidence

    # SPF Softfail
    email_softfail = make_parsed_email(
        headers_raw="Authentication-Results: mx.google.com; spf=softfail (google.com: domain transitioning) smtp.mailfrom=attacker.com\r\n"
    )
    result_softfail = analyze(email_softfail)
    spf_ind = next((i for i in result_softfail.indicators if i.id == "spf_fail"), None)
    assert spf_ind is not None
    assert spf_ind.weight == 15


def test_dkim_fail():
    email = make_parsed_email(
        headers_raw="Authentication-Results: mx.google.com; dkim=fail header.i=@example.com header.s=s1\r\n"
    )
    result = analyze(email)
    dkim_ind = next((i for i in result.indicators if i.id == "dkim_fail"), None)
    assert dkim_ind is not None
    assert dkim_ind.weight == 10
    assert dkim_ind.agent == "Forensic"
    assert "dkim=fail" in dkim_ind.evidence


def test_dmarc_fail():
    email = make_parsed_email(
        headers_raw="Authentication-Results: mx.google.com; dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=example.com\r\n"
    )
    result = analyze(email)
    dmarc_ind = next((i for i in result.indicators if i.id == "dmarc_fail"), None)
    assert dmarc_ind is not None
    assert dmarc_ind.weight == 15
    assert dmarc_ind.agent == "Forensic"
    assert "dmarc=fail" in dmarc_ind.evidence


def test_reply_to_mismatch():
    email = make_parsed_email(
        sender="Support Team <support@paypal.com>",
        reply_to="Attacker <evil@attacker.com>",
    )
    result = analyze(email)
    rep_ind = next((i for i in result.indicators if i.id == "reply_to_mismatch"), None)
    assert rep_ind is not None
    assert rep_ind.weight == 20
    assert rep_ind.agent == "Forensic"
    assert "support@paypal.com" in rep_ind.evidence
    assert "evil@attacker.com" in rep_ind.evidence


def test_return_path_mismatch():
    email = make_parsed_email(
        sender="Security <alert@chase.com>",
        return_path="bounce@suspicious-relay.net",
    )
    result = analyze(email)
    rp_ind = next((i for i in result.indicators if i.id == "return_path_mismatch"), None)
    assert rp_ind is not None
    assert rp_ind.weight == 15
    assert rp_ind.agent == "Forensic"
    assert "alert@chase.com" in rp_ind.evidence
    assert "bounce@suspicious-relay.net" in rp_ind.evidence


def test_matching_registered_domains():
    email = make_parsed_email(
        sender="Alice <alice@mail.corp.google.com>",
        reply_to="Bob <bob@support.google.com>",
        return_path="bounces@google.com",
    )
    result = analyze(email)
    assert len(result.indicators) == 0
    assert result.raw_notes is not None
    assert "Reply-To registered domain matches From: 'google.com'" in result.raw_notes
    assert "Return-Path registered domain matches From: 'google.com'" in result.raw_notes


def test_missing_headers_handled_gracefully():
    empty_email = make_parsed_email()
    result = analyze(empty_email)

    assert isinstance(result, AgentResult)
    assert result.agent_name == "Forensic"
    assert len(result.indicators) == 0
    assert isinstance(result.execution_time_ms, int)
    assert result.execution_time_ms >= 0

    assert result.raw_notes is not None
    assert "Authentication-Results header missing" in result.raw_notes
    assert "Reply-To header missing" in result.raw_notes
    assert "Return-Path header missing" in result.raw_notes


# ==========================================
# BATCH 2 TESTS: DOMAIN & URL ANALYSIS
# ==========================================

def test_lookalike_domain_detected():
    email = make_parsed_email(
        sender="support@paypa1.com",
        links=[{"visible_text": "Verify", "href": "https://paypa1.com/login"}],
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "lookalike_domain"), None)
    assert ind is not None
    assert ind.weight == 35
    assert ind.agent == "Forensic"
    assert "paypa1.com" in ind.evidence
    assert "paypal.com" in ind.evidence


def test_lookalike_domain_negative_legitimate():
    email = make_parsed_email(
        sender="service@paypal.com",
        links=[{"visible_text": "PayPal Home", "href": "https://paypal.com/signin"}],
    )
    result = analyze(email)
    assert not any(i.id == "lookalike_domain" for i in result.indicators)


def test_homoglyph_or_punycode_detected():
    email = make_parsed_email(
        sender="security@xn--pple-43d.com",
        links=[{"visible_text": "Confirm", "href": "http://xn--pple-43d.com/login"}],
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "homoglyph_or_punycode"), None)
    assert ind is not None
    assert ind.weight == 30
    assert ind.agent == "Forensic"


def test_homoglyph_negative_non_impersonating_idn():
    email = make_parsed_email(
        sender="user@xn--fiqs8s.cn",  # 中国.cn
        links=[{"visible_text": "Visit", "href": "https://xn--fiqs8s.cn/home"}],
    )
    result = analyze(email)
    assert not any(i.id == "homoglyph_or_punycode" for i in result.indicators)


def test_brand_keyword_stuffing():
    email = make_parsed_email(
        links=[{"visible_text": "Update Account", "href": "https://paypal.com.verify-account.attacker.net/login"}]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "brand_keyword_stuffing"), None)
    assert ind is not None
    assert ind.weight == 15
    assert ind.agent == "Forensic"
    assert "paypal" in ind.evidence


def test_anchor_href_mismatch():
    email = make_parsed_email(
        links=[{"visible_text": "https://www.paypal.com/signin", "href": "https://evil-phishing.com/session"}]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "anchor_href_mismatch"), None)
    assert ind is not None
    assert ind.weight == 25
    assert ind.agent == "Forensic"
    assert "paypal.com" in ind.evidence
    assert "evil-phishing.com" in ind.evidence


def test_anchor_href_mismatch_negative_click_here():
    email = make_parsed_email(
        links=[
            {"visible_text": "Click here", "href": "https://evil-phishing.com/session"},
            {"visible_text": "Please log in to your account", "href": "https://evil-phishing.com/login"},
        ]
    )
    result = analyze(email)
    assert not any(i.id == "anchor_href_mismatch" for i in result.indicators)


def test_ip_url():
    email = make_parsed_email(
        links=[{"visible_text": "Update Info", "href": "http://192.168.1.100/login.php"}]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "ip_url"), None)
    assert ind is not None
    assert ind.weight == 20
    assert ind.agent == "Forensic"
    assert "192.168.1.100" in ind.evidence


def test_at_sign_url():
    email = make_parsed_email(
        links=[{"visible_text": "Verify", "href": "https://google.com@attacker-site.com/auth"}]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "at_sign_url"), None)
    assert ind is not None
    assert ind.weight == 15
    assert ind.agent == "Forensic"
    assert "@" in ind.evidence


def test_url_shortener():
    email = make_parsed_email(
        links=[{"visible_text": "Special Offer", "href": "https://bit.ly/3xYqz1"}]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "url_shortener"), None)
    assert ind is not None
    assert ind.weight == 10
    assert ind.agent == "Forensic"
    assert "bit.ly" in ind.evidence


def test_excessive_subdomains():
    email = make_parsed_email(
        links=[{"visible_text": "Deep Link", "href": "https://a.b.c.d.example.com/login"}]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "excessive_subdomains"), None)
    assert ind is not None
    assert ind.weight == 15
    assert ind.agent == "Forensic"
    assert "a.b.c.d.example.com" in ind.evidence


def test_excessive_subdomains_negative_normal():
    email = make_parsed_email(
        links=[{"visible_text": "Regular Subdomain", "href": "https://mail.corp.company.com/login"}]
    )
    result = analyze(email)
    assert not any(i.id == "excessive_subdomains" for i in result.indicators)


def test_risky_tld():
    email = make_parsed_email(
        links=[{"visible_text": "Download Document", "href": "https://invoice-update.zip/archive"}]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "risky_tld"), None)
    assert ind is not None
    assert ind.weight == 15
    assert ind.agent == "Forensic"
    assert ".zip" in ind.evidence


def test_deduplication_of_indicators():
    email = make_parsed_email(
        links=[
            {"visible_text": "Link 1", "href": "http://10.0.0.1/page1"},
            {"visible_text": "Link 2", "href": "http://10.0.0.1/page2"},
        ]
    )
    result = analyze(email)
    ip_indicators = [i for i in result.indicators if i.id == "ip_url"]
    assert len(ip_indicators) == 1


# ==========================================
# BATCH 3 TESTS: ATTACHMENT ANALYSIS
# ==========================================

def test_double_extension_detected():
    email = make_parsed_email(
        attachments=[
            {
                "filename": "invoice.pdf.exe",
                "content_type": "application/x-msdownload",
                "size": "1024",
                "sha256": "fakehash1",
            },
            {
                "filename": "photo.jpg.js",
                "content_type": "text/javascript",
                "size": "512",
                "sha256": "fakehash2",
            },
        ]
    )
    result = analyze(email)
    double_exts = [i for i in result.indicators if i.id == "double_extension"]
    assert len(double_exts) == 2
    assert double_exts[0].weight == 35
    assert double_exts[0].agent == "Forensic"
    assert "invoice.pdf.exe" in double_exts[0].evidence
    assert "photo.jpg.js" in double_exts[1].evidence


def test_double_extension_negative_benign_compound():
    email = make_parsed_email(
        attachments=[
            {
                "filename": "backup.tar.gz",
                "content_type": "application/gzip",
                "size": "2048",
                "sha256": "fakehash3",
            }
        ]
    )
    result = analyze(email)
    assert not any(i.id == "double_extension" for i in result.indicators)


def test_macro_attachment_detected():
    email = make_parsed_email(
        attachments=[
            {
                "filename": "Invoice_Q3.xlsm",
                "content_type": "application/vnd.ms-excel.sheet.macroenabled.12",
                "size": "4096",
                "sha256": "macrohash1",
            }
        ]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "macro_attachment"), None)
    assert ind is not None
    assert ind.weight == 30
    assert ind.agent == "Forensic"
    assert "Invoice_Q3.xlsm" in ind.evidence
    assert ".xlsm" in ind.evidence


def test_macro_attachment_negative_normal_office():
    email = make_parsed_email(
        attachments=[
            {
                "filename": "Report.docx",
                "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "size": "4096",
                "sha256": "normalhash1",
            }
        ]
    )
    result = analyze(email)
    assert not any(i.id == "macro_attachment" for i in result.indicators)


def test_mime_extension_mismatch_detected():
    email = make_parsed_email(
        attachments=[
            {
                "filename": "statement.pdf",
                "content_type": "application/x-msdownload",
                "size": "8192",
                "sha256": "mismatchhash1",
            }
        ]
    )
    result = analyze(email)
    ind = next((i for i in result.indicators if i.id == "mime_extension_mismatch"), None)
    assert ind is not None
    assert ind.weight == 25
    assert ind.agent == "Forensic"
    assert "statement.pdf" in ind.evidence
    assert "application/x-msdownload" in ind.evidence


def test_mime_extension_mismatch_negative_generic_octet_stream():
    email = make_parsed_email(
        attachments=[
            {
                "filename": "document.pdf",
                "content_type": "application/octet-stream",
                "size": "1024",
                "sha256": "octethash",
            }
        ]
    )
    result = analyze(email)
    assert not any(i.id == "mime_extension_mismatch" for i in result.indicators)


def test_attachments_missing_metadata_handled_gracefully():
    email = make_parsed_email(
        attachments=[
            {
                "filename": "",
                "content_type": "",
                "size": "128",
                "sha256": "emptyhash",
            },
            {
                "filename": "no_ext_file",
                "content_type": "text/plain",
                "size": "128",
                "sha256": "noexthash",
            },
        ]
    )
    result = analyze(email)
    assert isinstance(result, AgentResult)
    assert not any(i.id in ("double_extension", "macro_attachment", "mime_extension_mismatch") for i in result.indicators)
    assert result.raw_notes is not None
    assert "Attachment missing filename" in result.raw_notes


def test_attachment_deduplication():
    email = make_parsed_email(
        attachments=[
            {
                "filename": "invoice.docm",
                "content_type": "application/vnd.ms-word.document.macroenabled.12",
                "size": "100",
                "sha256": "samehash",
            },
            {
                "filename": "invoice.docm",
                "content_type": "application/vnd.ms-word.document.macroenabled.12",
                "size": "100",
                "sha256": "samehash",
            },
        ]
    )
    result = analyze(email)
    macro_inds = [i for i in result.indicators if i.id == "macro_attachment"]
    assert len(macro_inds) == 1
