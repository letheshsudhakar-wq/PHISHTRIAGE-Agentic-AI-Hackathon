import hashlib
import base64
from app.utils.eml_parser import parse_eml
from app.models.schemas import ParsedEmail


def test_plain_text_email():
    raw_eml = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: Simple Hello\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hello Bob, this is a plain text email."
    )
    parsed = parse_eml(raw_eml)

    assert isinstance(parsed, ParsedEmail)
    assert parsed.sender == "alice@example.com"
    assert parsed.subject == "Simple Hello"
    assert parsed.reply_to is None
    assert parsed.return_path is None
    assert "From: alice@example.com" in parsed.headers_raw
    assert "Hello Bob, this is a plain text email." in parsed.body_text
    assert parsed.links == []
    assert parsed.attachments == []
    assert parsed.inline_images == []


def test_html_email_link_discrepancy():
    raw_eml = (
        b"From: security@paypal.com\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Urgent Account Verification\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<html><body>"
        b"<p>Please click here: <a href=\"https://phish-site.evil.com/login\">https://paypal.com/login</a></p>"
        b"</body></html>"
    )
    parsed = parse_eml(raw_eml)

    assert parsed.subject == "Urgent Account Verification"
    assert len(parsed.links) == 1
    link = parsed.links[0]
    assert link["visible_text"] == "https://paypal.com/login"
    assert link["href"] == "https://phish-site.evil.com/login"
    assert link["text"] == "https://paypal.com/login"
    assert link["url"] == "https://phish-site.evil.com/login"
    assert link["visible_text"] != link["href"]


def test_email_with_attachment_sha256():
    file_bytes = b"Sample malicious payload or harmless invoice content."
    expected_sha256 = hashlib.sha256(file_bytes).hexdigest()

    raw_eml = (
        b"From: billing@vendor.com\r\n"
        b"To: accounts@example.com\r\n"
        b"Subject: Monthly Invoice\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n"
        b"\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please find your invoice attached.\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"U2FtcGxlIG1hbGljaW91cyBwYXlsb2FkIG9yIGhhcm1sZXNzIGludm9pY2UgY29udGVudC4=\r\n"
        b"--BOUNDARY--"
    )
    parsed = parse_eml(raw_eml)

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att["filename"] == "invoice.pdf"
    assert att["content_type"] == "application/pdf"
    assert att["size"] == str(len(file_bytes))
    assert att["sha256"] == expected_sha256


def test_email_with_inline_image():
    image_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

    raw_eml = (
        b"From: newsletter@company.com\r\n"
        b"To: reader@example.com\r\n"
        b"Subject: Weekly Update\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/related; boundary=\"IMG_BOUNDARY\"\r\n"
        b"\r\n"
        b"--IMG_BOUNDARY\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<p>Check out our logo below:</p><img src=\"cid:logo123\" />\r\n"
        b"--IMG_BOUNDARY\r\n"
        b"Content-Type: image/png\r\n"
        b"Content-ID: <logo123>\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"iVBORw0KGgoAAAANSUhEUg==\r\n"
        b"--IMG_BOUNDARY--"
    )
    parsed = parse_eml(raw_eml)

    assert len(parsed.inline_images) == 1
    img = parsed.inline_images[0]
    assert img["content_type"] == "image/png"
    # Verify bytes were preserved via base64 decode
    assert base64.b64decode(img["data"]) == image_bytes


def test_email_with_missing_headers_no_crash():
    raw_eml = b"Random body text with no standard headers at all.\r\nJust lines."
    parsed = parse_eml(raw_eml)

    assert isinstance(parsed, ParsedEmail)
    assert parsed.sender == ""
    assert parsed.subject == ""
    assert parsed.reply_to is None
    assert parsed.return_path is None
    assert parsed.links == []
    assert parsed.attachments == []
    assert parsed.inline_images == []

    # Also test completely empty byte string
    empty_parsed = parse_eml(b"")
    assert isinstance(empty_parsed, ParsedEmail)
    assert empty_parsed.sender == ""
    assert empty_parsed.body_text == ""
