import base64
from email import policy
from email.parser import BytesParser
import hashlib
import re
from typing import Dict, List, Optional
from bs4 import BeautifulSoup

from app.models.schemas import ParsedEmail


_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_URL_TRAILING_PUNCTUATION = ".,;:!?)]}"


def parse_eml(raw: bytes) -> ParsedEmail:
    """
    Parses raw bytes of an .eml email file into Member 1's shared Pydantic ParsedEmail object.
    Never crashes on malformed or missing data.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raw = b""

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        msg = BytesParser(policy=policy.default).parsebytes(b"")

    def get_single_header(name: str) -> Optional[str]:
        val = msg.get(name)
        return str(val).strip() if val is not None else None

    message_id = get_single_header("Message-ID")
    from_header = get_single_header("From")
    sender = from_header if from_header is not None else ""
    reply_to = get_single_header("Reply-To")
    return_path = get_single_header("Return-Path")
    subject_header = get_single_header("Subject")
    subject = subject_header if subject_header is not None else ""

    raw_header_lines: List[str] = []
    for key, value in msg.items():
        raw_header_lines.append(f"{key}: {value}")
    headers_raw = "\r\n".join(raw_header_lines)

    text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, str]] = []
    inline_images: List[Dict[str, str]] = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        content_disposition = part.get_content_disposition()
        content_type = part.get_content_type()
        filename = part.get_filename()

        if content_disposition == "attachment" or filename:
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""

            attachments.append({
                "filename": filename or "untitled",
                "content_type": content_type or "application/octet-stream",
                "size": str(len(payload)),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            continue

        if content_type.startswith("image/"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""

            inline_images.append({
                "content_type": content_type,
                "data": base64.b64encode(payload).decode("ascii"),
            })
            continue

        if content_type == "text/plain":
            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    text_parts.append(payload)
                elif isinstance(payload, bytes):
                    text_parts.append(payload.decode(errors="replace"))
            except Exception:
                pass
        elif content_type == "text/html":
            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    html_parts.append(payload)
                elif isinstance(payload, bytes):
                    html_parts.append(payload.decode(errors="replace"))
            except Exception:
                pass

    text_body = "".join(text_parts)
    html_body = "".join(html_parts)
    body_text = text_body if text_body else html_body

    links: List[Dict[str, str]] = []
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            for anchor in soup.find_all("a"):
                href = anchor.get("href")
                if href is not None:
                    visible_text = str(anchor.get_text())
                    links.append({
                        "visible_text": visible_text,
                        "href": str(href),
                        "text": visible_text,
                        "url": str(href),
                    })
        except Exception:
            pass

    # Plain-text messages frequently contain URLs without HTML anchors. Include
    # those destinations so the forensic checks and UI analyze actual content.
    known_hrefs = {item.get("href") for item in links}
    for match in _URL_PATTERN.finditer(body_text):
        url = match.group(0).rstrip(_URL_TRAILING_PUNCTUATION)
        if url and url not in known_hrefs:
            links.append({"visible_text": url, "href": url, "text": url, "url": url})
            known_hrefs.add(url)

    return ParsedEmail(
        message_id=message_id,
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        subject=subject,
        headers_raw=headers_raw,
        body_text=body_text,
        links=links,
        attachments=attachments,
        inline_images=inline_images,
    )


# Alias for Member 1 API route integration
parse_eml_bytes = parse_eml
