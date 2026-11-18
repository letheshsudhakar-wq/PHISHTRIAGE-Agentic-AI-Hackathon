import base64
from email import policy
from email.parser import BytesParser
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from bs4 import BeautifulSoup

from app.models.schemas import ParsedEmail


def parse_eml(raw: bytes) -> ParsedEmail:
    """
    Parses raw bytes of an .eml email file into Member 1's shared Pydantic ParsedEmail object.
    Never crashes on malformed or missing data.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raw = b""

    # Parse raw bytes using Python's modern standard email policy
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        # Fallback to an empty message if parsing completely fails
        msg = BytesParser(policy=policy.default).parsebytes(b"")

    def get_single_header(name: str) -> Optional[str]:
        val = msg.get(name)
        return str(val).strip() if val is not None else None

    # Header fields
    message_id = get_single_header("Message-ID")
    from_header = get_single_header("From")
    sender = from_header if from_header is not None else ""
    reply_to = get_single_header("Reply-To")
    return_path = get_single_header("Return-Path")
    subject_header = get_single_header("Subject")
    subject = subject_header if subject_header is not None else ""

    # Build complete raw headers string so forensic checks can inspect all headers reliably
    raw_header_lines: List[str] = []
    for k, v in msg.items():
        raw_header_lines.append(f"{k}: {v}")
    headers_raw = "\r\n".join(raw_header_lines)

    text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, str]] = []
    inline_images: List[Dict[str, str]] = []

    # Walk through all MIME parts
    for part in msg.walk():
        if part.is_multipart():
            continue

        content_disposition = part.get_content_disposition()
        content_type = part.get_content_type()
        filename = part.get_filename()

        # Handle explicit attachments
        if content_disposition == "attachment" or filename:
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""

            sha256_hash = hashlib.sha256(payload).hexdigest()
            attachments.append({
                "filename": filename or "untitled",
                "content_type": content_type or "application/octet-stream",
                "size": str(len(payload)),
                "sha256": sha256_hash,
            })
            continue

        # Handle inline images without discarding image bytes
        if content_type.startswith("image/"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""

            b64_data = base64.b64encode(payload).decode("ascii")
            inline_images.append({
                "content_type": content_type,
                "data": b64_data,
            })
            continue

        # Handle text and html body content
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

    # Use text_body or fall back to html_body
    body_text = text_body if text_body else html_body

    # Extract links from HTML using BeautifulSoup
    links: List[Dict[str, str]] = []
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            for a_tag in soup.find_all("a"):
                href = a_tag.get("href")
                if href is not None:
                    visible_text = a_tag.get_text()
                    links.append({
                        "visible_text": str(visible_text),
                        "href": str(href),
                        "text": str(visible_text),
                        "url": str(href),
                    })
        except Exception:
            pass

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
