from app.utils.eml_parser import parse_eml


def test_plain_text_urls_are_extracted_as_links():
    parsed = parse_eml(
        b"From: sender@example.com\r\n"
        b"Subject: Review this link\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Visit https://phish.example/login, then report back."
    )

    assert parsed.links == [{
        "visible_text": "https://phish.example/login",
        "href": "https://phish.example/login",
        "text": "https://phish.example/login",
        "url": "https://phish.example/login",
    }]


def test_html_anchor_and_plain_url_are_not_duplicated():
    parsed = parse_eml(
        b"From: sender@example.com\r\n"
        b"Subject: Link\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<a href="https://phish.example/login">Sign in</a>'
    )

    assert len(parsed.links) == 1
    assert parsed.links[0]["href"] == "https://phish.example/login"
    assert parsed.links[0]["visible_text"] == "Sign in"
