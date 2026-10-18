"""Reading what matters from an email."""
from core.services.m365_email import authentication_results, links_in, text_of


def test_authentication_results():
    headers = [{"name": "Authentication-Results", "value": "spf=pass smtp.mailfrom=contoso.example; dkim=pass header.d=contoso.example;dmarc=pass action=none"}]
    assert authentication_results(headers) == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert authentication_results([]) == {"spf": None, "dkim": None, "dmarc": None}


def test_links_from_html_and_text_once_each():
    body = '<a href="https://a.example/x?y=1&amp;z=2">go</a> or https://b.example/path. Again: https://a.example/x?y=1&amp;z=2'
    assert links_in(body) == ["https://a.example/x?y=1&z=2", "https://b.example/path"]
    assert links_in('<a href="mailto:x@y.example">mail</a>') == []


def test_text_without_markup_or_scripts():
    body = {"contentType": "html", "content": "<style>p{}</style><p>Hello&nbsp;<b>there</b></p><script>alert(1)</script>"}
    assert text_of(body) == "Hello there"
    assert text_of({"contentType": "text", "content": "plain  text"}) == "plain text"
