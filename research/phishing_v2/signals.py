"""
Signals about an email's sender and links, beyond its text, for the phishing verdict.

The same function computes them in training (from the dataset's sender and urls columns)
and in the core engine (from an email event's fields), so the model sees the same thing
in both. Only properties of a message itself are used: nothing that identifies which
corpus an email came from (recipients, dates), which a model would otherwise learn instead
of phishing.
"""
import re
from email.utils import parseaddr

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr", "hotmail.com", "hotmail.co.uk", "outlook.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mail.com", "gmx.com", "gmx.de", "gmx.net", "web.de",
    "yandex.com", "yandex.ru", "mail.ru", "protonmail.com", "proton.me", "zoho.com", "qq.com", "163.com", "rediffmail.com",
}
DOMAIN_IN_TEXT = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}", re.IGNORECASE)

NAMES = [
    "sender_freemail",          # a free mail provider
    "sender_name_has_address",  # the display name holds an address or domain
    "sender_name_other_domain", # ... and it is not the sender's own domain
    "sender_local_digits",      # three or more digits in the address's local part
    "sender_missing",           # no usable sender address
    "has_links",                # the body has links
]


def sender_signals(sender: str) -> dict:
    name, address = parseaddr(str(sender or ""))
    address = address.lower()
    if "@" not in address:
        return {"sender_freemail": 0, "sender_name_has_address": 0, "sender_name_other_domain": 0, "sender_local_digits": 0, "sender_missing": 1}
    local, domain = address.rsplit("@", 1)
    domains_in_name = [d.lower() for d in DOMAIN_IN_TEXT.findall(name or "")]
    return {
        "sender_freemail": int(domain in FREEMAIL),
        "sender_name_has_address": int(bool(domains_in_name)),
        "sender_name_other_domain": int(any(not (d == domain or d.endswith("." + domain) or domain.endswith("." + d)) for d in domains_in_name)),
        "sender_local_digits": int(sum(c.isdigit() for c in local) >= 3),
        "sender_missing": 0,
    }


def signals(sender: str, has_links: bool) -> list:
    found = sender_signals(sender)
    found["has_links"] = int(bool(has_links))
    return [found[name] for name in NAMES]
