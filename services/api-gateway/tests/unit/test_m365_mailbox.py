"""Turning Exchange audit records into events, and the windows the Management API is asked for."""
from datetime import datetime, timedelta, timezone

from core.services.m365_mailbox import _client_ip, _window, mailbox_event


def record(**fields):
    return {"Id": "x", "CreationTime": "2026-10-18T06:31:00", "UserId": "ana@contoso.example", **fields}


def test_outlook_rules_are_read_too():
    event = mailbox_event(record(Operation="UpdateInboxRules", OperationProperties=[
        {"Name": "RuleOperation", "Value": "AddMailboxRule"}, {"Name": "RuleName", "Value": "."},
        {"Name": "RuleActions", "Value": '[{"ActionType":"Forward","Recipients":["x@evil.example"]},{"ActionType":"Delete"}]'},
    ]), {"contoso.example"})
    raw = event.raw_data
    assert raw["rule_name"] == "." and raw["forward_to"] == ["x@evil.example"] and raw["external_forward"] and raw["hides_mail"]


def test_the_users_own_domain_counts_as_inside_without_the_domain_list():
    event = mailbox_event(record(Operation="New-InboxRule", Parameters=[{"Name": "Name", "Value": "r"}, {"Name": "RedirectTo", "Value": "me@contoso.example"}]), set())
    assert event.raw_data["external_forward"] is False


def test_other_records_are_not_kept():
    assert mailbox_event(record(Operation="MailItemsAccessed"), set()) is None
    assert mailbox_event(record(Operation="Set-Mailbox", Parameters=[{"Name": "ProhibitSendQuota", "Value": "49 GB"}]), set()) is None


def test_addresses_without_ports():
    assert _client_ip("203.0.113.5:51234") == "203.0.113.5"
    assert _client_ip("[2001:db8::1]:443") == "2001:db8::1"
    assert _client_ip("2001:db8::1") == "2001:db8::1" and _client_ip(None) is None


def test_windows_are_at_most_a_day_within_the_last_week():
    now = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
    start, end = _window(None, now)
    assert (start, end) == (now - timedelta(days=1), now)
    start, end = _window((now - timedelta(days=30)).isoformat(), now)
    assert now - start < timedelta(days=7) and end - start == timedelta(days=1)
