"""Rule logic, as written in the dashboard, compiled to the core engine's conditions."""
import pytest

from core.services.rule_compiler import RuleNotSupported, RuleSyntaxError, compile_logic


@pytest.mark.parametrize(
    "logic, expected",
    [
        (
            "process_name == 'powershell.exe' and command_line matches '(?i)-enc(odedcommand)?'",
            {"condition_type": "AND", "conditions": {
                "data.process_name": {"eq": "powershell.exe"},
                "data.command_line": {"search": "(?i)-enc(odedcommand)?"},
            }},
        ),
        (
            "event_type == 'authentication' and status in ['failed', 'locked'] and attempts >= 5",
            {"condition_type": "AND", "conditions": {
                "event_type": {"eq": "authentication"},
                "data.status": {"in": ["failed", "locked"]},
                "data.attempts": {"gte": 5},
            }},
        ),
        (
            'protocol not in ["ssh", "rdp"] or dst_port > 1024',
            {"condition_type": "OR", "conditions": {
                "data.protocol": {"not_in": ["ssh", "rdp"]},
                "data.dst_port": {"gt": 1024},
            }},
        ),
        (
            "user.name exists and src_port != 22 and admin == true and path startswith 'C:\\\\Temp'",
            {"condition_type": "AND", "conditions": {
                "data.user.name": {"exists": True},
                "data.src_port": {"ne": 22},
                "data.admin": {"eq": True},
                "data.path": {"starts_with": "C:\\Temp"},
            }},
        ),
        # A regex may contain '|' and parentheses.
        (
            "command_line matches '(?i)vssadmin(.exe)? delete shadows|wmic shadowcopy delete'",
            {"condition_type": "AND", "conditions": {
                "data.command_line": {"search": "(?i)vssadmin(.exe)? delete shadows|wmic shadowcopy delete"},
            }},
        ),
        # Two comparisons of one field with 'and' are combined.
        ("bytes > 100 and bytes <= 5000", {"condition_type": "AND", "conditions": {"data.bytes": {"gt": 100, "lte": 5000}}}),
    ],
)
def test_logic_compiles_to_engine_conditions(logic, expected):
    assert compile_logic(logic) == expected


@pytest.mark.parametrize(
    "logic, reason",
    [
        ("event_type == 'authentication' | count by source_ip > 10 in 5m", "Aggregations"),
        ("hour(timestamp) not in 07..19", "Functions such as 'hour"),
        ("domain in threat_intel.domains", "Comparing with 'threat_intel.domains'"),
        ("a == 1 and (b == 2 or c == 3)", "Parentheses"),
        ("a == 1 and b == 2 or c == 3", "Mixing 'and' with 'or'"),
        ("a == 1 or a == 2", "compared the same way twice"),
        ("a == 1 or a contains 'x'", "several times with 'or'"),
    ],
)
def test_logic_the_engine_cannot_run_yet_is_kept_with_a_reason(logic, reason):
    with pytest.raises(RuleNotSupported, match=reason):
        compile_logic(logic)


@pytest.mark.parametrize(
    "logic, message",
    [
        ("", "empty"),
        ("a ==", "Expected a value"),
        ("a === 1", "Unexpected text"),
        ("a matches '(['", "Invalid regular expression"),
        ("a > 'x'", "needs a number"),
        ("a in 'x'", "needs a list"),
        ("a == 1 b == 2", "Expected 'and' or 'or'"),
        ("a resembles 'x'", "Unknown comparison 'resembles'"),
    ],
)
def test_malformed_logic_is_a_syntax_error(logic, message):
    with pytest.raises(RuleSyntaxError, match=message):
        compile_logic(logic)
