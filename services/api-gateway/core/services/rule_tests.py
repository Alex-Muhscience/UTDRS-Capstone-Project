"""
Test cases for detection rules: example events a rule must match, or must not.

A rule's logic is compiled (rule_compiler) and evaluated here exactly as the core engine's
signature detector does (core-engine core/detection/signature_detector.py): AND or OR across
fields, each field's comparisons all holding, and a missing field never matching. So a
rule's tests say what the engine will do with those events.

A test event is written like an event sent to the gateway: `event_type`, `source`,
`timestamp`, and the rest (`raw_data`, or fields given directly) as the event's data.
"""
import re
from typing import Any, Dict, List, Optional

from core.services.rule_compiler import RuleNotSupported, RuleSyntaxError, compile_logic

TOP_LEVEL = ("event_type", "source", "timestamp")
_MISSING = object()


def engine_event(example: Dict[str, Any]) -> Dict[str, Any]:
    """A test event in the shape the engine sees: top-level fields, and everything else under `data`."""
    data = dict(example.get("raw_data") or {})
    data.update({k: v for k, v in example.items() if k not in TOP_LEVEL and k not in ("raw_data", "data")})
    data.update(example.get("data") or {})
    return {**{k: example[k] for k in TOP_LEVEL if k in example}, "data": data}


def _value(event: Dict[str, Any], field: str) -> Any:
    current: Any = event
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _holds(value: Any, op: str, expected: Any) -> bool:
    number = isinstance(value, (int, float)) and not isinstance(value, bool)
    if op == "eq":
        return value == expected
    if op == "ne":
        return value != expected
    if op == "in":
        return value in expected
    if op == "not_in":
        return value not in expected
    if op == "search":
        try:
            return bool(re.search(expected, str(value)))
        except re.error:
            return False
    if op == "exists":
        return True
    if op in ("gt", "gte", "lt", "lte"):
        return number and {"gt": value > expected, "gte": value >= expected, "lt": value < expected, "lte": value <= expected}[op]
    if op in ("contains", "starts_with", "ends_with"):
        return isinstance(value, str) and {"contains": expected in value, "starts_with": value.startswith(expected),
                                           "ends_with": value.endswith(expected)}[op]
    return False


def matches(detection: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Whether the engine would match `event` with this compiled detection."""
    def field_holds(field: str, comparisons: Dict[str, Any]) -> bool:
        value = _value(event, field)
        if value is _MISSING or value is None:
            return False
        return all(_holds(value, op, expected) for op, expected in comparisons.items())

    checks = (field_holds(field, comparisons) for field, comparisons in detection["conditions"].items())
    return any(checks) if detection.get("condition_type") == "OR" else all(checks)


def run(logic: str, cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Run test cases against logic. `ran` is false when the engine cannot run the logic (then
    nothing is tested: `reason` says why); otherwise each case's result, and whether all passed.
    """
    try:
        detection = compile_logic(logic)
    except (RuleSyntaxError, RuleNotSupported) as e:
        return {"ran": False, "reason": str(e), "passed": False, "results": []}
    results = []
    for case in cases:
        matched = matches(detection, engine_event(case.get("event") or {}))
        expected = case.get("expect", "match") == "match"
        results.append({"name": case.get("name"), "expect": case.get("expect", "match"), "matched": matched, "passed": matched == expected})
    return {"ran": True, "reason": None, "passed": all(r["passed"] for r in results), "results": results}


def failures(result: Dict[str, Any]) -> Optional[str]:
    """A sentence about the failing tests, or None when all passed (or none could run)."""
    failed = [r for r in result["results"] if not r["passed"]]
    if not result["ran"] or not failed:
        return None
    named = "; ".join(f"'{r['name']}' expected {'a match' if r['expect'] == 'match' else 'no match'} but got {'one' if r['matched'] else 'none'}" for r in failed)
    return f"{len(failed)} of {len(result['results'])} test cases fail: {named}"
