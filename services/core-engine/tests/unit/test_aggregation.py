"""Counting rules' conditions as MongoDB filters: the same meaning as the signature detector's."""
from core.detection.aggregation import mongo_filter


def test_conditions_become_a_filter():
    detection = {"condition_type": "AND", "conditions": {
        "event_type": {"eq": "authentication"}, "data.status": {"in": ["failed", "locked"]}, "data.attempts": {"gte": 5},
        "data.command_line": {"search": "(?i)-enc"}, "data.path": {"starts_with": "C:\\\\Temp"},
    }}
    assert mongo_filter(detection) == {"$and": [
        {"event_type": {"$eq": "authentication"}}, {"data.status": {"$in": ["failed", "locked"]}}, {"data.attempts": {"$gte": 5}},
        {"data.command_line": {"$regex": "(?i)-enc"}}, {"data.path": {"$regex": "^C:\\\\\\\\Temp"}},
    ]}


def test_a_missing_field_never_matches_a_negative_comparison():
    assert mongo_filter({"conditions": {"data.user": {"ne": "svc"}}}) == {"$and": [{"data.user": {"$exists": True, "$ne": "svc"}}]}
    assert mongo_filter({"condition_type": "OR", "conditions": {"a": {"eq": 1}, "b": {"eq": 2}}}) == {"$or": [{"a": {"$eq": 1}}, {"b": {"$eq": 2}}]}
