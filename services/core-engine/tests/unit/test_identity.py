"""Normalising sign-ins for identity correlations."""
from core.detection.identity_detector import identity_of, km_between


def test_a_sign_in_is_normalised():
    identity = identity_of({"event_type": "authentication", "timestamp": "2026-10-18T06:01:12Z", "data": {
        "user": "JSmith@Contoso.example", "source_ip": "203.0.113.45", "status": "failure", "error_code": "50126",
        "latitude": 52.37, "longitude": 4.89, "city": "Amsterdam", "country": "NL"}})
    assert identity["user"] == "jsmith@contoso.example" and identity["outcome"] == "failure" and identity["error_code"] == 50126
    assert identity["place"] == "Amsterdam, NL" and identity["at"].isoformat() == "2026-10-18T06:01:12+00:00"


def test_other_names_for_the_same_things():
    identity = identity_of({"event_type": "authentication", "data": {"user_id": "ana", "src_ip": "10.0.0.1", "status": "failed"}})
    assert (identity["user"], identity["ip"], identity["outcome"], identity["lat"]) == ("ana", "10.0.0.1", "failure", None)
    assert identity_of({"event_type": "process", "data": {"user": "x"}}) is None


def test_distances():
    assert round(km_between(-1.29, 36.82, 52.37, 4.89)) in range(6600, 6750)  # Nairobi to Amsterdam, about 6,670 km
    assert km_between(1.0, 1.0, 1.0, 1.0) == 0
