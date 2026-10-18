"""TOTP as authenticator apps compute it (RFC 6238 test vectors)."""
import base64

from core.services.mfa import _hash, code_at, matching_step, new_recovery_codes

# RFC 6238, Appendix B: the SHA-1 secret "12345678901234567890".
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


def test_rfc_6238_vectors():
    # T = 59 s, 1111111109 s and 2000000000 s, 30-second steps, last six of eight digits.
    assert code_at(RFC_SECRET, 59 // 30) == "287082"
    assert code_at(RFC_SECRET, 1111111109 // 30) == "081804"
    assert code_at(RFC_SECRET, 2000000000 // 30) == "279037"


def test_a_code_is_good_for_its_step_and_one_either_side():
    now = 1111111109
    good = code_at(RFC_SECRET, now // 30)
    assert matching_step(RFC_SECRET, good, now) == now // 30
    assert matching_step(RFC_SECRET, good, now + 30) == now // 30
    assert matching_step(RFC_SECRET, good, now + 90) is None
    assert matching_step(RFC_SECRET, "12 34 5", now) is None and matching_step(RFC_SECRET, "abcdef", now) is None


def test_recovery_codes_are_typed_loosely():
    codes, hashes = new_recovery_codes()
    assert len(codes) == 10 and all(len(c) == 9 and c[4] == "-" for c in codes)
    assert _hash(codes[0].upper().replace("-", " ")) == hashes[0]
