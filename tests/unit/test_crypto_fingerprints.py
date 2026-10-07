"""Unit tests for keyed HMAC fingerprinting (INV-006)."""

from guardx.core.crypto import compute_keyed_fingerprint, generate_session_key


def test_keyed_hmac_fingerprint_deterministic_with_same_key():
    key = generate_session_key()
    secret = "sk-proj-test12345678901234567890"

    fp1 = compute_keyed_fingerprint(secret, key)
    fp2 = compute_keyed_fingerprint(secret, key)

    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hexdigest
    assert secret not in fp1


def test_keyed_hmac_fingerprint_differs_with_different_keys():
    key1 = generate_session_key()
    key2 = generate_session_key()
    secret = "sk-proj-test12345678901234567890"

    fp1 = compute_keyed_fingerprint(secret, key1)
    fp2 = compute_keyed_fingerprint(secret, key2)

    assert fp1 != fp2


def test_keyed_hmac_fingerprint_differs_for_different_secrets():
    key = generate_session_key()
    s1 = "sk-proj-test12345678901234567890"
    s2 = "sk-proj-other1234567890123456789"

    fp1 = compute_keyed_fingerprint(s1, key)
    fp2 = compute_keyed_fingerprint(s2, key)

    assert fp1 != fp2
