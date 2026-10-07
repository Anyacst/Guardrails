"""Unit tests for SafePayloadBuilder and sensitive content boundary (INV-001)."""

from guardx.core.crypto import generate_session_key
from guardx.core.sanitizer import SafePayloadBuilder, SensitiveContentScanner


def test_scanner_detects_credentials_and_pii():
    scanner = SensitiveContentScanner()

    assert scanner.contains_sensitive_data("sk-proj-abcdef12345678901234567890")
    assert scanner.contains_sensitive_data("sk-ant-abcdef12345678901234567890")
    assert scanner.contains_sensitive_data("AKIAIOSFODNN7EXAMPLE")
    assert scanner.contains_sensitive_data("Bearer sk-proj-abcdef12345678901234567890")
    assert scanner.contains_sensitive_data("user@example.com")
    assert scanner.contains_sensitive_data({"raw_secret": "normal_looking_value"})
    assert not scanner.contains_sensitive_data("This is a benign diagnostic message.")


def test_safe_payload_builder_masks_nested_secrets():
    builder = SafePayloadBuilder()
    key = generate_session_key()

    raw_payload = {
        "message": "Connected with key sk-proj-supersecretkey1234567890",
        "details": {
            "contact": "alice@example.com",
            "count": 42,
            "tokens": ["sk-ant-anothersecretkey1234567890", "public-token"],
        },
    }

    safe_payload, discovered = builder.sanitize_payload(raw_payload, key)

    # 1. No raw secrets exist in sanitized payload
    scanner = SensitiveContentScanner()
    assert not scanner.contains_sensitive_data(safe_payload)

    # 2. String values were masked
    assert "sk-proj-supersecretkey" not in safe_payload["message"]
    assert "[MASKED_OPENAI_KEY_" in safe_payload["message"]
    assert "[MASKED_EMAIL_" in safe_payload["details"]["contact"]
    assert "[MASKED_ANTHROPIC_KEY_" in safe_payload["details"]["tokens"][0]
    assert safe_payload["details"]["tokens"][1] == "public-token"
    assert safe_payload["details"]["count"] == 42

    # 3. Discovered entities record HMAC fingerprints, never raw secrets
    assert len(discovered) == 3
    for disc in discovered:
        assert "fingerprint_hmac" in disc
        assert len(disc["fingerprint_hmac"]) == 64
        assert "raw_secret" not in disc
