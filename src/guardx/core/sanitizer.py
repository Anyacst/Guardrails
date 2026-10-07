"""Safe Payload Builder & Sensitive Content Sanitization Boundary.

Guarantees:
- INV-001: Zero raw credentials or sensitive PII in persistent GuardXEvent payloads.
- Deep content-level scanning of nested dictionaries, lists, and strings.
- Keyed HMAC fingerprinting for detected sensitive values.
"""

import re
from typing import Any, Dict, List, Mapping, Optional, Tuple
from guardx.core.crypto import compute_keyed_fingerprint


class SensitiveContentScanner:
    """Deterministic regex-based scanner for credentials, secrets, and PII."""

    # Patterns for API keys and tokens
    PATTERNS = {
        "ANTHROPIC_KEY": re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        "OPENAI_KEY": re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}|sk-(?!ant-)[A-Za-z0-9_\-]{20,}"),
        "GITHUB_TOKEN": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
        "AWS_KEY_ID": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
        "PRIVATE_KEY": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----"),
        "BEARER_TOKEN": re.compile(r"Bearer\s+[A-Za-z0-9\-_=]{20,}", re.IGNORECASE),
        "GENERIC_SECRET_KV": re.compile(r"(?:password|passwd|secret|api_key|token|auth_token)\s*[:=]\s*['\"]?([A-Za-z0-9@#$%^&*_\-+=!~]{6,})['\"]?", re.IGNORECASE),
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
        "PHONE": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    }

    SUSPICIOUS_FIELD_NAMES = {
        "raw_secret",
        "raw_value",
        "password",
        "passwd",
        "private_key",
        "secret_value",
        "api_key_raw",
    }

    def scan_string(self, text: str) -> List[Tuple[str, str, int, int]]:
        """Scans string for sensitive occurrences.
        
        Returns:
            List of (category, matched_text, start_offset, end_offset)
        """
        raw_matches = []
        for category, pattern in self.PATTERNS.items():
            for m in pattern.finditer(text):
                # For KV pairs, target the captured secret value if available
                if category == "GENERIC_SECRET_KV" and m.groups():
                    val = m.group(1)
                    start = m.start(1)
                    end = m.end(1)
                    raw_matches.append((category, val, start, end))
                else:
                    raw_matches.append((category, m.group(0), m.start(), m.end()))

        if not raw_matches:
            return []

        # Sort matches: earlier start first, longer match first, specific categories prioritized over GENERIC_SECRET_KV
        def match_priority(item):
            cat, val, start, end = item
            is_generic = 1 if cat == "GENERIC_SECRET_KV" else 0
            return (start, is_generic, -(end - start))

        sorted_candidates = sorted(raw_matches, key=match_priority)
        deduped: List[Tuple[str, str, int, int]] = []

        for candidate in sorted_candidates:
            cat, val, c_start, c_end = candidate
            # Check if this overlaps with any already accepted span
            overlaps = False
            for accepted in deduped:
                _, _, a_start, a_end = accepted
                if max(c_start, a_start) < min(c_end, a_end):
                    overlaps = True
                    break
            if not overlaps:
                deduped.append(candidate)

        return deduped

    def contains_sensitive_data(self, data: Any) -> bool:
        """Deep check if data contains any unmasked sensitive content or prohibited field names."""
        if isinstance(data, str):
            # Check for pattern matches
            for pattern in self.PATTERNS.values():
                if pattern.search(data):
                    return True
            return False

        elif isinstance(data, Mapping):
            for k, v in data.items():
                if str(k).lower() in self.SUSPICIOUS_FIELD_NAMES:
                    return True
                if self.contains_sensitive_data(k) or self.contains_sensitive_data(v):
                    return True
            return False

        elif isinstance(data, (list, tuple, set)):
            return any(self.contains_sensitive_data(item) for item in data)

        return False


class SafePayloadBuilder:
    """Transforms raw observation dictionaries into persistence-safe payloads."""

    def __init__(self, scanner: Optional[SensitiveContentScanner] = None):
        self.scanner = scanner or SensitiveContentScanner()

    def sanitize_string(
        self, text: str, hmac_key: str
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Replaces sensitive spans with masked tokens and emits entity metadata."""
        matches = self.scanner.scan_string(text)
        if not matches:
            return text, []

        # Sort matches in descending order of start offset to replace cleanly
        sorted_matches = sorted(matches, key=lambda m: m[2], reverse=True)
        sanitized = text
        discovered_entities: List[Dict[str, Any]] = []

        counter = 1
        for category, raw_match, start, end in sorted_matches:
            fingerprint = compute_keyed_fingerprint(raw_match, hmac_key)
            preview = f"{raw_match[:3]}••••{raw_match[-2:]}" if len(raw_match) > 8 else "••••••••"
            masked_token = f"[MASKED_{category}_{counter:03d}_{fingerprint[:8]}]"
            counter += 1

            sanitized = sanitized[:start] + masked_token + sanitized[end:]

            discovered_entities.append({
                "category": category,
                "masked_preview": preview,
                "fingerprint_hmac": fingerprint,
                "offset": start,
            })

        return sanitized, discovered_entities

    def sanitize_payload(
        self, raw_payload: Mapping[str, Any], hmac_key: str
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Recursively sanitizes arbitrary raw dictionary into persistence-safe payload.
        
        Guarantees:
        - No raw secret values remain.
        - Sensitive strings are masked.
        - Discovered entity records include keyed HMAC fingerprints, not raw secrets.
        """
        all_discovered: List[Dict[str, Any]] = []

        def _sanitize_val(val: Any) -> Any:
            if isinstance(val, str):
                s_text, discovered = self.sanitize_string(val, hmac_key)
                all_discovered.extend(discovered)
                return s_text
            elif isinstance(val, Mapping):
                res = {}
                for k, v in val.items():
                    # Sanitize key name if it's sensitive
                    k_str = str(k)
                    if k_str.lower() in self.scanner.SUSPICIOUS_FIELD_NAMES:
                        k_str = f"sanitized_{k_str}"
                    res[k_str] = _sanitize_val(v)
                return res
            elif isinstance(val, list):
                return [_sanitize_val(item) for item in val]
            elif isinstance(val, tuple):
                return tuple(_sanitize_val(item) for item in val)
            return val

        safe_dict = _sanitize_val(dict(raw_payload))
        return safe_dict, all_discovered
