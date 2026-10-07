"""Domain Enums for GuardX."""

from enum import Enum


class EventType(str, Enum):
    """Categorization of GuardX domain events."""

    # Session & Scope Lifecycle
    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    SCOPE_START = "SCOPE_START"
    SCOPE_END = "SCOPE_END"
    USER_INPUT = "USER_INPUT"
    AGENT_ACTION = "AGENT_ACTION"
    INTENT_DECLARED = "INTENT_DECLARED"

    # Tool & Process Operations
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    PROCESS_EXEC = "PROCESS_EXEC"
    PROCESS_EXIT = "PROCESS_EXIT"

    # Filesystem Operations
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_DIFF = "FILE_DIFF"

    # Network Operations
    NETWORK_REQUEST = "NETWORK_REQUEST"
    NETWORK_RESPONSE = "NETWORK_RESPONSE"

    # Model Operations
    LLM_REQUEST = "LLM_REQUEST"
    LLM_RESPONSE = "LLM_RESPONSE"

    # Data & Lineage Operations
    DATA_DISCOVERED = "DATA_DISCOVERED"
    TRANSFORMATION = "TRANSFORMATION"
    TRUST_BOUNDARY_CROSSED = "TRUST_BOUNDARY_CROSSED"

    # Security Findings & Decisions
    RISK_DETECTED = "RISK_DETECTED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    DECISION = "DECISION"

    # Milestone 5 Runtime Policy Enforcement & Interception Events
    ACTION_PROPOSED = "ACTION_PROPOSED"
    POLICY_MATCHED = "POLICY_MATCHED"
    DECISION_CREATED = "DECISION_CREATED"
    ACTION_MODIFIED = "ACTION_MODIFIED"
    ACTION_BLOCKED = "ACTION_BLOCKED"
    REVIEW_REQUESTED = "REVIEW_REQUESTED"
    REVIEW_APPROVED = "REVIEW_APPROVED"
    REVIEW_DENIED = "REVIEW_DENIED"
    REVIEW_EXPIRED = "REVIEW_EXPIRED"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    POST_EXECUTION_VERIFIED = "POST_EXECUTION_VERIFIED"
    POST_EXECUTION_MISMATCH = "POST_EXECUTION_MISMATCH"


class ActorType(str, Enum):
    """Type of entity driving execution."""

    USER = "USER"
    AGENT = "AGENT"
    TOOL = "TOOL"
    SUBPROCESS = "SUBPROCESS"
    SYSTEM = "SYSTEM"


class ResourceType(str, Enum):
    """Type of entity being accessed or mutated."""

    FILE = "FILE"
    PROCESS = "PROCESS"
    TOOL = "TOOL"
    NETWORK_ENDPOINT = "NETWORK_ENDPOINT"
    LLM = "LLM"
    MEMORY_OBJECT = "MEMORY_OBJECT"


class TrustLevel(str, Enum):
    """Trust tier of an execution or network boundary."""

    LOCAL = "LOCAL"
    TRUSTED_INTERNAL = "TRUSTED_INTERNAL"
    TRUSTED_EXTERNAL = "TRUSTED_EXTERNAL"
    EXTERNAL_LLM = "EXTERNAL_LLM"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    UNKNOWN = "UNKNOWN"


class ProvenanceQuality(str, Enum):
    """Degree of certainty behind a captured event or relationship assertion."""

    OBSERVED = "OBSERVED"  # Directly observed via telemetry / collector (confidence = 1.0)
    DERIVED = "DERIVED"    # Deterministically computed / parsed (confidence >= 0.9)
    INFERRED = "INFERRED"  # Correlated or model-asserted (confidence <= 0.7)


class TransformationSecuritySemantics(str, Enum):
    """Security effect of a transformation on sensitive entity identity."""

    PRESERVING = "PRESERVING"       # Identity preserved (Base64, Hex, URL-encode)
    PROTECTING = "PROTECTING"       # Cryptographically protected (AES, RSA)
    SANITIZING = "SANITIZING"       # Redacted or tokenized (Value removed)
    AGGREGATING = "AGGREGATING"     # Statistically combined (average, sum, count)
    DECLASSIFYING = "DECLASSIFYING" # Policy-governed declassification
    UNKNOWN = "UNKNOWN"             # Ambiguous or unverified


class ScopeStatus(str, Enum):
    """Current state of an execution scope projection."""

    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INTERCEPTED = "INTERCEPTED"
