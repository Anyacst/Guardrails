# GuardX — AgentProvenance Analysis & Target Architecture Specification

**Status:** Phase 1 Approved with Final Architectural Refinements  
**Date:** October 2026  
**Target System:** GuardX (Python Agent Provenance + Runtime Information-Flow Security Platform)  
**Reference System:** AgentProvenance (`ByteYellow/AgentProvenance`) & AgentGuard Baseline (`/Users/neerajkahal/Documents/Unique`)

---

## 1. Executive Summary & Mission

GuardX is an independent, Python-first runtime security, execution provenance, information-flow control, and enforcement platform for autonomous AI agents.

AI agents are transitioning from conversational chat bots to autonomous task executors that read files, invoke shell processes, communicate over networks, and manage credentials. While traditional LLM observability tools capture chat latency and prompt tokens, and traditional host EDR tools capture raw OS syscalls, **neither bridges the semantic gap between what an agent intended to do and what runtime effects actually occurred across trust boundaries**.

GuardX synthesizes:
1. **AgentProvenance-style execution provenance `[AP-INSPIRED]`:** Multi-axis observability correlating agent intent, tool execution, and runtime process/file/network effects into a deterministic, queryable evidence Directed Acyclic Graph (DAG).
2. **AgentGuard sensitive-data protection `[EXISTING-GUARDX]`:** Ephemeral token reference stores, anti-tamper credential vaults, and atomic file reconstruction.
3. **GuardX information-flow control & enforcement `[NEW-GUARDX]`:** Fine-grained entity-level data lineage, transformation-aware taint propagation (Base64, JSON, URL-encoding, hashing, aggregation/declassification), trust-boundary modeling, deterministic graph-based risk path finding, and prospective runtime enforcement (`ALLOW`, `MODIFY`, `BLOCK`, `HUMAN_REVIEW`).

---

## 2. Architectural Core & Implementation Refinements

### 2.1 Event-Sourced ExecutionScope Lifecycle & Projections
GuardX separates immutable historical evidence from current state projections:
* `GuardXEvent` is strictly immutable (`frozen=True`).
* An `ExecutionScope` begins with an immutable `SCOPE_START` event.
* Tool invocations, file reads, and subprocess executions occur within the scope and reference its `execution_scope_id`.
* The scope closes with an immutable `SCOPE_END` event carrying the termination status (`COMPLETED`, `FAILED`, `INTERCEPTED`) and duration.
* The active/persisted state of a scope is a **derived current-state projection** (`ScopeProjection`) computed from these immutable lifecycle events. Historical events are never mutated.

### 2.2 Async-Safe Context Propagation via `contextvars.ContextVar`
Rather than relying solely on `threading.local` (which fails in modern async frameworks like FastAPI, WebSockets, asyncio, and parallel tool dispatch), GuardX uses Python `contextvars.ContextVar`:
* `current_session: ContextVar[Optional[Session]]`
* `current_execution_scope: ContextVar[Optional[ScopeProjection]]`
* `current_actor: ContextVar[Optional[Actor]]`
This ensures seamless context propagation across asyncio tasks, thread pools, and concurrent agent executions.

### 2.3 Safe Payload Boundary (`RawObservation` -> `SafePayloadBuilder`)
Collectors must **never** directly instantiate persistent `GuardXEvent`s containing arbitrary, uninspected dictionaries:
```
Runtime Activity
       │
       ▼
[Collector]
       │
       ▼
RawObservation (Transient, In-Memory Only, Never Persisted / Logged)
       │
       ▼
Sensitive Scanner / Sanitizer (Content-Level Inspection)
       │
       ▼
SafePayloadBuilder (Guarantees Zero Raw Secrets / Masks Values)
       │
       ▼
EventRecorder (Centralized Sequencer & Factory)
       │
       ▼
Immutable GuardXEvent
       │
       ▼
EventBus
```
The zero-raw-secret invariant (`INV-001`) actively inspects string and dictionary contents for API keys, passwords, private keys, and PII, rather than merely checking field names like `raw_secret`.

### 2.4 Centralized Event Creation and Sequencing (`EventRecorder`)
Individual collectors must **never** assign sequence numbers. Centralizing event creation into `EventRecorder` provides concurrency safety and unified validation:
1. **Canonical Identity Resolution:** Resolves actors via `ActorResolver` and resources via `ResourceResolver`.
2. **Context Attachment:** Automatically binds active `execution_scope_id` from `ContextVar`.
3. **Causal Validation:** Validates that `causal_event_id` refers to an existing, prior event in the session.
4. **Content Sanitization:** Passes raw observations through `SafePayloadBuilder`.
5. **Quality & Confidence Validation:** Validates `ProvenanceQuality` (`OBSERVED`, `DERIVED`, `INFERRED`) and confidence score ($0.0 - 1.0$).
6. **Atomic Monotonic Sequence Assignment:** Increments session-local sequence counter atomically ($S_{n+1} = S_n + 1$).
7. **Immutable Event Construction:** Creates frozen `GuardXEvent`.
8. **Event Publication:** Publishes the immutable event to `EventBus`.

### 2.5 Pluggable Telemetry Provider
GuardX is Python-first, cross-platform, and cleanly designed around a `RuntimeTelemetryProvider` interface:
* `ProcessTelemetryProvider`: Process monitoring via `psutil` / subprocess wrappers.
* `FileTelemetryProvider`: Filesystem interception and diffing.
* `NetworkTelemetryProvider`: Socket and HTTP client interception.
* `KernelTelemetryProvider`: Pluggable future provider for Linux eBPF or OS-native probes without architectural rewriting.

### 2.6 Three Decoupled Logical Evidence Layers
To maintain clarity and prevent distortion of the primary execution facts:
1. **Layer 1: Execution Provenance:** Causal DAG of scopes, tools, processes, files, and network sockets (`CAUSED_BY`, `SPAWNED`, `INVOKED`, `READ_FROM`, `WROTE_TO`).
2. **Layer 2: Data Lineage:** Entities, variables, and transformation hops (`CONTAINS`, `PRODUCED_BY`, `FLOWS_TO`, `DERIVED_FROM`, `TRANSFORMED_BY`).
3. **Layer 3: Analysis & Security Overlay:** Risk findings, policy violations, and decisions (`CROSSES_BOUNDARY`, `TRIGGERS_RISK`, `POLICY_VIOLATION`, `DECISION`).

---

## 3. Consolidated Six-Milestone Roadmap

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ M1: PROVENANCE FOUNDATION                                                   │
│ Core domain, ExecutionScope, collectors, execution DAG, SQLite, OpenCode    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ M2: LIVE INVESTIGATION                                                      │
│ FastAPI backend, WebSocket streaming, interactive console V1, live lenses   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ M3: INFORMATION FLOW                                                        │
│ DataEntity, HMAC fingerprinting, Data-Flow DAG, transformations, trust zones│
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ M4: SECURITY INTELLIGENCE                                                   │
│ Source-to-sink risk engine, intent conformance, attack chains, replay       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ M5: ENFORCEMENT                                                             │
│ Declarative policy engine, prospective gateway (ALLOW/MODIFY/BLOCK/REVIEW)  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ M6: ADVANCED RESEARCH                                                       │
│ Pluggable eBPF/OS-native telemetry, multi-framework adapters, LLM triage    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Phase 1 Implementation Specification

### 4.1 Enums (`guardx.core.enums`)
* `EventType`: `SESSION_START`, `SESSION_END`, `SCOPE_START`, `SCOPE_END`, `USER_INPUT`, `AGENT_ACTION`, `INTENT_DECLARED`, `TOOL_CALL`, `TOOL_RESULT`, `PROCESS_EXEC`, `PROCESS_EXIT`, `FILE_READ`, `FILE_WRITE`, `FILE_DIFF`, `NETWORK_REQUEST`, `NETWORK_RESPONSE`, `LLM_REQUEST`, `LLM_RESPONSE`, `DATA_DISCOVERED`, `TRANSFORMATION`, `TRUST_BOUNDARY_CROSSED`, `RISK_DETECTED`, `POLICY_VIOLATION`, `DECISION`.
* `ActorType`: `USER`, `AGENT`, `TOOL`, `SUBPROCESS`, `SYSTEM`.
* `ResourceType`: `FILE`, `PROCESS`, `TOOL`, `NETWORK_ENDPOINT`, `LLM`, `MEMORY_OBJECT`.
* `TrustLevel`: `LOCAL`, `TRUSTED_INTERNAL`, `TRUSTED_EXTERNAL`, `EXTERNAL_LLM`, `UNTRUSTED_EXTERNAL`, `UNKNOWN`.
* `ProvenanceQuality`: `OBSERVED`, `DERIVED`, `INFERRED`.
* `TransformationSecuritySemantics`: `PRESERVING`, `PROTECTING`, `SANITIZING`, `AGGREGATING`, `DECLASSIFYING`, `UNKNOWN`.
* `ScopeStatus`: `ACTIVE`, `COMPLETED`, `FAILED`, `INTERCEPTED`.

### 4.2 Core Models (`guardx.core.models`)
* `Actor`: Frozen dataclass with `actor_id`, `actor_type`, `display_name`, `metadata`.
* `Resource`: Frozen dataclass with `resource_id`, `resource_type`, `uri`, `trust_level`, `metadata`.
* `Session`: Frozen dataclass with `session_id`, `agent_name`, `workspace_root`, `hmac_key`, `start_time`, `end_time`, `metadata`.
* `ScopeProjection`: Derived state projection with `scope_id`, `session_id`, `parent_scope_id`, `actor_id`, `originating_event_id`, `scope_name`, `start_time`, `end_time`, `status`, `metadata`.
* `GuardXEvent`: Frozen dataclass with `event_id`, `session_id`, `sequence_number`, `timestamp`, `event_type`, `actor`, `source`, `destination`, `execution_scope_id`, `causal_event_id`, `data_lineage_ids`, `payload`, `provenance_quality`, `confidence`, `metadata`.
* `RawObservation`: Transient memory-only dataclass holding raw collector output before sanitization.
* `DataEntity` & `Transformation`: Forward-compatible lineage interfaces with keyed HMAC fingerprints and security semantics.

### 4.3 Invariants
* **INV-001 (Zero Raw Secret Content):** Event payloads must contain zero raw credentials or sensitive PII. Verified by deep content scanner.
* **INV-002 (Append-Only Event Immutability):** `GuardXEvent` is immutable (`frozen=True`).
* **INV-003 (Strict Sequence Monotonicity):** Sequence numbers are contiguous, atomic integers starting at 1.
* **INV-004 (Scope Attribution):** Operational execution events reference an active `execution_scope_id`.
* **INV-005 (Causal Integrity):** `causal_event_id` must reference a strictly prior event in the session ($seq_{causal} < seq_{current}$).
* **INV-006 (Keyed HMAC Fingerprint):** All sensitive entity matching must use session-salted HMAC-SHA256, never raw values or plain SHA-256.
* **INV-007 (Resolver Idempotency):** Duplicate paths or host representations resolve to identical canonical `resource_id`.
