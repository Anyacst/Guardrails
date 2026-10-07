# GuardX — Technical Handoff Report & Milestone 5 Readiness Analysis

**Document Status:** Complete Technical Handoff Report  
**Target Milestone for Next Work:** Milestone 5 (Policy Enforcement & Runtime Interception) — *NOT STARTED / PENDING APPROVAL*  
**Scope:** Full architectural inspection of Milestones 1–4, AgentGuard baseline integration, Groq test harness, test suite validation, and prospective enforcement gap analysis.

---

## Table of Contents
- [A. Executive Summary](#a-executive-summary)
- [B. Repository Architecture](#b-repository-architecture)
- [C. Milestone 1 Implementation (Provenance Foundation)](#c-milestone-1-implementation-provenance-foundation)
- [D. Milestone 2 Implementation (Runtime Observation & Investigation Console)](#d-milestone-2-implementation-runtime-observation--investigation-console)
- [E. Milestone 3 Implementation (Sensitive Data Lineage & Information Flow)](#e-milestone-3-implementation-sensitive-data-lineage--information-flow)
- [F. Milestone 4 Implementation (Security Intelligence)](#f-milestone-4-implementation-security-intelligence)
- [G. AgentGuard Integration Analysis](#g-agentguard-integration-analysis)
- [H. Groq Test Agent Harness & Sandbox Confinement](#h-groq-test-agent-harness--sandbox-confinement)
- [I. Execution Graph Architecture](#i-execution-graph-architecture)
- [J. Sensitive Data Lineage Architecture](#j-sensitive-data-lineage-architecture)
- [K. Security Intelligence Architecture](#k-security-intelligence-architecture)
- [L. Investigation GUI & Frontend Lens Architecture](#l-investigation-gui--frontend-lens-architecture)
- [M. Security Invariants & Enforcement Locations](#m-security-invariants--enforcement-locations)
- [N. API Contracts & Serialization Schemas](#n-api-contracts--serialization-schemas)
- [O. Complete Test Coverage Matrix](#o-complete-test-coverage-matrix)
- [P. Current Test Results](#p-current-test-results)
- [Q. Technical Debt & Architectural Fragilities](#q-technical-debt--architectural-fragilities)
- [R. Milestone 5 Readiness & Interception Gap Analysis](#r-milestone-5-readiness--interception-gap-analysis)
- [S. Recommended Milestone 5 Architecture Specification](#s-recommended-milestone-5-architecture-specification)
- [T. Milestone 5 Implementation Phasing Order](#t-milestone-5-implementation-phasing-order)

---

## A. Executive Summary

GuardX is a Python-first runtime security, execution provenance, information-flow lineage, and guardrail platform for autonomous AI agents.

### The Problem GuardX Solves
Autonomous AI agents are transitioning from conversational bots to tool-executing systems that autonomously read files, execute child processes, invoke APIs, query remote LLMs, and modify software environments. Existing monitoring tools suffer from a fatal semantic dichotomy:
1. **Application-level LLM Observability** (e.g., Langfuse, Helicone) monitors token counts, latency, and prompt history, but has zero visibility into operating system side effects, child processes, or file modifications.
2. **Host EDR & Kernel Observability** (e.g., Falco, Osquery, sysflow) captures raw syscalls, socket writes, and process fork events, but is completely blind to agent intent, reasoning chains, prompt context, and token transformations.
3. **Naive Content Filters & Guardrails** inspect only inputs and outputs at the prompt perimeter, failing to track how data moves, transforms (Base64, JSON, URL-encoding), or exfiltrates across tools and side channels.

### What GuardX Has Implemented (Milestones 1–4)
GuardX bridges this gap by establishing three decoupled, evidence-backed layers:
- **Layer 1: Execution Provenance (M1/M2):** Event-sourced causal DAG mapping actor actions, tool calls, filesystem operations, child processes, network traffic, and LLM completions into an immutable evidence graph partitioned into hierarchical `ExecutionScope` contexts.
- **Layer 2: Sensitive Data Lineage (M3):** Fine-grained tracking of identifiable `DataEntity` instances and `DataCarrier` containers across runtime boundaries, with keyed HMAC-SHA256 fingerprinting, synthetic token mapping, deterministic transformations, and a strict invariant: **temporal proximity does NOT imply information flow**.
- **Layer 3: Security Intelligence (M4):** Rule-driven evaluation of proven information flow across resolved `TrustLevel` boundaries, representation-aware risk analysis (RAW vs. TOKENIZED vs. ENCODED), deterministic intent contract conformance, and multi-event attack chain synthesis.

### What Milestone 5 Will Add
Milestone 5 will introduce **Layer 4: Policy Enforcement & Runtime Interception**, transitioning GuardX from an observational detection platform into an inline runtime enforcement gateway that prospective evaluates proposed actions (`ProspectiveAction`) and issues binding decisions (`ALLOW`, `MODIFY`, `BLOCK`, `HUMAN_REVIEW`) before side effects execute on the host or over the network.

---

## B. Repository Architecture

The GuardX repository is organized into distinct, modular subsystems with strict separation of concerns:

```
Tool/
├── .env                       # Root environment (contains GROQ_API_KEY; strictly ignored by git)
├── .env.example               # Template with zero real secrets
├── docs/                      # Technical specifications & analysis
│   ├── AGENTPROVENANCE_ANALYSIS.md
│   └── M5_READINESS_ANALYSIS.md (This report)
├── examples/                  # Standalone demonstration agents
│   └── groq_agent/            # Controlled tool-calling agent using Groq API
│       ├── agent.py           # Agent loop with hierarchical scopes
│       ├── cli.py             # CLI runner
│       ├── sandbox.py         # Path confinement sandbox (anti-traversal)
│       ├── tools.py           # list_files, read_file, write_file tool implementations
│       └── workspace/         # Isolated playground containing synthetic secrets only
├── src/guardx/                # Core GuardX platform source
│   ├── adapters/              # External agent bridges (OpenCode adapter)
│   ├── chains/                # Multi-event causal attack chain detector
│   ├── cli/                   # Command-line inspection utilities
│   ├── collectors/            # Telemetry collectors (Tool, File, Process, Network, LLM)
│   ├── core/                  # Invariant validator, models, enums, bus, recorder, sanitizer
│   ├── graph/                 # Execution Provenance DAG engine, models, and store
│   ├── intent/                # Intent contract and conformance engine
│   ├── lineage/               # Sensitive data lineage engine, extractors, transformations
│   ├── risk/                  # Risk path engine, rules, and explainable models
│   ├── security/              # SecurityOverlayStore (Layer 3 dedicated storage)
│   ├── server/                # FastAPI application, WebSocket broadcaster, session registry
│   └── trust/                 # TrustResolver and TrustBoundaryEngine
├── tests/                     # Comprehensive test suite
│   ├── conftest.py            # Global fixtures & sys.path configuration
│   ├── e2e/                   # End-to-end integration tests (5 test suites)
│   ├── frontend/              # Node.js native test runner frontend tests
│   └── unit/                  # Unit tests (24 test suites)
└── web/                       # Live Investigation Console (Frontend)
    ├── app.js                 # Cytoscape.js canvas logic, WebSocket handler, 3 lenses
    ├── index.html             # Multi-panel dark security UI
    └── style.css              # Cyber-security dark theme stylesheet
```

---

## C. Milestone 1 Implementation (Provenance Foundation)

**Location:** `src/guardx/core/`

Milestone 1 establishes the mathematical and domain foundation for all subsequent milestones.

### 1. Key Components
- [`enums.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/enums.py): Defines domain enums: `EventType`, `ActorType`, `ResourceType`, `TrustLevel`, `ProvenanceQuality`, `TransformationSecuritySemantics`, and `ScopeStatus`.
- [`models.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/models.py): Defines immutable domain entities (`Actor`, `Resource`, `Session`, `GuardXEvent`) and transient structures (`RawObservation`, `ScopeProjection`).
- [`context.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/context.py): Implements `ScopeManager` and `ScopeContext` using Python's `contextvars.ContextVar` (`_CURRENT_SESSION`, `_CURRENT_SCOPE`, `_CURRENT_ACTOR`) for async-safe, thread-safe hierarchical scope propagation.
- [`sanitizer.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/sanitizer.py): Contains `SensitiveContentScanner` (deep regex pattern matching for API keys, bearer tokens, private keys, PII) and `SafePayloadBuilder` which replaces raw secrets with masked representations (`[MASKED_<TYPE>_<COUNTER>_<HASH>]`) and extracts entity metadata before persistence.
- [`crypto.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/crypto.py): Implements keyed HMAC-SHA256 (`compute_keyed_fingerprint`) using ephemeral session keys (`generate_session_key`), preventing dictionary and rainbow table attacks.
- [`resolvers.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/resolvers.py): Implements idempotent `DefaultResourceResolver` (canonical paths, relative file URIs, parsed network hosts/ports) and `DefaultActorResolver`.
- [`recorder.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/recorder.py): The centralized coordinator that receives `RawObservation` instances, resolves actors/resources, binds active scopes, sanitizes payloads, assigns strictly monotonic sequence numbers under a threading lock, validates invariants, stores event history, and publishes to the bus.
- [`bus.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/bus.py): Concurrency-safe in-memory pub-sub bus (`InMemoryEventBus`) with subscriber protection.
- [`invariants.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/invariants.py): Active validation engine enforcing domain guarantees.

---

## D. Milestone 2 Implementation (Runtime Observation & Investigation Console)

**Location:** `src/guardx/collectors/`, `src/guardx/graph/`, `src/guardx/server/`, `web/`

Milestone 2 operationalizes telemetry capture and live visual investigation.

### 1. Collector Abstraction & Implementations
All collectors inherit from [`BaseCollector`](file:///Users/neerajkahal/Documents/Tool/src/guardx/collectors/base.py) and obey the invariant: **Collectors NEVER construct persistent `GuardXEvent`s directly.** They emit transient `RawObservation` instances to `EventRecorder`.
- [`ToolCollector`](file:///Users/neerajkahal/Documents/Tool/src/guardx/collectors/tool_collector.py): Observes `TOOL_CALL` and `TOOL_RESULT` events; supports `observe_call` context manager.
- [`FileCollector`](file:///Users/neerajkahal/Documents/Tool/src/guardx/collectors/file_collector.py): Observes `FILE_READ` and `FILE_WRITE` actions; captures bounded previews (1000 chars) that pass through `SafePayloadBuilder`.
- [`ProcessCollector`](file:///Users/neerajkahal/Documents/Tool/src/guardx/collectors/process_collector.py): Captures `PROCESS_EXEC` and `PROCESS_EXIT`, tracks PID, PPID, executable, and exit code; supports `observe_subprocess` lifecycle manager.
- [`NetworkCollector`](file:///Users/neerajkahal/Documents/Tool/src/guardx/collectors/network_collector.py): Captures outbound HTTP requests and responses, sanitizes authorization headers and request/response previews.
- [`LLMCollector`](file:///Users/neerajkahal/Documents/Tool/src/guardx/collectors/llm_collector.py): Observes `LLM_REQUEST` and `LLM_RESPONSE` across models and providers, recording token usage, endpoint, and prompt/completion previews.

### 2. Execution Provenance DAG
- [`models.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/graph/models.py): Canonical `GraphNode` (`USER`, `AGENT`, `TOOL`, `FILE`, `PROCESS`, `NETWORK_ENDPOINT`, `LLM`, `EXECUTION_SCOPE`) and `GraphEdge` (`INVOKED`, `READ_FROM`, `WROTE_TO`, `SPAWNED`, `SENT_TO`, `RECEIVED_FROM`, `CAUSED_BY`, `BELONGS_TO_SCOPE`, `RETURNED_TO`).
- [`store.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/graph/store.py): `InMemoryGraphStore` providing thread-safe mutation, idempotency, BFS ancestor/descendant traversal, shortest path finding, and scope subgraphs.
- [`engine.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/graph/engine.py): Subscribes to `EventBus`, projects events into DAG nodes and causal edges, and provides `explain_causality()` with an explicit semantic guarantee: **Explains execution causality only; does NOT imply unproven data flow.**

### 3. Server & Live Streaming
- [`app.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/server/app.py): FastAPI application serving REST endpoints, demo steppers, and static assets.
- [`broadcaster.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/server/broadcaster.py): `WebSocketBroadcaster` bridging synchronous event bus callbacks to asynchronous WebSocket clients with thread safety (`threading.RLock`) and loop binding.
- [`session_registry.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/server/session_registry.py): Encapsulates per-session state, stores, and engines.

---

## E. Milestone 3 Implementation (Sensitive Data Lineage & Information Flow)

**Location:** `src/guardx/lineage/`

Milestone 3 implements facts about information flow.

### 1. Data Models
- [`models.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/lineage/models.py):
  - `DataEntity`: Immutable entity tracking identifiable data, classification (`PUBLIC`, `INTERNAL`, `SOURCE_CODE`, `PII`, `SECRET`, `CREDENTIAL`, `CREDENTIAL_REFERENCE`), representation (`RAW`, `TOKENIZED`, `ENCODED`, `DERIVED`, `REDACTED`), origin resource, keyed HMAC fingerprint, and optional synthetic token.
  - `DataCarrier`: Container object (`FILE_CONTENT`, `TOOL_RESULT`, `AGENT_CONTEXT`, `LLM_REQUEST`, `LLM_RESPONSE`, `TOOL_ARGUMENT`, `NETWORK_REQUEST`, `NETWORK_RESPONSE`, `FILE_WRITE_CONTENT`) carrying entity IDs across boundaries.
  - `LineageEdge`: Directed edge (`CONTAINS`, `FLOWS_TO`, `DERIVED_FROM`, `PRODUCED_BY`, `USED_BY`, `TRANSFORMED_TO`) with supporting event handle and concrete `DetectionMethod` (`TOKEN_IDENTITY`, `HMAC_MATCH`, `EXACT_TRANSIENT_MATCH`, `STRUCTURED_PROPAGATION`, `TRANSFORMATION_MATCH`, `EXPLICIT_MAPPING`).
  - `Transformation`: Record of deterministic transformations (`COPY`, `CONCAT`, `FORMAT`, `JSON_SERIALIZE`, `BASE64_ENCODE`, `URL_ENCODE`, `TOKENIZE`, `REDACT`) with explicit security semantics (`PRESERVING`, `PROTECTING`, `SANITIZING`, `AGGREGATING`, `DECLASSIFYING`, `UNKNOWN`).

### 2. Extractors & Transformations
- [`extractors.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/lineage/extractors.py): `BoundaryEntityExtractor` parses `.env` files into sensitive credentials and public keys, extracts synthetic tokens (`{{SECRET_...}}`, `[MASKED_...]`), and invokes AgentGuard detectors if present. Emits zero raw secrets on entities.
- [`transformations.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/lineage/transformations.py): `TransformationEngine` manages derived entities, preserves backward traceability, and computes derived HMAC fingerprints.

### 3. DataFlowEngine & Lineage Store
- [`store.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/lineage/store.py): Dedicated `DataLineageStore` supporting forward BFS trace (`trace_forward`) and backward BFS trace (`trace_backward`). When an entity has no verified causal path to a sink, explicitly returns `has_proven_flow: False` and `"NO PROVEN FLOW"`.
- [`engine.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/lineage/engine.py): Subscribes to `EventBus` and correlates carriers across boundaries. **Enforces negative-flow semantics:** `FILE_READ .env` followed by `LLM_REQUEST` only creates a flow edge if the entity or token actually appears in the request payload.

---

## F. Milestone 4 Implementation (Security Intelligence)

**Location:** `src/guardx/trust/`, `src/guardx/risk/`, `src/guardx/intent/`, `src/guardx/chains/`, `src/guardx/security/`

Milestone 4 converts execution provenance and information lineage into explainable security findings without taking prospective enforcement actions.

### 1. Trust Boundaries & Resolver
- [`resolver.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/trust/resolver.py): `TrustResolver` classifies identifiers into `LOCAL`, `TRUSTED_INTERNAL`, `TRUSTED_EXTERNAL`, `EXTERNAL_LLM`, `UNTRUSTED_EXTERNAL`, `UNKNOWN`.
- [`engine.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/trust/engine.py): `TrustBoundaryEngine` detects when a proven information hop crosses between differing trust levels, creating `TrustBoundaryCrossing` records.

### 2. Deterministic Risk Path Engine
- [`rules.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/risk/rules.py): Declares 6 default `RiskRule` specifications matching combinations of classification, representation state, and destination trust tier.
- [`engine.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/risk/engine.py): `RiskPathEngine` evaluates forward traces from `DataLineageStore`. Implements strict invariants:
  - Requires `has_proven_flow: True`.
  - Disallows disclosure findings for `PUBLIC` data.
  - Distinguishes RAW (HIGH/CRITICAL) from TOKENIZED (LOW/PROTECTED) and ENCODED (HIGH).
  - Deduplicates findings via SHA256 path hashes.

### 3. Intent Conformance Engine
- [`models.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/intent/models.py): `IntentContract` declares allowed operations, allowed resources, and allowed network endpoints for a scope.
- [`engine.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/intent/engine.py): `IntentConformanceEngine` checks runtime events against active scope contracts. Detects `RESOURCE_SCOPE_MISMATCH`, `UNDECLARED_NETWORK_EFFECT`, and `OPERATION_NOT_ALLOWED`.

### 4. Attack Chain Detector & Security Store
- [`detector.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/chains/detector.py): `AttackChainDetector` synthesizes multi-event attack chains (`POTENTIAL_CREDENTIAL_EXFILTRATION`, `ENCODED_SECRET_EGRESS`, `UNEXPECTED_NETWORK_SIDE_EFFECT`).
- [`store.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/security/store.py): `SecurityOverlayStore` maintains isolated, thread-safe storage for Layer 3 security findings.

---

## G. AgentGuard Integration Analysis

GuardX evolved from an existing AgentGuard baseline located in `/Users/neerajkahal/Documents/Unique`.

### 1. Existing AgentGuard Capabilities
The AgentGuard codebase in `/Users/neerajkahal/Documents/Unique` provides:
1. **Secret & PII Detection:** `agentguard.detectors.secret_detector.SecretDetector` and `agentguard.detectors.pii_detector.PIIDetector` (regex-based scanning with context classification).
2. **Ephemeral Token Reference Store:** `agentguard.engine.token_store.SecretReferenceStore` binds `{{SECRET_XXX_nonce}}` tokens to `(session_id, canonical_file_path, bound_key, raw_secret_value)` in-memory.
3. **Anti-TOCTOU Protection:** `token_store.store_file_read_hash` and `get_file_read_hash` tracks SHA-256 hashes of files at read time. In `FileInterceptor.intercept_write()`, writes are rejected if file contents on disk changed between read and write.
4. **Atomic Reconstruction:** `agentguard.engine.reconstruction.ReconstructionEngine` parses written file diffs/contents, verifies tokens against caller file paths, and atomically swaps tokens back to raw credentials on disk while checking for tampering or mangled tokens.
5. **Outbound Sanitization:** `agentguard.interceptors.outbound_interceptor.OutboundInterceptor` catches raw secrets before transmission and replaces them with masked placeholders.
6. **Integrations:** OpenCode bridge (`agentguard.integrations.opencode_bridge`) and Claude Code MCP/hooks (`agentguard.claude.pre_tool_use_hook`).

### 2. What GuardX Reuses
- [`extractors.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/lineage/extractors.py) conditionally imports `AgentGuardSecretDetector` and `AgentGuardPIIDetector` via dynamic import:
  ```python
  try:
      from agentguard.detectors.secret_detector import SecretDetector as AgentGuardSecretDetector
      from agentguard.detectors.pii_detector import PIIDetector as AgentGuardPIIDetector
      HAS_AGENTGUARD_DETECTORS = True
  except ImportError:
      HAS_AGENTGUARD_DETECTORS = False
  ```
- [`opencode_adapter.py`](file:///Users/neerajkahal/Documents/Tool/src/guardx/adapters/opencode_adapter.py) imports `FileInterceptor` and `canonicalize_path` to preserve AgentGuard's tokenized file reading while emitting GuardX execution provenance events (`TOOL_CALL`, `FILE_READ`, `TOOL_RESULT`).
- `tests/conftest.py` imports `global_token_store` and registers an autouse cleanup fixture.

### 3. What Remains Separate
- GuardX maintains its own `SensitiveContentScanner` in `core/sanitizer.py` so that it operates standalone without hard external package dependencies.
- GuardX creates its own `DataEntity` instances with keyed HMAC fingerprints and does not store plaintext secrets inside `DataEntity`.
- AgentGuard's `token_store` maintains the raw plaintext in a private dictionary specifically to allow `ReconstructionEngine` to write secrets back to disk. GuardX Layer 1–3 components never hold raw plaintext in memory structures.

---

## H. Groq Test Agent Harness & Sandbox Confinement

**Location:** `examples/groq_agent/`

The Groq demo agent is an independent test harness designed to generate real autonomous agent actions for GuardX to observe.

### 1. Architecture & Design
- **Core Separation:** The demo agent is intentionally placed under `examples/groq_agent/` and does not introduce Groq SDK dependencies into `guardx.core`.
- **Instrumentation:** The agent wires directly to GuardX collectors:
  - `llm_collector` observes `LLM_REQUEST` and `LLM_RESPONSE` for each Groq API interaction.
  - `tool_collector` wraps tool dispatch in `tool:list_files`, `tool:read_file`, `tool:write_file` execution scopes.
  - `file_collector` captures `FILE_READ` and `FILE_WRITE` operations.
- **Hierarchical Scopes:**
  ```
  agent_task (Root Scope)
     ├── llm_round_1
     │      └── tool:list_files
     ├── llm_round_2
     │      └── tool:read_file
     └── llm_round_3
            └── tool:write_file
  ```
- **Max Rounds Guard:** Hard limit of `MAX_TOOL_ROUNDS = 10` prevents infinite LLM tool-calling loops.

### 2. Sandbox Confinement & Secret Isolation
- [`sandbox.py`](file:///Users/neerajkahal/Documents/Tool/examples/groq_agent/sandbox.py) enforces strict path confinement to `examples/groq_agent/workspace/`:
  - Traversal attempts (`..`) are rejected upfront with `SandboxSecurityError`.
  - Absolute paths outside the workspace root are rejected with `SandboxSecurityError`.
  - Symlinks pointing outside the workspace are detected and rejected.
- **Critical Isolation Invariant:** The root project `.env` (which contains the real `GROQ_API_KEY`) is located at `/Users/neerajkahal/Documents/Tool/.env`. The agent workspace is at `/Users/neerajkahal/Documents/Tool/examples/groq_agent/workspace/`. The agent cannot access the root `.env`. The workspace has its own synthetic `.env` containing only fake demo credentials (`DEMO_API_KEY=guardx-demo-not-real`).
- `load_project_groq_api_key()` reads `GROQ_API_KEY` for API authentication only; the key is never logged, printed, sent to collectors, or included in event payloads.

---

## I. Execution Graph Architecture

**Location:** `src/guardx/graph/`

Layer 1 models the physical and logical actions taken by actors across resources.

```
                      ┌──────────────┐
                      │  USER Node   │
                      └──────┬───────┘
                             │ INVOKED
                             ▼
                      ┌──────────────┐
       ┌─────────────►│  AGENT Node  │◄─────────────┐
       │              └──────┬───────┘              │
       │ RETURNED_TO         │                      │ RETURNED_TO
       │                     │ INVOKED              │
┌──────┴──────┐              ▼               ┌──────┴──────┐
│  LLM Node   │       ┌──────────────┐       │  TOOL Node  │
└──────┬──────┘       │  TOOL Node   │       └──────┬──────┘
       ▲              └──────┬───────┘              │
       │ SENT_TO             │ READ_FROM            │ WROTE_TO
┌──────┴──────┐              ▼                      ▼
│  AGENT Node │       ┌──────────────┐       ┌──────────────┐
└─────────────┘       │  FILE Node   │       │  FILE Node   │
                      │   (Source)   │       │(Destination) │
                      └──────────────┘       └──────────────┘
```

### Supported Entities & Relations
- **Node Types:** `USER`, `AGENT`, `TOOL`, `FILE`, `PROCESS`, `NETWORK_ENDPOINT`, `LLM`, `EXECUTION_SCOPE`.
- **Edge Types:**
  - `INVOKED`: Agent calls Tool, or Parent Scope invokes Child Scope.
  - `READ_FROM`: Tool or Agent reads from a File or resource.
  - `WROTE_TO`: Tool writes to a File or resource.
  - `SPAWNED`: Tool executes a child Process.
  - `SENT_TO`: Agent transmits request to an LLM or Network Endpoint.
  - `RECEIVED_FROM`: Tool/Agent receives response from Network Endpoint.
  - `RETURNED_TO`: Tool or LLM returns output/completion to Agent.
  - `CAUSED_BY`: Explicit causal link between events.
  - `BELONGS_TO_SCOPE`: Links execution nodes to their parent `EXECUTION_SCOPE`.

---

## J. Sensitive Data Lineage Architecture

**Location:** `src/guardx/lineage/`

Layer 2 tracks the propagation, identity, and transformation of fine-grained information.

```
┌──────────────┐        CONTAINS         ┌──────────────┐
│  FILE Node   │────────────────────────►│  DATA_ENTITY │
│ (e.g. .env)  │                         │ (RAW Cred)   │
└──────────────┘                         └──────┬───────┘
                                                │
                          ┌─────────────────────┴─────────────────────┐
                          │                                           │ TRANSFORMED_TO
                          │ FLOWS_TO                                  ▼ (TOKENIZE)
                          ▼                                    ┌──────────────┐
                   ┌──────────────┐                            │  DATA_ENTITY │
                   │ DATA_CARRIER │                            │  (TOKENIZED) │
                   │(FILE_CONTENT)│                            └──────┬───────┘
                   └──────┬───────┘                                   │ FLOWS_TO
                          │ FLOWS_TO                                  ▼
                          ▼                                    ┌──────────────┐
                   ┌──────────────┐        FLOWS_TO            │ DATA_CARRIER │
                   │ DATA_CARRIER │───────────────────────────►│ (LLM_REQUEST)│
                   │(TOOL_RESULT) │                            └──────┬───────┘
                   └──────────────┘                                   │ FLOWS_TO
                                                                      ▼
                                                               ┌──────────────┐
                                                               │   LLM Node   │
                                                               │  (Groq/Sink) │
                                                               └──────────────┘
```

### Propagation & Matching Algorithms
Lineage edges are established via concrete evidence matching:
1. **TOKEN_IDENTITY:** Direct string search for synthetic vault tokens (`{{SECRET_...}}`, `[MASKED_...]`).
2. **HMAC_MATCH:** Keyed HMAC-SHA256 fingerprint matching against candidate string tokens.
3. **STRUCTURED_PROPAGATION:** Explicit dictionary and carrier propagation across tool boundaries.
4. **TRANSFORMATION_MATCH:** Deterministic input-to-output mapping through `TransformationEngine`.

---

## K. Security Intelligence Architecture

**Location:** `src/guardx/trust/`, `src/guardx/risk/`, `src/guardx/intent/`, `src/guardx/chains/`

Layer 3 provides explainable threat detection over the proven evidence.

### 1. Risk Evaluation Matrix
The deterministic risk rules enforce the following behavior:

| Entity Classification | Representation | Destination Trust | Severity | Finding Category / Rule |
| :--- | :--- | :--- | :--- | :--- |
| `CREDENTIAL` / `SECRET` | `RAW` | `UNTRUSTED_EXTERNAL` | **CRITICAL** | `CREDENTIAL_EXFILTRATION` / `RULE_CREDENTIAL_RAW_TO_UNTRUSTED` |
| `CREDENTIAL` / `SECRET` | `RAW` | `EXTERNAL_LLM` | **HIGH** | `CREDENTIAL_DISCLOSURE` / `RULE_CREDENTIAL_RAW_TO_EXTERNAL_LLM` |
| `CREDENTIAL` / `SECRET` | `ENCODED` (Base64/URL) | `EXTERNAL_LLM` / `UNTRUSTED` | **HIGH** | `ENCODED_SECRET_DISCLOSURE` / `RULE_CREDENTIAL_ENCODED_TO_EXTERNAL` |
| `CREDENTIAL` / `SECRET` | `TOKENIZED` / `REDACTED` | `EXTERNAL_LLM` | **LOW / INFO** | `INFORMATIONAL` / `RULE_CREDENTIAL_TOKENIZED_TO_EXTERNAL_LLM` |
| `PII` | `RAW` / `ENCODED` | `UNTRUSTED_EXTERNAL` | **HIGH** | `PII_EXFILTRATION` / `RULE_PII_TO_UNTRUSTED` |
| `PII` | `RAW` / `ENCODED` | `EXTERNAL_LLM` | **MEDIUM** | `PII_DISCLOSURE` / `RULE_PII_TO_EXTERNAL_LLM` |
| `PUBLIC` | Any | `EXTERNAL_LLM` / Any | **NONE** | *Zero findings produced* |
| Any | Any | Any (No Proven Flow) | **NONE** | *Zero findings produced (Negative Flow Invariant)* |

### 2. Intent Conformance vs. Data Disclosure Findings
It is critical to distinguish between Intent Violations and Data Disclosure Findings:
- **Intent Violations (`INTENT_VIOLATION`):** Detect behavioral deviations from declared task parameters (e.g., agent declared scope for `config.py` only, but executed `FILE_READ .env`, or executed undeclared `NETWORK_REQUEST`). These are generated *regardless of whether sensitive data flowed*.
- **Data Disclosure Findings (`CREDENTIAL_DISCLOSURE`, `CREDENTIAL_EXFILTRATION`):** Detect actual movement of sensitive information across trust boundaries. These require verified M3 lineage proof.

---

## L. Investigation GUI & Frontend Lens Architecture

**Location:** `web/`

The frontend console is built with Vanilla JavaScript, Cytoscape.js, HTML5, and CSS3.

### 1. The Three Distinct Lenses
The UI enforces strict separation between three analytical viewpoints:
1. **Execution Provenance Lens (`[ Execution ]`):**
   - Answers: *"What did the agent do?"*
   - Visualizes physical entities: User, Agent, Tool, File, Process, Network Endpoint, LLM.
   - Directed edges: `INVOKED`, `READ_FROM`, `WROTE_TO`, `SPAWNED`, `SENT_TO`, `RECEIVED_FROM`.
2. **Sensitive Data Lineage Lens (`[ Data Flow ]`):**
   - Answers: *"What information actually moved, and where did it originate?"*
   - Visualizes: `DataEntity` (color-coded by representation state: Green for RAW, Cyan for TOKENIZED, Purple for ENCODED) and `DataCarrier` containers.
   - Directed edges: `CONTAINS`, `FLOWS_TO`, `TRANSFORMED_TO`.
3. **Security Intelligence Lens (`[ Security ]`):**
   - Answers: *"Why is this behavior dangerous, and what evidence proves it?"*
   - Visualizes: The active risk path hops from source origin to external sink, highlighting trust boundary crossings. Displays alerts, finding cards, and risk badges.

### 2. Graph Stability Governance
The frontend strictly prevents graph instability during live WebSocket streaming:
- **No Layout on Incremental Events:** Incoming `node.created` and `edge.created` messages do **NOT** re-run Dagre layout. Existing node positions remain locked.
- **Incremental Placement:** New nodes receive deterministic placement based on connected source nodes or tiered Y coordinates via `computeIncrementalPosition()`.
- **Explicit Layout Controls:** Full hierarchical Dagre layout only executes on initial `session.snapshot` or when the user clicks the explicit **Re-layout** button.
- **Independent Viewport:** The **Fit View** button adjusts zoom/pan to fit elements without modifying node positions.
- **Visual Pulse:** New nodes receive a temporary neon pulse class (`new-node-pulse`) that auto-cleans after 2.5 seconds.
- **Scope Node Filtering:** `EXECUTION_SCOPE` nodes are filtered from the primary DAG canvas by default and displayed in the hierarchical **Scope Tree** panel, with an optional toggle to show them on canvas.

---

## M. Security Invariants & Enforcement Locations

GuardX enforces 7 core architectural invariants:

| Invariant | Description | Enforcement Location |
| :--- | :--- | :--- |
| **INV-001** | **Zero Raw Secrets in Persistent Events:** Payload strings and dictionaries must not contain unmasked secrets or PII. | [`invariants.py:47`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/invariants.py#L47), [`sanitizer.py:144`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/sanitizer.py#L144), [`recorder.py:187`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/recorder.py#L187) |
| **INV-002** | **Append-Only Immutability:** Event instances and core records are immutable dataclasses (`frozen=True`). | [`models.py:76`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/models.py#L76), [`invariants.py:24`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/invariants.py#L24) |
| **INV-003** | **Strict Sequence Monotonicity:** Session event sequences are strictly monotonic integers ($S_{n+1} = S_n + 1$). | [`invariants.py:54`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/invariants.py#L54), [`recorder.py:199`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/recorder.py#L199) |
| **INV-004** | **Scope Attribution:** All operational events (`TOOL_CALL`, `FILE_READ`, etc.) must carry an active `execution_scope_id`. | [`invariants.py:61`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/invariants.py#L61), [`recorder.py:174`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/recorder.py#L174) |
| **INV-005** | **Causal Integrity:** If `causal_event_id` is specified, it must exist in prior session history ($seq_{causal} < seq_{current}$). | [`invariants.py:68`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/invariants.py#L68) |
| **INV-006** | **Keyed HMAC Fingerprints:** Sensitive entity matching must use session-keyed HMAC-SHA256, never raw secrets or unsalted hashes. | [`crypto.py:18`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/crypto.py#L18), [`extractors.py:104`](file:///Users/neerajkahal/Documents/Tool/src/guardx/lineage/extractors.py#L104) |
| **INV-007** | **Resolver Idempotency:** Identical paths, symlinks, or endpoints resolve to canonical identical `resource_id`s. | [`resolvers.py:20`](file:///Users/neerajkahal/Documents/Tool/src/guardx/core/resolvers.py#L20) |
| **NEGATIVE-FLOW** | **Strict Proven Flow Invariant:** Temporal proximity does not imply data flow. Zero disclosure findings without verified M3 lineage path. | [`engine.py:460`](file:///Users/neerajkahal/Documents/Tool/src/guardx/lineage/engine.py#L460), [`risk/engine.py:72`](file:///Users/neerajkahal/Documents/Tool/src/guardx/risk/engine.py#L72) |

---

## N. API Contracts & Serialization Schemas

### 1. REST Endpoints
- `GET /api/sessions` — List all registered sessions with event and node counts.
- `GET /api/sessions/{session_id}` — Session metadata and execution stats.
- `GET /api/sessions/{session_id}/events` — Ordered list of GuardXEvents (supports `limit`, `offset`).
- `GET /api/sessions/{session_id}/graph` — Full Execution Provenance DAG JSON.
- `GET /api/sessions/{session_id}/scopes` — Active and completed ExecutionScopes.
- `GET /api/events/{event_id}` — Single event lookup by ID.
- `GET /api/nodes/{node_id:path}` — Single graph node lookup with incoming/outgoing edges.
- `GET /api/sessions/{session_id}/lineage` — Full Data Lineage snapshot (nodes, edges, entities, carriers, transformations).
- `GET /api/sessions/{session_id}/lineage/entities` — List of all tracked `DataEntity` instances.
- `GET /api/sessions/{session_id}/lineage/trace/forward/{entity_id:path}` — Forward BFS information trace.
- `GET /api/sessions/{session_id}/lineage/trace/backward/{target_id:path}` — Backward BFS origin trace.
- `GET /api/sessions/{session_id}/security` — Full Layer 3 security intelligence snapshot.
- `GET /api/sessions/{session_id}/security/findings` — List of all `SecurityFinding`s.
- `GET /api/sessions/{session_id}/security/findings/{finding_id}` — Single finding details and hop path.
- `GET /api/sessions/{session_id}/security/trust-boundaries` — Detected trust boundary crossings.
- `GET /api/sessions/{session_id}/security/attack-chains` — Synthesized multi-event attack chains.
- `GET /api/sessions/{session_id}/security/intent-violations` — Intent conformance violations.
- `POST /api/sessions/{session_id}/demo/run_security_experiment` — Runs M4 experiments (`a`, `b`, `c`, `d`, `e`).
- `POST /api/sessions/{session_id}/demo/run_lineage_experiment` — Runs M3 experiments (`positive`, `negative`, `transformation`).
- `POST /api/sessions/{session_id}/demo/opencode_step` — Steps through OpenCode demo scenario (`step=1,2,3`).
- `POST /api/sessions/{session_id}/demo/run_groq_agent` — Dispatches Groq demo agent with user prompt.

### 2. WebSocket Protocol (`/ws/sessions/{session_id}`)
- **Client -> Server:**
  - `"ping"` -> Server responds `"pong"`.
- **Server -> Client (Outbound Frames):**
  - `session.snapshot`: Full snapshot on connection (`events`, `nodes`, `edges`, `lineage`, `security`).
  - `event.created`: Incremental new `GuardXEvent`.
  - `node.created`: Incremental new `GraphNode`.
  - `edge.created`: Incremental new `GraphEdge`.
  - `scope.started`: `ExecutionScope` initialized.
  - `scope.ended`: `ExecutionScope` closed with duration and status.
  - `entity.created`: New `DataEntity` registered.
  - `carrier.created`: New `DataCarrier` registered.
  - `flow.created`: New `LineageEdge` registered.
  - `transformation.created`: New `Transformation` recorded.
  - `trust_boundary.crossed`: New `TrustBoundaryCrossing` detected.
  - `risk.detected`: New `SecurityFinding` generated.
  - `intent.violation`: New `IntentViolation` detected.
  - `attack_chain.detected`: New `AttackChain` synthesized.

---

## O. Complete Test Coverage Matrix

| Capability / Subsystem | Implementation Files | Test Files | Tests |
| :--- | :--- | :--- | :--- |
| **Domain Enums & Models** | `core/enums.py`, `core/models.py` | `tests/unit/test_enums_and_models.py` | 3 |
| **Invariant Enforcement** | `core/invariants.py` | `tests/unit/test_invariants.py` | 4 |
| **Crypto & HMAC Fingerprinting** | `core/crypto.py` | `tests/unit/test_crypto_fingerprints.py` | 3 |
| **Sanitizer & Masking Boundary** | `core/sanitizer.py` | `tests/unit/test_sanitizer_boundary.py` | 2 |
| **Identity Resolvers** | `core/resolvers.py` | `tests/unit/test_resolvers.py` | 3 |
| **Scope Propagation & Context** | `core/context.py` | `tests/unit/test_context_scope_manager.py`, `test_nested_execution_scopes.py` | 5 |
| **Event Sequencer & Recorder** | `core/recorder.py` | `tests/unit/test_event_recorder_sequencing.py` | 3 |
| **Collectors (Tool/File/Proc/Net/LLM)** | `collectors/*.py` | `tests/unit/test_collectors.py` | 5 |
| **Provenance Graph & Store** | `graph/models.py`, `graph/store.py` | `tests/unit/test_provenance_graph.py` | 2 |
| **Causal DAG Queries** | `graph/engine.py` | `tests/unit/test_causal_dag_queries.py` | 1 |
| **Graph CLI & Formatter** | `graph/formatter.py`, `cli/inspect.py`| `tests/unit/test_graph_formatter_cli.py` | 1 |
| **OpenCode Reference Adapter** | `adapters/opencode_adapter.py` | `tests/unit/test_opencode_adapter.py` | 1 |
| **Groq Demo Agent & Sandbox** | `examples/groq_agent/*.py` | `tests/unit/test_groq_agent.py`, `tests/e2e/test_groq_agent_e2e.py` | 11 + 2 |
| **FastAPI REST API Contract** | `server/app.py`, `server/session_registry.py` | `tests/unit/test_server_api.py` | 8 |
| **WebSocket Streaming** | `server/broadcaster.py` | `tests/unit/test_websocket_streaming.py` | 7 |
| **Forward-Compatible Lineage Models** | `lineage/models.py` | `tests/unit/test_forward_compatible_lineage.py` | 2 |
| **Lineage Store & Forward/Backward Trace** | `lineage/store.py` | `tests/unit/test_data_lineage_store.py` | 4 |
| **DataFlowEngine & Negative Flow** | `lineage/engine.py`, `lineage/extractors.py` | `tests/unit/test_data_flow_engine.py` | 2 |
| **Deterministic Transformations** | `lineage/transformations.py` | `tests/unit/test_transformations.py` | 2 |
| **Trust Boundary & Resolver** | `trust/resolver.py`, `trust/engine.py` | `tests/unit/test_trust_boundary.py` | 2 |
| **Deterministic Risk Rules (M4)** | `risk/rules.py`, `risk/engine.py` | `tests/unit/test_risk_rules.py` | 8 |
| **Intent Conformance Engine (M4)** | `intent/models.py`, `intent/engine.py` | `tests/unit/test_intent_conformance.py` | 3 |
| **Attack Chain Detector (M4)** | `chains/models.py`, `chains/detector.py` | `tests/unit/test_attack_chains.py` | 3 |
| **Phase 2 E2E Provenance Pipeline** | Full M2 stack | `tests/e2e/test_phase2_end_to_end_provenance.py` | 1 |
| **Milestone 2 E2E Live Investigation** | Full M2 stack | `tests/e2e/test_milestone2_live_investigation.py` | 1 |
| **Milestone 3 E2E Lineage Flow** | Full M3 stack | `tests/e2e/test_milestone3_data_flow_e2e.py` | 4 |
| **Milestone 4 E2E Security Intelligence** | Full M4 stack | `tests/e2e/test_milestone4_security_intelligence_e2e.py` | 6 |
| **Frontend Visual, Lens & Stability** | `web/app.js` | `tests/frontend/test_frontend.test.mjs` | 22 |
| **AgentGuard Regression Suite** | Baseline `/Users/neerajkahal/Documents/Unique` | `/Users/neerajkahal/Documents/Unique/tests/` | 32 |

---

## P. Current Test Results

All test suites were executed cleanly without test modification:

### 1. GuardX Python Test Suite
- **Command:** `PYTHONPATH=.:src /Users/neerajkahal/Documents/Unique/.venv/bin/pytest tests/ -v`
- **Collected:** 102 tests
- **Passed:** 102 tests (100%)
- **Failed:** 0
- **Skipped:** 0
- **Warnings:** 1 (StarletteDeprecationWarning regarding httpx in testclient)
- **Execution Time:** 13.31s

### 2. GuardX Frontend Test Suite
- **Command:** `node --test tests/frontend/test_frontend.test.mjs`
- **Collected:** 22 tests
- **Passed:** 22 tests (100%)
- **Failed:** 0
- **Execution Time:** 98.18ms

### 3. AgentGuard Regression Test Suite
- **Command:** `PYTHONPATH=/Users/neerajkahal/Documents/Unique/src /Users/neerajkahal/Documents/Unique/.venv/bin/pytest /Users/neerajkahal/Documents/Unique/tests -v`
- **Collected:** 32 tests
- **Passed:** 32 tests (100%)
- **Failed:** 0
- **Warnings:** 1 (StarletteDeprecationWarning)
- **Execution Time:** 1.67s

### **Total Verification:** 156 passed tests across all suites with 0 failures.

---

## Q. Technical Debt & Architectural Fragilities

Prior to beginning Milestone 5, the following technical debt and architectural risks were identified:

### 1. CRITICAL BEFORE M5 (Must address during M5 design)
1. **Collectors are Observational, Not Interceptive:** All collectors currently observe events *after* or *as* they execute (`record_tool_call`, `record_file_read`, `record_process_exec`). To enforce `BLOCK` or `MODIFY`, there must be an explicit pre-execution interception gateway that pauses execution before side effects occur.
2. **Missing Synchronous Policy Interception Hook in `AgentToolExecutor`:** In `examples/groq_agent/tools.py`, `AgentToolExecutor.execute_tool()` invokes the real filesystem read/write immediately after calling `self.tool_collector.record_tool_call()`. There is no gateway hook to cancel or mutate the tool arguments before filesystem/network dispatch.
3. **Execution Projections vs. Prospective Actions:** Currently, `ScopeProjection` and `RawObservation` assume that the action will execute. A formal `ProspectiveAction` abstraction is needed to evaluate risk *prior* to creating operational provenance records.

### 2. SHOULD FIX (Important architectural improvements)
1. **In-Memory Store Scaling:** `InMemoryGraphStore`, `DataLineageStore`, and `SecurityOverlayStore` keep all session history in memory dictionaries. For very long-running agent tasks (thousands of tool calls), this will grow unboundedly. A persistent storage backend (e.g. SQLite) should be introduced.
2. **`session_registry.py` In-Memory Reset in Demo Endpoints:** In `server/app.py`, demo experiment runners manually reset engine state by clearing dictionaries on `ctx.risk_path_engine` and `ctx.data_flow_engine`. This should be encapsulated in a clean `reset_session()` method on `SessionContext`.
3. **`test_groq_agent_e2e.py` `PYTHONPATH` dependency:** When running pytest with `PYTHONPATH=src`, importing `examples.groq_agent` failed because `examples` is in project root. The command must use `PYTHONPATH=.:src`. Adding `__init__.py` to root or configuring `pyproject.toml`/`pytest.ini` `pythonpath = ["src", "."]` will prevent this developer friction.

### 3. CAN DEFER TO M6 (Post-Enforcement Enhancements)
1. **Kernel-Level Syscall Telemetry (eBPF):** Process and network collectors currently rely on application-level Python hooks. Unmonitored subprocesses spawned by arbitrary shell scripts bypass application hooks. Pluggable eBPF telemetry is planned for M6.
2. **Dynamic Policy Hot-Reloading:** Policies are currently defined as Python code structures. A declarative YAML policy loader with hot-reloading can be refined in M6.

---

## R. Milestone 5 Readiness & Interception Gap Analysis

Milestone 5 will introduce **Policy Enforcement & Runtime Interception** with the long-term target architecture:
$$\text{AI Agent} \longrightarrow \text{Proposed Action} \longrightarrow \text{Prospective Analysis} \longrightarrow \text{Policy Engine} \longrightarrow \text{Enforcement Gateway} \longrightarrow \{\text{ALLOW}, \text{MODIFY}, \text{BLOCK}, \text{HUMAN\_REVIEW}\} \longrightarrow \text{Runtime Effect}$$

### Answering Core Architectural Questions for M5:

#### 1. Where should interception occur?
Interception must occur at the boundary between the **Agent Reasoning Loop** and the **Tool/Resource Execution Gateway**. Specifically:
- **Pre-Tool-Execution:** Inside `AgentToolExecutor.execute_tool()` before calling `_read_file`, `_write_file`, or `subprocess.run`.
- **Pre-LLM-Egress:** Inside `GroqAgent._call_groq()` or outbound HTTP middleware before dispatching messages over TLS to remote model endpoints.
- **Pre-Filesystem-Mutation:** Inside `FileCollector`/`FileInterceptor` before calling `open(..., 'w')` or `write_text()`.

#### 2. Which current collectors observe AFTER execution versus BEFORE execution?
- `ToolCollector.record_tool_call()` is called **before** execution, but does not have a return value that halts the caller.
- `ToolCollector.record_tool_result()` is called **after** execution.
- `FileCollector.record_file_read()` is called **after** `safe_file.read_text()` has already completed.
- `FileCollector.record_file_write()` is called **after** `safe_file.write_text()` has already written bytes to disk.
- `ProcessCollector.record_process_exec()` is called **after** process spawn has occurred (it requires an existing `pid`).
- `NetworkCollector.record_request()` is called **after** HTTP headers/URL have been assembled.

**Conclusion:** All current collectors are *observational recording agents*. For M5, we must introduce a **Prospective Gateway** that intercepts the action *before* the collector records execution facts.

#### 3. Which actions can currently be prevented?
Currently, **NO** actions can be prevented by GuardX core because collectors only record occurrences after they happen. The only exception is inside the demo sandbox `WorkspaceSandbox.resolve_safe_path()`, which raises `SandboxSecurityError` if path traversal is attempted. GuardX must add a formal `EnforcementGateway` to intercept actions before dispatch.

#### 4. Which components must be adapted for prospective actions?
- Introduce `ProspectiveAction` domain model containing proposed operation, actor, target resource, arguments, and active scope.
- Introduce `PolicyEngine` evaluating `ProspectiveAction` against Layer 3 security intelligence (intent contracts, trust boundaries, risk path prediction) to yield an immutable `EnforcementDecision`.
- Adapt `AgentToolExecutor` and `OpenCodeGuardXAdapter` to call `EnforcementGateway.intercept(action)` before executing underlying methods.

#### 5. How can AgentGuard tokenization be reused?
AgentGuard's `SecretReferenceStore` and `FileInterceptor` already implement the exact `MODIFY` pattern required:
- When a file read accesses sensitive credentials, AgentGuard tokenizes them into ephemeral references (`{{SECRET_001_nonce}}`).
- The agent reasoning loop receives only tokens.
- When the agent writes the file back, `ReconstructionEngine` validates the token mapping and reconstructs the real secret on disk.
- In M5, `EnforcementGateway` will issue a `DecisionType.MODIFY` decision for read actions, delegating the tokenization to AgentGuard's token vault.

#### 6. How should decisions bind cryptographically to exact proposed actions?
Every `ProspectiveAction` will compute an action digest:
$$\text{ActionHash} = \text{HMAC-SHA256}(\text{action\_type} \parallel \text{actor\_id} \parallel \text{target\_uri} \parallel \text{canonical\_args}, \text{session\_key})$$
The resulting `EnforcementDecision` will embed `action_hash`. When the gateway allows or modifies the action, it verifies that the executed parameters match the signed `action_hash`, completely preventing post-decision parameter tampering.

#### 7. How do we guarantee BLOCK means zero side effects?
If the decision is `BLOCK`:
1. The `EnforcementGateway` immediately halts execution and raises `ActionBlockedException` or returns an error result payload to the agent context.
2. The underlying tool method (e.g. `_write_file`, `subprocess.run`, `requests.post`) is **never called**.
3. Zero filesystem bytes are modified, zero network packets are sent, zero processes are spawned.
4. An immutable `DECISION` event (`decision: BLOCK`) is recorded in provenance, but zero `FILE_WRITE` or `NETWORK_REQUEST` events are generated.

#### 8. How do we guarantee MODIFY means the original unsafe action never executes?
When a decision is `MODIFY`:
1. The gateway substitutes the unsafe raw arguments with a sanitized or tokenized alternative provided by the policy.
2. The original raw arguments are purged from the execution frame.
3. Only the modified safe action executes.
4. The event record captures `original_hash`, `modified_payload`, and `decision_id`.

#### 9. How should HUMAN_REVIEW pause execution?
1. The gateway places the `ProspectiveAction` into a thread-safe `HumanReviewQueue` in `SessionContext`.
2. The executing agent thread waits on a `threading.Event` or `asyncio.Future` associated with the action ID, with a configurable timeout.
3. The server broadcasts a `review.required` WebSocket event to the Investigation Console.
4. The reviewer reviews the action in a new Review Modal and clicks **Approve** or **Reject**.
5. The REST API resolves the future, unblocking the agent thread with `ALLOW` or `BLOCK`.

#### 10. How should actual observed effects be compared with proposed effects?
Post-execution verification:
1. When an action completes, its observed event (`FILE_WRITE`, `TOOL_RESULT`) is linked back to the originating `ProspectiveAction` via `prospective_action_id`.
2. A post-execution verifier checks for discrepancies (e.g., action was allowed for writing 50 bytes to `file.txt`, but 50,000 bytes were written, or a child process was spawned).
3. If an unauthorized discrepancy is discovered, an immediate `POLICY_VIOLATION` event is emitted.

---

## S. Recommended Milestone 5 Architecture Specification

### 1. New Core Models (`guardx/enforcement/models.py`)
```python
class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    MODIFY = "MODIFY"
    BLOCK = "BLOCK"
    HUMAN_REVIEW = "HUMAN_REVIEW"

@dataclass(frozen=True)
class ProspectiveAction:
    action_id: str
    session_id: str
    execution_scope_id: str
    actor_id: str
    action_type: str            # "TOOL_CALL", "FILE_READ", "FILE_WRITE", "NETWORK_REQUEST", "PROCESS_EXEC"
    target_resource_raw: str
    proposed_payload: Dict[str, Any]
    action_hash: str            # Keyed HMAC digest of action parameters
    timestamp: datetime

@dataclass(frozen=True)
class EnforcementDecision:
    decision_id: str
    action_id: str
    action_hash: str
    decision: DecisionType
    reason: str
    policy_rule_id: str
    modified_payload: Optional[Dict[str, Any]] = None
    required_review_id: Optional[str] = None
    timestamp: datetime
```

### 2. Enforcement Gateway (`guardx/enforcement/gateway.py`)
The `EnforcementGateway` sits in front of all tool and execution dispatches:
```python
class EnforcementGateway:
    def __init__(self, policy_engine: PolicyEngine, review_queue: HumanReviewQueue):
        self.policy_engine = policy_engine
        self.review_queue = review_queue

    def evaluate_and_intercept(self, action: ProspectiveAction) -> EnforcementDecision:
        decision = self.policy_engine.evaluate(action)
        
        if decision.decision == DecisionType.HUMAN_REVIEW:
            decision = self.review_queue.await_review(action, decision)
            
        if decision.decision == DecisionType.BLOCK:
            raise ActionBlockedException(decision.reason)
            
        return decision
```

---

## T. Milestone 5 Implementation Phasing Order

To ensure zero regressions of existing M1–M4 functionality and maintain 100% test pass rates throughout development, Milestone 5 should be implemented in 6 incremental phases:

1. **Phase 5.1 — Core Enforcement Models & Enums:**
   - Create `src/guardx/enforcement/` package.
   - Define `DecisionType`, `ProspectiveAction`, `EnforcementDecision`, and `ActionBlockedException`.
   - Implement action hashing utility (`compute_action_hash`).
   - Add unit tests for action immutability and cryptographic hashing.

2. **Phase 5.2 — Declarative Policy Engine:**
   - Implement `PolicyEngine` supporting deterministic rule sets.
   - Wire Layer 3 security intelligence: intent contract conformance checks, trust boundary checks, and proactive data leakage rules.
   - Support `ALLOW`, `MODIFY` (tokenization), and `BLOCK` decision synthesis.
   - Add unit tests validating policy evaluation under diverse security contexts.

3. **Phase 5.3 — Inline Enforcement Gateway & TOCTOU Protection:**
   - Implement `EnforcementGateway` managing interception lifecycle.
   - Integrate with AgentGuard `SecretReferenceStore` for `MODIFY` token replacement and file read hash tracking (anti-TOCTOU).
   - Verify fail-closed guarantee: `BLOCK` raises an exception before any side effect occurs.

4. **Phase 5.4 — Adapter & Tool Executor Integration:**
   - Adapt `AgentToolExecutor` in `examples/groq_agent/tools.py` to route through `EnforcementGateway`.
   - Adapt `OpenCodeGuardXAdapter` to route through `EnforcementGateway`.
   - Implement post-execution verification comparing proposed action hashes against observed events.
   - Add e2e tests verifying that blocked file writes and network requests leave zero side effects on disk or sockets.

5. **Phase 5.5 — Human Review Queue & Live Server Integration:**
   - Implement `HumanReviewQueue` with async futures and configurable review timeout.
   - Add REST endpoints: `GET /api/sessions/{session_id}/reviews` and `POST /api/reviews/{review_id}/decide`.
   - Emit `review.required` WebSocket frames to the frontend.
   - Add unit and e2e tests for human approval and rejection workflows.

6. **Phase 5.6 — Investigation Console Enforcement UI:**
   - Add **Enforcement Lens** or Review Queue panel to the web interface.
   - Implement interactive review modal with action details, risk explanation, **Approve (ALLOW)**, and **Reject (BLOCK)** buttons.
   - Add visual badge indicators for `INTERCEPTED`, `BLOCKED`, and `MODIFIED` scopes on the DAG canvas.
   - Add Node.js frontend tests verifying review card rendering and user action dispatch.

---

*Report prepared and verified for GuardX Development Handoff.*
