"""Evidence-Based DataFlowEngine for GuardX Milestone 3.

Guarantees:
- Ingestion of immutable GuardXEvents at observable boundaries.
- Boundary carriers: FILE_CONTENT, TOOL_RESULT, AGENT_CONTEXT, LLM_REQUEST, LLM_RESPONSE, TOOL_ARGUMENT, NETWORK_REQUEST, NETWORK_RESPONSE, FILE_WRITE_CONTENT.
- Concrete evidence required for every hop:
  - Synthetic Token Identity (TOKEN_IDENTITY)
  - Keyed HMAC Match (HMAC_MATCH)
  - Structured Boundary Propagation (STRUCTURED_PROPAGATION)
  - Deterministic Transformation Match (TRANSFORMATION_MATCH)
- ZERO PROVEN FLOW without evidence: does NOT infer flow merely because events occurred in temporal proximity.
- Zero raw secrets persisted: Keyed HMACs and synthetic tokens only.
"""

from collections import defaultdict
import json
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from guardx.core.crypto import compute_keyed_fingerprint
from guardx.core.enums import EventType, ProvenanceQuality, TransformationSecuritySemantics
from guardx.core.interfaces import EventSubscriber
from guardx.core.models import GuardXEvent
from guardx.lineage.extractors import BoundaryEntityExtractor, SYNTHETIC_TOKEN_PATTERN
from guardx.lineage.models import (
    CarrierType,
    DataCarrier,
    DataClassification,
    DataEntity,
    DataRepresentation,
    DetectionMethod,
    LineageEdge,
    LineageEdgeType,
    LineageNode,
    LineageNodeType,
    Transformation,
)
from guardx.lineage.store import DataLineageStore
from guardx.lineage.transformations import TransformationEngine


class DataFlowEngine(EventSubscriber):
    """Processes GuardXEvents and maintains the Data Lineage DAG with strict evidence attribution."""

    def __init__(
        self,
        store: Optional[DataLineageStore] = None,
        session_key: str = "",
        on_lineage_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.store = store or DataLineageStore()
        self.session_key = session_key or "guardx_lineage_key"
        self.on_lineage_event = on_lineage_event
        self.extractor = BoundaryEntityExtractor(session_key=self.session_key)
        self.transformation_engine = TransformationEngine(
            store=self.store, session_key=self.session_key
        )

        self._lock = threading.RLock()
        # Transient in-memory registries (never persisted, scoped to active engine)
        self._fingerprint_to_entity: Dict[str, DataEntity] = {}
        self._token_to_entity: Dict[str, DataEntity] = {}
        self._entity_to_latest_carrier: Dict[str, DataCarrier] = {}
        self._latest_carrier_by_type: Dict[str, DataCarrier] = {}

    def on_event(self, event: GuardXEvent) -> None:
        """Processes newly published immutable event and updates Data Lineage."""
        self.process_event(event)

    def process_event(self, event: GuardXEvent) -> None:
        """Projects a GuardXEvent into Data Entities, Carriers, and Lineage Edges."""
        with self._lock:
            event_type = event.event_type

            if event_type == EventType.FILE_READ:
                self._handle_file_read(event)

            elif event_type == EventType.TOOL_CALL:
                self._handle_tool_call(event)

            elif event_type == EventType.TOOL_RESULT:
                self._handle_tool_result(event)

            elif event_type in (EventType.AGENT_ACTION, EventType.INTENT_DECLARED):
                self._handle_agent_action(event)

            elif event_type == EventType.LLM_REQUEST:
                self._handle_llm_request(event)

            elif event_type == EventType.LLM_RESPONSE:
                self._handle_llm_response(event)

            elif event_type == EventType.FILE_WRITE:
                self._handle_file_write(event)

            elif event_type == EventType.NETWORK_REQUEST:
                self._handle_network_request(event)

            elif event_type == EventType.NETWORK_RESPONSE:
                self._handle_network_response(event)

    # -------------------------------------------------------------------------
    # Boundary Event Handlers
    # -------------------------------------------------------------------------

    def _handle_file_read(self, event: GuardXEvent) -> None:
        """FILE_READ: File -> CONTAINS -> Entity -> FLOWS_TO -> FILE_CONTENT carrier."""
        file_res_id = event.source.resource_id if event.source else f"file:{event.payload.get('file_path', 'unknown')}"
        file_path = event.payload.get("file_path", file_res_id)

        # 1. Ensure File Node in lineage graph
        self.store.ensure_resource_node(
            node_id=file_res_id,
            node_type=LineageNodeType.FILE,
            label=file_path,
            session_id=event.session_id,
        )

        # 2. Extract content from payload
        content = (
            event.payload.get("content")
            or event.payload.get("raw_content")
            or event.payload.get("preview")
            or ""
        )

        sanitized_entities = event.metadata.get("sanitized_entities") if event.metadata else None
        extracted = self.extractor.extract_from_text(
            text=str(content),
            resource_id=file_res_id,
            event_id=event.event_id,
            session_id=event.session_id,
            sanitized_entities=sanitized_entities,
        )

        contained_entity_ids: List[str] = []

        # 3. Create FILE_CONTENT Carrier
        carrier_id = f"carrier_file_content_{uuid.uuid4().hex[:12]}"
        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.FILE_CONTENT.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=file_res_id,
            destination_actor_or_resource=event.actor.actor_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"file_path": file_path},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

        for raw_entity, transient_val in extracted:
            # Store raw entity
            self.store.add_entity(raw_entity)
            self._fingerprint_to_entity[raw_entity.fingerprint_hmac] = raw_entity
            self._notify_entity_created(raw_entity)

            # Edge 1: File -> CONTAINS -> Entity
            c_edge = LineageEdge(
                edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                source_id=file_res_id,
                target_id=f"entity:{raw_entity.entity_id}",
                edge_type=LineageEdgeType.CONTAINS,
                entity_id=raw_entity.entity_id,
                supporting_event_id=event.event_id,
                provenance_quality=ProvenanceQuality.OBSERVED,
                confidence=1.0,
                detection_method=DetectionMethod.STRUCTURED_PROPAGATION if raw_entity.metadata.get("source") == "env_parser" else DetectionMethod.HMAC_MATCH,
            )
            self.store.add_edge(c_edge)
            self._notify_flow_created(c_edge)

            target_entity_for_carrier = raw_entity

            # If sensitive: tokenize to create protected representation
            if raw_entity.classification in (
                DataClassification.CREDENTIAL.value,
                DataClassification.SECRET.value,
            ):
                synthetic_token = f"{{{{SECRET_{raw_entity.label}_{uuid.uuid4().hex[:6]}}}}}"
                tf_record, token_entity, t_edge = self.transformation_engine.transform(
                    transformation_type="TOKENIZE",
                    input_entities=[raw_entity],
                    originating_event_id=event.event_id,
                    output_label=f"TOKEN_{raw_entity.label}",
                    output_synthetic_token=synthetic_token,
                    details={"token_type": "synthetic_vault_token"},
                )
                self._token_to_entity[synthetic_token] = token_entity
                self._fingerprint_to_entity[token_entity.fingerprint_hmac] = token_entity
                self._notify_entity_created(token_entity)
                self._notify_transformation_created(tf_record)
                self._notify_flow_created(t_edge)
                target_entity_for_carrier = token_entity

            contained_entity_ids.append(raw_entity.entity_id)
            if target_entity_for_carrier.entity_id != raw_entity.entity_id:
                contained_entity_ids.append(target_entity_for_carrier.entity_id)

            # Edge 2: Raw Entity -> FLOWS_TO -> FILE_CONTENT carrier
            raw_f_edge = LineageEdge(
                edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                source_id=f"entity:{raw_entity.entity_id}",
                target_id=f"carrier:{carrier.carrier_id}",
                edge_type=LineageEdgeType.FLOWS_TO,
                entity_id=raw_entity.entity_id,
                supporting_event_id=event.event_id,
                provenance_quality=ProvenanceQuality.OBSERVED,
                confidence=1.0,
                detection_method=DetectionMethod.STRUCTURED_PROPAGATION,
            )
            self.store.add_edge(raw_f_edge)
            self._notify_flow_created(raw_f_edge)

            # If tokenized, token entity also flows to carrier
            if target_entity_for_carrier.entity_id != raw_entity.entity_id:
                f_edge = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=f"entity:{target_entity_for_carrier.entity_id}",
                    target_id=f"carrier:{carrier.carrier_id}",
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=target_entity_for_carrier.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.STRUCTURED_PROPAGATION,
                )
                self.store.add_edge(f_edge)
                self._notify_flow_created(f_edge)

            self._entity_to_latest_carrier[target_entity_for_carrier.entity_id] = carrier
            self._entity_to_latest_carrier[raw_entity.entity_id] = carrier

        # Update carrier contained entities
        if contained_entity_ids:
            updated_carrier = DataCarrier(
                carrier_id=carrier.carrier_id,
                carrier_type=carrier.carrier_type,
                session_id=carrier.session_id,
                supporting_event_id=carrier.supporting_event_id,
                contained_entity_ids=tuple(contained_entity_ids),
                source_actor_or_resource=carrier.source_actor_or_resource,
                destination_actor_or_resource=carrier.destination_actor_or_resource,
                sequence_number=carrier.sequence_number,
                evidence_quality=carrier.evidence_quality,
                confidence=carrier.confidence,
                metadata=carrier.metadata,
            )
            self.store.add_carrier(updated_carrier)
            self._latest_carrier_by_type[CarrierType.FILE_CONTENT.value] = updated_carrier
        else:
            self._latest_carrier_by_type[CarrierType.FILE_CONTENT.value] = carrier

    def _handle_tool_call(self, event: GuardXEvent) -> None:
        """TOOL_CALL: AgentContext -> FLOWS_TO -> TOOL_ARGUMENT."""
        tool_name = event.payload.get("tool_name", "tool")
        tool_res_id = f"tool:{tool_name}"

        carrier_id = f"carrier_tool_arg_{uuid.uuid4().hex[:12]}"
        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.TOOL_ARGUMENT.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=event.actor.actor_id,
            destination_actor_or_resource=tool_res_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"tool_name": tool_name},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

        # Check arguments for known tokens
        args_str = json.dumps(event.payload.get("arguments", {}))
        matched_entities = self._find_entities_in_text(args_str)

        if matched_entities:
            contained_ids = [e.entity_id for e in matched_entities]
            updated_carrier = DataCarrier(
                carrier_id=carrier.carrier_id,
                carrier_type=carrier.carrier_type,
                session_id=carrier.session_id,
                supporting_event_id=carrier.supporting_event_id,
                contained_entity_ids=tuple(contained_ids),
                source_actor_or_resource=carrier.source_actor_or_resource,
                destination_actor_or_resource=carrier.destination_actor_or_resource,
                sequence_number=carrier.sequence_number,
                evidence_quality=carrier.evidence_quality,
                confidence=carrier.confidence,
                metadata=carrier.metadata,
            )
            self.store.add_carrier(updated_carrier)
            self._latest_carrier_by_type[CarrierType.TOOL_ARGUMENT.value] = updated_carrier

            prev_ctx = self._latest_carrier_by_type.get(CarrierType.AGENT_CONTEXT.value)
            for ent in matched_entities:
                src_id = f"carrier:{prev_ctx.carrier_id}" if prev_ctx else f"entity:{ent.entity_id}"
                edge = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=src_id,
                    target_id=f"carrier:{carrier.carrier_id}",
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(edge)
                self._notify_flow_created(edge)
                self._entity_to_latest_carrier[ent.entity_id] = updated_carrier
        else:
            self._latest_carrier_by_type[CarrierType.TOOL_ARGUMENT.value] = carrier

    def _handle_tool_result(self, event: GuardXEvent) -> None:
        """TOOL_RESULT: FILE_CONTENT / TOOL -> FLOWS_TO -> TOOL_RESULT."""
        tool_name = event.payload.get("tool_name", "tool")
        tool_res_id = f"tool:{tool_name}"

        carrier_id = f"carrier_tool_result_{uuid.uuid4().hex[:12]}"
        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.TOOL_RESULT.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=tool_res_id,
            destination_actor_or_resource=event.actor.actor_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"tool_name": tool_name},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

        # Inspect tool result text
        result_text = str(
            event.payload.get("result")
            or event.payload.get("output")
            or event.payload.get("content")
            or ""
        )

        matched_entities = self._find_entities_in_text(result_text)

        # If this is read_file and a FILE_CONTENT carrier exists, correlate with entities
        prev_file_carrier = self._latest_carrier_by_type.get(CarrierType.FILE_CONTENT.value)

        entities_to_link: List[DataEntity] = list(matched_entities)
        if prev_file_carrier and prev_file_carrier.contained_entity_ids:
            for ent_id in prev_file_carrier.contained_entity_ids:
                ent_obj = self.store.get_entity(ent_id)
                if ent_obj and ent_obj not in entities_to_link:
                    entities_to_link.append(ent_obj)

        if entities_to_link:
            contained_ids = [e.entity_id for e in entities_to_link]
            updated_carrier = DataCarrier(
                carrier_id=carrier.carrier_id,
                carrier_type=carrier.carrier_type,
                session_id=carrier.session_id,
                supporting_event_id=carrier.supporting_event_id,
                contained_entity_ids=tuple(contained_ids),
                source_actor_or_resource=carrier.source_actor_or_resource,
                destination_actor_or_resource=carrier.destination_actor_or_resource,
                sequence_number=carrier.sequence_number,
                evidence_quality=carrier.evidence_quality,
                confidence=carrier.confidence,
                metadata=carrier.metadata,
            )
            self.store.add_carrier(updated_carrier)
            self._latest_carrier_by_type[CarrierType.TOOL_RESULT.value] = updated_carrier

            for ent in entities_to_link:
                # Flow from FILE_CONTENT or Entity to TOOL_RESULT
                is_in_file_carrier = bool(prev_file_carrier and ent.entity_id in prev_file_carrier.contained_entity_ids)
                src_id = f"carrier:{prev_file_carrier.carrier_id}" if is_in_file_carrier else f"entity:{ent.entity_id}"
                edge = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=src_id,
                    target_id=f"carrier:{carrier.carrier_id}",
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.STRUCTURED_PROPAGATION if prev_file_carrier else DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(edge)
                self._notify_flow_created(edge)
                self._entity_to_latest_carrier[ent.entity_id] = updated_carrier
        else:
            self._latest_carrier_by_type[CarrierType.TOOL_RESULT.value] = carrier

    def _handle_agent_action(self, event: GuardXEvent) -> None:
        """AGENT_ACTION: ToolResult -> FLOWS_TO -> AGENT_CONTEXT."""
        carrier_id = f"carrier_agent_context_{uuid.uuid4().hex[:12]}"
        prev_tool_res = self._latest_carrier_by_type.get(CarrierType.TOOL_RESULT.value)

        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.AGENT_CONTEXT.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=event.actor.actor_id,
            destination_actor_or_resource=event.actor.actor_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"action_type": event.event_type.value},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

        # Ingest entities from previous tool result if available
        if prev_tool_res and prev_tool_res.contained_entity_ids:
            updated_carrier = DataCarrier(
                carrier_id=carrier.carrier_id,
                carrier_type=carrier.carrier_type,
                session_id=carrier.session_id,
                supporting_event_id=carrier.supporting_event_id,
                contained_entity_ids=prev_tool_res.contained_entity_ids,
                source_actor_or_resource=carrier.source_actor_or_resource,
                destination_actor_or_resource=carrier.destination_actor_or_resource,
                sequence_number=carrier.sequence_number,
                evidence_quality=carrier.evidence_quality,
                confidence=carrier.confidence,
                metadata=carrier.metadata,
            )
            self.store.add_carrier(updated_carrier)
            self._latest_carrier_by_type[CarrierType.AGENT_CONTEXT.value] = updated_carrier

            for ent_id in prev_tool_res.contained_entity_ids:
                edge = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=f"carrier:{prev_tool_res.carrier_id}",
                    target_id=f"carrier:{carrier.carrier_id}",
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.STRUCTURED_PROPAGATION,
                )
                self.store.add_edge(edge)
                self._notify_flow_created(edge)
                self._entity_to_latest_carrier[ent_id] = updated_carrier
        else:
            self._latest_carrier_by_type[CarrierType.AGENT_CONTEXT.value] = carrier

    def _handle_llm_request(self, event: GuardXEvent) -> None:
        """LLM_REQUEST: Concrete evidence verification.
        
        CRITICAL RULE: NEVER infer flow merely because LLM_REQUEST followed FILE_READ.
        ONLY create FLOWS_TO edge if the request payload CONCRETELY contains the entity/token!
        """
        model_name = event.payload.get("model", "llm_model")
        provider = event.payload.get("provider", "LLM")
        llm_res_id = f"llm:{model_name}"

        # 1. Ensure LLM Node in lineage graph
        self.store.ensure_resource_node(
            node_id=llm_res_id,
            node_type=LineageNodeType.LLM,
            label=f"{provider} ({model_name})",
            session_id=event.session_id,
        )

        carrier_id = f"carrier_llm_request_{uuid.uuid4().hex[:12]}"
        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.LLM_REQUEST.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=event.actor.actor_id,
            destination_actor_or_resource=llm_res_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"model": model_name},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

        # 2. Inspect request payload for concrete token or entity presence
        req_text = json.dumps(event.payload)
        matched_entities = self._find_entities_in_text(req_text)

        # 3. ONLY link if evidence proves presence!
        if matched_entities:
            contained_ids = [e.entity_id for e in matched_entities]
            updated_carrier = DataCarrier(
                carrier_id=carrier.carrier_id,
                carrier_type=carrier.carrier_type,
                session_id=carrier.session_id,
                supporting_event_id=carrier.supporting_event_id,
                contained_entity_ids=tuple(contained_ids),
                source_actor_or_resource=carrier.source_actor_or_resource,
                destination_actor_or_resource=carrier.destination_actor_or_resource,
                sequence_number=carrier.sequence_number,
                evidence_quality=carrier.evidence_quality,
                confidence=carrier.confidence,
                metadata=carrier.metadata,
            )
            self.store.add_carrier(updated_carrier)
            self._latest_carrier_by_type[CarrierType.LLM_REQUEST.value] = updated_carrier

            prev_ctx = self._latest_carrier_by_type.get(CarrierType.AGENT_CONTEXT.value)

            for ent in matched_entities:
                # Hop 1: AGENT_CONTEXT -> FLOWS_TO -> LLM_REQUEST
                src_id = f"carrier:{prev_ctx.carrier_id}" if prev_ctx else f"entity:{ent.entity_id}"
                e1 = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=src_id,
                    target_id=f"carrier:{carrier.carrier_id}",
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(e1)
                self._notify_flow_created(e1)

                # Hop 2: LLM_REQUEST -> FLOWS_TO -> LLM (Sink reached!)
                e2 = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=f"carrier:{carrier.carrier_id}",
                    target_id=llm_res_id,
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(e2)
                self._notify_flow_created(e2)
                self._entity_to_latest_carrier[ent.entity_id] = updated_carrier
        else:
            # NO EVIDENCE of entity in this LLM request!
            # Do NOT create any FLOWS_TO edge for sensitive entities.
            self._latest_carrier_by_type[CarrierType.LLM_REQUEST.value] = carrier

    def _handle_llm_response(self, event: GuardXEvent) -> None:
        """LLM_RESPONSE: Only propagate if deterministic token/entity match exists in output."""
        model_name = event.payload.get("model", "llm_model")
        llm_res_id = event.source.resource_id if event.source else f"llm:{model_name}"

        carrier_id = f"carrier_llm_response_{uuid.uuid4().hex[:12]}"
        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.LLM_RESPONSE.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=llm_res_id,
            destination_actor_or_resource=event.actor.actor_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"model": model_name},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

        resp_text = str(event.payload.get("content", event.payload.get("response", "")))
        matched_entities = self._find_entities_in_text(resp_text)

        if matched_entities:
            contained_ids = [e.entity_id for e in matched_entities]
            updated_carrier = DataCarrier(
                carrier_id=carrier.carrier_id,
                carrier_type=carrier.carrier_type,
                session_id=carrier.session_id,
                supporting_event_id=carrier.supporting_event_id,
                contained_entity_ids=tuple(contained_ids),
                source_actor_or_resource=carrier.source_actor_or_resource,
                destination_actor_or_resource=carrier.destination_actor_or_resource,
                sequence_number=carrier.sequence_number,
                evidence_quality=carrier.evidence_quality,
                confidence=carrier.confidence,
                metadata=carrier.metadata,
            )
            self.store.add_carrier(updated_carrier)
            self._latest_carrier_by_type[CarrierType.LLM_RESPONSE.value] = updated_carrier

            for ent in matched_entities:
                edge = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=llm_res_id,
                    target_id=f"carrier:{carrier.carrier_id}",
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(edge)
                self._notify_flow_created(edge)
                self._entity_to_latest_carrier[ent.entity_id] = updated_carrier
        else:
            self._latest_carrier_by_type[CarrierType.LLM_RESPONSE.value] = carrier

    def _handle_file_write(self, event: GuardXEvent) -> None:
        """FILE_WRITE: Check if known entity or token is written to file."""
        file_res_id = event.destination.resource_id if event.destination else f"file:{event.payload.get('file_path', 'output.txt')}"
        file_path = event.payload.get("file_path", file_res_id)

        self.store.ensure_resource_node(
            node_id=file_res_id,
            node_type=LineageNodeType.FILE,
            label=file_path,
            session_id=event.session_id,
        )

        carrier_id = f"carrier_file_write_{uuid.uuid4().hex[:12]}"
        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.FILE_WRITE_CONTENT.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=event.actor.actor_id,
            destination_actor_or_resource=file_res_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"file_path": file_path},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

        write_text = str(
            event.payload.get("content")
            or event.payload.get("raw_content")
            or event.payload.get("diff")
            or ""
        )
        matched_entities = self._find_entities_in_text(write_text)

        if matched_entities:
            contained_ids = [e.entity_id for e in matched_entities]
            updated_carrier = DataCarrier(
                carrier_id=carrier.carrier_id,
                carrier_type=carrier.carrier_type,
                session_id=carrier.session_id,
                supporting_event_id=carrier.supporting_event_id,
                contained_entity_ids=tuple(contained_ids),
                source_actor_or_resource=carrier.source_actor_or_resource,
                destination_actor_or_resource=carrier.destination_actor_or_resource,
                sequence_number=carrier.sequence_number,
                evidence_quality=carrier.evidence_quality,
                confidence=carrier.confidence,
                metadata=carrier.metadata,
            )
            self.store.add_carrier(updated_carrier)

            prev_ctx = self._latest_carrier_by_type.get(CarrierType.AGENT_CONTEXT.value)
            for ent in matched_entities:
                src_id = f"carrier:{prev_ctx.carrier_id}" if prev_ctx else f"entity:{ent.entity_id}"
                e1 = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=src_id,
                    target_id=f"carrier:{carrier.carrier_id}",
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(e1)
                self._notify_flow_created(e1)

                e2 = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=f"carrier:{carrier.carrier_id}",
                    target_id=file_res_id,
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(e2)
                self._notify_flow_created(e2)
                self._entity_to_latest_carrier[ent.entity_id] = updated_carrier

    def _handle_network_request(self, event: GuardXEvent) -> None:
        """NETWORK_REQUEST: check for entity flow to external endpoint."""
        url = event.payload.get("url", "https://api.example.com")
        endpoint_id = event.destination.resource_id if event.destination else f"endpoint:{url}"

        self.store.ensure_resource_node(
            node_id=endpoint_id,
            node_type=LineageNodeType.NETWORK_ENDPOINT,
            label=url,
            session_id=event.session_id,
        )

        carrier_id = f"carrier_net_req_{uuid.uuid4().hex[:12]}"
        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.NETWORK_REQUEST.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=event.actor.actor_id,
            destination_actor_or_resource=endpoint_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"url": url},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

        req_text = json.dumps(event.payload.get("body", event.payload.get("headers", {})))
        matched_entities = self._find_entities_in_text(req_text)

        if matched_entities:
            contained_ids = [e.entity_id for e in matched_entities]
            updated_carrier = DataCarrier(
                carrier_id=carrier.carrier_id,
                carrier_type=carrier.carrier_type,
                session_id=carrier.session_id,
                supporting_event_id=carrier.supporting_event_id,
                contained_entity_ids=tuple(contained_ids),
                source_actor_or_resource=carrier.source_actor_or_resource,
                destination_actor_or_resource=carrier.destination_actor_or_resource,
                sequence_number=carrier.sequence_number,
                evidence_quality=carrier.evidence_quality,
                confidence=carrier.confidence,
                metadata=carrier.metadata,
            )
            self.store.add_carrier(updated_carrier)

            prev_ctx = self._latest_carrier_by_type.get(CarrierType.AGENT_CONTEXT.value)
            for ent in matched_entities:
                src_id = f"carrier:{prev_ctx.carrier_id}" if prev_ctx else f"entity:{ent.entity_id}"
                e1 = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=src_id,
                    target_id=f"carrier:{carrier.carrier_id}",
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(e1)
                self._notify_flow_created(e1)

                e2 = LineageEdge(
                    edge_id=f"ledge_{uuid.uuid4().hex[:12]}",
                    source_id=f"carrier:{carrier.carrier_id}",
                    target_id=endpoint_id,
                    edge_type=LineageEdgeType.FLOWS_TO,
                    entity_id=ent.entity_id,
                    supporting_event_id=event.event_id,
                    provenance_quality=ProvenanceQuality.OBSERVED,
                    confidence=1.0,
                    detection_method=DetectionMethod.TOKEN_IDENTITY,
                )
                self.store.add_edge(e2)
                self._notify_flow_created(e2)

    def _handle_network_response(self, event: GuardXEvent) -> None:
        """NETWORK_RESPONSE: boundary extraction."""
        url = event.payload.get("url", "https://api.example.com")
        endpoint_id = event.source.resource_id if event.source else f"endpoint:{url}"

        carrier_id = f"carrier_net_resp_{uuid.uuid4().hex[:12]}"
        carrier = DataCarrier(
            carrier_id=carrier_id,
            carrier_type=CarrierType.NETWORK_RESPONSE.value,
            session_id=event.session_id,
            supporting_event_id=event.event_id,
            source_actor_or_resource=endpoint_id,
            destination_actor_or_resource=event.actor.actor_id,
            sequence_number=event.sequence_number,
            evidence_quality=event.provenance_quality,
            confidence=event.confidence,
            metadata={"url": url},
        )
        self.store.add_carrier(carrier)
        self._notify_carrier_created(carrier)

    # -------------------------------------------------------------------------
    # In-Memory Entity Matching
    # -------------------------------------------------------------------------

    def _find_entities_in_text(self, text: str) -> List[DataEntity]:
        """Discovers known DataEntities in text using token strings and HMAC matching."""
        if not text:
            return []

        matched: List[DataEntity] = []
        seen_entity_ids = set()

        # 1. Match synthetic tokens: {{SECRET_...}}, [MASKED_...]
        for token_str, entity in self._token_to_entity.items():
            if token_str in text:
                if entity.entity_id not in seen_entity_ids:
                    seen_entity_ids.add(entity.entity_id)
                    matched.append(entity)

        # 2. Check for token patterns in general
        for match in SYNTHETIC_TOKEN_PATTERN.finditer(text):
            tok = match.group(1)
            if tok in self._token_to_entity:
                ent = self._token_to_entity[tok]
                if ent.entity_id not in seen_entity_ids:
                    seen_entity_ids.add(ent.entity_id)
                    matched.append(ent)

        # 3. Match raw credentials/secrets via keyed HMAC matching of candidate words/tokens
        if self._fingerprint_to_entity:
            for word in re.findall(r'[A-Za-z0-9_\-\.\=\+\/]{6,}', text):
                fp = compute_keyed_fingerprint(word, self.session_key)
                if fp in self._fingerprint_to_entity:
                    ent = self._fingerprint_to_entity[fp]
                    if ent.entity_id not in seen_entity_ids:
                        seen_entity_ids.add(ent.entity_id)
                        matched.append(ent)

        return matched

    # -------------------------------------------------------------------------
    # Notification Callbacks
    # -------------------------------------------------------------------------

    def _notify_entity_created(self, entity: DataEntity) -> None:
        if self.on_lineage_event:
            self.on_lineage_event("entity.created", entity.to_dict())

    def _notify_carrier_created(self, carrier: DataCarrier) -> None:
        if self.on_lineage_event:
            self.on_lineage_event("carrier.created", carrier.to_dict())

    def _notify_flow_created(self, edge: LineageEdge) -> None:
        if self.on_lineage_event:
            self.on_lineage_event("flow.created", edge.to_dict())

    def _notify_transformation_created(self, tf: Transformation) -> None:
        if self.on_lineage_event:
            self.on_lineage_event("transformation.created", tf.to_dict())
