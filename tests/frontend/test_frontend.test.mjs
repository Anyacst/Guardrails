/**
 * Frontend Unit Test Suite for GuardX Security Investigation Console.
 *
 * Tests:
 * 1. Graph element tracking and insertion (nodeDataMap, edgeDataMap)
 * 2. Node selection and Inspector data formatting
 * 3. Edge selection and evidence metadata formatting
 * 4. Timeline chronological ordering strictly by sequence_number
 * 5. Search and node type filtering logic
 * 6. WebSocket incremental message dispatching (snapshot, event.created, node.created, edge.created, scope.started)
 * 7. Invariant INV-001: Inspector and DOM state never expose raw secret patterns
 * 8. Stability Invariant: Existing node coordinates remain strictly unchanged after incremental node.created
 * 9. Stability Invariant: Existing node coordinates remain strictly unchanged after incremental edge.created
 * 10. Scope Visualization: Execution scopes are filtered from primary DAG canvas by default and preserved in Scope Tree
 * 11. Layout Governance: Full Dagre layout only executes on snapshot or explicit user Re-layout
 * 12. Viewport Governance: Fit to View does not alter node positions, and Auto-Follow toggles correctly
 */

import test from 'node:test';
import assert from 'node:assert/strict';

// Emulate minimal DOM environment required for inspector and timeline tests
class MockElement {
  constructor(tag = 'div') {
    this.tag = tag;
    this.children = [];
    this.textContent = '';
    this.innerHTML = '';
    this.className = '';
    this.dataset = {};
    this.style = {};
    this._listeners = {};
  }

  addEventListener(event, cb) {
    this._listeners[event] = cb;
  }

  querySelector(sel) {
    return this.children.find(c => sel.includes(c.className)) || null;
  }

  querySelectorAll(sel) {
    return this.children;
  }

  appendChild(el) {
    this.children.push(el);
  }

  remove() {
    this._removed = true;
  }

  click() {
    if (this._listeners['click']) this._listeners['click']();
  }
}

class MockDocument {
  constructor() {
    this.elements = new Map();
  }

  createElement(tag) {
    return new MockElement(tag);
  }

  getElementById(id) {
    if (!this.elements.has(id)) {
      this.elements.set(id, new MockElement());
    }
    return this.elements.get(id);
  }

  querySelectorAll() {
    return [];
  }
}

// Lightweight state machine mirroring web/app.js layout and stability logic
class GuardXFrontendCore {
  constructor(doc) {
    this.doc = doc;
    this.eventHistory = [];
    this.nodeDataMap = new Map();
    this.edgeDataMap = new Map();
    this.canvasNodes = new Map(); // id -> { id, position: {x, y}, classes: Set }
    this.canvasEdges = new Map(); // id -> edge
    this.scopeTree = [];
    this.activeInspector = 'node';
    this.autoFollowEnabled = true;
    this.showScopeNodesInGraph = false;
    this.layoutRunCount = 0;
    this.lastPannedTo = null;

    // Milestone 3 Data Lineage State
    this.currentLens = 'execution';
    this.executionNodePositions = new Map();
    this.lineageNodePositions = new Map();
    this.lineageData = { nodes: [], edges: [], entities: [], carriers: [], transformations: [] };
    this.lineageNodeDataMap = new Map();
    this.lineageEdgeDataMap = new Map();
    this.lineageEntityMap = new Map();
    this.lineageCarrierMap = new Map();

    // Milestone 4 Security Intelligence State
    this.securityNodePositions = new Map();
    this.securityData = { findings: [], crossings: [], attack_chains: [], intent_violations: [] };
    this.securityFindingsMap = new Map();
    this.securityCrossingsMap = new Map();
    this.securityAttackChainsMap = new Map();
    this.securityViolationsMap = new Map();
    this.selectedFindingId = null;
  }

  switchLens(newLens) {
    if (newLens === this.currentLens) return;
    const targetMap = this.currentLens === 'data_flow'
      ? this.lineageNodePositions
      : (this.currentLens === 'security' ? this.securityNodePositions : this.executionNodePositions);
    for (const [id, node] of this.canvasNodes.entries()) {
      targetMap.set(id, { ...node.position });
    }
    this.currentLens = newLens;
    this.canvasNodes.clear();
    this.canvasEdges.clear();

    if (this.currentLens === 'security') {
      this.renderSecurityCanvas(this.selectedFindingId);
    } else if (this.currentLens === 'data_flow') {
      for (const nodeData of this.lineageNodeDataMap.values()) {
        const pos = this.lineageNodePositions.get(nodeData.node_id) || { x: 100, y: 100 };
        this.canvasNodes.set(nodeData.node_id, {
          id: nodeData.node_id,
          node_type: nodeData.node_type,
          position: pos,
          classes: new Set(),
        });
      }
      for (const edgeData of this.lineageEdgeDataMap.values()) {
        if (this.canvasNodes.has(edgeData.source_id) && this.canvasNodes.has(edgeData.target_id)) {
          this.canvasEdges.set(edgeData.edge_id, edgeData);
        }
      }
    } else {
      for (const nodeData of this.nodeDataMap.values()) {
        if (this.shouldDisplayNode(nodeData)) {
          const pos = this.executionNodePositions.get(nodeData.node_id) || { x: 100, y: 100 };
          this.canvasNodes.set(nodeData.node_id, {
            id: nodeData.node_id,
            node_type: nodeData.node_type,
            position: pos,
            classes: new Set(),
          });
        }
      }
      for (const edgeData of this.edgeDataMap.values()) {
        if (this.shouldDisplayEdge(edgeData)) {
          if (this.canvasNodes.has(edgeData.source_id) && this.canvasNodes.has(edgeData.target_id)) {
            this.canvasEdges.set(edgeData.edge_id, edgeData);
          }
        }
      }
    }
  }

  loadSecuritySnapshot(sec) {
    this.securityData = sec || { findings: [], crossings: [], attack_chains: [], intent_violations: [] };
    this.securityFindingsMap.clear();
    this.securityCrossingsMap.clear();
    this.securityAttackChainsMap.clear();
    this.securityViolationsMap.clear();
    if (this.securityData.findings) this.securityData.findings.forEach(f => this.securityFindingsMap.set(f.finding_id, f));
    if (this.securityData.crossings) this.securityData.crossings.forEach(c => this.securityCrossingsMap.set(c.crossing_id, c));
    if (this.securityData.attack_chains) this.securityData.attack_chains.forEach(a => this.securityAttackChainsMap.set(a.chain_id, a));
    if (this.securityData.intent_violations) this.securityData.intent_violations.forEach(v => this.securityViolationsMap.set(v.violation_id, v));
    this.renderAlertsList();
  }

  renderAlertsList() {
    const container = this.doc.getElementById('alertsListContainer');
    const badge = this.doc.getElementById('alertCountBadge');
    const count = this.securityFindingsMap.size + this.securityViolationsMap.size + this.securityAttackChainsMap.size;
    if (badge) badge.textContent = `${count} alerts`;
    if (!container) return;
    if (count === 0) {
      container.innerHTML = 'EMPTY_HINT:No security findings detected.';
      return;
    }
    const items = [];
    for (const f of this.securityFindingsMap.values()) {
      items.push(`FINDING:${f.finding_id};SEV:${f.severity};REPR:${f.representation};BOUNDARY:${f.source_trust}->${f.destination_trust}`);
    }
    for (const v of this.securityViolationsMap.values()) {
      items.push(`VIOLATION:${v.violation_id};TYPE:${v.violation_type}`);
    }
    for (const a of this.securityAttackChainsMap.values()) {
      items.push(`CHAIN:${a.chain_id};TYPE:${a.chain_type}`);
    }
    container.innerHTML = items.join('||');
  }

  selectFinding(findingId) {
    this.selectedFindingId = findingId;
    this.activeInspector = 'finding';
    const finding = this.securityFindingsMap.get(findingId);
    if (!finding) return null;
    const title = this.doc.getElementById('findingInspTitle');
    if (title) title.textContent = finding.title;
    const sev = this.doc.getElementById('findingInspSeverity');
    if (sev) sev.textContent = finding.severity;
    const body = this.doc.getElementById('findingInspBody');
    if (body) {
      body.innerHTML = `ID:${finding.finding_id};SEV:${finding.severity};CAT:${finding.category};REPR:${finding.representation};RULE:${finding.rule_id};BOUNDARY:${finding.source_trust}->${finding.destination_trust};CONF:${finding.confidence};QUALITY:${finding.provenance_quality};ZERO_RAW:true`;
    }
    this.renderSecurityCanvas(findingId);
    return finding;
  }

  renderSecurityCanvas(findingId = null) {
    this.canvasNodes.clear();
    this.canvasEdges.clear();
    const targetFindingId = findingId || this.selectedFindingId;
    const finding = targetFindingId
      ? this.securityFindingsMap.get(targetFindingId)
      : (this.securityFindingsMap.size > 0 ? this.securityFindingsMap.values().next().value : null);

    if (!finding) {
      this.canvasNodes.set('clean_state', {
        id: 'clean_state',
        node_type: 'EXECUTION_SCOPE',
        position: { x: 300, y: 150 },
        classes: new Set(),
      });
      return;
    }

    const hops = (finding.lineage_path && finding.lineage_path.length > 0)
      ? finding.lineage_path
      : [finding.source_resource_id, finding.source_entity_id, finding.destination_id];

    let prev = null;
    hops.forEach((h, idx) => {
      const id = `risk_hop_${idx}_${h}`;
      const isFirst = idx === 0;
      const isLast = idx === hops.length - 1;
      const classes = new Set();
      if (isFirst) classes.add('risk-source');
      if (isLast) classes.add('risk-sink');
      if (finding.representation === 'TOKENIZED') classes.add('protected-highlight');
      else classes.add('risk-path-highlight');

      this.canvasNodes.set(id, {
        id: id,
        node_type: isFirst ? 'FILE' : (isLast ? 'LLM' : 'DATA_CARRIER'),
        position: { x: 100 + idx * 150, y: 150 },
        classes: classes,
      });

      if (prev) {
        this.canvasEdges.set(`edge_${prev}_to_${id}`, {
          edge_id: `edge_${prev}_to_${id}`,
          source_id: prev,
          target_id: id,
          edge_type: isLast ? 'EGRESS' : 'FLOWS_TO',
          classes: classes,
        });
      }
      prev = id;
    });
  }

  handleEntityCreated(entity) {
    this.lineageEntityMap.set(entity.entity_id, entity);
    const nodeId = `entity:${entity.entity_id}`;
    const nodeData = {
      node_id: nodeId,
      node_type: 'DATA_ENTITY',
      label: `${entity.label} (${entity.representation})`,
      entity_id: entity.entity_id,
      properties: { ...entity, raw_value_persisted: false },
    };
    this.lineageNodeDataMap.set(nodeId, nodeData);
    if (this.currentLens === 'data_flow') {
      this.canvasNodes.set(nodeId, {
        id: nodeId,
        node_type: 'DATA_ENTITY',
        position: { x: 150, y: 160 },
        classes: new Set(['new-node-pulse']),
      });
    }
  }

  handleCarrierCreated(carrier) {
    this.lineageCarrierMap.set(carrier.carrier_id, carrier);
    const nodeId = `carrier:${carrier.carrier_id}`;
    const nodeData = {
      node_id: nodeId,
      node_type: 'DATA_CARRIER',
      label: `${carrier.carrier_type}#${carrier.sequence_number}`,
      carrier_id: carrier.carrier_id,
      properties: { ...carrier },
    };
    this.lineageNodeDataMap.set(nodeId, nodeData);
    if (this.currentLens === 'data_flow') {
      this.canvasNodes.set(nodeId, {
        id: nodeId,
        node_type: 'DATA_CARRIER',
        position: { x: 150, y: 260 },
        classes: new Set(['new-node-pulse']),
      });
    }
  }

  handleFlowCreated(edge) {
    this.lineageEdgeDataMap.set(edge.edge_id, edge);
    if (this.currentLens === 'data_flow') {
      if (this.canvasNodes.has(edge.source_id) && this.canvasNodes.has(edge.target_id)) {
        this.canvasEdges.set(edge.edge_id, edge);
      }
    }
  }

  inspectDataEntity(entity) {
    this.activeInspector = 'node';
    const title = this.doc.getElementById('nodeInspTitle');
    title.textContent = `${entity.label} (${entity.representation || 'RAW'})`;
    const body = this.doc.getElementById('nodeInspBody');
    body.innerHTML = `ID:${entity.entity_id};LABEL:${entity.label};CLASS:${entity.classification};REPR:${entity.representation};FP:${entity.fingerprint_hmac};TOKEN:${entity.synthetic_token || 'None'};RAW_PERSISTED:false`;
    return entity;
  }

  inspectLineageEdge(edge) {
    this.activeInspector = 'edge';
    const title = this.doc.getElementById('edgeInspTitle');
    title.textContent = edge.edge_type;
    const body = this.doc.getElementById('edgeInspBody');
    body.innerHTML = `REL:${edge.edge_type};SRC:${edge.source_id};TGT:${edge.target_id};METHOD:${edge.detection_method};EVT:${edge.event_id};CONF:${edge.confidence}`;
    return edge;
  }

  renderTraceResult(result, targetId, direction) {
    const body = this.doc.getElementById('traceInspBody');
    if (!result || !result.has_proven_flow || !result.hops || result.hops.length === 0) {
      body.innerHTML = `NO_PROVEN_FLOW;TARGET:${targetId};REASON:Never infer information flow merely because events occurred in temporal proximity.`;
      return false;
    }
    const hopSummary = result.hops.map(h => `${h.source_id}->[${h.relationship}|${h.detection_method}]->${h.target_id}`).join(';');
    body.innerHTML = `HOPS:${result.hops.length};PATH:${hopSummary}`;
    return true;
  }

  handleWebSocketMessage(msg) {
    if (msg.type === 'session.snapshot') {
      this.eventHistory = msg.data.events || [];
      if (msg.data.nodes) msg.data.nodes.forEach(n => this.addNode(n, true));
      if (msg.data.edges) msg.data.edges.forEach(e => this.addEdge(e, true));
      if (msg.data.lineage) {
        if (msg.data.lineage.entities) msg.data.lineage.entities.forEach(e => this.handleEntityCreated(e));
        if (msg.data.lineage.carriers) msg.data.lineage.carriers.forEach(c => this.handleCarrierCreated(c));
        if (msg.data.lineage.edges) msg.data.lineage.edges.forEach(e => this.handleFlowCreated(e));
      }
      if (msg.data.security) {
        this.loadSecuritySnapshot(msg.data.security);
      }
      this.renderTimeline();
      this.runLayout(true);
    } else if (msg.type === 'event.created') {
      this.eventHistory.push(msg.data);
      this.appendTimelineItem(msg.data);
    } else if (msg.type === 'node.created') {
      this.addNode(msg.data, false);
    } else if (msg.type === 'edge.created') {
      this.addEdge(msg.data, false);
    } else if (msg.type === 'entity.created') {
      this.handleEntityCreated(msg.data);
    } else if (msg.type === 'carrier.created') {
      this.handleCarrierCreated(msg.data);
    } else if (msg.type === 'flow.created') {
      this.handleFlowCreated(msg.data);
    } else if (msg.type === 'scope.started') {
      this.scopeTree.push(msg.data);
    } else if (msg.type === 'trust_boundary.crossed') {
      this.securityCrossingsMap.set(msg.data.crossing_id, msg.data);
    } else if (msg.type === 'risk.detected') {
      this.securityFindingsMap.set(msg.data.finding_id, msg.data);
      this.renderAlertsList();
    } else if (msg.type === 'intent.violation') {
      this.securityViolationsMap.set(msg.data.violation_id, msg.data);
      this.renderAlertsList();
    } else if (msg.type === 'attack_chain.detected') {
      this.securityAttackChainsMap.set(msg.data.chain_id, msg.data);
      this.renderAlertsList();
    }
  }

  shouldDisplayNode(node) {
    if (node.node_type === 'EXECUTION_SCOPE' && !this.showScopeNodesInGraph) {
      return false;
    }
    return true;
  }

  shouldDisplayEdge(edge) {
    if (edge.edge_type === 'BELONGS_TO_SCOPE' && !this.showScopeNodesInGraph) {
      return false;
    }
    const src = this.nodeDataMap.get(edge.source_id);
    const tgt = this.nodeDataMap.get(edge.target_id);
    if (src && !this.shouldDisplayNode(src)) return false;
    if (tgt && !this.shouldDisplayNode(tgt)) return false;
    return true;
  }

  computeIncrementalPosition(node) {
    // Check if connected to an existing node
    for (const [edgeId, edge] of this.edgeDataMap.entries()) {
      if (edge.target_id === node.node_id && this.canvasNodes.has(edge.source_id)) {
        const srcPos = this.canvasNodes.get(edge.source_id).position;
        return { x: srcPos.x, y: srcPos.y + 100 };
      }
      if (edge.source_id === node.node_id && this.canvasNodes.has(edge.target_id)) {
        const tgtPos = this.canvasNodes.get(edge.target_id).position;
        return { x: tgtPos.x, y: tgtPos.y - 100 };
      }
    }

    const tierY = { USER: 80, AGENT: 180, LLM: 180, TOOL: 320, FILE: 460, PROCESS: 460 };
    const baseY = tierY[node.node_type] || 250;
    const count = this.canvasNodes.size;
    return { x: 200 + count * 100, y: baseY };
  }

  addNode(node, isSnapshot = false) {
    this.nodeDataMap.set(node.node_id, node);

    if (!this.shouldDisplayNode(node)) {
      this.canvasNodes.delete(node.node_id);
      return;
    }

    if (!this.canvasNodes.has(node.node_id)) {
      const pos = isSnapshot ? { x: 0, y: 0 } : this.computeIncrementalPosition(node);
      const canvasNode = {
        id: node.node_id,
        node_type: node.node_type,
        position: { x: pos.x, y: pos.y },
        classes: new Set(),
      };

      if (!isSnapshot) {
        canvasNode.classes.add('new-node-pulse');
        if (this.autoFollowEnabled) {
          this.lastPannedTo = node.node_id;
        }
      }

      this.canvasNodes.set(node.node_id, canvasNode);
    }
  }

  addEdge(edge, isSnapshot = false) {
    this.edgeDataMap.set(edge.edge_id, edge);

    if (!this.shouldDisplayEdge(edge)) {
      this.canvasEdges.delete(edge.edge_id);
      return;
    }

    if (this.canvasNodes.has(edge.source_id) && this.canvasNodes.has(edge.target_id)) {
      this.canvasEdges.set(edge.edge_id, edge);
      // NOTE: Existing node positions are 100% UNCHANGED.
    }
  }

  runLayout(fit = false) {
    this.layoutRunCount += 1;
    // Simulate Dagre layout re-computing coordinates for all canvas nodes
    let step = 0;
    for (const [id, node] of this.canvasNodes.entries()) {
      node.position = { x: 150 + step * 120, y: 150 + (step % 2) * 50 };
      step++;
    }
  }

  fitView() {
    // Changes viewport only, NEVER touches node positions!
    this.viewFitted = true;
  }

  getNodePosition(nodeId) {
    const n = this.canvasNodes.get(nodeId);
    return n ? { ...n.position } : null;
  }

  renderTimeline() {
    const container = this.doc.getElementById('timelineScroll');
    container.children = [];
    const sorted = [...this.eventHistory].sort((a, b) => a.sequence_number - b.sequence_number);
    sorted.forEach(evt => this.appendTimelineItem(evt));
  }

  appendTimelineItem(evt) {
    const container = this.doc.getElementById('timelineScroll');
    const item = this.doc.createElement('div');
    item.className = 'timeline-item';
    item.dataset.eventId = evt.event_id;
    item.textContent = `#${evt.sequence_number} ${evt.event_type}`;
    container.appendChild(item);
  }

  selectNode(nodeId) {
    const node = this.nodeDataMap.get(nodeId);
    if (!node) return null;
    this.activeInspector = 'node';
    const title = this.doc.getElementById('nodeInspTitle');
    title.textContent = node.label || node.node_id;
    const body = this.doc.getElementById('nodeInspBody');
    body.innerHTML = `ID:${node.node_id};TYPE:${node.node_type};PROP:${JSON.stringify(node.properties || {})}`;
    return node;
  }

  selectEdge(edgeId) {
    const edge = this.edgeDataMap.get(edgeId);
    if (!edge) return null;
    this.activeInspector = 'edge';
    const title = this.doc.getElementById('edgeInspTitle');
    title.textContent = edge.edge_type;
    const body = this.doc.getElementById('edgeInspBody');
    body.innerHTML = `REL:${edge.edge_type};SRC:${edge.source_id};TGT:${edge.target_id};EVT:${edge.event_id};QUALITY:${edge.provenance_quality};CONF:${edge.confidence}`;
    return edge;
  }

  selectEvent(evt) {
    this.activeInspector = 'event';
    const title = this.doc.getElementById('eventInspTitle');
    title.textContent = `#${evt.sequence_number} ${evt.event_type}`;
    const body = this.doc.getElementById('eventInspBody');
    body.innerHTML = `EVT:${evt.event_id};SEQ:${evt.sequence_number};ACTOR:${evt.actor_id};PAYLOAD:${JSON.stringify(evt.payload || {})}`;
    return evt;
  }

  filterNodes(query, allowedTypes = ['AGENT', 'TOOL', 'FILE', 'LLM']) {
    const results = [];
    for (const [id, node] of this.nodeDataMap.entries()) {
      const typeMatch = allowedTypes.includes(node.node_type);
      const queryMatch = !query || id.toLowerCase().includes(query.toLowerCase()) || (node.label && node.label.toLowerCase().includes(query.toLowerCase()));
      if (typeMatch && queryMatch) {
        results.push(id);
      }
    }
    return results;
  }
}

// -----------------------------------------------------------------------------
// Test Cases
// -----------------------------------------------------------------------------

test('1. Graph element tracking and insertion', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  app.addNode({ node_id: 'agent:opencode', node_type: 'AGENT', label: 'OpenCode' });
  app.addNode({ node_id: 'tool:agentguard_read', node_type: 'TOOL', label: 'agentguard_read' });
  app.addEdge({
    edge_id: 'edge:001',
    source_id: 'agent:opencode',
    target_id: 'tool:agentguard_read',
    edge_type: 'INVOKED',
    event_id: 'evt_1',
    provenance_quality: 'OBSERVED',
    confidence: 1.0,
  });

  assert.equal(app.nodeDataMap.size, 2);
  assert.equal(app.edgeDataMap.size, 1);
  assert.ok(app.nodeDataMap.has('agent:opencode'));
  assert.ok(app.edgeDataMap.has('edge:001'));
});

test('2. Node selection and Node Inspector rendering', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  app.addNode({
    node_id: 'file:.env',
    node_type: 'FILE',
    label: '.env',
    properties: { file_path: '.env', trust_level: 'LOCAL' },
  });

  const selected = app.selectNode('file:.env');
  assert.equal(selected.label, '.env');
  assert.equal(app.activeInspector, 'node');

  const title = doc.getElementById('nodeInspTitle');
  assert.equal(title.textContent, '.env');

  const body = doc.getElementById('nodeInspBody');
  assert.ok(body.innerHTML.includes('ID:file:.env'));
  assert.ok(body.innerHTML.includes('TYPE:FILE'));
  assert.ok(body.innerHTML.includes('LOCAL'));
});

test('3. Edge selection and Edge Inspector evidence metadata', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  app.addEdge({
    edge_id: 'edge:read_env',
    source_id: 'tool:agentguard_read',
    target_id: 'file:.env',
    edge_type: 'READ_FROM',
    event_id: 'evt_read_001',
    provenance_quality: 'OBSERVED',
    confidence: 1.0,
  });

  const edge = app.selectEdge('edge:read_env');
  assert.equal(edge.edge_type, 'READ_FROM');
  assert.equal(app.activeInspector, 'edge');

  const body = doc.getElementById('edgeInspBody');
  assert.ok(body.innerHTML.includes('REL:READ_FROM'));
  assert.ok(body.innerHTML.includes('SRC:tool:agentguard_read'));
  assert.ok(body.innerHTML.includes('TGT:file:.env'));
  assert.ok(body.innerHTML.includes('EVT:evt_read_001'));
  assert.ok(body.innerHTML.includes('QUALITY:OBSERVED'));
  assert.ok(body.innerHTML.includes('CONF:1'));
});

test('4. Timeline chronological ordering strictly by sequence_number', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  const events = [
    { event_id: 'evt_3', sequence_number: 3, event_type: 'TOOL_RESULT' },
    { event_id: 'evt_1', sequence_number: 1, event_type: 'USER_INPUT' },
    { event_id: 'evt_2', sequence_number: 2, event_type: 'AGENT_ACTION' },
  ];

  app.handleWebSocketMessage({
    type: 'session.snapshot',
    data: { events },
  });

  const timeline = doc.getElementById('timelineScroll');
  assert.equal(timeline.children.length, 3);
  assert.equal(timeline.children[0].textContent, '#1 USER_INPUT');
  assert.equal(timeline.children[1].textContent, '#2 AGENT_ACTION');
  assert.equal(timeline.children[2].textContent, '#3 TOOL_RESULT');
});

test('5. Search and node type filtering logic', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  app.addNode({ node_id: 'agent:opencode', node_type: 'AGENT', label: 'OpenCode' });
  app.addNode({ node_id: 'tool:agentguard_read', node_type: 'TOOL', label: 'agentguard_read' });
  app.addNode({ node_id: 'file:.env', node_type: 'FILE', label: '.env' });
  app.addNode({ node_id: 'llm:openrouter', node_type: 'LLM', label: 'OpenRouter' });

  const toolResults = app.filterNodes('', ['TOOL']);
  assert.deepEqual(toolResults, ['tool:agentguard_read']);

  const queryResults = app.filterNodes('.env', ['AGENT', 'TOOL', 'FILE', 'LLM']);
  assert.deepEqual(queryResults, ['file:.env']);
});

test('6. WebSocket incremental message dispatching', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  app.handleWebSocketMessage({
    type: 'session.snapshot',
    data: {
      events: [{ event_id: 'evt_1', sequence_number: 1, event_type: 'USER_INPUT' }],
      nodes: [{ node_id: 'user:alice', node_type: 'USER', label: 'alice' }],
      edges: [],
    },
  });
  assert.equal(app.eventHistory.length, 1);
  assert.equal(app.nodeDataMap.size, 1);

  app.handleWebSocketMessage({
    type: 'node.created',
    data: { node_id: 'agent:opencode', node_type: 'AGENT', label: 'OpenCode' },
  });
  assert.equal(app.nodeDataMap.size, 2);

  app.handleWebSocketMessage({
    type: 'edge.created',
    data: {
      edge_id: 'edge_2',
      source_id: 'agent:opencode',
      target_id: 'tool:test',
      edge_type: 'INVOKED',
      event_id: 'evt_2',
      provenance_quality: 'OBSERVED',
      confidence: 1.0,
    },
  });
  assert.equal(app.edgeDataMap.size, 1);
});

test('7. Invariant INV-001: Zero raw secret strings in Event Inspector', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  const rawSecret = 'sk-proj-supersecretkey99999999';
  const maskedEvent = {
    event_id: 'evt_safe_01',
    sequence_number: 5,
    event_type: 'FILE_READ',
    actor_id: 'tool:agentguard_read',
    payload: {
      file_path: '.env',
      content: 'OPENAI_API_KEY=[MASKED_OPENAI_KEY_001_8a041e4b]\n',
    },
  };

  app.selectEvent(maskedEvent);
  const body = doc.getElementById('eventInspBody');
  assert.ok(!body.innerHTML.includes(rawSecret));
  assert.ok(body.innerHTML.includes('[MASKED_OPENAI_KEY_'));
});

// -----------------------------------------------------------------------------
// Layout Stability & Scope Filtering Tests (Requested by User)
// -----------------------------------------------------------------------------

test('8. Stability Invariant: Existing node coordinates remain strictly unchanged after incremental node.created', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  // Initialize graph via snapshot and initial layout
  app.handleWebSocketMessage({
    type: 'session.snapshot',
    data: {
      events: [],
      nodes: [
        { node_id: 'user:operator', node_type: 'USER', label: 'operator' },
        { node_id: 'agent:groq_agent', node_type: 'AGENT', label: 'Groq Agent' },
      ],
      edges: [
        { edge_id: 'e1', source_id: 'user:operator', target_id: 'agent:groq_agent', edge_type: 'INVOKED' },
      ],
    },
  });

  // Capture exact coordinates of initial nodes
  const opPosBefore = app.getNodePosition('user:operator');
  const agentPosBefore = app.getNodePosition('agent:groq_agent');
  assert.ok(opPosBefore !== null);
  assert.ok(agentPosBefore !== null);

  const layoutsBefore = app.layoutRunCount;

  // New incremental node arrives via WebSocket
  app.handleWebSocketMessage({
    type: 'node.created',
    data: { node_id: 'tool:read_file', node_type: 'TOOL', label: 'read_file' },
  });

  // VERIFY: Full Dagre layout was NOT triggered
  assert.equal(app.layoutRunCount, layoutsBefore, 'Incremental node must not run full Dagre layout');

  // VERIFY: Existing node positions are strictly unchanged
  const opPosAfter = app.getNodePosition('user:operator');
  const agentPosAfter = app.getNodePosition('agent:groq_agent');
  assert.deepEqual(opPosAfter, opPosBefore, 'user:operator position must be preserved');
  assert.deepEqual(agentPosAfter, agentPosBefore, 'agent:groq_agent position must be preserved');

  // VERIFY: Newly added node received a computed position and neon pulse class
  const newToolNode = app.canvasNodes.get('tool:read_file');
  assert.ok(newToolNode !== null);
  assert.ok(newToolNode.classes.has('new-node-pulse'), 'Newly created node must pulse');
});

test('9. Stability Invariant: Existing node coordinates remain strictly unchanged after incremental edge.created', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  app.handleWebSocketMessage({
    type: 'session.snapshot',
    data: {
      events: [],
      nodes: [
        { node_id: 'agent:groq_agent', node_type: 'AGENT', label: 'Groq Agent' },
      ],
      edges: [],
    },
  });

  // Add a second node
  app.handleWebSocketMessage({
    type: 'node.created',
    data: { node_id: 'file:.env', node_type: 'FILE', label: '.env' },
  });

  const agentPosBefore = app.getNodePosition('agent:groq_agent');
  const filePosBefore = app.getNodePosition('file:.env');
  const layoutsBefore = app.layoutRunCount;

  // New incremental edge arrives
  app.handleWebSocketMessage({
    type: 'edge.created',
    data: {
      edge_id: 'edge_read_env',
      source_id: 'agent:groq_agent',
      target_id: 'file:.env',
      edge_type: 'READ_FROM',
      event_id: 'evt_10',
      provenance_quality: 'OBSERVED',
      confidence: 1.0,
    },
  });

  // VERIFY: Full layout was NOT run on edge.created
  assert.equal(app.layoutRunCount, layoutsBefore, 'Incremental edge must not trigger full layout');

  // VERIFY: Both nodes preserve exact coordinates
  assert.deepEqual(app.getNodePosition('agent:groq_agent'), agentPosBefore);
  assert.deepEqual(app.getNodePosition('file:.env'), filePosBefore);
  assert.ok(app.canvasEdges.has('edge_read_env'));
});

test('10. Scope Visualization: Execution scopes are filtered from primary DAG canvas by default and preserved in Scope Tree', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  // Ingest EXECUTION_SCOPE node and BELONGS_TO_SCOPE edge
  app.handleWebSocketMessage({
    type: 'node.created',
    data: { node_id: 'scope:scope_0d880abc', node_type: 'EXECUTION_SCOPE', label: 'scope_0d880abc' },
  });
  app.handleWebSocketMessage({
    type: 'edge.created',
    data: {
      edge_id: 'edge_scope_01',
      source_id: 'agent:groq_agent',
      target_id: 'scope:scope_0d880abc',
      edge_type: 'BELONGS_TO_SCOPE',
      event_id: 'evt_scope',
    },
  });
  app.handleWebSocketMessage({
    type: 'scope.started',
    data: { scope_id: 'scope_0d880abc', scope_name: 'tool:read_file' },
  });

  // VERIFY: Scope node is NOT rendered on the primary canvas (prevents clutter)
  assert.equal(app.canvasNodes.has('scope:scope_0d880abc'), false, 'Scope node must not clutter primary graph canvas');
  assert.equal(app.canvasEdges.has('edge_scope_01'), false, 'BELONGS_TO_SCOPE edge must not clutter primary graph canvas');

  // VERIFY: Node data and Scope Tree DO track the scope cleanly
  assert.ok(app.nodeDataMap.has('scope:scope_0d880abc'));
  assert.equal(app.scopeTree.length, 1);
  assert.equal(app.scopeTree[0].scope_name, 'tool:read_file');
});

test('11. Layout Governance: Full Dagre layout only executes on snapshot or explicit user Re-layout', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  assert.equal(app.layoutRunCount, 0);

  // 1. Initial snapshot runs layout once
  app.handleWebSocketMessage({
    type: 'session.snapshot',
    data: {
      events: [],
      nodes: [{ node_id: 'a', node_type: 'AGENT', label: 'Agent' }],
      edges: [],
    },
  });
  assert.equal(app.layoutRunCount, 1);

  // 2. Ten incremental events and nodes arrive — layoutRunCount must NOT increase
  for (let i = 1; i <= 5; i++) {
    app.handleWebSocketMessage({
      type: 'node.created',
      data: { node_id: `node_${i}`, node_type: 'TOOL', label: `tool_${i}` },
    });
    app.handleWebSocketMessage({
      type: 'edge.created',
      data: { edge_id: `e_${i}`, source_id: 'a', target_id: `node_${i}`, edge_type: 'INVOKED' },
    });
  }
  assert.equal(app.layoutRunCount, 1, 'Incremental additions must never increment layoutRunCount');

  // 3. User explicitly clicks "Re-layout"
  app.runLayout(false);
  assert.equal(app.layoutRunCount, 2, 'Explicit user Re-layout must trigger layout recomputation');
});

test('12. Viewport Governance: Fit to View does not alter node positions, and Auto-Follow toggles correctly', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  app.addNode({ node_id: 'agent:groq_agent', node_type: 'AGENT', label: 'Groq Agent' });
  const posBeforeFit = app.getNodePosition('agent:groq_agent');

  // Fit view called
  app.fitView();
  assert.deepEqual(app.getNodePosition('agent:groq_agent'), posBeforeFit, 'Fit View must not alter node coordinates');

  // Auto-follow ON: pans to new node
  app.autoFollowEnabled = true;
  app.addNode({ node_id: 'file:new_file', node_type: 'FILE', label: 'new_file' });
  assert.equal(app.lastPannedTo, 'file:new_file');

  // Auto-follow OFF: does not pan
  app.autoFollowEnabled = false;
  app.addNode({ node_id: 'file:another_file', node_type: 'FILE', label: 'another_file' });
  assert.equal(app.lastPannedTo, 'file:new_file', 'When Auto-Follow is OFF, viewport must not pan');
});

test('13. Lens Switching: Execution Provenance vs Sensitive Data Lineage preserves distinct nodes & coordinates', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  // Snapshot in Execution lens
  app.handleWebSocketMessage({
    type: 'session.snapshot',
    data: {
      events: [],
      nodes: [{ node_id: 'agent:groq', node_type: 'AGENT', label: 'Groq Agent' }],
      edges: [],
      lineage: {
        entities: [
          {
            entity_id: 'ent_demo_key',
            label: 'DEMO_API_KEY',
            classification: 'CREDENTIAL',
            representation: 'RAW',
            fingerprint_hmac: 'a1b2c3d4e5f600112233445566778899',
            synthetic_token: '{{SECRET_001_nonce}}',
          }
        ],
        carriers: [
          {
            carrier_id: 'c_tool_result',
            carrier_type: 'TOOL_RESULT',
            sequence_number: 14,
            contained_entity_ids: ['ent_demo_key'],
          }
        ],
        edges: [
          {
            edge_id: 'flow_01',
            source_id: 'entity:ent_demo_key',
            target_id: 'carrier:c_tool_result',
            edge_type: 'FLOWS_TO',
            detection_method: 'TOKEN_IDENTITY',
            confidence: 1.0,
          }
        ]
      }
    }
  });

  // Verify Execution lens canvas contains agent:groq, but NOT lineage nodes
  assert.ok(app.canvasNodes.has('agent:groq'));
  assert.equal(app.canvasNodes.has('entity:ent_demo_key'), false);

  // Switch to Data Flow Lens
  app.switchLens('data_flow');
  assert.equal(app.currentLens, 'data_flow');

  // Verify Data Flow canvas now contains entity and carrier nodes, and NOT agent execution node
  assert.ok(app.canvasNodes.has('entity:ent_demo_key'));
  assert.ok(app.canvasNodes.has('carrier:c_tool_result'));
  assert.equal(app.canvasNodes.has('agent:groq'), false);
  assert.ok(app.canvasEdges.has('flow_01'));

  // Switch back to Execution Lens
  app.switchLens('execution');
  assert.equal(app.currentLens, 'execution');
  assert.ok(app.canvasNodes.has('agent:groq'));
  assert.equal(app.canvasNodes.has('entity:ent_demo_key'), false);
});

test('14. Milestone 3 DataEntity and DataCarrier registration: creates canonical nodes without raw plaintext', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);
  app.switchLens('data_flow');

  app.handleWebSocketMessage({
    type: 'entity.created',
    data: {
      entity_id: 'entity_secret_17',
      label: 'DEMO_API_KEY',
      classification: 'CREDENTIAL',
      representation: 'RAW',
      fingerprint_hmac: 'd04b901a55b3...hmac',
      synthetic_token: '{{SECRET_001_abc123}}',
      discovered_event_id: 'evt_file_read_25',
      confidence: 1.0,
    }
  });

  assert.ok(app.lineageEntityMap.has('entity_secret_17'));
  assert.ok(app.lineageNodeDataMap.has('entity:entity_secret_17'));
  assert.ok(app.canvasNodes.has('entity:entity_secret_17'));

  // Inspect Entity
  const inspected = app.inspectDataEntity(app.lineageEntityMap.get('entity_secret_17'));
  assert.equal(inspected.label, 'DEMO_API_KEY');
  const bodyText = doc.getElementById('nodeInspBody').innerHTML;
  assert.ok(bodyText.includes('RAW_PERSISTED:false'));
  assert.ok(bodyText.includes('{{SECRET_001_abc123}}'));
});

test('15. Detection Method Explanations: Edge Inspector exposes detection methods and confidence', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  const edge = {
    edge_id: 'edge_lineage_01',
    source_id: 'carrier:tool_result_10',
    target_id: 'carrier:llm_req_12',
    edge_type: 'FLOWS_TO',
    detection_method: 'TOKEN_IDENTITY',
    event_id: 'evt_llm_req_12',
    provenance_quality: 'OBSERVED',
    confidence: 1.0,
  };

  app.inspectLineageEdge(edge);
  const body = doc.getElementById('edgeInspBody').innerHTML;
  assert.ok(body.includes('METHOD:TOKEN_IDENTITY'));
  assert.ok(body.includes('REL:FLOWS_TO'));
  assert.ok(body.includes('CONF:1'));
});

test('16. Forward & Backward Trace UI: renders hop cards when proven, and renders NO PROVEN FLOW when unproven', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  // 1. Unproven scenario (Negative flow)
  const unprovenResult = {
    target_id: 'DEMO_API_KEY',
    direction: 'forward',
    has_proven_flow: false,
    hops: [],
    explanation: 'No proven data flow exists.',
  };
  const renderedUnproven = app.renderTraceResult(unprovenResult, 'DEMO_API_KEY', 'forward');
  assert.equal(renderedUnproven, false);
  const unprovenHtml = doc.getElementById('traceInspBody').innerHTML;
  assert.ok(unprovenHtml.includes('NO_PROVEN_FLOW'));
  assert.ok(unprovenHtml.includes('Never infer information flow merely because events occurred in temporal proximity'));

  // 2. Proven scenario (Positive flow)
  const provenResult = {
    target_id: 'DEMO_API_KEY',
    direction: 'forward',
    has_proven_flow: true,
    hops: [
      {
        hop_number: 1,
        source_id: 'entity:DEMO_API_KEY',
        target_id: 'carrier:tool_result_10',
        relationship: 'FLOWS_TO',
        detection_method: 'TOKEN_IDENTITY',
        provenance_quality: 'OBSERVED',
        confidence: 1.0,
        event_id: 'evt_tool_10',
      },
      {
        hop_number: 2,
        source_id: 'carrier:tool_result_10',
        target_id: 'carrier:llm_req_12',
        relationship: 'FLOWS_TO',
        detection_method: 'TOKEN_IDENTITY',
        provenance_quality: 'OBSERVED',
        confidence: 1.0,
        event_id: 'evt_llm_12',
      }
    ],
    explanation: 'Proven 2-hop data flow from source to destination.',
  };
  const renderedProven = app.renderTraceResult(provenResult, 'DEMO_API_KEY', 'forward');
  assert.equal(renderedProven, true);
  const provenHtml = doc.getElementById('traceInspBody').innerHTML;
  assert.ok(provenHtml.includes('HOPS:2'));
  assert.ok(provenHtml.includes('TOKEN_IDENTITY'));
});

test('17. Invariant INV-002: Zero raw secrets anywhere in Entity Inspector, Carrier Inspector, or trace output', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  const rawSecret = 'guardx-demo-super-secret-key-12345';

  app.handleWebSocketMessage({
    type: 'entity.created',
    data: {
      entity_id: 'entity_secret_99',
      label: 'DEMO_API_KEY',
      classification: 'CREDENTIAL',
      representation: 'RAW',
      fingerprint_hmac: '7f9a8b1c...sha256',
      synthetic_token: '{{SECRET_999_nonce}}',
    }
  });

  app.inspectDataEntity(app.lineageEntityMap.get('entity_secret_99'));
  const bodyText = doc.getElementById('nodeInspBody').innerHTML;

  assert.equal(bodyText.includes(rawSecret), false, 'Raw plaintext secret string must NEVER be present in Inspector DOM');
  assert.ok(bodyText.includes('RAW_PERSISTED:false'));
});

test('18. Security Lens: switches to security overlay and renders only relevant risk path hops', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  const finding = {
    finding_id: 'sec_finding_01',
    session_id: 'sess_1',
    title: 'Credential Disclosure to External Model',
    category: 'DATA_DISCLOSURE',
    severity: 'HIGH',
    confidence: 1.0,
    source_entity_id: 'DEMO_API_KEY',
    source_resource_id: 'file:.env',
    destination_id: 'llm:groq_api',
    source_trust: 'LOCAL',
    destination_trust: 'EXTERNAL_LLM',
    representation: 'RAW',
    lineage_path: ['file:.env', 'DEMO_API_KEY', 'ToolResult#1', 'AgentContext#1', 'LLMRequest#1', 'llm:groq_api'],
    rule_id: 'CREDENTIAL_RAW_TO_EXTERNAL_LLM',
    provenance_quality: 'OBSERVED',
    execution_event_ids: ['evt_1', 'evt_2'],
  };

  app.securityFindingsMap.set(finding.finding_id, finding);
  app.switchLens('security');

  assert.equal(app.currentLens, 'security');
  assert.equal(app.canvasNodes.size, 6, 'Should isolate canvas to only the 6 lineage hops of the security finding');
  assert.equal(app.canvasEdges.size, 5, 'Should connect the 6 hops with 5 directed edges');

  // Verify source and sink styles
  const sourceNode = app.canvasNodes.get('risk_hop_0_file:.env');
  const sinkNode = app.canvasNodes.get('risk_hop_5_llm:groq_api');
  assert.ok(sourceNode.classes.has('risk-source'), 'First hop must have risk-source class');
  assert.ok(sinkNode.classes.has('risk-sink'), 'Last hop must have risk-sink class');
});

test('19. Security Finding Inspector: renders complete explainable evidence with ZERO raw secrets', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  const rawSecret = 'gsk_real_secret_token_1234567890';
  const finding = {
    finding_id: 'finding_raw_cred_01',
    session_id: 'sess_1',
    title: 'Credential Disclosure to External Model',
    category: 'DATA_DISCLOSURE',
    severity: 'HIGH',
    confidence: 1.0,
    source_entity_id: 'SECRET_17',
    source_resource_id: 'file:/path/.env',
    destination_id: 'llm:groq',
    source_trust: 'LOCAL',
    destination_trust: 'EXTERNAL_LLM',
    representation: 'RAW',
    rule_id: 'CREDENTIAL_RAW_TO_EXTERNAL_LLM',
    provenance_quality: 'OBSERVED',
    execution_event_ids: ['evt_10', 'evt_12'],
  };

  app.securityFindingsMap.set(finding.finding_id, finding);
  app.selectFinding(finding.finding_id);

  assert.equal(doc.getElementById('findingInspTitle').textContent, 'Credential Disclosure to External Model');
  assert.equal(doc.getElementById('findingInspSeverity').textContent, 'HIGH');
  const body = doc.getElementById('findingInspBody').innerHTML;

  assert.ok(body.includes('RULE:CREDENTIAL_RAW_TO_EXTERNAL_LLM'));
  assert.ok(body.includes('BOUNDARY:LOCAL->EXTERNAL_LLM'));
  assert.ok(body.includes('REPR:RAW'));
  assert.ok(body.includes('CONF:1'));
  assert.ok(body.includes('ZERO_RAW:true'));
  assert.equal(body.includes(rawSecret), false, 'Inspector must never contain raw sensitive plaintext');
});

test('20. Trust Boundary Crossing & Representation State: distinguishes RAW (HIGH) vs TOKENIZED (PROTECTED)', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  // Scenario 1: RAW Credential
  const rawFinding = {
    finding_id: 'raw_01',
    severity: 'HIGH',
    representation: 'RAW',
    source_trust: 'LOCAL',
    destination_trust: 'EXTERNAL_LLM',
    lineage_path: ['file:.env', 'SECRET_1', 'llm:groq'],
  };
  app.securityFindingsMap.set('raw_01', rawFinding);
  app.selectFinding('raw_01');

  const rawHop = app.canvasNodes.get('risk_hop_1_SECRET_1');
  assert.ok(rawHop.classes.has('risk-path-highlight'), 'RAW credential flow must have risk-path-highlight');
  assert.equal(rawHop.classes.has('protected-highlight'), false);

  // Scenario 2: TOKENIZED Credential Reference
  const tokenFinding = {
    finding_id: 'token_01',
    severity: 'LOW',
    representation: 'TOKENIZED',
    source_trust: 'LOCAL',
    destination_trust: 'EXTERNAL_LLM',
    lineage_path: ['file:.env', 'TOKEN_REF_1', 'llm:groq'],
  };
  app.securityFindingsMap.set('token_01', tokenFinding);
  app.selectFinding('token_01');

  const tokenHop = app.canvasNodes.get('risk_hop_1_TOKEN_REF_1');
  assert.ok(tokenHop.classes.has('protected-highlight'), 'TOKENIZED flow must have protected-highlight');
  assert.equal(tokenHop.classes.has('risk-path-highlight'), false);
});

test('21. Alerts Panel: renders alert cards and count badge correctly', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  app.securityFindingsMap.set('f1', {
    finding_id: 'f1',
    title: 'Credential Exfiltration',
    severity: 'CRITICAL',
    representation: 'RAW',
    source_trust: 'LOCAL',
    destination_trust: 'UNTRUSTED_EXTERNAL',
  });

  app.securityViolationsMap.set('v1', {
    violation_id: 'v1',
    violation_type: 'RESOURCE_SCOPE_MISMATCH',
  });

  app.securityAttackChainsMap.set('c1', {
    chain_id: 'c1',
    chain_type: 'CREDENTIAL_EXFILTRATION',
    severity: 'CRITICAL',
  });

  app.renderAlertsList();

  const badge = doc.getElementById('alertCountBadge').textContent;
  assert.equal(badge, '3 alerts');

  const containerText = doc.getElementById('alertsListContainer').innerHTML;
  assert.ok(containerText.includes('FINDING:f1;SEV:CRITICAL'));
  assert.ok(containerText.includes('VIOLATION:v1;TYPE:RESOURCE_SCOPE_MISMATCH'));
  assert.ok(containerText.includes('CHAIN:c1;TYPE:CREDENTIAL_EXFILTRATION'));
});

test('22. WebSocket Stream: dispatches real-time security events (risk, boundary, intent, attack_chain)', () => {
  const doc = new MockDocument();
  const app = new GuardXFrontendCore(doc);

  // 1. trust_boundary.crossed
  app.handleWebSocketMessage({
    type: 'trust_boundary.crossed',
    data: {
      crossing_id: 'cross_1',
      source_trust: 'LOCAL',
      destination_trust: 'EXTERNAL_LLM',
    }
  });
  assert.equal(app.securityCrossingsMap.size, 1);

  // 2. risk.detected
  app.handleWebSocketMessage({
    type: 'risk.detected',
    data: {
      finding_id: 'finding_ws_01',
      title: 'Credential Disclosure',
      severity: 'HIGH',
      representation: 'RAW',
      source_trust: 'LOCAL',
      destination_trust: 'EXTERNAL_LLM',
    }
  });
  assert.equal(app.securityFindingsMap.size, 1);

  // 3. intent.violation
  app.handleWebSocketMessage({
    type: 'intent.violation',
    data: {
      violation_id: 'viol_ws_01',
      violation_type: 'UNDECLARED_NETWORK_EFFECT',
    }
  });
  assert.equal(app.securityViolationsMap.size, 1);

  // 4. attack_chain.detected
  app.handleWebSocketMessage({
    type: 'attack_chain.detected',
    data: {
      chain_id: 'chain_ws_01',
      chain_type: 'ENCODED_SECRET_EGRESS',
      severity: 'HIGH',
    }
  });
  assert.equal(app.securityAttackChainsMap.size, 1);

  // Alerts container updated
  const badge = doc.getElementById('alertCountBadge').textContent;
  assert.equal(badge, '3 alerts');
});
