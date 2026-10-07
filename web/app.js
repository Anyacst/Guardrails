/**
 * GuardX Security Investigation Console — Frontend Application
 * 
 * Powered by Cytoscape.js for Execution Provenance & Sensitive Data Lineage.
 * Streams live runtime events over WebSockets.
 * 
 * Milestone 3 Invariants:
 * - Strict separation of Execution Provenance and Sensitive Data Lineage lenses.
 * - Evidence-based data propagation: NEVER infer flow from temporal proximity alone.
 * - Zero raw secrets in DOM, Inspectors, console logs, or client state.
 * - Stable incremental graph coordinates: layout only runs on initial snapshot or explicit Re-layout.
 */

// State
let cy = null;
let currentSessionId = "opencode_live_session";
let currentLens = "execution"; // "execution" | "data_flow"
let ws = null;
let eventHistory = [];
let nodeDataMap = new Map();
let edgeDataMap = new Map();
let scopeTree = [];
let demoStepCounter = 1;
let autoFollowEnabled = true;
let showScopeNodesInGraph = false;
let lastPlacedPosition = { x: 300, y: 150 };

// Milestone 3 Data Lineage State
let lineageData = { nodes: [], edges: [], entities: [], carriers: [], transformations: [] };
let lineageNodeDataMap = new Map();
let lineageEdgeDataMap = new Map();
let lineageEntityMap = new Map();
let lineageCarrierMap = new Map();
let executionNodePositions = new Map();
let lineageNodePositions = new Map();

// Milestone 4 Security Intelligence State
let securityData = { findings: [], crossings: [], attack_chains: [], intent_violations: [] };
let securityFindingsMap = new Map();
let securityCrossingsMap = new Map();
let securityAttackChainsMap = new Map();
let securityViolationsMap = new Map();
let securityNodePositions = new Map();
let selectedFindingId = null;

// Document Ready
document.addEventListener("DOMContentLoaded", () => {
  initCytoscape();
  initUIEventListeners();
  loadSessionList();
  connectWebSocket(currentSessionId);
});

/* -------------------------------------------------------------------------- */
/* Cytoscape Initialization & Stylesheet                                      */
/* -------------------------------------------------------------------------- */
function initCytoscape() {
  cy = cytoscape({
    container: document.getElementById("cy"),
    boxSelectionEnabled: false,
    autounselectify: false,
    elements: [],
    style: [
      {
        selector: "node",
        style: {
          "label": "data(label)",
          "color": "#f1f5f9",
          "font-family": "Inter, sans-serif",
          "font-size": "11px",
          "text-valign": "bottom",
          "text-margin-y": "6px",
          "text-wrap": "ellipsis",
          "text-max-width": "140px",
          "width": "42px",
          "height": "42px",
          "background-color": "#334155",
          "border-width": "2px",
          "border-color": "#64748b",
          "transition-property": "border-color, border-width, background-color",
          "transition-duration": "0.2s"
        }
      },
      // Execution Provenance Node Types
      {
        selector: 'node[node_type = "USER"]',
        style: {
          "shape": "ellipse",
          "background-color": "#0284c7",
          "border-color": "#38bdf8",
        }
      },
      {
        selector: 'node[node_type = "AGENT"]',
        style: {
          "shape": "hexagon",
          "background-color": "#7e22ce",
          "border-color": "#a855f7",
          "width": "48px",
          "height": "48px",
        }
      },
      {
        selector: 'node[node_type = "TOOL"]',
        style: {
          "shape": "round-rectangle",
          "background-color": "#b45309",
          "border-color": "#f59e0b",
        }
      },
      {
        selector: 'node[node_type = "FILE"]',
        style: {
          "shape": "rectangle",
          "background-color": "#1e3a8a",
          "border-color": "#3b82f6",
        }
      },
      {
        selector: 'node[node_type = "PROCESS"]',
        style: {
          "shape": "octagon",
          "background-color": "#334155",
          "border-color": "#94a3b8",
        }
      },
      {
        selector: 'node[node_type = "NETWORK_ENDPOINT"]',
        style: {
          "shape": "diamond",
          "background-color": "#831843",
          "border-color": "#f43f5e",
          "width": "46px",
          "height": "46px",
        }
      },
      {
        selector: 'node[node_type = "LLM"]',
        style: {
          "shape": "round-hexagon",
          "background-color": "#b45309",
          "border-color": "#f59e0b",
          "width": "48px",
          "height": "48px",
        }
      },
      {
        selector: 'node[node_type = "EXECUTION_SCOPE"]',
        style: {
          "shape": "round-rectangle",
          "background-color": "rgba(168, 85, 247, 0.08)",
          "border-color": "#c084fc",
          "border-style": "dashed",
          "border-width": "1.5px",
        }
      },
      // Milestone 3 Data Lineage Node Styles
      {
        selector: 'node[node_type = "DATA_ENTITY"]',
        style: {
          "shape": "round-tag",
          "background-color": "#065f46",
          "border-color": "#10b981",
          "border-width": "2.5px",
          "width": "48px",
          "height": "48px",
        }
      },
      {
        selector: 'node[representation = "TOKENIZED"]',
        style: {
          "background-color": "#155e75",
          "border-color": "#06b6d4",
          "border-width": "2.5px",
        }
      },
      {
        selector: 'node[representation = "ENCODED"]',
        style: {
          "background-color": "#701a75",
          "border-color": "#d946ef",
          "border-width": "2.5px",
        }
      },
      {
        selector: 'node[node_type = "DATA_CARRIER"]',
        style: {
          "shape": "round-rectangle",
          "background-color": "#4c1d95",
          "border-color": "#8b5cf6",
          "border-width": "2px",
          "width": "54px",
          "height": "44px",
        }
      },
      // Selected & Highlighted Node State
      {
        selector: "node:selected",
        style: {
          "border-color": "#00f0ff",
          "border-width": "4px",
          "shadow-blur": "12px",
          "shadow-color": "#00f0ff",
          "shadow-opacity": "0.8"
        }
      },
      {
        selector: "node.causal-highlight",
        style: {
          "border-color": "#a855f7",
          "border-width": "4px",
          "shadow-blur": "15px",
          "shadow-color": "#a855f7",
          "shadow-opacity": "0.9"
        }
      },
      {
        selector: "node.new-node-pulse",
        style: {
          "border-color": "#00f0ff",
          "border-width": "5px",
          "shadow-blur": "25px",
          "shadow-color": "#00f0ff",
          "shadow-opacity": "1.0",
        }
      },
      {
        selector: "node.trace-path-highlight",
        style: {
          "border-color": "#f43f5e",
          "border-width": "5px",
          "shadow-blur": "25px",
          "shadow-color": "#f43f5e",
          "shadow-opacity": "1.0",
        }
      },
      // Directed Edges
      {
        selector: "edge",
        style: {
          "label": "data(edge_type)",
          "color": "#94a3b8",
          "font-family": "Inter, sans-serif",
          "font-size": "9px",
          "text-rotation": "autorotate",
          "text-margin-y": "-6px",
          "curve-style": "bezier",
          "target-arrow-shape": "triangle",
          "line-color": "#475569",
          "target-arrow-color": "#475569",
          "arrow-scale": 0.9,
          "width": 2,
          "transition-property": "line-color, target-arrow-color, width",
          "transition-duration": "0.2s"
        }
      },
      // Milestone 3 Lineage Edges
      {
        selector: 'edge[edge_type = "FLOWS_TO"]',
        style: {
          "line-color": "#10b981",
          "target-arrow-color": "#10b981",
          "width": 3,
        }
      },
      {
        selector: 'edge[edge_type = "CONTAINS"]',
        style: {
          "line-color": "#38bdf8",
          "target-arrow-color": "#38bdf8",
          "line-style": "dashed",
          "width": 2,
        }
      },
      {
        selector: 'edge[edge_type = "TRANSFORMED_TO"], edge[edge_type = "DERIVED_FROM"]',
        style: {
          "line-color": "#e879f9",
          "target-arrow-color": "#e879f9",
          "line-style": "dotted",
          "width": 2.5,
        }
      },
      {
        selector: 'edge[edge_type = "PRODUCED_BY"], edge[edge_type = "USED_BY"]',
        style: {
          "line-color": "#a855f7",
          "target-arrow-color": "#a855f7",
          "width": 2,
        }
      },
      {
        selector: "edge:selected",
        style: {
          "line-color": "#00f0ff",
          "target-arrow-color": "#00f0ff",
          "width": 3.5,
          "color": "#00f0ff"
        }
      },
      {
        selector: "edge.trace-path-highlight",
        style: {
          "line-color": "#f43f5e",
          "target-arrow-color": "#f43f5e",
          "width": 4.5,
          "shadow-blur": "15px",
          "shadow-color": "#f43f5e",
          "shadow-opacity": "0.9",
        }
      },
      {
        selector: 'edge[edge_type = "BELONGS_TO_SCOPE"]',
        style: {
          "line-style": "dashed",
          "opacity": 0.45,
          "width": 1.2,
          "label": ""
        }
      },
      // Milestone 4 Security Intelligence Styles
      {
        selector: 'node[node_type = "TRUST_BOUNDARY"]',
        style: {
          "shape": "round-rectangle",
          "background-color": "rgba(225, 29, 72, 0.25)",
          "border-color": "#f43f5e",
          "border-style": "dashed",
          "border-width": "2.5px",
          "width": "68px",
          "height": "46px",
          "color": "#fecdd3",
          "font-size": "10px",
          "font-weight": "bold"
        }
      },
      {
        selector: "node.risk-source",
        style: {
          "border-color": "#ef4444",
          "border-width": "5px",
          "shadow-blur": "25px",
          "shadow-color": "#ef4444",
          "shadow-opacity": "1.0",
        }
      },
      {
        selector: "node.risk-sink",
        style: {
          "border-color": "#f97316",
          "border-width": "5px",
          "shadow-blur": "25px",
          "shadow-color": "#f97316",
          "shadow-opacity": "1.0",
        }
      },
      {
        selector: "node.risk-path-highlight",
        style: {
          "border-color": "#dc2626",
          "border-width": "4.5px",
          "shadow-blur": "20px",
          "shadow-color": "#dc2626",
          "shadow-opacity": "0.9",
        }
      },
      {
        selector: "node.protected-highlight",
        style: {
          "border-color": "#10b981",
          "border-width": "4.5px",
          "shadow-blur": "20px",
          "shadow-color": "#10b981",
          "shadow-opacity": "0.9",
        }
      },
      {
        selector: "node.dimmed",
        style: {
          "opacity": 0.15
        }
      },
      {
        selector: "edge.risk-path-highlight",
        style: {
          "line-color": "#ef4444",
          "target-arrow-color": "#ef4444",
          "width": 5,
          "shadow-blur": "18px",
          "shadow-color": "#ef4444",
          "shadow-opacity": "0.9",
        }
      },
      {
        selector: "edge.protected-highlight",
        style: {
          "line-color": "#10b981",
          "target-arrow-color": "#10b981",
          "width": 4.5,
          "shadow-blur": "15px",
          "shadow-color": "#10b981",
          "shadow-opacity": "0.8",
        }
      },
      {
        selector: "edge.trust-boundary-edge",
        style: {
          "line-color": "#f43f5e",
          "target-arrow-color": "#f43f5e",
          "line-style": "dashed",
          "width": 3.5,
        }
      },
      {
        selector: "edge.dimmed",
        style: {
          "opacity": 0.12
        }
      }
    ],
    layout: {
      name: "cose",
      animate: false,
      padding: 50,
      nodeRepulsion: 6500,
      idealEdgeLength: 80
    }
  });

  // Node Click Inspector Handler
  cy.on("tap", "node", (evt) => {
    const node = evt.target;
    selectNode(node.id());
  });

  // Edge Click Inspector Handler
  cy.on("tap", "edge", (evt) => {
    const edge = evt.target;
    selectEdge(edge.id());
  });

  // Canvas Tap (Deselect)
  cy.on("tap", (evt) => {
    if (evt.target === cy) {
      clearHighlights();
    }
  });
}

/* -------------------------------------------------------------------------- */
/* Lens Switching (Execution Provenance vs Sensitive Data Lineage)            */
/* -------------------------------------------------------------------------- */
function switchLens(newLens) {
  if (newLens === currentLens) return;

  // Save positions of current active canvas
  saveCurrentNodePositions();

  currentLens = newLens;

  // Update Lens Tab Buttons
  document.querySelectorAll(".lens-tab").forEach(tab => {
    tab.classList.toggle("active", tab.dataset.lens === currentLens);
  });

  // Update Semantic Disclaimer Banner
  const bannerBadge = document.querySelector(".lens-disclaimer-banner .banner-badge");
  const bannerText = document.querySelector(".lens-disclaimer-banner .banner-text");

  if (currentLens === "security") {
    if (bannerBadge) bannerBadge.textContent = "LENS: SECURITY INTELLIGENCE OVERLAY (M4)";
    if (bannerText) bannerText.innerHTML = "Displays explainable risk paths, trust boundary crossings, and attack chains. <strong>(Strict proven-flow invariant &bull; Zero raw secrets)</strong>";
    renderSecurityCanvas(selectedFindingId);
  } else if (currentLens === "data_flow") {
    if (bannerBadge) bannerBadge.textContent = "LENS: SENSITIVE DATA LINEAGE (M3)";
    if (bannerText) bannerText.innerHTML = "Displays proven information flow and data entity carriers. <strong>(Zero raw secrets persisted &bull; Evidence-based hops)</strong>";
    renderDataFlowCanvas();
  } else {
    if (bannerBadge) bannerBadge.textContent = "LENS: EXECUTION PROVENANCE";
    if (bannerText) bannerText.innerHTML = "Displays runtime execution and causal task relationships. <strong>(Data Lineage unestablished until Milestone 3)</strong>";
    renderExecutionCanvas();
  }
}

function saveCurrentNodePositions() {
  if (!cy) return;
  const targetMap = currentLens === "data_flow"
    ? lineageNodePositions
    : (currentLens === "security" ? securityNodePositions : executionNodePositions);
  cy.nodes().forEach(n => {
    targetMap.set(n.id(), { ...n.position() });
  });
}

function renderSecurityCanvas(findingId = null) {
  cy.elements().remove();

  const targetFindingId = findingId || selectedFindingId;
  const finding = targetFindingId
    ? securityFindingsMap.get(targetFindingId)
    : (securityFindingsMap.size > 0 ? securityFindingsMap.values().next().value : null);

  // If there are no findings, check intent violations or display clean state
  if (!finding) {
    if (securityViolationsMap.size > 0) {
      const v = securityViolationsMap.values().next().value;
      cy.add({
        group: "nodes",
        data: {
          id: `violation:${v.violation_id}`,
          label: `INTENT VIOLATION\n${v.violation_type}\nScope: ${v.scope_id}`,
          node_type: "EXECUTION_SCOPE",
        },
        position: { x: 300, y: 150 },
      });
      cy.add({
        group: "nodes",
        data: {
          id: `violation_desc:${v.violation_id}`,
          label: `${v.description}\n(Zero sensitive leak)`,
          node_type: "FILE",
        },
        position: { x: 550, y: 150 },
      });
      cy.add({
        group: "edges",
        data: {
          id: `v_edge:${v.violation_id}`,
          source: `violation:${v.violation_id}`,
          target: `violation_desc:${v.violation_id}`,
          edge_type: "VIOLATES_CONTRACT",
        }
      });
      cy.fit(null, 50);
      return;
    }

    cy.add({
      group: "nodes",
      data: {
        id: "clean_state_m4",
        label: "NO DANGEROUS DATA FLOWS DETECTED\n(Proven-Flow Invariant Enforced: 0 Unproven Alerts)",
        node_type: "EXECUTION_SCOPE"
      },
      position: { x: 350, y: 200 }
    });
    cy.fit(null, 50);
    return;
  }

  // Construct visual graph for the explainable risk path
  let pathHops = [];
  if (finding.lineage_path && finding.lineage_path.length > 0) {
    if (typeof finding.lineage_path[0] === "string") {
      pathHops = [...finding.lineage_path];
    } else {
      const ordered = [];
      finding.lineage_path.forEach(h => {
        if (h && h.source && !ordered.includes(h.source)) ordered.push(h.source);
        if (h && h.destination && !ordered.includes(h.destination)) ordered.push(h.destination);
      });
      pathHops = ordered;
    }
  } else {
    pathHops = [finding.source_resource_id || "SOURCE", finding.source_entity_id || "DATA_ENTITY", finding.destination_id || "DESTINATION"];
  }

  const isProtected = finding.representation === "TOKENIZED" || finding.severity === "NONE" || finding.severity === "LOW";
  const nodesToAdd = [];
  const edgesToAdd = [];
  let prevId = null;

  pathHops.forEach((hop, idx) => {
    const isFirst = idx === 0;
    const isLast = idx === pathHops.length - 1;
    const hopId = `risk_hop_${idx}_${hop.replace(/[^a-zA-Z0-9_-]/g, '_')}`;

    let nodeType = "DATA_CARRIER";
    if (isFirst) nodeType = hop.includes("file:") || hop.includes(".env") ? "FILE" : "DATA_CARRIER";
    else if (isLast) nodeType = hop.includes("llm:") || hop.includes("groq") ? "LLM" : "NETWORK_ENDPOINT";
    else if (hop.includes("DEMO_API_KEY") || hop.includes("SECRET") || hop.includes("KEY")) nodeType = "DATA_ENTITY";

    const label = isFirst
      ? `SOURCE: ${hop}`
      : (isLast ? `DESTINATION: ${hop}\n[${finding.destination_trust}]` : hop);

    const xPos = 120 + idx * 170;
    const yPos = 220 + (idx % 2 === 0 ? 0 : 25);

    nodesToAdd.push({
      group: "nodes",
      data: {
        id: hopId,
        label: label,
        node_type: nodeType,
        representation: finding.representation,
        properties: { hop: hop, step: idx + 1, finding_id: finding.finding_id }
      },
      position: { x: xPos, y: yPos }
    });

    if (prevId) {
      edgesToAdd.push({
        group: "edges",
        data: {
          id: `edge_${prevId}_to_${hopId}`,
          source: prevId,
          target: hopId,
          edge_type: idx === pathHops.length - 1 ? "EGRESS" : "FLOWS_TO"
        }
      });
    }

    prevId = hopId;
  });

  nodesToAdd.forEach(n => cy.add(n));
  edgesToAdd.forEach(e => cy.add(e));

  // Style the hops
  const firstEle = cy.getElementById(nodesToAdd[0].data.id);
  const lastEle = cy.getElementById(nodesToAdd[nodesToAdd.length - 1].data.id);

  if (firstEle.length > 0) firstEle.addClass("risk-source");
  if (lastEle.length > 0) lastEle.addClass("risk-sink");

  if (isProtected) {
    cy.nodes().addClass("protected-highlight");
    cy.edges().addClass("protected-highlight");
  } else {
    cy.nodes().addClass("risk-path-highlight");
    cy.edges().addClass("risk-path-highlight");
  }

  cy.fit(null, 50);
}

function renderExecutionCanvas() {
  cy.elements().remove();
  let hasRestoredPositions = false;

  for (const nodeData of nodeDataMap.values()) {
    if (shouldDisplayNode(nodeData)) {
      const pos = executionNodePositions.get(nodeData.node_id);
      const nodeOpts = {
        group: "nodes",
        data: {
          id: nodeData.node_id,
          label: nodeData.label || nodeData.node_id,
          node_type: nodeData.node_type,
          session_id: nodeData.session_id,
          properties: nodeData.properties
        }
      };
      if (pos) {
        nodeOpts.position = pos;
        hasRestoredPositions = true;
      }
      cy.add(nodeOpts);
    }
  }

  for (const edgeData of edgeDataMap.values()) {
    if (shouldDisplayEdge(edgeData)) {
      if (cy.getElementById(edgeData.source_id).length > 0 && cy.getElementById(edgeData.target_id).length > 0) {
        cy.add({
          group: "edges",
          data: {
            id: edgeData.edge_id,
            source: edgeData.source_id,
            target: edgeData.target_id,
            edge_type: edgeData.edge_type,
            event_id: edgeData.event_id,
            provenance_quality: edgeData.provenance_quality,
            confidence: edgeData.confidence
          }
        });
      }
    }
  }

  if (!hasRestoredPositions && cy.nodes().length > 0) {
    runLayout(true);
  } else {
    cy.fit(null, 40);
  }
}

function renderDataFlowCanvas() {
  cy.elements().remove();
  let hasRestoredPositions = false;

  for (const nodeData of lineageNodeDataMap.values()) {
    const pos = lineageNodePositions.get(nodeData.node_id);
    const nodeOpts = {
      group: "nodes",
      data: {
        id: nodeData.node_id,
        label: nodeData.label || nodeData.node_id,
        node_type: nodeData.node_type,
        session_id: nodeData.session_id,
        representation: (nodeData.properties && nodeData.properties.representation) || "RAW",
        properties: nodeData.properties
      }
    };
    if (pos) {
      nodeOpts.position = pos;
      hasRestoredPositions = true;
    }
    cy.add(nodeOpts);
  }

  for (const edgeData of lineageEdgeDataMap.values()) {
    if (cy.getElementById(edgeData.source_id).length > 0 && cy.getElementById(edgeData.target_id).length > 0) {
      cy.add({
        group: "edges",
        data: {
          id: edgeData.edge_id,
          source: edgeData.source_id,
          target: edgeData.target_id,
          edge_type: edgeData.edge_type,
          event_id: edgeData.event_id,
          provenance_quality: edgeData.provenance_quality,
          confidence: edgeData.confidence,
          detection_method: edgeData.detection_method,
        }
      });
    }
  }

  if (!hasRestoredPositions && cy.nodes().length > 0) {
    runLayout(true);
  } else {
    cy.fit(null, 40);
  }
}

/* -------------------------------------------------------------------------- */
/* WebSocket Real-Time Connection & Live Stream Management                     */
/* -------------------------------------------------------------------------- */
function connectWebSocket(sessionId) {
  if (ws) {
    ws.close();
  }

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/sessions/${sessionId}`;

  ws = new WebSocket(wsUrl);

  const statusBadge = document.getElementById("connectionStatus");
  const statusText = statusBadge.querySelector(".status-text");

  ws.onopen = () => {
    statusBadge.className = "status-badge status-live";
    statusText.textContent = "LIVE STREAM";
    console.log(`[GuardX] WebSocket connected to session ${sessionId}`);
  };

  ws.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      handleWebSocketMessage(msg);
    } catch (e) {
      console.error("[GuardX] WS message parse error:", e);
    }
  };

  ws.onclose = () => {
    statusBadge.className = "status-badge";
    statusBadge.style.background = "rgba(244, 63, 94, 0.2)";
    statusBadge.style.color = "#fb7185";
    statusText.textContent = "OFFLINE";
    // Attempt reconnect after 3 seconds
    setTimeout(() => connectWebSocket(currentSessionId), 3000);
  };
}

function shouldDisplayNode(nodeData) {
  if (nodeData.node_type === "EXECUTION_SCOPE" && !showScopeNodesInGraph) {
    return false;
  }
  return true;
}

function shouldDisplayEdge(edgeData) {
  if (edgeData.edge_type === "BELONGS_TO_SCOPE" && !showScopeNodesInGraph) {
    return false;
  }
  const src = nodeDataMap.get(edgeData.source_id);
  const tgt = nodeDataMap.get(edgeData.target_id);
  if (src && !shouldDisplayNode(src)) return false;
  if (tgt && !shouldDisplayNode(tgt)) return false;
  return true;
}

function computeIncrementalPosition(nodeData) {
  const isLineage = currentLens === "data_flow";
  const edgeMap = isLineage ? lineageEdgeDataMap : edgeDataMap;

  // Check if this node is connected to an existing node
  let referenceNode = null;
  let isTarget = false;

  for (const [edgeId, edge] of edgeMap.entries()) {
    if (edge.target_id === nodeData.node_id) {
      const srcNode = cy.getElementById(edge.source_id);
      if (srcNode.length > 0) {
        referenceNode = srcNode;
        isTarget = true;
        break;
      }
    } else if (edge.source_id === nodeData.node_id) {
      const tgtNode = cy.getElementById(edge.target_id);
      if (tgtNode.length > 0) {
        referenceNode = tgtNode;
        isTarget = false;
        break;
      }
    }
  }

  if (referenceNode && referenceNode.length > 0) {
    const refPos = referenceNode.position();
    const jitterX = (Math.random() - 0.5) * 40;
    const offsetY = isTarget ? 95 + Math.random() * 20 : -95 - Math.random() * 20;
    return {
      x: refPos.x + jitterX,
      y: refPos.y + offsetY
    };
  }

  // Tiered fallback positions
  const tierY = {
    USER: 80,
    AGENT: 180,
    LLM: 180,
    TOOL: 320,
    FILE: 460,
    PROCESS: 460,
    NETWORK_ENDPOINT: 320,
    EXECUTION_SCOPE: 120,
    DATA_ENTITY: 160,
    DATA_CARRIER: 280,
  };

  const baseY = tierY[nodeData.node_type] || 250;
  const existingCount = cy.nodes(`[node_type = "${nodeData.node_type}"]`).length;
  const baseX = nodeData.node_type === "LLM" ? 560 : (240 + existingCount * 130);

  const pos = {
    x: baseX,
    y: baseY + (existingCount % 2 === 0 ? 0 : 25)
  };
  lastPlacedPosition = pos;
  return pos;
}

function handleWebSocketMessage(msg) {
  if (msg.type === "session.snapshot") {
    // Initial Snapshot
    eventHistory = msg.data.events || [];
    renderTimeline();

    // Execution Nodes & Edges
    nodeDataMap.clear();
    edgeDataMap.clear();
    if (msg.data.nodes) {
      msg.data.nodes.forEach(n => nodeDataMap.set(n.node_id, n));
    }
    if (msg.data.edges) {
      msg.data.edges.forEach(e => edgeDataMap.set(e.edge_id, e));
    }

    // Lineage Snapshot
    if (msg.data.lineage) {
      loadLineageSnapshot(msg.data.lineage);
    }

    // Security Intelligence Snapshot (Milestone 4)
    if (msg.data.security) {
      loadSecuritySnapshot(msg.data.security);
    }

    if (currentLens === "security") {
      renderSecurityCanvas(selectedFindingId);
    } else if (currentLens === "data_flow") {
      renderDataFlowCanvas();
    } else {
      renderExecutionCanvas();
    }

  } else if (msg.type === "event.created") {
    eventHistory.push(msg.data);
    appendTimelineItem(msg.data);
    updateEventCounter();

  } else if (msg.type === "node.created") {
    nodeDataMap.set(msg.data.node_id, msg.data);
    if (currentLens === "execution") {
      addOrUpdateNode(msg.data, false);
    }

  } else if (msg.type === "edge.created") {
    edgeDataMap.set(msg.data.edge_id, msg.data);
    if (currentLens === "execution") {
      addOrUpdateEdge(msg.data, false);
    }

  } else if (msg.type === "entity.created") {
    handleEntityCreated(msg.data);

  } else if (msg.type === "carrier.created") {
    handleCarrierCreated(msg.data);

  } else if (msg.type === "flow.created") {
    handleFlowCreated(msg.data);

  } else if (msg.type === "transformation.created") {
    lineageData.transformations.push(msg.data);

  } else if (msg.type === "scope.started") {
    addScopeTreeItem(msg.data);

  } else if (msg.type === "trust_boundary.crossed") {
    securityCrossingsMap.set(msg.data.crossing_id, msg.data);
    if (currentLens === "security") {
      renderSecurityCanvas(selectedFindingId);
    }

  } else if (msg.type === "risk.detected") {
    securityFindingsMap.set(msg.data.finding_id, msg.data);
    renderAlertsList();
    if (currentLens === "security") {
      renderSecurityCanvas(selectedFindingId || msg.data.finding_id);
    }

  } else if (msg.type === "intent.violation") {
    securityViolationsMap.set(msg.data.violation_id, msg.data);
    renderAlertsList();
    if (currentLens === "security") {
      renderSecurityCanvas();
    }

  } else if (msg.type === "attack_chain.detected") {
    securityAttackChainsMap.set(msg.data.chain_id, msg.data);
    renderAlertsList();
  }
}

/* -------------------------------------------------------------------------- */
/* Lineage Event Processing & Real-Time Sync                                  */
/* -------------------------------------------------------------------------- */
function loadLineageSnapshot(lineage) {
  lineageData = lineage;
  lineageNodeDataMap.clear();
  lineageEdgeDataMap.clear();
  lineageEntityMap.clear();
  lineageCarrierMap.clear();

  if (lineage.entities) {
    lineage.entities.forEach(e => lineageEntityMap.set(e.entity_id, e));
  }
  if (lineage.carriers) {
    lineage.carriers.forEach(c => lineageCarrierMap.set(c.carrier_id, c));
  }
  if (lineage.nodes) {
    lineage.nodes.forEach(n => lineageNodeDataMap.set(n.node_id, n));
  }
  if (lineage.edges) {
    lineage.edges.forEach(e => lineageEdgeDataMap.set(e.edge_id, e));
  }

  renderEntitiesList();
}

/* -------------------------------------------------------------------------- */
/* Security Intelligence Processing & Real-Time Sync (Milestone 4)            */
/* -------------------------------------------------------------------------- */
function loadSecuritySnapshot(sec) {
  securityData = sec || { findings: [], crossings: [], attack_chains: [], intent_violations: [] };
  securityFindingsMap.clear();
  securityCrossingsMap.clear();
  securityAttackChainsMap.clear();
  securityViolationsMap.clear();

  if (securityData.findings) {
    securityData.findings.forEach(f => securityFindingsMap.set(f.finding_id, f));
  }
  if (securityData.crossings) {
    securityData.crossings.forEach(c => securityCrossingsMap.set(c.crossing_id, c));
  }
  if (securityData.attack_chains) {
    securityData.attack_chains.forEach(a => securityAttackChainsMap.set(a.chain_id, a));
  }
  if (securityData.intent_violations) {
    securityData.intent_violations.forEach(v => securityViolationsMap.set(v.violation_id, v));
  }

  renderAlertsList();
  if (currentLens === "security") {
    renderSecurityCanvas(selectedFindingId);
  }
}

function renderAlertsList() {
  const container = document.getElementById("alertsListContainer");
  const countBadge = document.getElementById("alertCountBadge");
  if (!container) return;

  const totalCount = securityFindingsMap.size + securityViolationsMap.size + securityAttackChainsMap.size;
  if (countBadge) {
    countBadge.textContent = `${totalCount} alert${totalCount === 1 ? '' : 's'}`;
  }

  if (totalCount === 0) {
    container.innerHTML = '<div class="empty-hint">No security findings detected.</div>';
    return;
  }

  container.innerHTML = "";

  // 1. Findings
  for (const finding of securityFindingsMap.values()) {
    const card = document.createElement("div");
    card.className = `alert-card ${finding.severity} ${selectedFindingId === finding.finding_id ? 'selected' : ''}`;
    card.dataset.findingId = finding.finding_id;

    const isTokenized = finding.representation === "TOKENIZED";
    const repBadge = isTokenized ? "badge-tokenized" : (finding.representation === "ENCODED" ? "badge-encoded" : "badge-raw");

    card.innerHTML = `
      <div class="alert-card-header">
        <span class="alert-card-title">${finding.title}</span>
        <span class="badge badge-${finding.severity.toLowerCase()}">${finding.severity}</span>
      </div>
      <div class="entity-card-meta">
        <span class="badge ${repBadge}">${finding.representation || "RAW"}</span>
        <span class="badge" style="background: rgba(244, 63, 94, 0.2); color: #fda4af; border: 1px solid #f43f5e;">
          ${finding.source_trust} ➔ ${finding.destination_trust}
        </span>
      </div>
      <div class="alert-card-route mono">${finding.source_resource_id || finding.source_entity_id || 'unknown'} ➔ ${finding.destination_id || 'unknown'}</div>
    `;

    card.addEventListener("click", () => {
      document.querySelectorAll(".alert-card").forEach(c => c.classList.remove("selected"));
      card.classList.add("selected");
      switchLens("security");
      selectFinding(finding.finding_id);
    });

    container.appendChild(card);
  }

  // 2. Intent Violations
  for (const v of securityViolationsMap.values()) {
    const card = document.createElement("div");
    card.className = `alert-card HIGH`;
    card.dataset.violationId = v.violation_id;
    card.innerHTML = `
      <div class="alert-card-header">
        <span class="alert-card-title">Intent Violation: ${v.violation_type}</span>
        <span class="badge badge-high">HIGH</span>
      </div>
      <div class="alert-card-route mono">${v.description}</div>
    `;
    card.addEventListener("click", () => {
      switchLens("security");
      renderSecurityCanvas();
    });
    container.appendChild(card);
  }

  // 3. Attack Chains
  for (const chain of securityAttackChainsMap.values()) {
    const card = document.createElement("div");
    card.className = `alert-card ${chain.severity || 'HIGH'}`;
    card.dataset.chainId = chain.chain_id;
    card.innerHTML = `
      <div class="alert-card-header">
        <span class="alert-card-title">Attack Chain: ${chain.chain_type}</span>
        <span class="badge badge-${(chain.severity || 'high').toLowerCase()}">${chain.severity || 'HIGH'}</span>
      </div>
      <div class="alert-card-route mono">${chain.explanation}</div>
    `;
    container.appendChild(card);
  }
}

function selectFinding(findingId) {
  selectedFindingId = findingId;
  const finding = securityFindingsMap.get(findingId);
  if (!finding) return;

  switchInspectorTab("findingInsp");

  const titleEl = document.getElementById("findingInspTitle");
  if (titleEl) titleEl.textContent = finding.title;

  const sevBadge = document.getElementById("findingInspSeverity");
  if (sevBadge) {
    sevBadge.textContent = finding.severity;
    sevBadge.className = `badge badge-${finding.severity.toLowerCase()}`;
  }

  const bodyEl = document.getElementById("findingInspBody");
  if (bodyEl) {
    const repBadge = finding.representation === "TOKENIZED"
      ? "badge-tokenized"
      : (finding.representation === "ENCODED" ? "badge-encoded" : "badge-raw");

    bodyEl.innerHTML = `
      <div class="insp-row">
        <span class="insp-field">Finding ID</span>
        <span class="insp-val mono">${finding.finding_id}</span>
      </div>
      <div class="insp-row">
        <span class="insp-field">Severity & Category</span>
        <div style="display: flex; gap: 6px; margin-top: 4px;">
          <span class="badge badge-${finding.severity.toLowerCase()}">${finding.severity}</span>
          <span class="badge badge-info">${finding.category}</span>
          <span class="badge ${repBadge}">${finding.representation || "RAW"}</span>
        </div>
      </div>
      <div class="insp-row">
        <span class="insp-field">Confidence</span>
        <span class="insp-val bold">${finding.confidence} (${finding.provenance_quality})</span>
      </div>
      <div class="insp-row">
        <span class="insp-field">Trust Boundary Crossing</span>
        <span class="insp-val bold" style="color: #f43f5e;">
          ${finding.source_trust} ➔ ${finding.destination_trust}
        </span>
      </div>
      <div class="insp-row">
        <span class="insp-field">Source</span>
        <span class="insp-val mono">${finding.source_resource_id || finding.source_entity_id}</span>
      </div>
      <div class="insp-row">
        <span class="insp-field">Destination</span>
        <span class="insp-val mono">${finding.destination_id}</span>
      </div>
      <div class="insp-row">
        <span class="insp-field">Security Rule</span>
        <span class="insp-val mono bold">${finding.rule_id}</span>
      </div>
      <div class="insp-row">
        <span class="insp-field">Explanation</span>
        <p style="font-size: 0.78rem; line-height: 1.4; color: var(--text-main); margin-top: 4px;">${finding.explanation}</p>
      </div>
      <div class="insp-row">
        <span class="insp-field">Supporting Events</span>
        <span class="insp-val mono">${(finding.execution_event_ids || []).join(", ") || "None"}</span>
      </div>
      <button id="btnShowRiskPath" class="btn-show-risk-path">🔍 SHOW RISK PATH IN CANVAS</button>
    `;

    const btnShow = document.getElementById("btnShowRiskPath");
    if (btnShow) {
      btnShow.addEventListener("click", () => {
        switchLens("security");
        renderSecurityCanvas(finding.finding_id);
      });
    }
  }

  if (currentLens === "security") {
    renderSecurityCanvas(findingId);
  }
}

function handleEntityCreated(entity) {
  lineageEntityMap.set(entity.entity_id, entity);
  renderEntitiesList();

  // Create or update canonical LineageNode
  const nodeId = `entity:${entity.entity_id}`;
  const nodeData = {
    node_id: nodeId,
    node_type: "DATA_ENTITY",
    label: `${entity.label} (${entity.representation})`,
    session_id: entity.session_id,
    entity_id: entity.entity_id,
    properties: {
      classification: entity.classification,
      representation: entity.representation,
      fingerprint_hmac: entity.fingerprint_hmac,
      synthetic_token: entity.synthetic_token,
      origin_resource_id: entity.origin_resource_id,
      discovered_event_id: entity.discovered_event_id,
      raw_value_persisted: false,
      confidence: entity.confidence,
    }
  };
  lineageNodeDataMap.set(nodeId, nodeData);

  if (currentLens === "data_flow") {
    addLineageNodeToCanvas(nodeData, false);
  }
}

function handleCarrierCreated(carrier) {
  lineageCarrierMap.set(carrier.carrier_id, carrier);

  const nodeId = `carrier:${carrier.carrier_id}`;
  const nodeData = {
    node_id: nodeId,
    node_type: "DATA_CARRIER",
    label: `${carrier.carrier_type}#${carrier.sequence_number}`,
    session_id: carrier.session_id,
    carrier_id: carrier.carrier_id,
    properties: {
      carrier_type: carrier.carrier_type,
      supporting_event_id: carrier.supporting_event_id,
      contained_entity_ids: carrier.contained_entity_ids || [],
      source: carrier.source_actor_or_resource,
      destination: carrier.destination_actor_or_resource,
      sequence_number: carrier.sequence_number,
      confidence: carrier.confidence,
    }
  };
  lineageNodeDataMap.set(nodeId, nodeData);

  if (currentLens === "data_flow") {
    addLineageNodeToCanvas(nodeData, false);
  }
}

function handleFlowCreated(edge) {
  lineageEdgeDataMap.set(edge.edge_id, edge);

  if (currentLens === "data_flow") {
    addLineageEdgeToCanvas(edge, false);
  }
}

function addLineageNodeToCanvas(nodeData, isInitial = false) {
  const existing = cy.getElementById(nodeData.node_id);
  if (existing.length === 0) {
    const nodeOpts = {
      group: "nodes",
      data: {
        id: nodeData.node_id,
        label: nodeData.label || nodeData.node_id,
        node_type: nodeData.node_type,
        session_id: nodeData.session_id,
        representation: (nodeData.properties && nodeData.properties.representation) || "RAW",
        properties: nodeData.properties
      }
    };

    if (!isInitial) {
      nodeOpts.position = computeIncrementalPosition(nodeData);
    }

    const newNode = cy.add(nodeOpts);

    if (!isInitial) {
      newNode.addClass("new-node-pulse");
      setTimeout(() => {
        if (newNode.inside()) newNode.removeClass("new-node-pulse");
      }, 2500);

      if (autoFollowEnabled) {
        cy.animate({ center: { eles: newNode }, duration: 250 });
      }
    }
  }
}

function addLineageEdgeToCanvas(edgeData, isInitial = false) {
  const existing = cy.getElementById(edgeData.edge_id);
  if (existing.length === 0) {
    if (cy.getElementById(edgeData.source_id).length > 0 && cy.getElementById(edgeData.target_id).length > 0) {
      cy.add({
        group: "edges",
        data: {
          id: edgeData.edge_id,
          source: edgeData.source_id,
          target: edgeData.target_id,
          edge_type: edgeData.edge_type,
          event_id: edgeData.event_id,
          provenance_quality: edgeData.provenance_quality,
          confidence: edgeData.confidence,
          detection_method: edgeData.detection_method,
        }
      });
      // NOTE: Edges NEVER trigger a re-layout!
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Entities Panel List Rendering                                              */
/* -------------------------------------------------------------------------- */
function renderEntitiesList() {
  const container = document.getElementById("entityListContainer");
  if (!container) return;

  if (lineageEntityMap.size === 0) {
    container.innerHTML = '<div class="empty-hint">No entities discovered yet...</div>';
    return;
  }

  container.innerHTML = "";
  for (const entity of lineageEntityMap.values()) {
    const item = document.createElement("div");
    item.className = "entity-card";
    item.dataset.entityId = entity.entity_id;

    const classBadge = (entity.classification || "PUBLIC").toLowerCase();
    const isTokenized = entity.representation === "TOKENIZED";

    item.innerHTML = `
      <div class="entity-card-header">
        <span class="entity-label">${entity.label}</span>
        <span class="badge badge-${classBadge}">${entity.classification}</span>
      </div>
      <div class="entity-card-meta">
        <span class="badge ${isTokenized ? 'badge-tokenized' : 'badge-raw'}">${entity.representation}</span>
        <span class="entity-origin mono">${entity.origin_resource_id || "unknown"}</span>
      </div>
      ${entity.synthetic_token ? `<div class="entity-token-preview mono">${entity.synthetic_token}</div>` : ''}
    `;

    item.addEventListener("click", () => {
      document.querySelectorAll(".entity-card").forEach(c => c.classList.remove("active"));
      item.classList.add("active");
      inspectDataEntity(entity);
    });

    container.appendChild(item);
  }
}

/* -------------------------------------------------------------------------- */
/* Graph Manipulation & Incremental Updates (Execution Lens)                   */
/* -------------------------------------------------------------------------- */
function addOrUpdateNode(nodeData, isInitialSnapshot = false) {
  if (!shouldDisplayNode(nodeData)) {
    const existing = cy.getElementById(nodeData.node_id);
    if (existing.length > 0) existing.remove();
    return;
  }

  const existing = cy.getElementById(nodeData.node_id);
  if (existing.length === 0) {
    const nodeOpts = {
      group: "nodes",
      data: {
        id: nodeData.node_id,
        label: nodeData.label || nodeData.node_id,
        node_type: nodeData.node_type,
        session_id: nodeData.session_id,
        properties: nodeData.properties
      }
    };

    if (!isInitialSnapshot) {
      nodeOpts.position = computeIncrementalPosition(nodeData);
    }

    const newNode = cy.add(nodeOpts);

    if (!isInitialSnapshot) {
      newNode.addClass("new-node-pulse");
      setTimeout(() => {
        if (newNode.inside()) {
          newNode.removeClass("new-node-pulse");
        }
      }, 2500);

      if (autoFollowEnabled) {
        cy.animate({ center: { eles: newNode }, duration: 250 });
      }
    }
  }
}

function addOrUpdateEdge(edgeData, isInitialSnapshot = false) {
  if (!shouldDisplayEdge(edgeData)) {
    const existing = cy.getElementById(edgeData.edge_id);
    if (existing.length > 0) existing.remove();
    return;
  }

  const existing = cy.getElementById(edgeData.edge_id);
  if (existing.length === 0) {
    if (cy.getElementById(edgeData.source_id).length > 0 && cy.getElementById(edgeData.target_id).length > 0) {
      cy.add({
        group: "edges",
        data: {
          id: edgeData.edge_id,
          source: edgeData.source_id,
          target: edgeData.target_id,
          edge_type: edgeData.edge_type,
          event_id: edgeData.event_id,
          provenance_quality: edgeData.provenance_quality,
          confidence: edgeData.confidence
        }
      });
      // NOTE: Edges NEVER trigger a re-layout! Existing node coordinates remain strictly preserved.
    }
  }
}

function syncGraphElementsWithVisibility() {
  for (const nodeData of nodeDataMap.values()) {
    const isVisible = shouldDisplayNode(nodeData);
    const existing = cy.getElementById(nodeData.node_id);
    if (isVisible && existing.length === 0) {
      addOrUpdateNode(nodeData, true);
    } else if (!isVisible && existing.length > 0) {
      existing.remove();
    }
  }

  for (const edgeData of edgeDataMap.values()) {
    const isVisible = shouldDisplayEdge(edgeData);
    const existing = cy.getElementById(edgeData.edge_id);
    if (isVisible && existing.length === 0) {
      addOrUpdateEdge(edgeData, true);
    } else if (!isVisible && existing.length > 0) {
      existing.remove();
    }
  }
}

function runLayout(fit = false) {
  const layoutName = typeof cytoscape('core', 'dagre') === 'function' ? 'dagre' : 'cose';
  const layout = cy.layout({
    name: layoutName,
    animate: false,
    padding: 40,
    fit: fit,
    nodeDimensionsIncludeLabels: true
  });
  layout.run();
  if (fit) {
    cy.fit(null, 40);
  }
}

/* -------------------------------------------------------------------------- */
/* Timeline Rendering & Interaction                                          */
/* -------------------------------------------------------------------------- */
function renderTimeline() {
  const container = document.getElementById("timelineScroll");
  container.innerHTML = "";

  if (eventHistory.length === 0) {
    container.innerHTML = '<div class="timeline-empty">Awaiting events from live agent execution...</div>';
    return;
  }

  // Sort strictly by sequence_number
  const sorted = [...eventHistory].sort((a, b) => a.sequence_number - b.sequence_number);
  sorted.forEach(evt => appendTimelineItem(evt, false));
  updateEventCounter();
}

function appendTimelineItem(evt, scroll = true) {
  const container = document.getElementById("timelineScroll");
  const empty = container.querySelector(".timeline-empty");
  if (empty) empty.remove();

  const item = document.createElement("div");
  item.className = "timeline-item";
  item.dataset.eventId = evt.event_id;

  item.innerHTML = `
    <span class="timeline-item-seq">#${evt.sequence_number}</span>
    <span class="timeline-item-type">${evt.event_type}</span>
    <span class="timeline-item-actor">${evt.actor_label || evt.actor_id}</span>
  `;

  item.addEventListener("click", () => {
    document.querySelectorAll(".timeline-item").forEach(el => el.classList.remove("active"));
    item.classList.add("active");
    selectEvent(evt);
  });

  container.appendChild(item);
  if (scroll) {
    container.scrollLeft = container.scrollWidth;
  }
}

function updateEventCounter() {
  const badge = document.getElementById("eventCountBadge");
  if (badge) badge.textContent = eventHistory.length;
}

/* -------------------------------------------------------------------------- */
/* Inspectors (Node, Edge, Event, Trace)                                      */
/* -------------------------------------------------------------------------- */
function selectNode(nodeId) {
  // Check if this is a Security node
  if (nodeId.startsWith("risk_hop_") || nodeId.startsWith("finding:") || nodeId.startsWith("boundary:")) {
    const cyNode = cy.getElementById(nodeId);
    if (cyNode.length > 0 && cyNode.data("properties") && cyNode.data("properties").finding_id) {
      selectFinding(cyNode.data("properties").finding_id);
      return;
    } else if (selectedFindingId) {
      selectFinding(selectedFindingId);
      return;
    }
  }

  // Check if this is a Lineage node
  if (currentLens === "data_flow" || nodeId.startsWith("entity:") || nodeId.startsWith("carrier:")) {
    const lineageNode = lineageNodeDataMap.get(nodeId);
    if (lineageNode) {
      if (lineageNode.node_type === "DATA_ENTITY") {
        const entity = lineageEntityMap.get(lineageNode.entity_id) || lineageNode.properties;
        inspectDataEntity(entity, nodeId);
        return;
      } else if (lineageNode.node_type === "DATA_CARRIER") {
        const carrier = lineageCarrierMap.get(lineageNode.carrier_id) || lineageNode.properties;
        inspectDataCarrier(carrier, nodeId);
        return;
      }
    }
  }

  // Standard Execution Node Inspector
  const nodeData = nodeDataMap.get(nodeId);
  if (!nodeData) return;

  switchInspectorTab("nodeInsp");

  document.getElementById("nodeInspTitle").textContent = nodeData.label;
  const typeBadge = document.getElementById("nodeInspType");
  typeBadge.textContent = nodeData.node_type;
  typeBadge.className = `badge badge-${nodeData.node_type.toLowerCase()}`;

  const body = document.getElementById("nodeInspBody");
  body.innerHTML = `
    <div class="insp-row">
      <span class="insp-field">Canonical ID</span>
      <span class="insp-val mono">${nodeData.node_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Session</span>
      <span class="insp-val mono">${nodeData.session_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Properties</span>
      <pre class="json-box">${JSON.stringify(nodeData.properties || {}, null, 2)}</pre>
    </div>
    <button id="btnTraceCausality" class="btn-causal-action">⚡ Highlight Causal Ancestors</button>
  `;

  document.getElementById("btnTraceCausality").addEventListener("click", () => {
    highlightCausalAncestors(nodeId);
  });
}

function inspectDataEntity(entity, nodeId = null) {
  switchInspectorTab("nodeInsp");
  const actualNodeId = nodeId || `entity:${entity.entity_id}`;

  const titleEl = document.getElementById("nodeInspTitle");
  titleEl.textContent = `${entity.label} (${entity.representation || "RAW"})`;

  const typeBadge = document.getElementById("nodeInspType");
  typeBadge.textContent = "DATA_ENTITY";
  typeBadge.className = `badge badge-${(entity.classification || "secret").toLowerCase()}`;

  const fp = entity.fingerprint_hmac || "";
  const fpPreview = fp.length > 16 ? `${fp.substring(0, 16)}...` : (fp || "None");

  const body = document.getElementById("nodeInspBody");
  body.innerHTML = `
    <div class="insp-row">
      <span class="insp-field">Entity ID</span>
      <span class="insp-val mono">${entity.entity_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Label</span>
      <span class="insp-val bold">${entity.label}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Classification</span>
      <span class="insp-val badge badge-${(entity.classification || 'secret').toLowerCase()}">${entity.classification}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Origin Resource</span>
      <span class="insp-val mono">${entity.origin_resource_id || "unknown"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Protection State</span>
      <span class="insp-val badge ${entity.representation === 'TOKENIZED' ? 'badge-tokenized' : 'badge-raw'}">${entity.representation || "RAW"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Raw Value Persisted</span>
      <span class="insp-val badge badge-safe">NO (Zero Plaintext Invariant)</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">HMAC Fingerprint</span>
      <span class="insp-val mono">${fpPreview}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Synthetic Token</span>
      <span class="insp-val mono">${entity.synthetic_token || "None"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Discovery Event</span>
      <span class="insp-val mono">${entity.discovered_event_id || "None"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Provenance Quality</span>
      <span class="insp-val badge">${entity.provenance_quality || "OBSERVED"} (Confidence: ${entity.confidence || 1.0})</span>
    </div>
    <div class="trace-action-buttons">
      <button id="btnTraceOrigin" class="btn btn-secondary trace-btn">🔍 TRACE ORIGIN</button>
      <button id="btnTraceDest" class="btn btn-primary trace-btn">➡️ TRACE DESTINATIONS</button>
    </div>
  `;

  document.getElementById("btnTraceOrigin").addEventListener("click", () => {
    traceEntity(entity.entity_id, "backward");
  });

  document.getElementById("btnTraceDest").addEventListener("click", () => {
    traceEntity(entity.entity_id, "forward");
  });

  // Center on node if present in canvas
  const canvasNode = cy.getElementById(actualNodeId);
  if (canvasNode.length > 0) {
    cy.nodes().unselect();
    canvasNode.select();
    if (autoFollowEnabled) {
      cy.animate({ center: { eles: canvasNode }, duration: 250 });
    }
  }
}

function inspectDataCarrier(carrier, nodeId = null) {
  switchInspectorTab("nodeInsp");
  const actualNodeId = nodeId || `carrier:${carrier.carrier_id}`;

  document.getElementById("nodeInspTitle").textContent = `${carrier.carrier_type} #${carrier.sequence_number || ""}`;
  const typeBadge = document.getElementById("nodeInspType");
  typeBadge.textContent = "DATA_CARRIER";
  typeBadge.className = "badge badge-carrier";

  const contained = carrier.contained_entity_ids || [];

  const body = document.getElementById("nodeInspBody");
  body.innerHTML = `
    <div class="insp-row">
      <span class="insp-field">Carrier ID</span>
      <span class="insp-val mono">${carrier.carrier_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Carrier Type</span>
      <span class="insp-val badge badge-carrier">${carrier.carrier_type}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Supporting Event</span>
      <span class="insp-val mono">${carrier.supporting_event_id || "None"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Contained Entities</span>
      <span class="insp-val mono">${contained.length > 0 ? contained.join(", ") : "None"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Source</span>
      <span class="insp-val mono">${carrier.source_actor_or_resource || carrier.source || "None"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Destination</span>
      <span class="insp-val mono">${carrier.destination_actor_or_resource || carrier.destination || "None"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Sequence Number</span>
      <span class="insp-val mono">#${carrier.sequence_number || 0}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Confidence</span>
      <span class="insp-val badge">${carrier.confidence || 1.0}</span>
    </div>
    <div class="trace-action-buttons">
      <button id="btnTraceCarrierBack" class="btn btn-secondary trace-btn">🔍 TRACE ORIGIN</button>
    </div>
  `;

  document.getElementById("btnTraceCarrierBack").addEventListener("click", () => {
    traceEntity(actualNodeId, "backward");
  });
}

function selectEdge(edgeId) {
  // Check if edge is from Lineage store
  const lineageEdge = lineageEdgeDataMap.get(edgeId);
  if (lineageEdge) {
    inspectLineageEdge(lineageEdge);
    return;
  }

  // Standard Execution Edge
  const edgeData = edgeDataMap.get(edgeId);
  if (!edgeData) return;

  switchInspectorTab("edgeInsp");

  document.getElementById("edgeInspTitle").textContent = edgeData.edge_type;
  document.getElementById("edgeInspType").textContent = "EDGE";

  const body = document.getElementById("edgeInspBody");
  body.innerHTML = `
    <div class="insp-row">
      <span class="insp-field">Relationship</span>
      <span class="insp-val mono">${edgeData.edge_type}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Source Node</span>
      <span class="insp-val mono">${edgeData.source_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Target Node</span>
      <span class="insp-val mono">${edgeData.target_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Supporting Event</span>
      <span class="insp-val mono">${edgeData.event_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Evidence Quality</span>
      <span class="insp-val badge">${edgeData.provenance_quality} (Confidence: ${edgeData.confidence})</span>
    </div>
  `;
}

function inspectLineageEdge(edge) {
  switchInspectorTab("edgeInsp");

  document.getElementById("edgeInspTitle").textContent = edge.edge_type;
  const typeBadge = document.getElementById("edgeInspType");
  typeBadge.textContent = "LINEAGE_EDGE";
  typeBadge.className = "badge badge-lineage";

  const detectionMethod = edge.detection_method || "TOKEN_IDENTITY";
  let explanation = "Concrete evidence established data propagation.";

  if (detectionMethod === "TOKEN_IDENTITY") {
    explanation = "Synthetic Token Identity: The secure synthetic token was verified present across the boundary payload.";
  } else if (detectionMethod === "HMAC_MATCH") {
    explanation = "Keyed HMAC Match: Observed transient payload matched the entity fingerprint without storing raw secrets.";
  } else if (detectionMethod === "STRUCTURED_PROPAGATION") {
    explanation = "Structured Boundary Propagation: Explicit insertion of result data into agent context / boundary payload.";
  } else if (detectionMethod === "TRANSFORMATION_MATCH") {
    explanation = "Deterministic Transformation Match: Input representation was deterministically converted to output representation.";
  } else if (detectionMethod === "EXPLICIT_MAPPING") {
    explanation = "Explicit boundary mapping between carrier and downstream sink.";
  }

  const body = document.getElementById("edgeInspBody");
  body.innerHTML = `
    <div class="insp-row">
      <span class="insp-field">Relationship</span>
      <span class="insp-val bold">${edge.edge_type}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Source</span>
      <span class="insp-val mono">${edge.source_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Destination</span>
      <span class="insp-val mono">${edge.target_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Detection Method</span>
      <span class="insp-val badge badge-method">${detectionMethod}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Supporting Event</span>
      <span class="insp-val mono">${edge.event_id || "None"}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Evidence Quality</span>
      <span class="insp-val badge">${edge.provenance_quality} (Confidence: ${edge.confidence})</span>
    </div>
    <div class="detection-explanation-box">
      <div class="box-title">Why GuardX Proves This Flow:</div>
      <div class="box-text">${explanation}</div>
    </div>
  `;
}

function selectEvent(evt) {
  switchInspectorTab("eventInsp");

  document.getElementById("eventInspTitle").textContent = `#${evt.sequence_number} ${evt.event_type}`;
  document.getElementById("eventInspType").textContent = evt.event_type;

  const body = document.getElementById("eventInspBody");
  body.innerHTML = `
    <div class="insp-row">
      <span class="insp-field">Event ID</span>
      <span class="insp-val mono">${evt.event_id}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Sequence & Timestamp</span>
      <span class="insp-val">#${evt.sequence_number} &bull; ${evt.timestamp}</span>
    </div>
    <div class="insp-row">
      <span class="insp-field">Actor</span>
      <span class="insp-val mono">${evt.actor_label || evt.actor_id}</span>
    </div>
    ${evt.source_id ? `
    <div class="insp-row">
      <span class="insp-field">Source Resource</span>
      <span class="insp-val mono">${evt.source_id}</span>
    </div>` : ""}
    ${evt.destination_id ? `
    <div class="insp-row">
      <span class="insp-field">Destination Resource</span>
      <span class="insp-val mono">${evt.destination_id}</span>
    </div>` : ""}
    ${evt.execution_scope_id ? `
    <div class="insp-row">
      <span class="insp-field">Execution Scope</span>
      <span class="insp-val mono">${evt.execution_scope_id}</span>
    </div>` : ""}
    ${evt.causal_event_id ? `
    <div class="insp-row">
      <span class="insp-field">Causal Trigger Event</span>
      <span class="insp-val mono">${evt.causal_event_id}</span>
    </div>` : ""}
    <div class="insp-row">
      <span class="insp-field">Safe Payload (Sanitized)</span>
      <pre class="json-box">${JSON.stringify(evt.payload || {}, null, 2)}</pre>
    </div>
  `;

  // Highlight in graph if matching element exists
  const targetId = evt.destination_id || evt.source_id || evt.actor_id;
  if (targetId) {
    const el = cy.getElementById(targetId);
    if (el.length > 0) {
      cy.nodes().unselect();
      el.select();
      cy.animate({ center: { eles: el }, duration: 300 });
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Forward & Backward Lineage Tracing (API + Highlighting)                    */
/* -------------------------------------------------------------------------- */
async function traceEntity(targetId, direction = "forward") {
  clearHighlights();
  switchInspectorTab("traceInsp");

  const titleEl = document.getElementById("traceInspTitle");
  titleEl.textContent = `Trace: ${targetId} (${direction.toUpperCase()})`;

  const badgeEl = document.getElementById("traceInspBadge");
  badgeEl.textContent = direction.toUpperCase();

  const bodyEl = document.getElementById("traceInspBody");
  bodyEl.innerHTML = '<div class="loading-hint">Computing deterministic provenance trace...</div>';

  try {
    const res = await fetch(`/api/sessions/${currentSessionId}/lineage/trace/${direction}/${targetId}`);
    const data = await res.json();
    renderTraceResult(data, targetId, direction);
  } catch (err) {
    bodyEl.innerHTML = `<div class="trace-error">Trace query failed: ${err.message}</div>`;
  }
}

function renderTraceResult(result, targetId, direction) {
  const bodyEl = document.getElementById("traceInspBody");

  if (!result || !result.has_proven_flow || !result.hops || result.hops.length === 0) {
    bodyEl.innerHTML = `
      <div class="trace-no-flow-card">
        <div class="no-flow-header">🛡️ NO PROVEN FLOW</div>
        <p class="no-flow-message">
          <strong>GuardX Semantic Rule:</strong> Never infer information flow merely because events occurred in temporal proximity.
        </p>
        <div class="no-flow-detail">
          Concrete evidence is insufficient to prove that <code>${targetId}</code> propagated to any downstream boundary.
        </div>
      </div>
    `;
    return;
  }

  // Highlight all nodes and edges traversed in the proven path
  const nodesToHighlight = new Set();
  const edgeIdsToHighlight = new Set();

  result.hops.forEach(hop => {
    nodesToHighlight.add(hop.source_id);
    nodesToHighlight.add(hop.target_id);

    // Find cy edge
    const matchingCyEdges = cy.edges().filter(e => 
      e.data("source") === hop.source_id && e.data("target") === hop.target_id
    );
    matchingCyEdges.forEach(e => edgeIdsToHighlight.add(e.id()));
  });

  nodesToHighlight.forEach(nId => {
    const nodeEl = cy.getElementById(nId);
    if (nodeEl.length > 0) nodeEl.addClass("trace-path-highlight");
  });

  edgeIdsToHighlight.forEach(eId => {
    const edgeEl = cy.getElementById(eId);
    if (edgeEl.length > 0) edgeEl.addClass("trace-path-highlight");
  });

  // Render Hop Cards
  let hopsHtml = `
    <div class="trace-summary">
      <span class="trace-hops-count">Proven Hops: <strong>${result.hops.length}</strong></span>
      <span class="badge badge-safe">Concrete Evidence Verified</span>
    </div>
    <div class="trace-hops-list">
  `;

  result.hops.forEach(hop => {
    hopsHtml += `
      <div class="trace-hop-card">
        <div class="hop-header">
          <span class="hop-num">Hop #${hop.hop_number}</span>
          <span class="badge badge-method">${hop.detection_method}</span>
        </div>
        <div class="hop-flow">
          <span class="hop-node mono">${hop.source_id}</span>
          <span class="hop-arrow">➔ [${hop.relationship}] ➔</span>
          <span class="hop-node mono">${hop.target_id}</span>
        </div>
        <div class="hop-meta">
          <span>Event: <code class="mono">${hop.event_id || "None"}</code></span>
          <span>Quality: <strong>${hop.provenance_quality}</strong> (${(hop.confidence * 100).toFixed(0)}%)</span>
        </div>
        ${hop.transformation ? `<div class="hop-transform">Transformation: <code>${hop.transformation}</code></div>` : ""}
      </div>
    `;
  });

  hopsHtml += `</div>`;
  bodyEl.innerHTML = hopsHtml;
}

function switchInspectorTab(panelId) {
  document.querySelectorAll(".insp-tab").forEach(tab => {
    tab.classList.toggle("active", tab.dataset.insp === panelId);
  });
  document.querySelectorAll(".insp-panel").forEach(panel => {
    panel.classList.toggle("active", panel.id === panelId);
  });
}

function highlightCausalAncestors(nodeId) {
  clearHighlights();
  const target = cy.getElementById(nodeId);
  if (target.length === 0) return;

  const ancestors = target.predecessors();
  ancestors.nodes().addClass("causal-highlight");
  target.addClass("causal-highlight");
  ancestors.edges().select();
}

function clearHighlights() {
  cy.nodes().removeClass("causal-highlight");
  cy.nodes().removeClass("trace-path-highlight");
  cy.nodes().removeClass("risk-path-highlight");
  cy.nodes().removeClass("risk-source");
  cy.nodes().removeClass("risk-sink");
  cy.nodes().removeClass("protected-highlight");
  cy.nodes().removeClass("dimmed");
  cy.edges().removeClass("trace-path-highlight");
  cy.edges().removeClass("risk-path-highlight");
  cy.edges().removeClass("protected-highlight");
  cy.edges().removeClass("dimmed");
}

/* -------------------------------------------------------------------------- */
/* Scope Hierarchy Tree                                                       */
/* -------------------------------------------------------------------------- */
function addScopeTreeItem(scopeData) {
  const container = document.getElementById("scopeTreeList");
  const hint = container.querySelector(".empty-hint");
  if (hint) hint.remove();

  const item = document.createElement("div");
  item.className = "scope-item";
  item.dataset.scopeId = scopeData.scope_id;
  item.innerHTML = `
    <span class="scope-item-name">${scopeData.scope_name}</span>
    <span class="scope-item-id mono">${scopeData.scope_id}</span>
  `;

  item.addEventListener("click", () => {
    document.querySelectorAll(".scope-item").forEach(el => el.classList.remove("active"));
    item.classList.add("active");
    highlightScopeEntities(scopeData.scope_id);
  });

  container.appendChild(item);
}

function highlightScopeEntities(scopeId) {
  clearHighlights();

  const scopeNode = cy.getElementById(`scope:${scopeId}`);
  if (scopeNode.length > 0) {
    cy.nodes().unselect();
    scopeNode.select();
    if (autoFollowEnabled) {
      cy.animate({ center: { eles: scopeNode }, duration: 250 });
    }
    return;
  }

  const matchingEvents = eventHistory.filter(
    e => e.execution_scope_id === scopeId || (e.payload && e.payload.scope_id === scopeId)
  );
  const entityIds = new Set();
  matchingEvents.forEach(e => {
    if (e.actor_id) entityIds.add(e.actor_id);
    if (e.source_id) entityIds.add(e.source_id);
    if (e.destination_id) entityIds.add(e.destination_id);
  });

  const elesToHighlight = cy.nodes().filter(n => entityIds.has(n.id()));
  if (elesToHighlight.length > 0) {
    elesToHighlight.addClass("causal-highlight");
    if (autoFollowEnabled) {
      cy.animate({ center: { eles: elesToHighlight }, duration: 250 });
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Sessions & Demo Step Trigger                                              */
/* -------------------------------------------------------------------------- */
async function loadSessionList() {
  try {
    const res = await fetch("/api/sessions");
    const sessions = await res.json();
    const select = document.getElementById("sessionSelect");
    select.innerHTML = "";

    sessions.forEach(s => {
      const opt = document.createElement("option");
      opt.value = s.session_id;
      opt.textContent = `${s.session_id} (${s.agent_name})`;
      select.appendChild(opt);
    });

    select.value = currentSessionId;
  } catch (e) {
    console.error("[GuardX] Failed to load sessions:", e);
  }
}

function initUIEventListeners() {
  // Lens Switcher Tabs
  const lensExecutionBtn = document.getElementById("lensExecution");
  const lensDataFlowBtn = document.getElementById("lensDataFlow");
  const lensSecurityBtn = document.getElementById("lensSecurity");

  if (lensExecutionBtn) {
    lensExecutionBtn.addEventListener("click", () => switchLens("execution"));
  }
  if (lensDataFlowBtn) {
    lensDataFlowBtn.addEventListener("click", () => switchLens("data_flow"));
  }
  if (lensSecurityBtn) {
    lensSecurityBtn.addEventListener("click", () => switchLens("security"));
  }

  // Security Experiments (Milestone 4)
  const secExpButtons = [
    { id: "btnSecExpA", name: "raw_credential" },
    { id: "btnSecExpB", name: "tokenized_credential" },
    { id: "btnSecExpC", name: "encoded_credential" },
    { id: "btnSecExpD", name: "negative_no_flow" },
    { id: "btnSecExpE", name: "intent_mismatch" },
  ];
  secExpButtons.forEach(({ id, name }) => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.addEventListener("click", () => runSecurityExperiment(name, btn));
    }
  });

  // Session Switcher
  document.getElementById("sessionSelect").addEventListener("change", (e) => {
    currentSessionId = e.target.value;
    const agentNameSpan = document.getElementById("agentNameDisplay");
    if (agentNameSpan) {
      agentNameSpan.textContent = currentSessionId.includes("groq") ? "GroqAgent" : "OpenCode";
    }
    connectWebSocket(currentSessionId);
  });

  // Fit View (only adjusts viewport zoom/pan; NEVER changes node positions)
  document.getElementById("btnFitGraph").addEventListener("click", () => {
    cy.fit(null, 40);
  });

  // Re-layout (explicit full hierarchical Dagre recalculation)
  document.getElementById("btnResetLayout").addEventListener("click", () => {
    runLayout(false);
  });

  // Auto-Follow Toggle
  const btnAutoFollow = document.getElementById("btnAutoFollow");
  if (btnAutoFollow) {
    btnAutoFollow.addEventListener("click", () => {
      autoFollowEnabled = !autoFollowEnabled;
      btnAutoFollow.classList.toggle("active", autoFollowEnabled);
      btnAutoFollow.innerHTML = autoFollowEnabled
        ? '<span class="toggle-icon">🎯</span> Auto-Follow: ON'
        : '<span class="toggle-icon">⏸️</span> Auto-Follow: OFF';
    });
  }

  // Scope Nodes In Graph Toggle
  const scopeToggle = document.getElementById("toggleScopeNodesInGraph");
  if (scopeToggle) {
    scopeToggle.checked = showScopeNodesInGraph;
    scopeToggle.addEventListener("change", (e) => {
      showScopeNodesInGraph = e.target.checked;
      syncGraphElementsWithVisibility();
      runLayout(false);
    });
  }

  // Zoom Controls
  document.getElementById("zoomInBtn").addEventListener("click", () => {
    cy.zoom(cy.zoom() * 1.25);
  });
  document.getElementById("zoomOutBtn").addEventListener("click", () => {
    cy.zoom(cy.zoom() * 0.8);
  });
  document.getElementById("centerBtn").addEventListener("click", () => {
    cy.center();
  });

  // Validation Experiments (Milestone 3)
  const btnExpA = document.getElementById("btnExpA");
  const btnExpB = document.getElementById("btnExpB");
  const btnExpC = document.getElementById("btnExpC");

  if (btnExpA) {
    btnExpA.addEventListener("click", () => runValidationExperiment("positive", btnExpA));
  }
  if (btnExpB) {
    btnExpB.addEventListener("click", () => runValidationExperiment("negative", btnExpB));
  }
  if (btnExpC) {
    btnExpC.addEventListener("click", () => runValidationExperiment("transformation", btnExpC));
  }

  // Run Groq Demo Agent
  const btnRunGroq = document.getElementById("btnRunGroqAgent");
  if (btnRunGroq) {
    btnRunGroq.addEventListener("click", async () => {
      btnRunGroq.disabled = true;
      btnRunGroq.textContent = "⏳ Agent Running...";
      try {
        const res = await fetch(`/api/sessions/${currentSessionId}/demo/run_groq_agent`, {
          method: "POST"
        });
        const data = await res.json();
        console.log("[GuardX] Groq Demo Agent response:", data);
      } catch (e) {
        console.error("[GuardX] Groq agent demo error:", e);
      } finally {
        btnRunGroq.disabled = false;
        btnRunGroq.textContent = "🤖 Run Groq Agent";
      }
    });
  }

  // Trigger OpenCode Demo Step
  document.getElementById("btnRunDemoStep").addEventListener("click", async () => {
    const btn = document.getElementById("btnRunDemoStep");
    btn.disabled = true;
    try {
      const res = await fetch(`/api/sessions/${currentSessionId}/demo/opencode_step?step=${demoStepCounter}`, {
        method: "POST"
      });
      const data = await res.json();
      console.log(`[GuardX] Demo Step ${demoStepCounter} executed:`, data);
      demoStepCounter = demoStepCounter >= 3 ? 1 : demoStepCounter + 1;
      btn.textContent = `▶ OpenCode Step (${demoStepCounter}/3)`;
    } catch (e) {
      console.error("[GuardX] Demo step error:", e);
    } finally {
      btn.disabled = false;
    }
  });

  // Sidebar Tab Switching
  document.querySelectorAll(".side-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".side-tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".side-panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(tab.dataset.panel).classList.add("active");
    });
  });

  // Inspector Tab Switching
  document.querySelectorAll(".insp-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      switchInspectorTab(tab.dataset.insp);
    });
  });

  // Search Filter
  document.getElementById("searchInput").addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase().trim();
    if (!q) {
      cy.nodes().style("opacity", 1);
      return;
    }
    cy.nodes().forEach(n => {
      const label = (n.data("label") || "").toLowerCase();
      const id = n.id().toLowerCase();
      n.style("opacity", label.includes(q) || id.includes(q) ? 1 : 0.15);
    });
  });
}

/* -------------------------------------------------------------------------- */
/* Validation Experiments Trigger Helper                                      */
/* -------------------------------------------------------------------------- */
async function runValidationExperiment(experimentName, buttonEl) {
  const origText = buttonEl.textContent;
  buttonEl.disabled = true;
  buttonEl.textContent = "⏳ Running...";

  const banner = document.getElementById("expResultBanner");
  if (banner) {
    banner.style.display = "block";
    banner.className = "exp-result-banner banner-running";
    banner.textContent = `Running Experiment: ${experimentName}...`;
  }

  try {
    const res = await fetch(`/api/sessions/${currentSessionId}/demo/run_lineage_experiment?experiment=${experimentName}`, {
      method: "POST"
    });
    const data = await res.json();

    // Auto-switch to Data Flow lens to inspect results immediately!
    switchLens("data_flow");

    // Fetch updated lineage store for the session
    const lineageRes = await fetch(`/api/sessions/${currentSessionId}/lineage`);
    const updatedLineage = await lineageRes.json();
    loadLineageSnapshot(updatedLineage);
    renderDataFlowCanvas();

    if (banner) {
      banner.className = "exp-result-banner banner-success";
      const statusTitle = data.explanation || `Experiment ${data.experiment}: ${data.status.toUpperCase()}`;
      banner.innerHTML = `
        <div class="banner-exp-title"><strong>${statusTitle}</strong></div>
        <div class="banner-sub mono">Hops: ${data.hops_count || (data.destinations && data.destinations.length ? 'Proven' : 'None')} &bull; Status: ${data.status}</div>
      `;
    }

    // Automatically trigger relevant trace for demonstration
    if (experimentName === "positive") {
      setTimeout(() => traceEntity("DEMO_API_KEY", "forward"), 400);
    } else if (experimentName === "negative") {
      setTimeout(() => traceEntity("DEMO_API_KEY", "forward"), 400);
    } else if (experimentName === "transformation") {
      const target = (data.transformed_entities && data.transformed_entities[1]) 
        || (data.transformed_entities && data.transformed_entities[0]) 
        || "SECRET_API_TOKEN";
      setTimeout(() => traceEntity(target, "backward"), 400);
    }

  } catch (err) {
    if (banner) {
      banner.className = "exp-result-banner banner-error";
      banner.textContent = `Experiment failed: ${err.message}`;
    }
  } finally {
    buttonEl.disabled = false;
    buttonEl.textContent = origText;
  }
}

/* -------------------------------------------------------------------------- */
/* Security Intelligence Experiments (Milestone 4)                            */
/* -------------------------------------------------------------------------- */
async function runSecurityExperiment(experimentName, buttonEl) {
  const origText = buttonEl.textContent;
  buttonEl.disabled = true;
  buttonEl.textContent = "⏳ Running...";

  const banner = document.getElementById("expResultBanner");
  if (banner) {
    banner.style.display = "block";
    banner.className = "exp-result-banner banner-running";
    banner.textContent = `Running Security Experiment: ${experimentName}...`;
  }

  try {
    const res = await fetch(`/api/sessions/${currentSessionId}/demo/run_security_experiment?experiment=${experimentName}`, {
      method: "POST"
    });
    const data = await res.json();

    // Fetch updated security store & lineage store for the session
    const [secRes, lineageRes] = await Promise.all([
      fetch(`/api/sessions/${currentSessionId}/security`),
      fetch(`/api/sessions/${currentSessionId}/lineage`)
    ]);
    const secData = await secRes.json();
    const linData = await lineageRes.json();

    loadLineageSnapshot(linData);
    loadSecuritySnapshot(secData);

    // Switch to Security Overlay lens immediately
    switchLens("security");

    if (banner) {
      banner.className = "exp-result-banner banner-success";
      const title = data.explanation || `Security Experiment: ${data.experiment}`;
      banner.innerHTML = `
        <div class="banner-exp-title"><strong>${title}</strong></div>
        <div class="banner-sub mono">Findings: ${data.findings_count} &bull; Crossings: ${data.crossings_count} &bull; Status: ${data.status}</div>
      `;
    }

    // If findings produced, select the first finding
    if (secData.findings && secData.findings.length > 0) {
      const topFinding = secData.findings[secData.findings.length - 1];
      selectFinding(topFinding.finding_id);
    }

  } catch (err) {
    if (banner) {
      banner.className = "exp-result-banner banner-error";
      banner.textContent = `Security Experiment failed: ${err.message}`;
    }
  } finally {
    buttonEl.disabled = false;
    buttonEl.textContent = origText;
  }
}
