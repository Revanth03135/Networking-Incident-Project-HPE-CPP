"""
causalInference.py — Unified Causal Inference Engine.

Responsibility: score event pairs, build a directed causal graph, detect
root-cause nodes, and extract propagation chains.

Preprocessing (flatten / timestamps / skew / window) is handled by
preprocessing.py and imported here.

Public API for timeline_reconstruction.py:
    analyze_cluster(events, threshold) -> (causal_links, root_cause_event)
"""

import json
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from preprocessing import (
    normalize_string,
    flatten_event,
    flatten_events,
    normalize_timestamps,
    correct_clock_skew,
    compute_dynamic_window,
)

logger = logging.getLogger(__name__)


# ============================================================
# CAUSAL DOMAIN MAP  (extended — authoritative copy)
# ============================================================

DEFAULT_CAUSAL_MAP: Dict[str, List[str]] = {
    "arp":                    ["spanning_tree", "interface", "security", "stability"],
    "spanning_tree":          ["interface", "bgp"],
    "interface":              ["bgp", "security", "system"],
    "bgp":                    ["bgp", "interface", "routing", "dns"],
    "security":               ["system"],
    "stability":              ["security", "interface"],
    "system":                 ["interface"],
    "packet_drop":            ["routing", "network", "security"],
    "authentication_failure": ["security", "system"],
    "link_down":              ["routing", "bgp"],
    "routing":                ["network", "bgp", "dns"],
    "dns":                    ["application"],
    "cpu":                    ["system"],
    "protocol":               ["network", "system"],
}

SEVERITY_MAP: Dict[str, int] = {
    "info":     1,
    "warning":  2,
    "error":    3,
    "critical": 4,
}


# ============================================================
# STEP 1 — TIME UTILITIES
# ============================================================

def time_diff(a: Dict, b: Dict) -> float:
    """Absolute time difference between two events (seconds)."""
    t1 = a.get("corrected_time") or a.get("event_time")
    t2 = b.get("corrected_time") or b.get("event_time")

    if isinstance(t1, str):
        t1 = datetime.fromisoformat(t1.replace("Z", "+00:00"))
    if isinstance(t2, str):
        t2 = datetime.fromisoformat(t2.replace("Z", "+00:00"))

    return abs((t2 - t1).total_seconds())


# ============================================================
# STEP 2 — GENERATE CANDIDATE PAIRS
# ============================================================

def generate_pairs(
    events: List[Dict],
    max_time_window: Optional[float] = None,
) -> List[Tuple[Dict, Dict]]:
    """
        Candidate causal pairs where:
            - A happens strictly before B
            - time gap ≤ max_time_window
            - same device OR same interface OR semantic relationship
    """
    if max_time_window is None:
        max_time_window = compute_dynamic_window(events)

    pairs = []
    n     = len(events)

    for i in range(n):
        for j in range(i + 1, n):

            A = events[i]
            B = events[j]

            t_a = A.get("corrected_time") or A.get("event_time")
            t_b = B.get("corrected_time") or B.get("event_time")

            if t_a >= t_b:
                continue

            if time_diff(A, B) > max_time_window:
                continue

            same_device    = A.get("device") == B.get("device")
            same_interface = (
                A.get("interface_id")
                and A.get("interface_id") == B.get("interface_id")
            )

            semantic_related = has_semantic_relationship(A, B)

            if same_device or same_interface or semantic_related:
                pairs.append((A, B))

    return pairs


# ============================================================
# STEP 3 — SEVERITY SCORING
# ============================================================

def get_severity_score(event: Dict) -> int:
    return SEVERITY_MAP.get(event.get("severity", "info").lower(), 1)


# ============================================================
# STEP 4 — DOMAIN PROGRESSION SCORE
# ============================================================

def get_domain_progression_score(cause_type: str, effect_type: str) -> float:
    """Score based on how well cause->effect matches the domain map."""
    cause_norm  = normalize_string(cause_type)
    effect_norm = normalize_string(effect_type)

    possible_effects = DEFAULT_CAUSAL_MAP.get(cause_norm, [])

    if not possible_effects:
        return 0.0

    if effect_norm in possible_effects:
        return 1.0

    for effect in possible_effects:
        if effect in effect_norm or effect_norm in effect:
            return 0.7

    return 0.0


def has_semantic_relationship(A: Dict, B: Dict) -> bool:
    """Check subtype/type-level semantic plausibility for A -> B."""
    subtype_score = get_domain_progression_score(
        A.get("subtype", "unknown"),
        B.get("subtype", "unknown"),
    )
    if subtype_score > 0:
        return True

    type_score = get_domain_progression_score(
        A.get("type", "unknown"),
        B.get("type", "unknown"),
    )
    return type_score > 0


# ============================================================
# STEP 5 — CAUSALITY SCORING
# ============================================================

def causality_score(
    A: Dict,
    B: Dict,
    causal_map: Optional[Dict] = None,
) -> float:
    """
    Composite score for the likelihood that A causes B.

    Factors:
      1. Time proximity   (closer  -> stronger)
      2. Same interface   (strong  signal)
      3. Same device      (medium  signal)
      4. Domain progression via DEFAULT_CAUSAL_MAP
      5. Severity escalation
    """
    score = 0.0

    # 1. Time proximity
    score += 1.0 / (1.0 + time_diff(A, B))

    # 2. Same interface
    if A.get("interface_id") and A.get("interface_id") == B.get("interface_id"):
        score += 1.0

    # 3. Same device
    if A.get("device") == B.get("device"):
        score += 0.5

    # 4. Domain progression (subtype first, then type fallback)
    domain_score = get_domain_progression_score(
        A.get("subtype", "unknown"),
        B.get("subtype", "unknown"),
    )
    if domain_score == 0.0:
        domain_score = get_domain_progression_score(
            A.get("type", "unknown"),
            B.get("type", "unknown"),
        )
    score += domain_score

    # 5. Severity escalation
    if get_severity_score(A) < get_severity_score(B):
        score += 0.5

    return score


# ============================================================
# STEP 6 — BUILD CAUSAL GRAPH
# ============================================================

def build_causal_graph(
    events:     List[Dict],
    threshold:  float          = 1.5,
    time_window: Optional[float] = None,
) -> nx.DiGraph:
    """
    Directed causal graph.
    Nodes  = events  (keyed by event_uid)
    Edges  = probable causal links  (weight = confidence score)
    Pruning keeps only the strongest predecessor per node.
    """
    G = nx.DiGraph()

    for event in events:
        G.add_node(
            event["event_uid"],
            data     = event,
            device   = event.get("device"),
            subtype  = event.get("subtype"),
            severity = event.get("severity"),
            time     = event.get("corrected_time") or event.get("event_time"),
        )

    pairs = generate_pairs(events, time_window)

    # Edge pruning: keep only the highest-scoring predecessor for each target
    best_edges: Dict[str, Tuple[str, str, float]] = {}

    for A, B in pairs:
        score = causality_score(A, B)

        if score < threshold:
            continue

        target = B["event_uid"]

        if target not in best_edges or score > best_edges[target][2]:
            best_edges[target] = (A["event_uid"], B["event_uid"], score)

    for source, target, score in best_edges.values():
        G.add_edge(source, target, weight=score, confidence=score)

    logger.info(
        f"Causal graph: {G.number_of_nodes()} nodes, "
        f"{G.number_of_edges()} edges"
    )

    return G


# ============================================================
# STEP 7 — ROOT CAUSE DETECTION
# ============================================================

def find_root_causes(G: nx.DiGraph) -> List[str]:
    """
    Root cause nodes: no incoming edges AND at least one outgoing edge.
    (not caused by anything inside the cluster, but does cause something)
    """
    return [
        node
        for node in G.nodes()
        if G.in_degree(node) == 0 and G.out_degree(node) > 0
    ]


# ============================================================
# STEP 8 — EXTRACT CAUSAL CHAINS
# ============================================================

def extract_chains(
    G:           nx.DiGraph,
    root_nodes:  List[str],
) -> List[List[str]]:
    """Root-to-leaf causal paths via nx.all_simple_paths."""
    chains = []

    leaf_nodes = [n for n in G.nodes() if G.out_degree(n) == 0]

    for root in root_nodes:
        for leaf in leaf_nodes:
            if root == leaf:
                continue
            try:
                for path in nx.all_simple_paths(G, source=root, target=leaf):
                    chains.append(path)
            except nx.NetworkXNoPath:
                continue

    return chains


def select_primary_root(G: nx.DiGraph, root_ids: List[str]) -> Optional[str]:
    """
    Select the strongest root candidate:
    - highest out_degree
    - then highest outgoing confidence sum
    - then earliest timestamp
    """
    if not root_ids:
        return None

    ranked = []
    for root_id in root_ids:
        out_degree = G.out_degree(root_id)
        confidence_sum = sum(
            G.edges[root_id, child].get("confidence", 0.0)
            for child in G.successors(root_id)
        )
        root_event = G.nodes[root_id].get("data", {})
        root_time = root_event.get("corrected_time") or root_event.get("event_time")
        if isinstance(root_time, str):
            root_time = datetime.fromisoformat(root_time.replace("Z", "+00:00"))

        ranked.append((root_id, out_degree, confidence_sum, root_time))

    ranked.sort(
        key=lambda item: (
            item[1],
            item[2],
            -item[3].timestamp() if isinstance(item[3], datetime) else float("-inf"),
        ),
        reverse=True,
    )
    return ranked[0][0]


def build_incident_flows(
    G: nx.DiGraph,
    root_ids: List[str],
) -> List[Dict]:
    """
    Build ordered incident flows from root causes to leaves.
    Each flow includes the node sequence and step-level metadata.
    """
    chain_paths = extract_chains(G, root_ids)
    if not chain_paths and root_ids:
        chain_paths = [[root_id] for root_id in root_ids]

    flows: List[Dict] = []

    for idx, path in enumerate(chain_paths, start=1):
        steps = []
        edge_confidences = []

        for node_id in path:
            event = G.nodes[node_id].get("data", {})
            steps.append(
                {
                    "event_uid": event.get("event_uid"),
                    "subtype": event.get("subtype"),
                    "severity": event.get("severity"),
                    "device": event.get("device"),
                    "interface_id": event.get("interface_id"),
                    "timestamp": event.get("corrected_time") or event.get("event_time"),
                }
            )

        for i in range(len(path) - 1):
            source_id = path[i]
            target_id = path[i + 1]
            edge_confidences.append(G.edges[source_id, target_id].get("confidence", 0.0))

        flow_score = round(sum(edge_confidences), 3)
        flow_confidence = round(sum(edge_confidences) / len(edge_confidences), 3) if edge_confidences else 0.0

        flows.append(
            {
                "flow_id": f"FLOW-{idx:03d}",
                "root_event_id": path[0],
                "leaf_event_id": path[-1],
                "path_event_ids": path,
                "length": len(path),
                "flow_score": flow_score,
                "flow_confidence": flow_confidence,
                "steps": steps,
            }
        )

    flows.sort(
        key=lambda flow: (flow["length"], flow["flow_score"]),
        reverse=True,
    )

    return flows


# ============================================================
# STEP 9 — FORMAT CAUSAL LINK
# ============================================================

def format_causal_link(
    G:         nx.DiGraph,
    source_id: str,
    target_id: str,
) -> Dict:
    """Serialisable dict for one directed causal edge."""
    source = G.nodes[source_id]["data"]
    target = G.nodes[target_id]["data"]
    edge   = G.edges[source_id, target_id]

    return {
        "cause_id":       source_id,
        "cause_subtype":  source.get("subtype"),
        "cause_device":   source.get("device"),
        "cause_severity": source.get("severity"),

        "effect_id":       target_id,
        "effect_subtype":  target.get("subtype"),
        "effect_device":   target.get("device"),
        "effect_severity": target.get("severity"),

        "lag_sec":    round(time_diff(source, target), 2),
        "confidence": round(edge.get("confidence", 0),  2),
    }


# ============================================================
# STEP 10 — INCIDENT SUMMARY  (used by standalone CLI)
# ============================================================

def get_incident_summary(
    G:           nx.DiGraph,
    root_causes: List[str],
    chains:      List[List[str]],
    incident_flows: Optional[List[Dict]] = None,
) -> Dict:

    all_events  = list(G.nodes(data=True))
    times       = [e[1]["time"] for e in all_events if e[1]["time"]]
    start_time  = min(times) if times else None
    end_time    = max(times) if times else None
    duration    = (end_time - start_time).total_seconds() if (start_time and end_time) else 0
    devices     = {e[1]["device"] for e in all_events if e[1]["device"] != "unknown"}
    causal_links = [
        format_causal_link(G, src, tgt)
        for src, tgt in G.edges()
    ]

    return {
        "num_events":       G.number_of_nodes(),
        "num_causal_links": G.number_of_edges(),
        "num_chains":       len(chains),
        "root_causes":      root_causes,
        "affected_devices": list(devices),
        "start_time":       start_time.isoformat() if start_time else None,
        "end_time":         end_time.isoformat()   if end_time   else None,
        "duration_sec":     round(duration, 2),
        "causal_links":     causal_links,
        "chains":           chains,
        "incident_flows":   incident_flows or [],
    }


# ============================================================
# PUBLIC API FOR timeline_reconstruction.py
# ============================================================

def analyze_cluster(
    events:    List[Dict],
    threshold: float = 1.5,
) -> Tuple[List[Dict], Optional[Dict]]:
    """
    Run causal analysis on an already-preprocessed cluster of flat events.
    Called by timeline_reconstruction.build_incidents() for each cluster.

    Args:
        events    : flat, skew-corrected events (output of preprocessing pipeline)
        threshold : minimum causality score to add a graph edge

    Returns:
        (causal_links, root_cause_event)
        causal_links — list of format_causal_link dicts
        root_cause_event — the event dict identified as root cause, or earliest event
    """
    links, root, _ = analyze_cluster_detailed(events, threshold=threshold)
    return links, root


def analyze_cluster_detailed(
    events: List[Dict],
    threshold: float = 1.5,
) -> Tuple[List[Dict], Optional[Dict], List[Dict]]:
    """
    Detailed cluster analysis returning links, chosen root, and ordered incident flows.
    """
    if not events:
        return [], None, []

    time_window  = compute_dynamic_window(events)
    G            = build_causal_graph(events, threshold=threshold, time_window=time_window)
    root_ids     = find_root_causes(G)
    incident_flows = build_incident_flows(G, root_ids)

    causal_links = [
        format_causal_link(G, src, tgt)
        for src, tgt in G.edges()
    ]

    root_event: Optional[Dict] = None

    primary_root_id = select_primary_root(G, root_ids)
    if primary_root_id:
        root_event = G.nodes[primary_root_id].get("data")

    # Fallback: earliest event in the cluster
    if root_event is None and events:
        root_event = min(
            events,
            key=lambda x: x.get("corrected_time") or x.get("event_time"),
        )

    return causal_links, root_event, incident_flows


# ============================================================
# PRETTY PRINT  (standalone / CLI)
# ============================================================

def print_chains(G: nx.DiGraph, chains: List[List[str]]) -> None:

    if not chains:
        print("\n[WARNING] No causal chains found")
        return

    print("\n" + "=" * 70)
    print("CAUSAL CHAINS")
    print("=" * 70)

    for i, chain in enumerate(chains, 1):
        print(f"\nCHAIN {i} ({len(chain)} events):")

        for j, node_id in enumerate(chain):
            event  = G.nodes[node_id]["data"]
            arrow  = "-> " if j < len(chain) - 1 else "== "

            print(
                f"  {arrow}[{event['event_uid']}] "
                f"{event['device']} | "
                f"{event['subtype']} ({event['severity']}) | "
                f"{event.get('corrected_time') or event.get('event_time')}"
            )


# ============================================================
# STANDALONE PIPELINE  (CLI entry-point only)
# ============================================================

def run_causal_inference(
    input_data:     List[Dict],
    dynamic_window: bool           = True,
    threshold:      float          = 1.5,
    causal_map:     Optional[Dict] = None,
) -> Dict:
    """
    Full pipeline from raw HPE events to incident summary.
    Used when causalInference.py is run directly (not via timeline_reconstruction).
    """
    logger.info("=" * 70)
    logger.info("CAUSAL INFERENCE PIPELINE")
    logger.info("=" * 70)

    # Step 1: Flatten  (preprocessing.py)
    logger.info("\n[STEP 1] Flattening events...")
    flat_events = flatten_events(input_data)

    if not flat_events:
        logger.error("No valid events to process")
        return {"error": "No valid events"}

    # Step 2: Timestamps  (preprocessing.py)
    logger.info("\n[STEP 2] Normalising timestamps...")
    valid_events, dropped = normalize_timestamps(flat_events)

    if not valid_events:
        logger.error("No valid timestamps")
        return {"error": "No valid timestamps"}

    # Step 3: Sort
    logger.info("\n[STEP 3] Sorting events...")
    sorted_events = sorted(valid_events, key=lambda x: x["event_time"])
    logger.info(f"OK Sorted {len(sorted_events)} events")

    # Step 4: Clock skew  (preprocessing.py)
    logger.info("\n[STEP 4] Correcting clock skew...")
    correct_clock_skew(sorted_events)

    # Step 5: Time window  (preprocessing.py)
    if dynamic_window:
        logger.info("\n[STEP 5] Computing dynamic time window...")
        time_window = compute_dynamic_window(sorted_events)
    else:
        logger.info("\n[STEP 5] Using static time window: 10s")
        time_window = 10.0

    # Step 6: Causal graph
    logger.info("\n[STEP 6] Building causal graph...")
    G = build_causal_graph(sorted_events, threshold=threshold, time_window=time_window)

    # Step 7: Root causes
    logger.info("\n[STEP 7] Detecting root causes...")
    root_causes = find_root_causes(G)
    logger.info(f"OK Found {len(root_causes)} root cause(s)")

    # Step 8: Chains
    logger.info("\n[STEP 8] Extracting causal chains...")
    chains = extract_chains(G, root_causes)
    logger.info(f"OK Extracted {len(chains)} chain(s)")

    logger.info("\n[STEP 8.1] Building incident flows...")
    incident_flows = build_incident_flows(G, root_causes)
    logger.info(f"OK Extracted {len(incident_flows)} ranked flow(s)")

    # Step 9: Summary
    logger.info("\n[STEP 9] Generating incident summary...")
    summary = get_incident_summary(G, root_causes, chains, incident_flows=incident_flows)

    print_chains(G, chains)

    logger.info("=" * 70)
    logger.info("PIPELINE COMPLETE")
    logger.info("=" * 70)

    return summary


# ============================================================
# I/O HELPERS
# ============================================================

def _load_events_from_json(path: Path) -> List[Dict]:
    """Accept a bare list or a dict with an 'events' key."""
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    if isinstance(payload, list):
        return payload

    if isinstance(payload, dict):
        maybe = payload.get("events")
        if isinstance(maybe, list):
            return maybe

    raise ValueError(
        "Unsupported JSON structure. Expected a list of events "
        "or a dict with an 'events' list."
    )


def _write_json(path: Path, data: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    project_root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description="Run the causal inference pipeline on an events JSON file."
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        default=None,
        help=(
            "Path to input JSON (list of events). "
            "If omitted, uses datasetphase1.json in the project root when present; "
            "otherwise runs the built-in sample."
        ),
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=1.0,
        help="Causality confidence threshold (default: 1.0)",
    )
    parser.add_argument(
        "--static-window",
        action="store_true",
        help="Use a static 10s time window instead of a dynamic one.",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="causal_inference_output.json",
        help="Write the incident summary JSON to this path (default: causal_inference_output.json).",
    )
    args = parser.parse_args()

    # ── built-in sample ───────────────────────────────────────────────────────
    sample_nested_events = [
        {
            "event": {
                "event_uid": "e1", "event_id": "PKT_DROP",
                "type": "network", "subtype": "packet drop",
                "severity": "warning", "message": "packet drop occurred",
            },
            "device":  {"hostname": "switch-3", "ip": "10.0.0.2", "vendor": "Aruba", "os": "AOS-CX"},
            "network": {"interface_id": "Gig1/0/4", "vlan": 30, "protocol": None},
            "timestamps": {
                "event_time":     "2026-04-20T10:00:02Z",
                "ingestion_time": "2026-04-20T10:00:22Z",
            },
            "raw": {"message": "RAW LOG: packet drop"},
        },
        {
            "event": {
                "event_uid": "e2", "event_id": "ROUTING_CHANGE",
                "type": "network", "subtype": "routing failure",
                "severity": "error", "message": "routing failure detected",
            },
            "device":  {"hostname": "switch-3", "ip": "10.0.0.2", "vendor": "Aruba", "os": "AOS-CX"},
            "network": {"interface_id": "Gig1/0/4", "vlan": 30, "protocol": "BGP"},
            "timestamps": {
                "event_time":     "2026-04-20T10:00:05Z",
                "ingestion_time": "2026-04-20T10:00:25Z",
            },
            "raw": {"message": "RAW LOG: routing failure"},
        },
        {
            "event": {
                "event_uid": "e3", "event_id": "BGP_DOWN",
                "type": "network", "subtype": "bgp session down",
                "severity": "critical", "message": "BGP session terminated",
            },
            "device":  {"hostname": "switch-3", "ip": "10.0.0.2", "vendor": "Aruba", "os": "AOS-CX"},
            "network": {"interface_id": "Gig1/0/4", "vlan": 30, "protocol": "BGP"},
            "timestamps": {
                "event_time":     "2026-04-20T10:00:08Z",
                "ingestion_time": "2026-04-20T10:00:28Z",
            },
            "raw": {"message": "RAW LOG: BGP DOWN"},
        },
    ]
    # ─────────────────────────────────────────────────────────────────────────

    if args.input:
        input_path = Path(args.input).expanduser()
        if not input_path.is_file():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        input_events = _load_events_from_json(input_path)
        source_desc  = str(input_path)
    else:
        default_path = project_root / "datasetphase1.json"
        if default_path.is_file():
            input_events = _load_events_from_json(default_path)
            source_desc  = str(default_path)
        else:
            input_events = sample_nested_events
            source_desc  = "built-in sample_nested_events"

    logger.info(f"Input source: {source_desc} ({len(input_events)} raw events)")

    result = run_causal_inference(
        input_events,
        dynamic_window = not args.static_window,
        threshold      = args.threshold,
    )

    if args.output:
        output_path = Path(args.output).expanduser()
        _write_json(output_path, result)
        logger.info(f"Wrote output JSON: {output_path.resolve()}")

    print("\n" + "=" * 70)
    print("INCIDENT SUMMARY")
    print("=" * 70)
    print(f"Input:           {source_desc}")
    print(f"Events:          {result['num_events']}")
    print(f"Causal Links:    {result['num_causal_links']}")
    print(f"Chains:          {result['num_chains']}")
    print(f"Root Causes:     {result['root_causes']}")
    print(f"Affected Devices:{result['affected_devices']}")
    print(f"Duration:        {result['duration_sec']}s")

    print("\nCausal Links:")
    for link in result["causal_links"]:
        print(
            f"  {link['cause_subtype']} ({link['cause_device']}) "
            f"-> {link['effect_subtype']} ({link['effect_device']}) "
            f"[lag={link['lag_sec']}s, conf={link['confidence']}]"
        )

    print("\nCausal Chains:")
    for i, chain in enumerate(result["chains"], 1):
        print(f"  Chain {i}: {' -> '.join(chain)}")
