"""
timeline_reconstruction.py — Production Incident Timeline Reconstruction Engine

Revised architecture (Stages 3-5):
  Stage 3: Temporal alignment (sort by corrected_time)
  Stage 4: Pairwise compatibility scoring (symmetric, topology-first)
  Stage 5: Incident graph partitioning via Louvain community detection

This replaces the old time-window clustering + cross-device UnionFind merge
approach.  The key architectural change: shared topology/identifiers are the
primary grouping signal, and time is secondary.  This correctly separates
overlapping incidents that happen to be temporally proximate but are causally
unrelated.

Input : preprocessed_events.json or schema_output.json
Output: timeline_output.json
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from preprocessing import (
    compute_dynamic_window,
    correct_clock_skew,
    flatten_events,
    json_serializable,
    load_data,
    normalize_timestamps,
    restore_datetime_fields,
)
from topology_extraction import (
    extract_topology,
    same_client_mac,
    save_topology,
    shares_explicit_reference,
    shares_interface_reference,
    shares_vlan_or_subnet,
)


# =========================================================
# CONSTANTS
# =========================================================

# Maximum plausible span of a single incident (seconds).
# Events further apart than this are never considered for the same incident.
MAX_PLAUSIBLE_INCIDENT_SPAN = 1800  # 30 minutes

# Minimum compatibility score for an edge in the compatibility graph.
COMPAT_THRESHOLD = 0.40

# Louvain resolution parameter.
# Higher = more, smaller communities.  Lower = fewer, larger ones.
LOUVAIN_RESOLUTION = 0.3

# Domain classification rules — reused from earlier design.
DOMAIN_RULES = [
    ("hardware", ["power", "psu", "fan", "temperature", "thermal", "hw", "hardware"]),
    ("security", ["ssh login failed", "maximum attempts", "security", "bruteforce", "brute force", "radius"]),
    ("authentication", ["802.1x", "mac-auth", "auth", "authentication"]),
    ("routing", ["bgp", "ospf", "routing", "neighbor", "peer"]),
    ("stp_topology", ["mstp", "stp", "topology change", "forwarding", "learning"]),
    ("physical_link", ["crc", "transceiver", "optic", "sfp", "link down", "off-line", "offline", "port"]),
    ("configuration", ["configuration changed", "config changed", "config"]),
    ("service", ["ntp", "snmp", "daemon", "vsftpd"]),
    ("inventory", ["lldp", "vlan"]),
]

COMPATIBLE_DOMAINS = {
    "hardware": {"hardware", "physical_link", "stp_topology", "routing"},
    "physical_link": {"physical_link", "stp_topology", "routing", "authentication"},
    "stp_topology": {"physical_link", "stp_topology", "routing"},
    "routing": {"physical_link", "stp_topology", "routing", "configuration"},
    "authentication": {"authentication", "security", "physical_link"},
    "security": {"security", "authentication"},
    "configuration": {"configuration", "routing", "physical_link", "authentication"},
    "service": {"service"},
    "inventory": {"inventory"},
    "unknown": {"unknown"},
}

# Historical subtype co-occurrence patterns — subtypes commonly observed
# together in the same incident (regardless of causal direction).
COOCCURRING_SUBTYPES = {
    frozenset({"interface_down", "stp_topology_change"}),
    frozenset({"interface_down", "bgp"}),
    frozenset({"interface_down", "ospf"}),
    frozenset({"interface_down", "ospf_interface_down"}),
    frozenset({"interface_down", "ospf_neighbor_down"}),
    frozenset({"stp_topology_change", "bgp"}),
    frozenset({"stp_topology_change", "ospf"}),
    frozenset({"stp_topology_change", "ospf_interface_down"}),
    frozenset({"stp_topology_change", "ospf_neighbor_down"}),
    frozenset({"power", "fan"}),
    frozenset({"power", "interface_down"}),
    frozenset({"crc_errors", "interface_down"}),
    frozenset({"config_change", "bgp"}),
    frozenset({"config_change", "ospf"}),
    frozenset({"config_change", "interface_down"}),
    frozenset({"dot1x_failure", "interface_down"}),
    frozenset({"radius_failure", "dot1x_failure"}),
    frozenset({"bgp", "ospf"}),
    # VXLAN co-occurrences
    frozenset({"tunnel_nexthop_delete", "tunnel_activating"}),
    frozenset({"tunnel_nexthop_delete", "vtep_down"}),
    frozenset({"tunnel_activating", "tunnel_operational"}),
    frozenset({"interface_down", "tunnel_nexthop_delete"}),
}

SEVERITY_RANK = {
    "debug": 0, "info": 1, "notice": 1,
    "warning": 2, "warn": 2,
    "error": 3, "err": 3,
    "critical": 4, "crit": 4,
    "alert": 5, "emergency": 6,
}


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def text_of(e: Dict[str, Any]) -> str:
    return " ".join(
        str(e.get(k, ""))
        for k in ["subtype", "type", "severity", "message", "raw_message", "process"]
    ).lower()


def normalize_domain(e: Dict[str, Any]) -> str:
    txt = text_of(e)
    for domain, keys in DOMAIN_RULES:
        if any(k in txt for k in keys):
            return domain
    return "unknown"


def extract_port(e: Dict[str, Any]) -> Optional[str]:
    """Helper to extract physical port identifier if present."""
    val = e.get("interface_id")
    if val and str(val) != "<IFACE>":
        return str(val)
    txt = text_of(e)
    # E.g. "port 1/1/2" or "interface 1/1/2"
    m = re.search(r'\b(?:port|interface)\s+(\d+/\d+/\d+|\d+/\d+|\d+)\b', txt, re.I)
    if m:
        return m.group(1)
    return None


def severity_rank(e: Dict[str, Any]) -> int:
    return SEVERITY_RANK.get(str(e.get("severity", "info")).lower(), 1)


def event_time(e: Dict[str, Any]) -> datetime:
    if "corrected_time" not in e:
        print(f"CRITICAL ERROR: corrected_time missing from event with uid {e.get('event_uid', 'NONE')}")
        print(f"Event keys: {list(e.keys())}")
    return e["corrected_time"]


def _normalize_subtype(e: Dict[str, Any]) -> str:
    """Quick subtype normalizer for co-occurrence matching."""
    txt = text_of(e).lower()
    if "power supply" in txt or "psu" in txt: return "power"
    if "fan" in txt: return "fan"
    if "crc" in txt: return "crc_errors"
    if "off-line" in txt or "offline" in txt or "link down" in txt or "status changed to down" in txt or "state to down" in txt: return "interface_down"
    if "on-line" in txt or "online" in txt or "link up" in txt or "state to up" in txt: return "interface_up"
    if "topology change" in txt: return "stp_topology_change"
    if "ospf" in txt:
        if "neighbor" in txt and "down" in txt: return "ospf_neighbor_down"
        if "interface" in txt and "down" in txt: return "ospf_interface_down"
        if "calculation" in txt or "recalculation" in txt: return "ospf_recalculation"
        return "ospf"
    if "bgp" in txt: return "bgp"
    if "configuration changed" in txt or "configured from console" in txt or "sys-5-config" in txt: return "config_change"
    if "ssh login failed" in txt or "maximum attempts" in txt or "denied tcp" in txt: return "ssh_bruteforce"
    if "authentication failure for user" in txt: return "admin_auth_failure"
    if "radius" in txt and ("unreachable" in txt or "failed" in txt or "timeout" in txt): return "radius_failure"
    if "802.1x" in txt and ("failed" in txt or "failure" in txt): return "dot1x_failure"
    if "mac-auth" in txt: return "mac_auth"
    if "transceiver" in txt: return "transceiver"
    if "lldp" in txt: return "lldp"
    if "nexthop delete" in txt: return "tunnel_nexthop_delete"
    if "nexthop add" in txt: return "tunnel_nexthop_add"
    if "activating" in txt: return "tunnel_activating"
    if "operational" in txt and "tunnel" in txt: return "tunnel_operational"
    if "vtep" in txt: return "vtep_down" if "down" in txt else "vtep_operational"
    if "vni" in txt: return "vni_create"
    if "vxlan" in txt: return "vxlan_interface"
    if "vlan" in txt: return "vlan"
    if "snmp" in txt: return "snmp"
    if "ntp" in txt: return "ntp"
    return e.get("subtype", "unknown")


def subtypes_cooccur(a: Dict, b: Dict) -> bool:
    """Check if two event subtypes are historically seen in the same incident."""
    sa = _normalize_subtype(a)
    sb = _normalize_subtype(b)
    return frozenset({sa, sb}) in COOCCURRING_SUBTYPES


# =========================================================
# STAGE 4: PAIRWISE COMPATIBILITY SCORING
# =========================================================

def compatibility_score(
    a: Dict[str, Any],
    b: Dict[str, Any],
    topo: nx.Graph,
) -> float:
    """
    Compute a symmetric compatibility score between two events.

    This answers: "do these two events belong to the same incident story?"
    NOT "did A cause B" (that's causal inference, Stage 6).

    The score is deliberately permissive on timing but strict on
    topological/identifier evidence.  This inversion from the old design
    is the key fix: previously, time-window proximity was the primary
    grouping signal (which causes incident-merging errors when unrelated
    things happen close in time).  Now, shared identity/topology is
    primary, and time is secondary.

    Parameters
    ----------
    a, b : flat event dicts with corrected_time, device, device_ip, etc.
    topo : undirected topology graph from Stage 2

    Returns
    -------
    float in [0, 1] — higher means more likely same incident
    """
    score = 0.0

    dev_a = a.get("device", "unknown")
    dev_b = b.get("device", "unknown")

    # --------------------------------------------------
    # 1. Topological connection (from inferred topology)
    # --------------------------------------------------
    if dev_a != "unknown" and dev_b != "unknown" and dev_a != dev_b:
        if topo.has_edge(dev_a, dev_b):
            score += 0.40
        elif topo.has_node(dev_a) and topo.has_node(dev_b):
            try:
                path_len = nx.shortest_path_length(topo, dev_a, dev_b)
                if path_len <= 2:
                    score += 0.20  # 2-hop connection, weaker
            except nx.NetworkXNoPath:
                pass

    # Same device is a moderate signal (not as strong as shared identifiers)
    if dev_a == dev_b and dev_a != "unknown":
        score += 0.15

    # Explicit cross-references in log content
    if shares_explicit_reference(a, b):
        score += 0.30

    # --------------------------------------------------
    # 2. Shared identifiers — strong same-story signal
    # --------------------------------------------------
    # Check for shared STP instances (e.g. "Instance 0")
    text_a = a.get("message", a.get("raw_message", ""))
    text_b = b.get("message", b.get("raw_message", ""))
    inst_a = re.search(r'Instance (\d+)', text_a, re.I)
    inst_b = re.search(r'Instance (\d+)', text_b, re.I)
    shares_stp = inst_a and inst_b and inst_a.group(1) == inst_b.group(1)
    
    pa, pb = extract_port(a), extract_port(b)
    if pa and pb and pa != pb:
        # Heavily penalize explicitly different ports on the same device.
        # This prevents an 802.1x failure on 1/1/8 from being grouped with interface 1/1/1 down.
        if dev_a == dev_b:
            if shares_stp:
                score += 0.50 # Bonus for Domino pattern sharing the same STP instance
            else:
                score -= 0.30

    if shares_vlan_or_subnet(a, b):
        score += 0.20

    if shares_interface_reference(a, b) and dev_a == dev_b:
        score += 0.15

    if same_client_mac(a, b):
        score += 0.15

    # --------------------------------------------------
    # 3. Domain compatibility
    # --------------------------------------------------
    da = a.get("incident_domain", normalize_domain(a))
    db = b.get("incident_domain", normalize_domain(b))
    if da == db and da != "unknown":
        score += 0.20
    elif db in COMPATIBLE_DOMAINS.get(da, set()):
        score += 0.10
        
    # Prevent independent interface flaps from being swept into routing incidents
    # just because they happen within the time window.
    if {"physical_link", "routing"}.issubset({da, db}):
        if not (shares_stp or shares_explicit_reference(a, b) or shares_interface_reference(a, b) or shares_vlan_or_subnet(a, b)):
            ta_val, tb_val = event_time(a), event_time(b)
            lag_val = abs((tb_val - ta_val).total_seconds())
            if dev_a == dev_b and lag_val <= 5:
                score += 0.30 # Strong bonus to bind same-device L1->L3 cascades
            else:
                score -= 0.10

    # --------------------------------------------------
    # 4. Temporal compatibility
    # NOT proximity — "could a real propagation delay explain this gap?"
    # Intentionally generous, since Stage 6 will narrow with causal direction.
    # --------------------------------------------------
    ta = event_time(a)
    tb = event_time(b)
    lag = abs((tb - ta).total_seconds())

    if lag <= MAX_PLAUSIBLE_INCIDENT_SPAN:
        # Linear decay: full bonus at lag=0, zero at MAX_PLAUSIBLE_INCIDENT_SPAN
        score += 0.10 * (1 - lag / MAX_PLAUSIBLE_INCIDENT_SPAN)

    # --------------------------------------------------
    # 5. Historical subtype co-occurrence
    # --------------------------------------------------
    if subtypes_cooccur(a, b):
        score += 0.15

    return min(score, 1.0)


# =========================================================
# STAGE 5: INCIDENT GRAPH PARTITIONING (Louvain)
# =========================================================

def _candidate_pairs_within_window(
    events: List[Dict[str, Any]],
    max_window: timedelta,
) -> List[Tuple[Dict, Dict]]:
    """
    Generate candidate event pairs within the time window.
    Events must be sorted by corrected_time.
    """
    pairs = []
    for i in range(len(events)):
        ta = event_time(events[i])
        for j in range(i + 1, len(events)):
            tb = event_time(events[j])
            if (tb - ta).total_seconds() > max_window.total_seconds():
                break
            pairs.append((events[i], events[j]))
    return pairs


def build_compatibility_graph(
    events: List[Dict[str, Any]],
    topo: nx.Graph,
    threshold: float = COMPAT_THRESHOLD,
) -> nx.Graph:
    """
    Build an undirected compatibility graph over all events.

    Nodes: event_uid
    Edges: compatibility score >= threshold

    Parameters
    ----------
    events : sorted list of flat event dicts
    topo : topology graph from Stage 2
    threshold : minimum compatibility score for an edge

    Returns
    -------
    nx.Graph with event-level compatibility edges
    """
    G = nx.Graph()
    for e in events:
        G.add_node(e["event_uid"], **e)

    pairs = _candidate_pairs_within_window(
        events,
        max_window=timedelta(seconds=MAX_PLAUSIBLE_INCIDENT_SPAN),
    )

    edge_count = 0
    for a, b in pairs:
        score = compatibility_score(a, b, topo)
        if score >= threshold:
            G.add_edge(a["event_uid"], b["event_uid"], weight=score)
            edge_count += 1

    print(f"[COMPAT]     ✔ Compatibility graph: {G.number_of_nodes()} nodes, "
          f"{edge_count} edges (from {len(pairs)} candidate pairs)")

    return G


def partition_into_incidents(
    G: nx.Graph,
    resolution: float = LOUVAIN_RESOLUTION,
) -> List[Set[str]]:
    """
    Use Louvain community detection to partition events into incidents.

    Each community is a set of event_uid strings representing one incident.
    Singleton nodes (no compatible neighbors) become their own incidents.

    Parameters
    ----------
    G : compatibility graph
    resolution : Louvain resolution parameter

    Returns
    -------
    list of sets of event_uid strings
    """
    if G.number_of_nodes() == 0:
        return []

    # Handle disconnected components: run Louvain on each connected component
    # separately, since Louvain works best on connected graphs.
    communities = []
    _NOISE_DOMAINS = {"service", "inventory"}

    for component in nx.connected_components(G):
        subgraph = G.subgraph(component)

        if len(component) == 1:
            communities.append(set(component))
            continue
            
        elif len(component) == 2:
            # Small components are trivially one community
            communities.append(set(component))
            continue

        try:
            sub_communities = nx.community.louvain_communities(
                subgraph,
                weight="weight",
                resolution=resolution,
                seed=42,  # deterministic
            )
            communities.extend(sub_communities)
        except Exception as e:
            # Fallback: treat entire component as one community
            print(f"[PARTITION]  ⚠ Louvain failed on component of size {len(component)}: {e}")
            communities.append(set(component))

    print(f"[PARTITION]  ✔ Louvain partitioned {G.number_of_nodes()} events "
          f"into {len(communities)} incident communities "
          f"(resolution={resolution})")

    return communities


# =========================================================
# INCIDENT BUILDING
# =========================================================

def deduplicate_cluster(cluster: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate events in a cluster by content signature."""
    seen: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for e in cluster:
        key = (
            e.get("device"),
            e.get("incident_domain"),
            e.get("subtype"),
            e.get("interface_id"),
            (e.get("message") or "")[:150],
        )
        if key in seen:
            seen[key]["duplicate_count"] = seen[key].get("duplicate_count", 1) + 1
        else:
            e["duplicate_count"] = 1
            seen[key] = e
    return list(seen.values())


def build_incidents(
    communities: List[Set[str]],
    events_by_uid: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Build incident dicts from community-detected event sets.

    Parameters
    ----------
    communities : list of sets of event_uid strings
    events_by_uid : uid -> event dict lookup

    Returns
    -------
    list of incident dicts
    """
    incidents = []
    # Sort communities by earliest event time for consistent INC-XXXX numbering
    community_list = []
    for comm in communities:
        comm_events = [events_by_uid[uid] for uid in comm if uid in events_by_uid]
        if comm_events:
            earliest = min(event_time(e) for e in comm_events)
            community_list.append((earliest, comm_events))

    community_list.sort(key=lambda x: x[0])

    for idx, (_, comm_events) in enumerate(community_list, start=1):
        deduped = sorted(deduplicate_cluster(comm_events), key=event_time)
        domains = sorted({e.get("incident_domain", "unknown") for e in deduped})
        devices = sorted({e.get("device") or "unknown" for e in deduped})
        start = min(event_time(e) for e in deduped)
        end = max(event_time(e) for e in deduped)

        incident = {
            "incident_id": f"INC-{idx:04d}",
            "incident_domain": domains[0] if len(domains) == 1 else "+".join(domains),
            "start_time": start,
            "end_time": end,
            "duration_sec": (end - start).total_seconds(),
            "devices": devices,
            "event_count": len(deduped),
            "events": deduped,
        }
        incidents.append(incident)
        print(f"[INCIDENT]   {incident['incident_id']} | {incident['incident_domain']} "
              f"| {len(deduped)} events | devices: {', '.join(devices)}")

    return incidents


# =========================================================
# TIMELINE DISPLAY
# =========================================================

def print_timeline(incidents: List[Dict[str, Any]]) -> None:
    print("\n" + "=" * 70)
    print("INCIDENT TIMELINE")
    print("=" * 70)
    for inc in incidents:
        print(f"\n{'─' * 70}")
        print(f"  {inc['incident_id']} | domain: {inc['incident_domain']}")
        print(f"{'─' * 70}")
        print(f"  Start    : {inc['start_time']}")
        print(f"  End      : {inc['end_time']}")
        print(f"  Duration : {inc['duration_sec']} sec")
        print(f"  Devices  : {', '.join(inc['devices'])}")
        print(f"  Events   : {inc['event_count']}")
        print(f"\n  {'TIME':<23} {'DEVICE':<16} {'SEVERITY':<9} {'DOMAIN':<16} {'SUBTYPE':<18} MESSAGE")
        print(f"  {'─'*21} {'─'*14} {'─'*8} {'─'*14} {'─'*16} {'─'*30}")
        for e in inc["events"]:
            print(
                f"  {str(e.get('corrected_time')):<23} "
                f"{str(e.get('device') or 'unknown')[:15]:<16} "
                f"{str(e.get('severity') or 'info')[:8]:<9} "
                f"{str(e.get('incident_domain') or 'unknown')[:15]:<16} "
                f"{str(e.get('subtype') or 'unknown')[:17]:<18} "
                f"{str(e.get('message') or '')[:80]}"
            )
    print(f"\n{'=' * 70}")
    print(f"Total incidents: {len(incidents)}")
    print("=" * 70)


# =========================================================
# MAIN PIPELINE
# =========================================================

def run_pipeline(
    input_path: str,
    output_path: str = "timeline_output.json",
    topo: nx.Graph = None,
    threshold: float = COMPAT_THRESHOLD,
    resolution: float = LOUVAIN_RESOLUTION,
):
    """
    Run the full timeline reconstruction pipeline (Stages 3-5).

    Parameters
    ----------
    input_path : path to preprocessed_events.json or schema_output.json
    output_path : path for timeline_output.json
    topo : pre-computed topology graph (if None, will be extracted from events)
    threshold : compatibility score threshold for graph edges
    resolution : Louvain resolution parameter

    Returns
    -------
    list of incident dicts (serializable)
    """
    print("\n" + "═" * 60)
    print(" HPE PRODUCTION INCIDENT TIMELINE RECONSTRUCTION ENGINE ")
    print("    (Graph-Partitioned Architecture)")
    print("═" * 60)

    # Load and preprocess
    raw = load_data(input_path)
    is_preprocessed = raw and isinstance(raw[0], dict) and "corrected_time" in raw[0]

    if is_preprocessed:
        print("[LOAD]       Already preprocessed — skipping flatten/skew")
        norm = restore_datetime_fields(raw)
    else:
        flat = flatten_events(raw)
        norm, _ = normalize_timestamps(flat)
        correct_clock_skew(norm)

    if not norm:
        print("[ERROR]      No events to process")
        return []

    # Stage 3: Temporal alignment (sort)
    print("\n[STAGE 3]    Temporal alignment...")
    for e in norm:
        e["incident_domain"] = normalize_domain(e)
        e["interface_id"] = e.get("interface_id") or extract_port(e)
    norm = sorted(norm, key=event_time)
    print(f"[STAGE 3]    ✔ {len(norm)} events sorted by corrected_time")

    # Stage 2: Topology extraction (if not provided)
    if topo is None:
        print("\n[STAGE 2]    Extracting implicit topology...")
        topo = extract_topology(norm)

    # Stage 4: Pairwise compatibility scoring
    print("\n[STAGE 4]    Building compatibility graph...")
    compat_graph = build_compatibility_graph(norm, topo, threshold=threshold)

    # Stage 5: Louvain community detection
    print("\n[STAGE 5]    Partitioning into incidents...")
    communities = partition_into_incidents(compat_graph, resolution=resolution)

    # Build incident structures
    events_by_uid = {e["event_uid"]: e for e in norm}
    print("\n[BUILD]      Building production incidents...")
    incidents = build_incidents(communities, events_by_uid)

    # Display
    print_timeline(incidents)

    # Serialize and save
    serializable = json.loads(json.dumps(incidents, default=json_serializable))
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)

    print(f"\n[OUTPUT]     ✔ Timeline written to '{output_path}'")
    print("═" * 60)
    return serializable


# =========================================================
# CLI
# =========================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Production HPE Incident Timeline Reconstruction (Graph-Partitioned)"
    )
    parser.add_argument("input", nargs="?", default="preprocessed_events.json")
    parser.add_argument("-o", "--output", default="timeline_output.json")
    parser.add_argument("--threshold", type=float, default=COMPAT_THRESHOLD,
                        help=f"Compatibility score threshold (default: {COMPAT_THRESHOLD})")
    parser.add_argument("--resolution", type=float, default=LOUVAIN_RESOLUTION,
                        help=f"Louvain resolution (default: {LOUVAIN_RESOLUTION})")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[ERROR] File not found: {args.input}")
        sys.exit(1)

    run_pipeline(
        args.input, args.output,
        threshold=args.threshold,
        resolution=args.resolution,
    )
