"""
causalInference.py — Production Network Root Cause Analysis Engine

Reads timeline_output.json and produces deterministic production-safe RCA.
Uses NetworkX to build a causal DAG and extract causal sequences.
"""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

SEV = {"debug": 0, "info": 1, "notice": 1, "warning": 2, "warn": 2, "error": 3, "err": 3, "critical": 4, "crit": 4}
BENIGN = {"snmp", "ntp", "vlan", "lldp", "transceiver", "interface_up", "mac_auth_success", "dot1x_logout",
          "vtep_operational", "tunnel_operational", "vni_create", "vxlan_interface", "tunnel_nexthop_add"}
ACTIONABLE_LOW_OK = {"stp_topology_change", "config_change", "tunnel_nexthop_delete"}

# BASE scores reflect the causal weight of each event type.
# Hardware/Physical failures score highest. VXLAN/tunnel events are Layer 2/3 overlay.
BASE = {
    # --- Layer 0: Hardware ---
    "power": 130, "fan": 110,
    # --- Layer 1: Physical Link ---
    "crc_errors": 120, "interface_down": 115, "transceiver": 70,
    # --- Layer 2: Switching / Topology / VXLAN Overlay ---
    "stp_topology_change": 85, "vlan": 20, "lldp": 18,
    "mac_auth_success": 5, "dot1x_failure": 30, "dot1x_logout": 5,
    "vni_create": 25, "vxlan_interface": 30,
    "vtep_operational": 10, "vtep_down": 90,
    # --- Layer 3: Routing / Tunnel Underlay ---
    "ospf": 95, "bgp": 80,
    "tunnel_nexthop_delete": 95,  # nexthop withdraw = routing change, high-weight root cause
    "tunnel_nexthop_add": 10,     # nexthop add = recovery, low root-cause weight
    "tunnel_activating": 40,
    "tunnel_operational": 8,      # tunnel up = recovery indicator
    # --- Configuration ---
    "config_change": 60,
    # --- Security ---
    "ssh_bruteforce": 25, "admin_auth_failure": 20,
    # --- Informational / noise ---
    "interface_up": 5, "snmp": 3, "ntp": 3,
}

# LAYER maps each subtype to its OSI-ish tier.
LAYER = {
    "power": 0, "fan": 0,
    "crc_errors": 1, "interface_down": 1,
    "interface_up": 1, "transceiver": 1,
    "stp_topology_change": 2, "vlan": 2, "lldp": 2,
    "mac_auth_success": 2, "dot1x_failure": 2,
    "vni_create": 2, "vxlan_interface": 2, "vtep_operational": 2, "vtep_down": 2,
    "ospf": 3, "bgp": 3, "config_change": 3,
    "tunnel_nexthop_delete": 3, "tunnel_nexthop_add": 3,
    "tunnel_activating": 3, "tunnel_operational": 3,
    "ssh_bruteforce": 4, "admin_auth_failure": 4,
}

# Network domain classification (5-tier + VXLAN overlay):
DOMAIN_TIER = {
    "power": "Layer 0 - Hardware",
    "fan": "Layer 0 - Hardware",
    "crc_errors": "Layer 1 - Physical",
    "interface_down": "Layer 1 - Physical",
    "interface_up": "Layer 1 - Physical",
    "transceiver": "Layer 1 - Physical",
    "stp_topology_change": "Layer 2 - Switching",
    "vlan": "Layer 2 - Switching",
    "lldp": "Layer 2 - Switching",
    "mac_auth_success": "Layer 2 - Switching",
    "dot1x_failure": "Layer 2 - Switching",
    "dot1x_logout": "Layer 2 - Switching",
    "vni_create": "Layer 2 - VXLAN Overlay",
    "vxlan_interface": "Layer 2 - VXLAN Overlay",
    "vtep_operational": "Layer 2 - VXLAN Overlay",
    "vtep_down": "Layer 2 - VXLAN Overlay",
    "ospf": "Layer 3 - Routing",
    "bgp": "Layer 3 - Routing",
    "config_change": "Layer 3 - Routing",
    "tunnel_nexthop_delete": "Layer 3 - VXLAN Underlay",
    "tunnel_nexthop_add": "Layer 3 - VXLAN Underlay",
    "tunnel_activating": "Layer 3 - VXLAN Underlay",
    "tunnel_operational": "Layer 3 - VXLAN Underlay",
    "ssh_bruteforce": "Layer 4 - Security",
    "admin_auth_failure": "Layer 4 - Security",
    "snmp": "Layer 4 - Management",
    "ntp": "Layer 4 - Management",
}

RECOVERY_EVENTS = {"interface_up", "bgp", "ospf", "fan", "power", "ntp",
                   "tunnel_operational", "vtep_operational", "tunnel_nexthop_add"}
RECOVERY_KEYWORDS = {"established", "up", "on-line", "online", "restored", "synchronized",
                     "forwarding", "operational", "activating"}


def n(v) -> str:
    return str(v or "").lower().strip()


def parse_dt(v):
    if isinstance(v, datetime): return v
    return datetime.fromisoformat(str(v).replace("Z", "+00:00"))


def get_time(e):
    return e.get("corrected_time") or e.get("event_time") or e.get("timestamp")


def text(e):
    return " ".join([n(e.get("type")), n(e.get("subtype")), n(e.get("message")), n(e.get("raw_message")), n(e.get("domain"))])


def subtype(e):
    s = text(e)
    # --- Standard syslog events ---
    if "snmpd" in s: return "snmp"
    if "ntp" in s: return "ntp"
    if "power supply" in s or "psu" in s: return "power"
    if "fan" in s: return "fan"
    if "crc" in s: return "crc_errors"
    if "off-line" in s or "offline" in s or "link down" in s: return "interface_down"
    if "on-line" in s or "online" in s or "link up" in s: return "interface_up"
    if "topology change" in s: return "stp_topology_change"
    if "ospf" in s: return "ospf"
    if "bgp" in s: return "bgp"
    if "configuration changed" in s: return "config_change"
    if "ssh login failed" in s or "maximum attempts" in s: return "ssh_bruteforce"
    if "authentication failure for user" in s: return "admin_auth_failure"
    if "802.1x" in s and ("failed" in s or "failure" in s): return "dot1x_failure"
    if "802.1x" in s and "logged out" in s: return "dot1x_logout"
    if "mac-auth" in s: return "mac_auth_success"
    if "transceiver" in s: return "transceiver"
    if "lldp" in s: return "lldp"
    if "vlan" in s and "vxlan" not in s and "vni" not in s: return "vlan"
    # --- HPE 9300 / VXLAN / EVPN events ---
    if "nexthop delete" in s: return "tunnel_nexthop_delete"
    if "nexthop add" in s: return "tunnel_nexthop_add"
    if "forwarding_state is activating" in s or "tunnel_activating" in s: return "tunnel_activating"
    if ("forwarding_state is operational" in s or "tunnel_operational" in s
            or "tunnel_forwarding_state" in s): return "tunnel_operational"
    if "vtep-peer" in s or "vtep_peer" in s:
        if "operational" in s: return "vtep_operational"
        return "vtep_down"
    if "vni" in s: return "vni_create"
    if "vxlan" in s: return "vxlan_interface"
    # Fallback to schema-assigned subtype
    schema_st = n(e.get("subtype"))
    if schema_st and schema_st not in ("unknown", ""):
        return schema_st
    return "unknown"


def domain(e):
    """Return the 5-tier network domain classification for an event."""
    st = subtype(e)
    return DOMAIN_TIER.get(st, n(e.get("domain")) or n(e.get("type")) or "generic")


def port(e):
    val = e.get("interface_id")
    if val and str(val) != "<IFACE>": return str(val)
    m = re.search(r"\bport\s+(\d+/\d+/\d+|\d+/\d+|\d+)\b", text(e), re.I)
    return m.group(1) if m else None


def is_recovery(e):
    st = subtype(e)
    s = text(e)
    if st in RECOVERY_EVENTS and any(kw in s for kw in RECOVERY_KEYWORDS):
        return True
    return False


# Event types that should NEVER be selected as root cause because they are
# almost always downstream effects or independent noise in network incidents.
_SECURITY_NOISE = {"ssh_bruteforce", "admin_auth_failure", "dot1x_logout", "mac_auth_success"}
# Hardware/physical events that should be strongly boosted as root cause candidates.
_INFRA_CRITICAL = {"power", "fan", "crc_errors", "interface_down", "transceiver"}
_ROUTING_CRITICAL = {"ospf", "bgp"}


def root_score(e, idx, total):
    """Compute a root-cause score for an event.

    Higher score = more likely to be the initiating root cause.

    Design principles
    -----------------
    * Hardware failures (PSU, fan) and physical-link failures (CRC, interface
      down) get the highest possible base scores because they physically cause
      downstream network effects.
    * Routing convergence failures (OSPF/BGP) score high as they represent
      control-plane impact that correlates with infrastructure disruption.
    * Security/auth events (SSH brute-force, admin login failures) score VERY
      LOW — they are rarely the initiator of infrastructure outages and are
      typically either independent noise or a consequence of service disruption.
    * Events earlier in the timeline get a small recency bonus because root
      causes tend to appear before symptoms.
    """
    st = subtype(e)
    sev = SEV.get(n(e.get("severity")), 1)
    s = text(e)

    # --- Base score from type priority ---
    score = BASE.get(st, 20)

    # --- Severity multiplier (smaller than before to avoid inflating security events) ---
    score += sev * 8

    # --- Infrastructure-specific boosts ---
    if st in _INFRA_CRITICAL:
        score += 40  # Strong physical/hardware evidence bonus
    if st in _ROUTING_CRITICAL:
        score += 25  # Control-plane failure bonus

    # --- Keyword boosts (only for infra events to avoid inflating auth noise) ---
    if st in _INFRA_CRITICAL or st in _ROUTING_CRITICAL:
        if "failure" in s or "failed" in s: score += 15
        if "down" in s or "off-line" in s or "offline" in s: score += 15
        if "crc" in s or "error" in s: score += 12

    # --- Penalise benign/informational events ---
    if st in BENIGN and sev <= 1: score -= 80

    # --- Heavily penalise security noise events ---
    # SSH brute-force and admin auth failures score so low they will never
    # displace hardware/physical events as root cause.
    if st in _SECURITY_NOISE:
        score -= 60

    # --- Penalise recovery events ---
    if is_recovery(e): score -= 60

    # --- Small early-in-timeline bonus (root causes appear first) ---
    score += max(0, total - idx) * 0.3

    return round(score, 2)


def is_actionable(e):
    st = subtype(e)
    sev = SEV.get(n(e.get("severity")), 1)
    if st in {"snmp", "ntp"} and sev <= 2:
        return False
    if st in BENIGN and sev <= 1:
        return False
    return sev >= 2 or st in ACTIONABLE_LOW_OK


def relation(a, b) -> Tuple[float, Optional[str]]:
    ta, tb = parse_dt(get_time(a)), parse_dt(get_time(b))
    if tb <= ta: return 0, None
    lag = (tb - ta).total_seconds()
    if lag > 1800: return 0, None
    sa, sb = subtype(a), subtype(b)
    da, db = domain(a), domain(b)
    score, reasons = 0.0, []
    if a.get("device") == b.get("device"):
        score += 0.15; reasons.append("same device")
    if port(a) and port(a) == port(b):
        score += 0.35; reasons.append("same port")

    pairs = {
        # Standard syslog causal chains
        "power": {"fan", "interface_down", "crc_errors"},
        "crc_errors": {"interface_down", "stp_topology_change", "ospf", "bgp"},
        "interface_down": {"stp_topology_change", "ospf", "bgp", "dot1x_failure",
                           "tunnel_nexthop_delete", "vtep_down"},
        "stp_topology_change": {"ospf", "bgp"},
        "config_change": {"interface_down", "stp_topology_change", "ospf", "bgp", "dot1x_failure"},
        "admin_auth_failure": {"ssh_bruteforce"},
        "dot1x_failure": {"dot1x_logout"},
        # VXLAN/tunnel reconvergence chain:
        # underlay routing change → nexthop delete → tunnel activating → nexthop add → operational → vtep up
        "tunnel_nexthop_delete": {"tunnel_activating", "tunnel_nexthop_add"},
        "tunnel_activating":     {"tunnel_nexthop_add", "tunnel_operational"},
        "tunnel_nexthop_add":    {"tunnel_operational"},
        "tunnel_operational":    {"vtep_operational"},
        "vxlan_interface":       {"vni_create", "tunnel_nexthop_delete", "vtep_operational"},
        "vni_create":            {"tunnel_nexthop_delete", "vtep_operational"},
        "vtep_down":             {"tunnel_nexthop_delete", "ospf", "bgp"},
    }
    if sb in pairs.get(sa, set()):
        score += 0.45; reasons.append(f"{sa} can lead to {sb}")

    # Cross-device correlation based on IP in messages
    txt_b = text(b)
    ips_a = re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', text(a))
    if a.get("device_ip"): ips_a.append(a.get("device_ip"))
    for ip in ips_a:
        if ip in txt_b:
            score += 0.35; reasons.append("shared IP reference")
            break

    # VXLAN: correlate events sharing the same tunnel IP (e.g. 9.9.9.9)
    tunnel_ips_a = re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', text(a))
    tunnel_ips_b = re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', txt_b)
    if set(tunnel_ips_a) & set(tunnel_ips_b):
        score += 0.25; reasons.append("shared tunnel IP")

    if da == db and da in {"security", "access_control", "hardware", "physical_link", "routing"}:
        score += 0.2; reasons.append("same incident domain")

    layer_a = LAYER.get(sa, 2)
    layer_b = LAYER.get(sb, 2)
    if layer_a < layer_b:
        score += 0.2
        reasons.append(f"L{layer_a}->L{layer_b} propagation")
    elif layer_a > layer_b:
        score -= 0.15

    if lag <= 300: score += 0.15
    elif lag <= 900: score += 0.08
    if score < 0.45: return 0, None
    return round(min(score, 0.99), 2), ", ".join(reasons)


def build_causal_graph(events, window_sec=1800):
    G = nx.DiGraph()
    sorted_events = sorted(events, key=lambda e: parse_dt(get_time(e)))
    for e in sorted_events:
        G.add_node(e["event_uid"], **e)
        
    for i, a in enumerate(sorted_events):
        ta = parse_dt(get_time(a))
        for j in range(i + 1, len(sorted_events)):
            b = sorted_events[j]
            tb = parse_dt(get_time(b))
            lag = (tb - ta).total_seconds()
            if lag > window_sec:
                break
            conf, reason = relation(a, b)
            if conf > 0:
                G.add_edge(a["event_uid"], b["event_uid"], confidence=conf, lag_seconds=lag, reason=reason)
    return G


def extract_causal_sequences(G):
    sequences = []
    root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0 and G.out_degree(n) > 0]
    leaf_nodes = [n for n in G.nodes() if G.out_degree(n) == 0 and G.in_degree(n) > 0]
    
    for root in root_nodes:
        best_path = []
        for leaf in leaf_nodes:
            try:
                for path in nx.all_simple_paths(G, root, leaf, cutoff=10):
                    if len(path) > len(best_path):
                        best_path = path
            except nx.NetworkXNoPath:
                continue
                
        if len(best_path) >= 2:
            sequence = []
            for step_idx, node_id in enumerate(best_path):
                node_data = G.nodes[node_id]
                role = "root_cause" if step_idx == 0 else ("terminal_effect" if step_idx == len(best_path) - 1 else "propagation")
                edge_data = {}
                if step_idx > 0:
                    edge_data = G.edges[best_path[step_idx-1], node_id]
                
                sequence.append({
                    "step": step_idx + 1,
                    "event_uid": node_id,
                    "role": role,
                    "device": node_data.get("device"),
                    "subtype": node_data.get("normalized_subtype"),
                    "severity": node_data.get("severity"),
                    "message": node_data.get("message"),
                    "timestamp": str(node_data.get("corrected_time") or node_data.get("event_time")),
                    "confidence_from_previous": edge_data.get("confidence"),
                    "lag_from_previous": edge_data.get("lag_seconds"),
                    "reason": edge_data.get("reason"),
                })
                
            sequences.append({
                "sequence_id": f"SEQ-{len(sequences)+1:03d}",
                "root_event": best_path[0],
                "terminal_event": best_path[-1],
                "length": len(best_path),
                "total_confidence": round(sum(G.edges[best_path[i], best_path[i+1]].get("confidence", 0) for i in range(len(best_path)-1)) / (len(best_path) - 1), 3),
                "steps": sequence,
            })
            
    sequences.sort(key=lambda s: (s["length"], s["total_confidence"]), reverse=True)
    return sequences


def analyze_incident(inc: Dict) -> Dict:
    events = sorted(inc.get("events", []), key=lambda e: parse_dt(get_time(e)))
    normalized = []
    for i, e in enumerate(events, 1):
        x = dict(e)
        x.setdefault("event_uid", i)
        x["normalized_subtype"] = subtype(x)
        x["normalized_domain"] = domain(x)
        x["root_score"] = root_score(x, i, len(events))
        x["actionable"] = is_actionable(x)
        normalized.append(x)

    actionable_events = [e for e in normalized if e["actionable"]]
    if actionable_events:
        root = max(actionable_events, key=lambda e: e["root_score"])
        classification = "actionable"
    else:
        root = max(normalized, key=lambda e: e["root_score"], default=None)
        classification = "informational"

    G = build_causal_graph(normalized)
    sequences = extract_causal_sequences(G)
    
    links = []
    for u, v, d in G.edges(data=True):
        links.append({
            "source_event_uid": u,
            "target_event_uid": v,
            "source_subtype": G.nodes[u].get("normalized_subtype"),
            "target_subtype": G.nodes[v].get("normalized_subtype"),
            "lag_seconds": d.get("lag_seconds"),
            "confidence": d.get("confidence"),
            "reason": d.get("reason"),
        })
    links.sort(key=lambda x: x["confidence"], reverse=True)
    
    linked_uids = set(G.nodes()) - set(n for n in G.nodes() if G.degree(n) == 0)
    unrelated = [e.get("event_uid") for e in normalized if e.get("event_uid") not in linked_uids and (not root or e.get("event_uid") != root.get("event_uid"))]

    return {
        "incident_id": inc.get("incident_id"),
        "incident_type": inc.get("incident_type"),
        "classification": classification,
        "event_count": len(normalized),
        "root_cause": root,
        "causal_links": links,
        "causal_sequences": sequences,
        "possibly_unrelated_events": unrelated,
        "source": "dag-production-rules",
    }


def load_timeline(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "incidents" in data: return data["incidents"]
    if isinstance(data, list): return data
    raise ValueError("Invalid timeline JSON format")


def save_json(data, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def print_report(results):
    print("\n" + "=" * 70)
    print("PRODUCTION NETWORK ROOT CAUSE ANALYSIS REPORT")
    print("=" * 70)
    for r in results:
        root = r.get("root_cause") or {}
        print(f"\nIncident: {r.get('incident_id')} | {r.get('incident_type')} | {r.get('classification')}")
        print(f"Events  : {r.get('event_count')}")
        if r.get("classification") == "informational":
            print("Observation")
        else:
            print("Root Cause")
        print(f"  Event UID : {root.get('event_uid')}")
        print(f"  Device    : {root.get('device')}")
        print(f"  Subtype   : {root.get('normalized_subtype')}")
        print(f"  Severity  : {root.get('severity')}")
        print(f"  Score     : {root.get('root_score')}")
        print(f"  Message   : {root.get('message')}")
        
        seqs = r.get("causal_sequences", [])
        if seqs:
            print("\nCausal Sequences Found")
            for seq in seqs:
                print(f"  Sequence {seq['sequence_id']} (length {seq['length']}, conf {seq['total_confidence']})")
                for step in seq["steps"]:
                    print(f"    [{step['step']}] {step['role']}: {step['device']} - {step['subtype']} ({step['severity']})")
        
        print("\nCausal Links")
        for l in r.get("causal_links", [])[:5]:
            print(f"  {l['source_subtype']} -> {l['target_subtype']} [lag={l['lag_seconds']}s, conf={l['confidence']}] {l['reason']}")
        if len(r.get("causal_links", [])) > 5:
            print(f"  ... and {len(r.get('causal_links')) - 5} more links")
            
        print(f"\nPossibly unrelated events: {r.get('possibly_unrelated_events')}")


def main():
    parser = argparse.ArgumentParser(description="HPE Production Causal Inference")
    parser.add_argument("--timeline", required=True)
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()
    print("\n" + "=" * 60)
    print(" HPE PRODUCTION CAUSAL INFERENCE ENGINE")
    print("=" * 60)
    incidents = load_timeline(args.timeline)
    results = [analyze_incident(i) for i in incidents]
    output = {"total_incidents": len(results), "incidents": results}
    save_json(output, args.output)
    print_report(results)
    print("\n" + "=" * 60)
    print(f"[OUTPUT] Causal analysis written to '{args.output}'")
    print("=" * 60)


if __name__ == "__main__":
    main()
