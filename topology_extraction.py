"""
topology_extraction.py — Stage 2: Implicit Topology Extraction

Infers device-to-device connectivity from log events without requiring
an explicit physical topology file.  Relationships are extracted from
the events themselves using three tiers of evidence:

  Tier 1: Explicit cross-references (device A's log mentions device B's IP)
  Tier 2: Shared VLAN / subnet co-membership
  Tier 3: BGP / OSPF peer relationships

Output: an undirected weighted NetworkX graph where nodes are device
hostnames and edges represent inferred connectivity.
"""

import json
import re
from collections import defaultdict
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx


# =========================================================
# HELPERS
# =========================================================

_IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_MAC_RE = re.compile(r'\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b')
_PORT_RE = re.compile(r'[Pp]ort\s+(\d+/\d+/\d+|\d+/\d+|\d+)')


def _text_of(e: Dict[str, Any]) -> str:
    """Concatenate all textual fields of an event for pattern matching."""
    return " ".join(
        str(e.get(k, ""))
        for k in ["subtype", "type", "severity", "message", "raw_message", "process"]
    ).lower()


def _extract_ips(e: Dict[str, Any]) -> Set[str]:
    """Extract all IPv4 addresses mentioned in an event."""
    ips = set(_IP_RE.findall(_text_of(e)))
    dev_ip = e.get("device_ip")
    if dev_ip and dev_ip != "unknown":
        ips.add(str(dev_ip))
    return ips


def _extract_macs(e: Dict[str, Any]) -> Set[str]:
    """Extract all MAC addresses mentioned in an event."""
    return set(_MAC_RE.findall(_text_of(e)))


def _extract_interface(e: Dict[str, Any]) -> Optional[str]:
    """Extract interface/port ID from an event."""
    iface = e.get("interface_id")
    if iface and str(iface) not in ("", "<IFACE>", "None"):
        return str(iface)
    m = _PORT_RE.search(_text_of(e))
    return m.group(1) if m else None


def _extract_vlan(e: Dict[str, Any]) -> Optional[int]:
    """Extract VLAN ID from an event."""
    v = e.get("vlan")
    if v is not None:
        try:
            return int(v)
        except (ValueError, TypeError):
            pass
    return None


def _ip_to_subnet(ip_str: str, prefix_len: int = 24) -> Optional[str]:
    """Convert an IP to its /24 subnet string (for co-membership comparison)."""
    try:
        net = IPv4Network(f"{ip_str}/{prefix_len}", strict=False)
        return str(net)
    except (ValueError, TypeError):
        return None


# =========================================================
# TOPOLOGY EXTRACTION
# =========================================================

def extract_topology(events: List[Dict[str, Any]]) -> nx.Graph:
    """
    Build an undirected weighted topology graph from event data.

    Nodes: device hostnames
    Edges: inferred connectivity with weight (higher = stronger evidence)

    Parameters
    ----------
    events : list of flat event dicts (output of preprocessing pipeline)

    Returns
    -------
    nx.Graph with device-to-device edges
    """
    G = nx.Graph()

    # Build per-device indices
    device_ips: Dict[str, Set[str]] = defaultdict(set)      # device -> IPs it owns
    device_vlans: Dict[str, Set[int]] = defaultdict(set)     # device -> VLANs referenced
    device_subnets: Dict[str, Set[str]] = defaultdict(set)   # device -> /24 subnets
    device_macs: Dict[str, Set[str]] = defaultdict(set)      # device -> MACs referenced
    device_mentioned_ips: Dict[str, Set[str]] = defaultdict(set)  # device -> IPs mentioned in logs
    ip_to_device: Dict[str, str] = {}                        # IP -> device that owns it

    for e in events:
        dev = e.get("device", "unknown")
        if dev == "unknown":
            continue

        G.add_node(dev)

        # Collect device's own IP
        dev_ip = e.get("device_ip")
        if dev_ip and dev_ip != "unknown":
            device_ips[dev].add(dev_ip)
            ip_to_device[dev_ip] = dev
            subnet = _ip_to_subnet(dev_ip)
            if subnet:
                device_subnets[dev].add(subnet)

        # Collect VLANs
        vlan = _extract_vlan(e)
        if vlan is not None:
            device_vlans[dev].add(vlan)

        # Collect all IPs mentioned in event text
        all_ips = _extract_ips(e)
        device_mentioned_ips[dev].update(all_ips)
        for ip in all_ips:
            subnet = _ip_to_subnet(ip)
            if subnet:
                device_subnets[dev].add(subnet)

        # Collect MACs
        macs = _extract_macs(e)
        device_macs[dev].update(macs)

    # Now build edges between device pairs
    devices = list(G.nodes())
    edge_evidence: Dict[Tuple[str, str], Dict[str, float]] = defaultdict(
        lambda: {"weight": 0.0, "reasons": []}
    )

    for i in range(len(devices)):
        for j in range(i + 1, len(devices)):
            dev_a, dev_b = devices[i], devices[j]
            key = (dev_a, dev_b)

            # --------------------------------------------------
            # Tier 1: Explicit IP cross-references (strongest)
            # Device A's logs mention Device B's IP, or vice versa
            # --------------------------------------------------
            a_mentions_b = device_mentioned_ips[dev_a] & device_ips[dev_b]
            b_mentions_a = device_mentioned_ips[dev_b] & device_ips[dev_a]

            if a_mentions_b or b_mentions_a:
                edge_evidence[key]["weight"] += 1.0
                shared = a_mentions_b | b_mentions_a
                edge_evidence[key]["reasons"].append(
                    f"explicit IP cross-ref: {', '.join(sorted(shared))}"
                )

            # --------------------------------------------------
            # Tier 3: BGP/OSPF peer IP matches device IP
            # (checked as part of Tier 1 above — if device A's
            #  BGP peer IP matches device B's management IP,
            #  that's already caught by the IP cross-reference)
            # --------------------------------------------------

            # --------------------------------------------------
            # Tier 2: Shared VLAN co-membership
            # --------------------------------------------------
            shared_vlans = device_vlans[dev_a] & device_vlans[dev_b]
            if shared_vlans:
                edge_evidence[key]["weight"] += 0.6
                edge_evidence[key]["reasons"].append(
                    f"shared VLANs: {', '.join(str(v) for v in sorted(shared_vlans))}"
                )

            # --------------------------------------------------
            # Tier 2b: Shared /24 subnet
            # --------------------------------------------------
            shared_subnets = device_subnets[dev_a] & device_subnets[dev_b]
            if shared_subnets and not (a_mentions_b or b_mentions_a):
                # Only add if not already covered by explicit cross-ref
                edge_evidence[key]["weight"] += 0.4
                edge_evidence[key]["reasons"].append(
                    f"shared subnets: {', '.join(sorted(shared_subnets))}"
                )

            # --------------------------------------------------
            # Tier 2c: Shared MAC references (rare but strong)
            # --------------------------------------------------
            shared_macs = device_macs[dev_a] & device_macs[dev_b]
            if shared_macs:
                edge_evidence[key]["weight"] += 0.5
                edge_evidence[key]["reasons"].append(
                    f"shared MACs: {', '.join(sorted(shared_macs))}"
                )

    # Add edges to the graph (only those with positive weight)
    for (dev_a, dev_b), evidence in edge_evidence.items():
        if evidence["weight"] > 0:
            G.add_edge(
                dev_a, dev_b,
                weight=round(min(evidence["weight"], 2.0), 2),
                reasons=evidence["reasons"],
            )

    print(f"[TOPOLOGY]   ✔ Inferred topology: {G.number_of_nodes()} devices, "
          f"{G.number_of_edges()} connections")

    for u, v, d in G.edges(data=True):
        print(f"[TOPOLOGY]     {u} <-> {v} (weight={d['weight']:.1f}: "
              f"{'; '.join(d['reasons'])})")

    return G


# =========================================================
# PAIRWISE EVENT HELPERS (used by timeline_reconstruction)
# =========================================================

def shares_explicit_reference(a: Dict, b: Dict) -> bool:
    """Check if event A references device B's IP or vice versa."""
    # If they are on the same device, this is not a cross-device reference
    if a.get("device") == b.get("device"):
        return False
        
    ips_a = _extract_ips(a)
    ips_b = _extract_ips(b)
    dev_ip_a = a.get("device_ip")
    dev_ip_b = b.get("device_ip")

    if dev_ip_b and dev_ip_b != "unknown" and dev_ip_b in ips_a:
        return True
    if dev_ip_a and dev_ip_a != "unknown" and dev_ip_a in ips_b:
        return True
    return False


def shares_vlan_or_subnet(a: Dict, b: Dict) -> bool:
    """Check if two events share a VLAN ID or IP subnet."""
    va, vb = _extract_vlan(a), _extract_vlan(b)
    if va is not None and vb is not None and va == vb:
        return True

    # Check subnet overlap
    ips_a = _extract_ips(a)
    ips_b = _extract_ips(b)
    subnets_a = {_ip_to_subnet(ip) for ip in ips_a} - {None}
    subnets_b = {_ip_to_subnet(ip) for ip in ips_b} - {None}
    return bool(subnets_a & subnets_b)


def shares_interface_reference(a: Dict, b: Dict) -> bool:
    """Check if two events reference the same interface."""
    ia = _extract_interface(a)
    ib = _extract_interface(b)
    return ia is not None and ib is not None and ia == ib


def same_client_mac(a: Dict, b: Dict) -> bool:
    """Check if two events reference the same MAC address."""
    macs_a = _extract_macs(a)
    macs_b = _extract_macs(b)
    return bool(macs_a & macs_b)


# =========================================================
# SERIALIZATION
# =========================================================

def topology_to_json(G: nx.Graph) -> Dict:
    """Serialize topology graph to a JSON-serializable dict."""
    return {
        "nodes": list(G.nodes()),
        "edges": [
            {
                "source": u,
                "target": v,
                "weight": d.get("weight", 0),
                "reasons": d.get("reasons", []),
            }
            for u, v, d in G.edges(data=True)
        ],
    }


def save_topology(G: nx.Graph, path: Path) -> None:
    """Save topology graph to JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(topology_to_json(G), f, indent=2)
    print(f"[TOPOLOGY]   ✔ Topology saved to '{path}'")
