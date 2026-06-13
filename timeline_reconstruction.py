"""
timeline_reconstruction.py — Production Incident Timeline Reconstruction Engine

This version avoids the main production bug in the old code:
  - It does NOT merge every same-device event into one huge incident.
  - It clusters using time + device + incident-domain compatibility.
  - Security, hardware, routing, auth, config, and generic daemon events are separated.

Input : preprocessed_events.json or schema_output.json
Output: timeline_output.json
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from collections import defaultdict

from preprocessing import (
    load_data,
    flatten_events,
    normalize_timestamps,
    correct_clock_skew,
    compute_dynamic_window,
    json_serializable,
    restore_datetime_fields,
)


DOMAIN_RULES = [
    ("hardware", ["power", "psu", "fan", "temperature", "thermal", "hw", "hardware"]),
    ("physical_link", ["crc", "transceiver", "optic", "sfp", "link down", "off-line", "offline", "port"]),
    ("stp_topology", ["mstp", "stp", "topology change", "forwarding", "learning"]),
    ("routing", ["bgp", "ospf", "routing", "neighbor", "peer"]),
    ("authentication", ["802.1x", "mac-auth", "auth", "authentication"]),
    ("security", ["ssh login failed", "maximum attempts", "security", "bruteforce", "brute force"]),
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

SEVERITY_RANK = {
    "debug": 0,
    "info": 1,
    "notice": 1,
    "warning": 2,
    "warn": 2,
    "error": 3,
    "err": 3,
    "critical": 4,
    "crit": 4,
    "alert": 5,
    "emergency": 6,
}


def text_of(e: Dict[str, Any]) -> str:
    return " ".join(str(e.get(k, "")) for k in ["subtype", "type", "severity", "message", "raw_message", "process"]).lower()


def normalize_domain(e: Dict[str, Any]) -> str:
    txt = text_of(e)
    for domain, keys in DOMAIN_RULES:
        if any(k in txt for k in keys):
            return domain
    return "unknown"


def extract_port(e: Dict[str, Any]) -> Optional[str]:
    txt = text_of(e)
    m = re.search(r"port\s+(\d+/\d+/\d+|\d+)", txt)
    return m.group(1) if m else e.get("interface_id")


def severity_rank(e: Dict[str, Any]) -> int:
    return SEVERITY_RANK.get(str(e.get("severity", "info")).lower(), 1)


def compatible(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    da, db = a.get("incident_domain"), b.get("incident_domain")
    if db in COMPATIBLE_DOMAINS.get(da, set()):
        return True
    pa, pb = extract_port(a), extract_port(b)
    if pa and pb and pa == pb:
        return True
    return False


def event_time(e: Dict[str, Any]) -> datetime:
    return e["corrected_time"]


def cluster_events(events: List[Dict[str, Any]], base_window_sec: float) -> List[List[Dict[str, Any]]]:
    if not events:
        return []

    for e in events:
        e["incident_domain"] = normalize_domain(e)
        e["interface_id"] = e.get("interface_id") or extract_port(e)

    events = sorted(events, key=event_time)
    clusters: List[List[Dict[str, Any]]] = []

    # Production cap: dynamic windows can become too large on sparse logs.
    normal_window = min(max(base_window_sec, 120), 600)
    strict_window = min(normal_window, 180)

    for event in events:
        placed = False
        best_cluster = None
        best_score = -1.0

        for cluster in clusters:
            last = cluster[-1]
            gap = (event_time(event) - event_time(last)).total_seconds()
            if gap < 0:
                continue

            same_device = event.get("device") == last.get("device")
            domain_ok = any(compatible(x, event) for x in cluster[-5:])
            same_port = any(extract_port(x) and extract_port(x) == extract_port(event) for x in cluster[-5:])

            window = normal_window if domain_ok or same_port else strict_window

            # Do not merge low-value service/inventory noise into real incidents.
            if event["incident_domain"] in {"service", "inventory"} and not same_port:
                window = 60

            if same_device and gap <= window and (domain_ok or same_port or gap <= 60):
                score = (window - gap) + (200 if same_port else 0) + (100 if domain_ok else 0)
                if score > best_score:
                    best_score = score
                    best_cluster = cluster
                    placed = True

        if placed and best_cluster is not None:
            best_cluster.append(event)
        else:
            clusters.append([event])

    print(f"[CLUSTER]    ✔ {len(clusters)} incident clusters formed")
    return clusters


class UnionFind:
    def __init__(self, size: int):
        self.parent = list(range(size))
        self.sz = [1] * size

    def find(self, p: int) -> int:
        while p != self.parent[p]:
            self.parent[p] = self.parent[self.parent[p]]
            p = self.parent[p]
        return p

    def union(self, p: int, q: int) -> None:
        root_p = self.find(p)
        root_q = self.find(q)
        if root_p == root_q:
            return
        if self.sz[root_p] < self.sz[root_q]:
            self.parent[root_p] = root_q
            self.sz[root_q] += self.sz[root_p]
        else:
            self.parent[root_q] = root_p
            self.sz[root_p] += self.sz[root_q]

    def size(self, p: int) -> int:
        return self.sz[self.find(p)]


def compute_cross_device_score(cluster_a: List[Dict], cluster_b: List[Dict], ip_to_clusters: Dict) -> float:
    score = 0.0

    domains_a = {e.get("incident_domain") for e in cluster_a}
    domains_b = {e.get("incident_domain") for e in cluster_b}
    vlans_a = {str(e.get("vlan")) for e in cluster_a if e.get("vlan")}
    vlans_b = {str(e.get("vlan")) for e in cluster_b if e.get("vlan")}

    domain_ok = False
    for da in domains_a:
        if da in COMPATIBLE_DOMAINS:
            if domains_b.intersection(COMPATIBLE_DOMAINS[da]):
                domain_ok = True
                break
    if domain_ok:
        score += 0.2

    if vlans_a and vlans_b and vlans_a.intersection(vlans_b):
        score += 0.15

    start_a = min(event_time(e) for e in cluster_a)
    end_a = max(event_time(e) for e in cluster_a)
    start_b = min(event_time(e) for e in cluster_b)
    end_b = max(event_time(e) for e in cluster_b)

    gap = 0.0
    if end_a < start_b:
        gap = (start_b - end_a).total_seconds()
    elif end_b < start_a:
        gap = (start_a - end_b).total_seconds()

    if gap <= 300:
        score += 0.2

    ips_a = set()
    for e in cluster_a:
        ips_a.update(re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', text_of(e)))
    dev_ip_a = cluster_a[0].get("device_ip")
    if dev_ip_a and dev_ip_a != "unknown":
        ips_a.add(dev_ip_a)

    ips_b = set()
    for e in cluster_b:
        ips_b.update(re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', text_of(e)))
    dev_ip_b = cluster_b[0].get("device_ip")
    if dev_ip_b and dev_ip_b != "unknown":
        ips_b.add(dev_ip_b)

    if ips_a.intersection(ips_b):
        score += 0.4

    max_sev_a = max(severity_rank(e) for e in cluster_a)
    max_sev_b = max(severity_rank(e) for e in cluster_b)
    if start_b >= start_a and max_sev_b > max_sev_a:
        score += 0.15
    elif start_a >= start_b and max_sev_a > max_sev_b:
        score += 0.15

    return score


def correlate_cross_device(clusters: List[List[Dict[str, Any]]], merge_threshold: float = 0.5, max_events: int = 50) -> List[List[Dict[str, Any]]]:
    if not clusters:
        return []

    ip_to_clusters = defaultdict(set)
    for idx, cluster in enumerate(clusters):
        for event in cluster:
            ips = re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', text_of(event))
            for ip in ips:
                ip_to_clusters[ip].add(idx)

    merged = UnionFind(len(clusters))

    for i in range(len(clusters)):
        for j in range(i + 1, len(clusters)):
            if clusters[i][0].get("device") == clusters[j][0].get("device"):
                continue

            score = compute_cross_device_score(clusters[i], clusters[j], ip_to_clusters)
            if score >= merge_threshold:
                combined = merged.size(i) + merged.size(j)
                if combined <= max_events:
                    merged.union(i, j)

    groups = defaultdict(list)
    for idx in range(len(clusters)):
        groups[merged.find(idx)].extend(clusters[idx])

    final_clusters = [sorted(events, key=event_time) for events in groups.values()]
    print(f"[CORRELATE]  ✔ {len(clusters)} device clusters merged into {len(final_clusters)} cross-device incidents")
    return final_clusters



def deduplicate_cluster(cluster: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for e in cluster:
        key = (
            e.get("device"),
            e.get("incident_domain"),
            e.get("subtype"),
            e.get("interface_id"),
            (e.get("message") or "")[:80],
        )
        if key in seen:
            seen[key]["duplicate_count"] = seen[key].get("duplicate_count", 1) + 1
        else:
            e["duplicate_count"] = 1
            seen[key] = e
    return list(seen.values())


def build_incidents(clusters: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    incidents = []
    for idx, cluster in enumerate(clusters, start=1):
        deduped = sorted(deduplicate_cluster(cluster), key=event_time)
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
        print(f"[INCIDENT]   {incident['incident_id']} | {incident['incident_domain']} | {len(deduped)} events")
    return incidents


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


def run_pipeline(input_path: str, output_path: str = "timeline_output.json"):
    print("\n" + "═" * 60)
    print(" HPE PRODUCTION INCIDENT TIMELINE RECONSTRUCTION ENGINE ")
    print("═" * 60)

    raw = load_data(input_path)
    is_preprocessed = raw and isinstance(raw[0], dict) and "corrected_time" in raw[0]

    if is_preprocessed:
        print("[LOAD]       Already preprocessed — skipping flatten/skew")
        norm = restore_datetime_fields(raw)
    else:
        flat = flatten_events(raw)
        norm, _ = normalize_timestamps(flat)
        correct_clock_skew(norm)

    window = compute_dynamic_window(norm)
    clusters = cluster_events(norm, window)
    clusters = correlate_cross_device(clusters)

    print("\n[BUILD]      Building production incidents...")
    incidents = build_incidents(clusters)
    print_timeline(incidents)

    serializable = json.loads(json.dumps(incidents, default=json_serializable))
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)

    print(f"\n[OUTPUT]     ✔ Timeline written to '{output_path}'")
    print("═" * 60)
    return serializable


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Production HPE Incident Timeline Reconstruction")
    parser.add_argument("input", nargs="?", default="preprocessed_events.json")
    parser.add_argument("-o", "--output", default="timeline_output.json")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[ERROR] File not found: {args.input}")
        sys.exit(1)

    run_pipeline(args.input, args.output)
