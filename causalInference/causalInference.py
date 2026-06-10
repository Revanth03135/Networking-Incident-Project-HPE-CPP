"""
causalInference.py — Production Network Root Cause Analysis Engine

Reads timeline_output.json and produces deterministic production-safe RCA.
No LLM can override deterministic sanity checks.
"""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEV = {"debug": 0, "info": 1, "notice": 1, "warning": 2, "warn": 2, "error": 3, "err": 3, "critical": 4, "crit": 4}
BENIGN = {"snmp", "ntp", "vlan", "lldp", "transceiver", "interface_up", "mac_auth_success", "dot1x_logout", "bgp"}
ACTIONABLE_LOW_OK = {"stp_topology_change", "config_change"}

BASE = {
    "power": 100, "fan": 55, "crc_errors": 90, "interface_down": 88,
    "ospf": 80, "bgp": 55, "stp_topology_change": 65,
    "config_change": 75, "ssh_bruteforce": 78, "admin_auth_failure": 70,
    "dot1x_failure": 72, "interface_up": 10, "snmp": 5, "ntp": 3,
    "vlan": 8, "lldp": 8, "transceiver": 15, "mac_auth_success": 5,
    "dot1x_logout": 5,
}


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
    if "snmpd" in s: return "snmp"
    if "ntp" in s: return "ntp"
    if "power supply" in s or "psu" in s: return "power"
    if "fan" in s: return "fan"
    if "crc" in s: return "crc_errors"
    if "off-line" in s or "offline" in s or "link down" in s: return "interface_down"
    if "on-line" in s or "online" in s: return "interface_up"
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
    if "vlan" in s: return "vlan"
    return n(e.get("subtype")) or "unknown"


def domain(e):
    st = subtype(e)
    if st in {"power", "fan"}: return "hardware"
    if st in {"crc_errors", "interface_down", "interface_up"}: return "physical_link"
    if st in {"ospf", "bgp"}: return "routing"
    if st == "stp_topology_change": return "topology"
    if st == "config_change": return "configuration"
    if st in {"ssh_bruteforce", "admin_auth_failure"}: return "security"
    if st in {"dot1x_failure", "dot1x_logout", "mac_auth_success"}: return "access_control"
    if st in {"snmp", "ntp"}: return "service"
    return n(e.get("domain")) or n(e.get("type")) or "generic"


def port(e):
    val = e.get("interface_id")
    if val and str(val) != "<IFACE>": return str(val)
    m = re.search(r"\bport\s+(\d+/\d+/\d+|\d+/\d+|\d+)\b", text(e), re.I)
    return m.group(1) if m else None


def root_score(e, idx, total):
    st = subtype(e)
    sev = SEV.get(n(e.get("severity")), 1)
    s = text(e)
    score = BASE.get(st, 20) + sev * 18
    if "failure" in s or "failed" in s: score += 20
    if "down" in s or "off-line" in s or "offline" in s: score += 18
    if "crc" in s or "error" in s: score += 18
    if st in BENIGN and sev <= 1: score -= 80
    if st == "bgp" and "established" in s: score -= 45
    score += max(0, total - idx) * 0.2
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
        "power": {"fan", "interface_down", "crc_errors"},
        "crc_errors": {"interface_down", "stp_topology_change", "ospf", "bgp"},
        "interface_down": {"stp_topology_change", "ospf", "bgp", "dot1x_failure"},
        "stp_topology_change": {"ospf", "bgp"},
        "config_change": {"interface_down", "stp_topology_change", "ospf", "bgp", "dot1x_failure"},
        "admin_auth_failure": {"ssh_bruteforce"},
        "dot1x_failure": {"dot1x_logout"},
    }
    if sb in pairs.get(sa, set()):
        score += 0.45; reasons.append(f"{sa} can lead to {sb}")
    if da == db and da in {"security", "access_control", "hardware", "physical_link", "routing"}:
        score += 0.2; reasons.append("same incident domain")
    if lag <= 300: score += 0.15
    elif lag <= 900: score += 0.08
    if score < 0.45: return 0, None
    return round(min(score, 0.99), 2), ", ".join(reasons)


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

    links = []
    linked_uids = set()
    for i, a in enumerate(normalized):
        for b in normalized[i + 1:]:
            conf, reason = relation(a, b)
            if conf:
                links.append({
                    "source_event_uid": a.get("event_uid"),
                    "target_event_uid": b.get("event_uid"),
                    "source_subtype": subtype(a),
                    "target_subtype": subtype(b),
                    "lag_seconds": (parse_dt(get_time(b)) - parse_dt(get_time(a))).total_seconds(),
                    "confidence": conf,
                    "reason": reason,
                })
                linked_uids.add(a.get("event_uid")); linked_uids.add(b.get("event_uid"))
    links = sorted(links, key=lambda x: x["confidence"], reverse=True)[:10]
    unrelated = [e.get("event_uid") for e in normalized if e.get("event_uid") not in linked_uids and (not root or e.get("event_uid") != root.get("event_uid"))]

    return {
        "incident_id": inc.get("incident_id"),
        "incident_type": inc.get("incident_type"),
        "classification": classification,
        "event_count": len(normalized),
        "root_cause": root,
        "causal_links": links,
        "possibly_unrelated_events": unrelated,
        "source": "deterministic-production-rules",
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
        print("\nCausal Links")
        for l in r.get("causal_links", []):
            print(f"  {l['source_subtype']} -> {l['target_subtype']} [lag={l['lag_seconds']}s, conf={l['confidence']}] {l['reason']}")
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
