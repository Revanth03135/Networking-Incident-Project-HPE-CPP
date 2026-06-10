"""
STAGE 3 — Production Pipeline Output Formatter
----------------------------------------------
Fixes wrong semantic labels from earlier stages using deterministic
network-log normalization before writing schema_output.json.

Input : stage2_output.json
Output: schema_output.json / output path supplied by CLI
"""

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


MONTHLESS_YEAR = 2026

SEVERITY_NORMALIZE = {
    "emerg": "critical", "emergency": "critical", "alert": "critical",
    "crit": "critical", "critical": "critical",
    "err": "error", "error": "error",
    "warn": "warning", "warning": "warning",
    "notice": "info", "info": "info", "informational": "info",
    "debug": "info",
}


def _text(*parts) -> str:
    return " ".join(str(p or "") for p in parts).lower()


def _extract_syslog_facility_severity(raw: str) -> Tuple[Optional[str], Optional[str]]:
    m = re.search(r"\[([a-zA-Z0-9_\-.]+)\.([a-zA-Z0-9_\-]+)\]", raw or "")
    if not m:
        return None, None
    return m.group(1).lower(), SEVERITY_NORMALIZE.get(m.group(2).lower(), m.group(2).lower())


def _extract_process(raw: str) -> str:
    m = re.search(r"\s([a-zA-Z0-9_.-]+)(?:\[\d+\])?:\s", raw or "")
    return m.group(1).lower() if m else ""


def _extract_interface(raw: str, msg: str) -> Optional[str]:
    s = f"{raw or ''} {msg or ''}"
    m = re.search(r"\bport\s+(\d+/\d+/\d+|\d+/\d+|\d+)\b", s, re.I)
    return m.group(1) if m else None


def _extract_vlan(raw: str, msg: str) -> Optional[str]:
    s = f"{raw or ''} {msg or ''}"
    m = re.search(r"\bvlan\s+(\d+)\b", s, re.I)
    return m.group(1) if m else None


def normalize_event(raw_log: str, core_message: str, semantic: Dict) -> Dict[str, Optional[str]]:
    """Return production-safe type/subtype/severity/interface/vlan."""
    raw = raw_log or ""
    msg = core_message or semantic.get("canonical_event_msg") or ""
    process = _extract_process(raw)
    facility, syslog_sev = _extract_syslog_facility_severity(raw)
    s = _text(raw, msg, process, facility)

    severity = syslog_sev or semantic.get("severity") or "info"
    severity = SEVERITY_NORMALIZE.get(str(severity).lower(), str(severity).lower())

    event_type = semantic.get("type") or "generic"
    subtype = semantic.get("subtype") or "unknown"

    # Highest-confidence process/facility/message based correction.
    if "snmpd" in process or " snmpd" in s:
        event_type, subtype = "service", "snmp"
    elif "ntp" in process or "ntp synchronized" in s:
        event_type, subtype = "service", "ntp"
    elif "power supply" in s or re.search(r"\bpsu[-\w]*\b", s):
        event_type, subtype = "hardware", "power"
        if "fail" in s:
            severity = "critical"
    elif "fan" in s:
        event_type, subtype = "hardware", "fan"
    elif "excessive crc" in s or "crc error" in s:
        event_type, subtype = "physical_link", "crc_errors"
        if severity == "info":
            severity = "warning"
    elif "off-line" in s or "offline" in s or "link down" in s or " is down" in s:
        event_type, subtype = "physical_link", "interface_down"
        if severity == "info":
            severity = "error"
    elif "on-line" in s or "online" in s or "link up" in s:
        event_type, subtype = "physical_link", "interface_up"
    elif "transceiver" in s:
        event_type, subtype = "inventory", "transceiver"
    elif "lldp" in s:
        event_type, subtype = "discovery", "lldp"
    elif "topology change" in s or "mstp" in s or "spanning" in s:
        event_type, subtype = "topology", "stp_topology_change"
    elif "ospf" in s:
        event_type, subtype = "routing", "ospf"
    elif "bgp" in s:
        event_type, subtype = "routing", "bgp"
    elif "configuration changed" in s or "hpe-config" in s or facility == "config":
        event_type, subtype = "configuration", "config_change"
    elif "ssh login failed" in s or "maximum attempts" in s:
        event_type, subtype = "security", "ssh_bruteforce"
        if severity == "info":
            severity = "warning"
    elif "authentication failure for user" in s:
        event_type, subtype = "security", "admin_auth_failure"
        if severity == "info":
            severity = "warning"
    elif "802.1x" in s and ("failed" in s or "failure" in s):
        event_type, subtype = "access_control", "dot1x_failure"
        if severity == "info":
            severity = "error"
    elif "802.1x" in s and "logged out" in s:
        event_type, subtype = "access_control", "dot1x_logout"
    elif "mac-auth" in s:
        event_type, subtype = "access_control", "mac_auth_success"
    elif "vlan" in s:
        event_type, subtype = "inventory", "vlan"

    return {
        "type": event_type,
        "subtype": subtype,
        "severity": severity,
        "interface_id": _extract_interface(raw, msg) or semantic.get("interface_id"),
        "vlan": _extract_vlan(raw, msg),
        "process": process,
        "facility": facility,
    }


def format_event_record(stage_data: Dict, line_number: int) -> Dict:
    raw_log = stage_data.get("raw_log", "")
    core_message = stage_data.get("core_message", "")
    timestamp = stage_data.get("timestamp")
    hostname = stage_data.get("hostname")
    ip = stage_data.get("ip")
    vendor = stage_data.get("vendor") or "unknown"
    os_name = stage_data.get("os")

    semantic = stage_data.get("semantic_analysis", {}) or {}
    canonical_msg = semantic.get("canonical_event_msg") or core_message or raw_log
    fixed = normalize_event(raw_log, canonical_msg, semantic)

    return {
        "event": {
            "event_uid": line_number,
            "event_id": None,
            "type": fixed["type"],
            "subtype": fixed["subtype"],
            "severity": fixed["severity"],
            "message": canonical_msg,
        },
        "device": {
            "hostname": hostname or ip,
            "ip": ip or hostname,
            "vendor": vendor,
            "os": os_name,
        },
        "network": {
            "interface_id": fixed["interface_id"],
            "vlan": fixed["vlan"],
        },
        "metadata": {
            "process": fixed["process"],
            "facility": fixed["facility"],
            "stage3_corrected": True,
        },
        "timestamps": {"event_time": timestamp},
        "raw": {"message": raw_log},
    }


def process_stage2_output(stage2_file: str, output_file: str) -> List[Dict]:
    with open(stage2_file, "r", encoding="utf-8") as f:
        stage2_data = json.load(f)
    if not isinstance(stage2_data, list):
        raise ValueError("Stage2 output must be a list")

    records = [format_event_record(entry, idx + 1) for idx, entry in enumerate(stage2_data)]
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"[OK] Formatted {len(records)} records")
    print(f"[OK] Saved to: {output_file}")
    return records


def print_summary(records: List[Dict]):
    type_counts, sev_counts = {}, {}
    for r in records:
        t = r.get("event", {}).get("type", "unknown")
        s = r.get("event", {}).get("severity", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print("\n" + "=" * 70)
    print("STAGE 3 PRODUCTION SUMMARY")
    print("=" * 70)
    print(f"Total records: {len(records)}")
    print("Event types:")
    for k, v in sorted(type_counts.items()):
        print(f"  - {k}: {v}")
    print("Severities:")
    for k, v in sorted(sev_counts.items()):
        print(f"  - {k}: {v}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stage 3 - Production Output Formatter")
    parser.add_argument("input", nargs="?", default="stage2_output.json")
    parser.add_argument("-o", "--output", default="schema_output.json")
    args = parser.parse_args()
    records = process_stage2_output(args.input, args.output)
    print_summary(records)
