import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from dotenv import load_dotenv

from causalInference.causalInference import analyze_incident, analyze_and_validate, is_actionable
from preprocessing import (
    json_serializable,
    restore_datetime_fields,
    run_preprocessing_pipeline,
)
from schema_conversion.log_processor import LogProcessor
from timeline_reconstruction import run_pipeline as run_timeline_pipeline
from topology_extraction import extract_topology, save_topology


load_dotenv()


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def parse_input_logs(input_path: Path, normalized_output_path: Path, skip_schema_llm: bool = False) -> Tuple[List[Dict], str]:
    ext = input_path.suffix.lower()

    if ext in {".txt", ".log"}:
        processor = LogProcessor(
            final_output_file=normalized_output_path,
        )
        # Honor skip_schema_llm so LogProcessor avoids calling external LLMs
        processor.no_llm = bool(skip_schema_llm)
        records = processor.process_logs_file(str(input_path))
        processor.save_output()
        processor.save_template_registry()
        processor.print_stats()

        if not records:
            # Schema conversion produced no records (likely LLM endpoint unavailable).
            # Smart fallback: split each syslog line into a separate event with
            # extracted hostname, severity, and subtype from the log header.
            print("[WARN] Schema conversion produced 0 records — using fallback extractor")
            fallback = []
            try:
                import re as _re

                try:
                    from dateutil import parser as date_parser  # type: ignore
                except Exception:
                    date_parser = None

                text = input_path.read_text(encoding="utf-8")
                lines = [l.strip() for l in text.splitlines() if l.strip()]

                # Detect if lines are individual syslog entries (most start with timestamps)
                _ts_pat = _re.compile(r'^(\d{4}-\d{2}-\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d{2}:)')
                ts_count = sum(1 for l in lines if _ts_pat.match(l))

                if ts_count >= len(lines) * 0.4:
                    chunks = lines  # Each line is a separate event (syslog format)
                else:
                    # Multi-line log entries — split on blank lines
                    chunks = [c.strip() for c in text.split("\n\n") if c.strip()]
                    if not chunks:
                        chunks = lines

                now_iso = datetime.now(timezone.utc).isoformat()

                # Syslog header patterns for field extraction
                _syslog_host = _re.compile(
                    r'^(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
                    r'(\S+)'
                )
                _severity_bracket = _re.compile(r'\[([a-zA-Z0-9_.-]+)\.([a-zA-Z]+)\]')
                _SEVERITY_MAP = {
                    "emerg": "critical", "emergency": "critical", "alert": "critical",
                    "crit": "critical", "critical": "critical",
                    "err": "error", "error": "error",
                    "warn": "warning", "warning": "warning",
                    "notice": "info", "info": "info", "debug": "info",
                }
                # Quick subtype detection from message content
                _SUBTYPE_RULES = [
                    # Standard syslog patterns
                    ("power_failure",          ["power supply", "psu failure", "psu failed", "power failure"]),
                    ("fan_failure",            ["fan tray", "fan failure", "fan stopped", "speed out of normal range", "fan tray failed", "speed below threshold"]),
                    ("fan_nominal",            ["speed nominal", "fan nominal"]),
                    ("linecard_disabled",    ["linecard slot", "disabled due to"]),
                    ("thermal",              ["temperature critical", "thermal protection", "temperature exceeded"]),
                    ("crc_errors",           ["crc error", "excessive crc"]),
                    ("interface_down",       ["off-line", "offline", "link down", "is down", "operational status changed to down", "administratively down", "l3-interface", "interface deleted"]),
                    ("dot1x_success",        ["authentication succeeded", "authentication successful", "mac authentication successful"]),
                    ("interface_up",         ["on-line", "online", "link up", "operational status changed to up"]),
                    ("stp_topology_change",  ["topology change", "mstp", "recalculating spanning tree", "spanning tree"]),
                    ("stp_converged",        ["topology converged", "root bridge unchanged", "stp converged", "spanning tree converged"]),
                    ("ospf_interface_down",  ["ptp to down", "changed from bdr to", "changed from dr to", "input: if_interface_down", "input: if_dr_other"]),
                    ("ospf_interface_up",    ["down to ptp"]),
                    ("ospf_neighbor_down",   ["full to down", "rpd_ospf_nbrdown", "ospf-5-adjchg", "down", "adjchg:", "full -> down"]),
                    ("ospf_neighbor_up",     ["down to full", "rpd_ospf_nbrup", "ospf-5-adjchg", "up", "down -> full"]),
                    ("route_recalculation_started",   ["routing table recalculation started"]),
                    ("route_recalculation_completed", ["routing table recalculation completed"]),
                    ("routes_withdrawn",    ["routes withdrawn"]),
                    ("bgp_session_lost",     ["session lost", "session down", "hold timer expired", "bgp-5-adjchange", "down"]),
                    ("bgp_session_established", ["session established", "bgp-5-adjchange", "up"]),
                    ("route_withdrawal",     ["route withdrawal"]),
                    ("routes_relearned",     ["routes successfully relearned"]),
                    ("bgp",                  ["bgp"]),
                    ("ospf",                 ["ospf"]),
                    ("dot1x_logout",         ["logged out", "dot1x_logout"]),
                    ("dot1x_failure",        ["authentication failed"]),
                    ("port_blocked",         ["blocked due to repeated", "temporarily blocked", "blocked after repeated"]),
                    ("radius_failure",       ["radius server unreachable", "radius unreachable", "unreachable, authentication timeout"]),
                    ("radius_recovered",     ["backup radius", "radius restored"]),
                    ("mac_auth",             ["mac-auth", "mac authentication"]),
                    ("ssh_source_blocked",   ["ssh source", "blocked after maximum"]),
                    ("ssh_bruteforce",       ["ssh login failed", "maximum attempts", "maximum failed attempts"]),
                    ("admin_auth_failure",   ["authentication failure for user", "authfail"]),
                    ("config_change",        ["configuration changed", "config_i", "configured from", "configuration saved", "configuration modified", "configuration updated"]),
                    ("lldp_neighbor_removed", ["lldp neighbor removed", "neighbor removed from port"]),
                    ("lldp_neighbor_discovered", ["lldp neighbor discovered", "neighbor discovered on port", "lldp"]),
                    ("transceiver",         ["transceiver"]),
                    ("ntp",                 ["ntp"]),
                    ("snmp",                ["snmpd", "snmp"]),
                    # HPE 9300 / VXLAN / EVPN patterns — must be checked before generic "vlan"
                    ("tunnel_nexthop_delete", ["nexthop delete", "nexthop", "resolved nexthop", "nexthop removed"]),
                    ("tunnel_nexthop_add",    ["nexthop add"]),
                    ("tunnel_activating",     ["forwarding_state is activating", "state is activating"]),
                    ("tunnel_operational",    ["forwarding_state is operational", "state is operational"]),
                    ("vtep_deleted",          ["has been deleted", "vtep removed", "vtep deleted"]),
                    ("vtep_operational",      ["vtep-peer", "vtep_peer"]),
                    ("vni_delete",            ["vni:", "vni is deleted", "vni id", "vni_id"]),
                    ("vxlan_interface",       ["interface vxlan", "vxlan"]),
                    ("high_cpu",              ["cpu utilization", "high cpu"]),
                    ("high_memory",           ["memory utilization", "memory leak"]),
                    ("queue_drop",            ["queue drop", "tail drop"]),
                    ("buffer_overflow",       ["buffer full", "buffer overflow"]),
                    ("vrrp_state_change",     ["vrrp"]),
                    ("hsrp_state_change",     ["hsrp"]),
                    ("mlag_peer_down",        ["mlag", "vsx", "vpc"]),
                    ("acl_deny",              ["acl deny", "list deny"]),
                    ("arp_spoofing",          ["arp inspection", "spoofing"]),
                    ("mac_flap",              ["mac flapping", "host flapping"]),
                    ("ipsec_tunnel_down",     ["ipsec"]),
                    ("ike_failure",           ["ike phase", "isakmp"]),
                    ("pim_neighbor_down",     ["pim neighbor"]),
                    ("igmp_snooping_error",   ["igmp"]),
                    # Generic vlan — after vxlan/vni to avoid false matches
                    ("vlan",                ["vlan"]),
                ]

                for i, chunk in enumerate(chunks):
                    # --- Extract timestamp ---
                    event_time = None
                    try:
                        ts_str = chunk[:15]
                        current_year = datetime.now(timezone.utc).year
                        parsed = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
                        parsed = parsed.replace(tzinfo=timezone.utc)
                        event_time = parsed.isoformat()
                    except Exception as e:
                        pass

                    if not event_time:
                        event_time = now_iso

                    # --- Extract hostname/IP ---
                    hostname = "unknown"
                    m = _syslog_host.match(chunk)
                    if m:
                        hostname = m.group(1)

                    # --- Extract severity from [facility.severity] ---
                    severity = "info"
                    m_sev = _severity_bracket.search(chunk)
                    if m_sev:
                        severity = _SEVERITY_MAP.get(m_sev.group(2).lower(), m_sev.group(2).lower())
                    else:
                        # Fallback for Cisco like %LINK-3-UPDOWN
                        m_cisco = _re.search(r'%[A-Z_]+-(\d)-', chunk)
                        if m_cisco:
                            sev_num = int(m_cisco.group(1))
                            if sev_num <= 2: severity = "critical"
                            elif sev_num == 3: severity = "error"
                            elif sev_num == 4: severity = "warning"
                            else: severity = "info"

                    # --- Detect subtype from content ---
                    chunk_lower = chunk.lower()
                    detected_subtype = "raw"
                    detected_type = "log"
                    for st, keywords in _SUBTYPE_RULES:
                        if st in ("ospf_neighbor_down", "ospf_neighbor_up", "bgp_session_lost", "bgp_session_established"):
                            proto = "ospf" if "ospf" in st else "bgp"
                            # Unambiguous keywords that are definitively OSPF/BGP — no protocol guard needed
                            _UNAMBIGUOUS = {"full to down", "down to full", "adjchg:", "full -> down", "down -> full",
                                            "rpd_ospf_nbrdown", "rpd_ospf_nbrup", "ospf-5-adjchg", "bgp-5-adjchange"}
                            for kw in keywords:
                                if kw in chunk_lower:
                                    if kw in _UNAMBIGUOUS or proto in chunk_lower:
                                        detected_subtype = st
                                        break
                            if detected_subtype != "raw":
                                break
                        else:
                            if any(kw in chunk_lower for kw in keywords):
                                detected_subtype = st
                                break

                    if detected_subtype != "raw":
                        st = detected_subtype
                        # Map to high-level type
                        if st in ("power_failure", "fan_failure", "fan_nominal", "thermal", "linecard_disabled"):
                            detected_type = "hardware"
                        elif st in ("crc_errors", "interface_down", "interface_up", "transceiver"):
                            detected_type = "physical_link"
                        elif st in ("stp_topology_change", "stp_converged", "lldp_neighbor_removed", "lldp_neighbor_discovered"):
                            detected_type = "topology"
                        elif st in ("ospf", "bgp", "ospf_interface_down", "ospf_interface_up", "ospf_neighbor_down", "ospf_neighbor_up", "route_recalculation_started", "route_recalculation_completed", "bgp_session_lost", "bgp_session_established", "route_withdrawal", "routes_relearned", "routes_withdrawn"):
                            detected_type = "routing"
                        elif st in ("dot1x_failure", "mac_auth", "dot1x_success", "port_blocked"):
                            detected_type = "access_control"
                        elif st in ("ssh_bruteforce", "admin_auth_failure", "ssh_source_blocked", "acl_deny", "arp_spoofing", "mac_flap", "radius_recovered"):
                            detected_type = "security"
                        elif st in ("config_change",):
                            detected_type = "configuration"
                        elif st in ("vlan",):
                            detected_type = "inventory"
                        elif st in ("ntp", "snmp"):
                            detected_type = "service"
                        elif st in ("tunnel_nexthop_delete", "tunnel_nexthop_add", "tunnel_activating", "tunnel_operational", "vtep_operational", "vtep_deleted", "vni_create", "vni_delete", "vxlan_interface"):
                            detected_type = "tunnel"
                        elif st in ("high_cpu", "high_memory", "queue_drop", "buffer_overflow"):
                            detected_type = "performance"
                        elif st in ("vrrp_state_change", "hsrp_state_change", "mlag_peer_down"):
                            detected_type = "high_availability"
                        elif st in ("ipsec_tunnel_down", "ike_failure"):
                            detected_type = "vpn"
                        elif st in ("pim_neighbor_down", "igmp_snooping_error"):
                            detected_type = "multicast"

                    # --- Semantic Severity Overrides ---
                    if detected_subtype in ("interface_up", "ospf_interface_up", "ospf_neighbor_up", "bgp_session_established", "routes_relearned", "radius_recovered", "fan_nominal", "dot1x_success", "stp_converged", "lldp_neighbor_discovered"):
                        severity = "info"
                    elif detected_subtype in ("interface_down", "ospf_interface_down", "ospf_neighbor_down", "bgp_session_lost", "power_failure", "fan_failure", "thermal", "crc_errors", "ssh_bruteforce", "dot1x_failure", "linecard_disabled"):
                        if detected_subtype in ("power_failure", "thermal", "linecard_disabled"):
                            severity = "critical"
                        elif detected_subtype in ("dot1x_failure", "crc_errors"):
                            severity = "error"
                        else:
                            severity = "warning"

                    # --- Extract interface/port ---
                    interface_id = None
                    m_port = _re.search(r'[Pp]ort\s+(\d+/\d+/\d+|\d+/\d+|\d+)', chunk)
                    if m_port:
                        interface_id = m_port.group(1)

                    # --- Extract core message (strip syslog header) ---
                    core_msg = chunk
                    m_syslog = _re.search(r'^(?:[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+)?[\w\.-]+(?:\s+[\w\.-]+)?(?:\[\d+\]|\s+\d+)?:\s+', chunk)
                    if m_syslog:
                        core_msg = chunk[m_syslog.end():]

                    raw_event = {
                        "event": {
                            "event_uid": f"fallback-{i+1}",
                            "event_id": f"fallback-{i+1}",
                            "type": detected_type,
                            "subtype": detected_subtype,
                            "severity": severity,
                            "message": core_msg,
                        },
                        "device": {
                            "hostname": hostname,
                            "ip": hostname if _re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else None,
                        },
                        "network": {
                            "interface_id": interface_id,
                        },
                        "timestamps": {"event_time": event_time, "ingestion_time": now_iso},
                        "raw": {"message": chunk},
                    }
                    fallback.append(raw_event)

                # Save fallback to the expected normalized output path and return
                save_json(normalized_output_path, fallback)
                print(f"[OK] Fallback extractor produced {len(fallback)} records -> {normalized_output_path}")
                return fallback, "fallback_text"

            except Exception as e:
                print(f"[ERROR] Fallback extraction failed: {e}")
                raise ValueError("No events were produced by schema conversion and fallback failed")

        return records, "schema_conversion"

    if ext == ".json":
        payload = load_json(input_path)

        if not isinstance(payload, list) or not payload:
            raise ValueError("JSON input must be a non-empty list of events")

        # Accept nested schema events directly.
        if isinstance(payload[0], dict) and "event" in payload[0] and "device" in payload[0]:
            save_json(normalized_output_path, payload)
            return payload, "json_nested"

        raise ValueError(
            "Unsupported JSON schema. Provide either raw .txt/.log logs or nested event JSON from schema pipeline."
        )

    raise ValueError("Unsupported input extension. Use .txt, .log, or .json")


def generate_visualization_html(timeline_incidents: List[Dict], output_path: Path) -> None:
    rows = []
    for inc in timeline_incidents:
        rows.append(
            "<tr>"
            f"<td>{inc.get('incident_id', 'N/A')}</td>"
            f"<td>{inc.get('start_time', 'N/A')}</td>"
            f"<td>{inc.get('end_time', 'N/A')}</td>"
            f"<td>{inc.get('duration_sec', 0)}</td>"
            f"<td>{len(inc.get('events', []))}</td>"
            f"<td>{', '.join(inc.get('devices', []))}</td>"
            f"<td>{inc.get('summary', {}).get('primary_issue', 'unknown')}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Incident Visualization</title>
  <style>
    :root {{
      --bg: #f4f2ea;
      --paper: #fffdf7;
      --ink: #1f1a14;
      --accent: #b84c2a;
      --line: #d6cab5;
    }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top right, #f6e3d6 0%, transparent 38%),
        radial-gradient(circle at bottom left, #e9f0d8 0%, transparent 42%),
        var(--bg);
    }}
    .wrap {{ max-width: 1100px; margin: 30px auto; padding: 0 16px; }}
    .card {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.08);
      padding: 18px;
    }}
    h1 {{ margin: 0 0 8px 0; color: var(--accent); }}
    p {{ margin: 0 0 14px 0; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; }}
    th, td {{ border: 1px solid var(--line); text-align: left; padding: 10px; font-size: 14px; }}
    th {{ background: #f7efe2; }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <div class=\"card\">
      <h1>Network Incident Timeline Overview</h1>
      <p>Generated at {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}</p>
      <table>
        <thead>
          <tr>
            <th>Incident</th><th>Start</th><th>End</th><th>Duration(s)</th>
            <th>Events</th><th>Devices</th><th>Primary Issue</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")


def generate_fallback_report(timeline_incidents: List[Dict], causal_summary: Dict, output_path: Path) -> None:
    """Generate a structured investigation report with clear category segregation."""
    from datetime import datetime, timezone

    now_str   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_local = datetime.now().strftime("%Y-%m-%d")

    # -- Pull data from causal summary
    causal_incidents   = causal_summary.get("incidents", [])
    alert_incidents    = causal_summary.get("alert_incidents", [])
    workflow_incidents = causal_summary.get("workflow_incidents", [])
    noise_incidents    = causal_summary.get("noise_incidents", [])
    total_links        = causal_summary.get("total_causal_links", 0)
    devices            = causal_summary.get("affected_devices", [])

    total_events    = sum(len(i.get("events", [])) for i in timeline_incidents)
    n_reconstructed = len(causal_incidents)
    n_alerts        = len(alert_incidents)
    n_workflows     = len(workflow_incidents)
    n_routine       = sum(len(i.get("events", [])) for i in noise_incidents)
    if n_routine == 0:
        n_routine = len(noise_incidents)

    highest_sev = "Info"
    sev_rank = {"critical": 4, "error": 3, "warning": 2, "info": 1}
    for inc_list in [causal_incidents, alert_incidents]:
        for inc in inc_list:
            for e in inc.get("events", []):
                s = e.get("severity", "info").lower()
                if sev_rank.get(s, 0) > sev_rank.get(highest_sev.lower(), 0):
                    highest_sev = s.capitalize()

    device_str = ", ".join(devices) if devices else "N/A"

    active     = any(inc.get("status", "").lower() == "active"     for inc in causal_incidents)
    recovering = any(inc.get("status", "").lower() == "recovering" for inc in causal_incidents)
    if active:
        status_str = "Active — Unresolved incidents require immediate attention"
    elif recovering:
        status_str = "Recovering — Incidents partially resolved"
    elif n_reconstructed == 0:
        status_str = "Stable — No reconstructed incidents detected"
    else:
        status_str = "Resolved"

    def _fmt_time(t):
        if not t:
            return "—"
        return str(t)[:19].replace("T", " ") + " UTC"

    def _humanize(s):
        return str(s).replace("_", " ").title()

    lines = []

    # 1. EXECUTIVE SUMMARY
    lines += [
        "# Network Incident Investigation Report",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Investigation Date** | {now_local} |",
        f"| **Device(s) Analyzed** | {device_str} |",
        f"| **Logs Analyzed** | {total_events} |",
        f"| **Reconstructed Incidents** | **{n_reconstructed}** — proven causal chain + RCA |",
        f"| **Standalone Alerts** | {n_alerts} |",
        f"| **Operational Workflows** | {n_workflows} |",
        f"| **Routine Informational Events** | {n_routine} |",
        f"| **Highest Severity Observed** | {highest_sev} |",
        f"| **Overall Investigation Status** | {status_str} |",
        "",
    ]

    if n_reconstructed == 0:
        lines += [
            "> No incidents with a proven causal chain were detected.",
            "> Only standalone alerts and operational workflows were found.",
            "",
        ]
    else:
        lines += [
            f"> **{n_reconstructed} incident(s)** have a proven causal chain and receive full Root Cause Analysis below.",
            f"> The remaining {n_alerts + n_workflows + n_routine} events are categorized as alerts ({n_alerts}), "
            f"workflows ({n_workflows}), or routine ({n_routine}) — none of these are incidents.",
            "",
        ]

    # 2. INVESTIGATION SCOPE — compute time range
    all_times = []
    for inc in timeline_incidents:
        if inc.get("start_time"): all_times.append(inc["start_time"])
        if inc.get("end_time"):   all_times.append(inc["end_time"])
    t_start = _fmt_time(min(all_times)) if all_times else "N/A"
    t_end   = _fmt_time(max(all_times)) if all_times else "N/A"

    scope_sentence = (
        f"This investigation covers {total_events} log events collected from {len(devices)} device(s) "
        f"({device_str}) between {t_start} and {t_end}. "
        f"A total of {n_reconstructed} incident(s) were reconstructed with full RCA, alongside "
        f"{n_alerts} standalone alert(s), {n_workflows} operational workflow(s), and "
        f"{n_routine} routine informational event(s) — overall status: {status_str.split(' —')[0]}."
    )

    lines += [
        "---",
        "",
        "## 2. Investigation Scope",
        "",
        scope_sentence,
        "",
    ]


    # 3. INCIDENT CLASSIFICATION SUMMARY
    inc_ids_str   = ", ".join(i.get("incident_id", "?") for i in causal_incidents)   or "None"
    alert_ids_str = ", ".join(i.get("incident_id", "?") for i in alert_incidents)    or "None"
    wf_ids_str    = ", ".join(i.get("incident_id", "?") for i in workflow_incidents) or "None"

    routine_labels = []
    for inc in noise_incidents:
        for e in inc.get("events", []):
            label = _humanize(e.get("normalized_subtype", e.get("subtype", "?")))
            if label not in routine_labels:
                routine_labels.append(label)
    routine_str = ", ".join(routine_labels) if routine_labels else "None"

    lines += [
        "---",
        "",
        "## 3. Incident Classification Summary",
        "",
        "| Category | Count | IDs / Labels |",
        "|---|---|---|",
        f"| Logs Analyzed | {total_events} | All parsed log events |",
        f"| **Reconstructed Incidents (RCA)** | **{n_reconstructed}** | {inc_ids_str} |",
        f"| Standalone Alerts | {n_alerts} | {alert_ids_str} |",
        f"| Operational Workflows | {n_workflows} | {wf_ids_str} |",
        f"| Routine Informational Events | {n_routine} | {routine_str} |",
        "",
        "> **How to read this table:** Only Reconstructed Incidents have a proven causal chain.",
        "> Standalone alerts, workflows, and routine events are **not incidents** — classified separately below.",
        "",
    ]

    # 4. RECONSTRUCTED INCIDENTS
    lines += [
        "---",
        "",
        "## 4. Reconstructed Incidents — Full Root Cause Analysis",
        "",
    ]

    if not causal_incidents:
        lines += ["> No reconstructed incidents found.", ""]
    else:
        lines += [
            f"> Only **{n_reconstructed}** incident(s) below have a proven causal chain.",
            "> Each section: Incident Overview (incl. impact) · Timeline · Root Cause · Cause-Effect Chain · Supporting Evidence · Recommendations",
            "",
        ]

    for idx, inc in enumerate(causal_incidents, 1):
        iid          = inc.get("incident_id", "N/A")
        status       = inc.get("status", "Unknown")
        start        = _fmt_time(inc.get("start_time", ""))
        end          = _fmt_time(inc.get("end_time", ""))
        duration     = inc.get("duration_sec", 0)
        events       = inc.get("events", [])
        root         = inc.get("root_cause") or {}
        causal_links = inc.get("causal_links", [])
        seq_list     = inc.get("causal_sequences", [])

        root_subtype = root.get("normalized_subtype") or root.get("subtype", "unknown")
        root_score   = root.get("root_score", 0)
        root_msg     = root.get("message", "")
        root_sev     = (inc.get("severity") or root.get("severity") or "info").capitalize()
        root_device  = root.get("device", device_str)
        root_iface   = root.get("interface_id") or "—"

        best_conf = max((s.get("total_confidence", 0) for s in seq_list), default=0)
        conf_pct  = f"{int(best_conf * 100)}%"

        failures   = [e for e in events if not e.get("is_recovery")]
        fail_types = " -> ".join(dict.fromkeys(
            _humanize(e.get("normalized_subtype", e.get("subtype", "?"))) for e in failures[:3]
        ))
        title = f"Incident {iid} — {fail_types}"

        lines += ["---", "", f"### {title}", ""]
        
        if "ssh_bruteforce" in " ".join([e.get("normalized_subtype", "") for e in events]).lower():
            lines += ["> **Summary:** Repeated SSH authentication failures detected. Automatic source IP blocking was triggered. No successful authentication occurred before mitigation.", ""]

        # 4.x.1 Overview (merged with Impact Assessment — no duplication)
        iface_set = sorted({e.get("interface_id") for e in events if e.get("interface_id")})
        iface_str = ", ".join(iface_set) if iface_set else "—"
        
        same_device = "✓ Same device<br>" if len(set(e.get("hostname") for e in events if e.get("hostname"))) == 1 else ""
        same_iface = "✓ Same interface<br>" if len(iface_set) == 1 else ""
        recov_obs = "✓ Recovery observed<br>" if status.lower() == "resolved" else ""
        temp_prox = "✓ Temporal proximity<br>"
        known_chain = "✓ Known propagation chain" if causal_links else ""
        conf_reasons = f"{same_device}{same_iface}{recov_obs}{temp_prox}{known_chain}"
        
        lines += [
            f"#### 4.{idx}.1  Incident Overview",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| **Incident ID** | {iid} |",
            f"| **Status** | {status} |",
            f"| **Start Time** | {start} |",
            f"| **End Time** | {end} |",
            f"| **Duration** | {duration}s |",
            f"| **Severity** | {root_sev} |",
            f"| **Affected Device** | {root_device} |",
            f"| **Affected Interface(s)** | {iface_str} |",
            f"| **Events in Chain** | {len(events)} |",
            f"| **Causal Confidence** | {conf_pct} |",
            f"| **Confidence Reasons** | {conf_reasons} |",
            "",
        ]

        sorted_events = sorted(events, key=lambda e: e.get("corrected_time") or e.get("event_time") or "")
        recovery_events = [e for e in sorted_events if e.get("is_recovery")]
        main_events = [e for e in sorted_events if not e.get("is_recovery")]

        # 4.x.2 Timeline
        lines += [f"#### 4.{idx}.2  Timeline Reconstruction", "", "```"]
        prev = None
        for e in main_events:
            t    = _fmt_time(e.get("corrected_time") or e.get("event_time") or "")
            sub  = _humanize(e.get("normalized_subtype", e.get("subtype", "?")))
            sev  = e.get("severity", "info").upper()
            msg  = e.get("message", "")
            if prev:
                lines.append("        |")
                lines.append("        v")
                lines.append("")
            lines.append(f"{t}")
            lines.append(f"[{sev}]  {sub}")
            lines.append(f"       {msg}")
            prev = t
        lines += ["```", ""]
        
        if recovery_events:
            rec_start = datetime.fromisoformat(main_events[0].get("corrected_time") or main_events[0].get("event_time")).replace(tzinfo=None) if main_events else None
            rec_end = datetime.fromisoformat(recovery_events[-1].get("corrected_time") or recovery_events[-1].get("event_time")).replace(tzinfo=None)
            rec_dur = int((rec_end - rec_start).total_seconds()) if rec_start else 0
            
            lines += [f"#### 4.{idx}.3  Recovery Events", ""]
            lines += [f"**Status = RESOLVED** (Recovery Duration: {rec_dur} seconds)", ""]
            for e in recovery_events:
                sub  = _humanize(e.get("normalized_subtype", e.get("subtype", "?")))
                lines.append(f"- {sub}")
            lines.append("")
            root_idx = 4
        else:
            root_idx = 3

        # Root Cause
        lines += [
            f"#### 4.{idx}.{root_idx}  Root Cause Analysis",
            "",
            "| Field | Detail |",
            "|---|---|",
            f"| **Root Cause** | {_humanize(root_subtype)} |",
            f"| **Root Trigger Event** | {root_msg} |",
            f"| **Device** | {root_device} |",
            f"| **Causal Confidence** | {conf_pct} |",
            f"| **Causal Links Found** | {len(causal_links)} |",
            "",
        ]

        # Propagation
        best_seq = max(seq_list, key=lambda s: s.get("total_confidence", 0), default=None)
        if best_seq:
            lines += [f"#### 4.{idx}.{root_idx+1}  Propagation", ""]
            steps = best_seq.get("steps", [])
            prop_str = " -> ".join(_humanize(step.get("subtype", "?")) for step in steps if "recovery" not in step.get("role", ""))
            if recovery_events:
                prop_str += " -> Recovery Completed"
            lines += [
                f"**Root Cause:** {_humanize(root_subtype)} on {root_device}",
                "",
                "**Propagation:**",
                prop_str,
                ""
            ]

        # 4.x.5 Evidence
        lines += [
            f"#### 4.{idx}.5  Supporting Evidence",
            "",
            "| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |",
            "|---|---|---|---|---|---|",
        ]
        for e in sorted_events:
            t    = _fmt_time(e.get("corrected_time") or e.get("event_time") or "")[:19]
            uid  = e.get("event_uid", "—")
            ifc  = e.get("interface_id") or "—"
            sev  = e.get("severity", "info").capitalize()
            sub  = _humanize(e.get("normalized_subtype", e.get("subtype", "?")))
            msg  = e.get("message", "")
            lines.append(f"| {t} | {uid} | {ifc} | {sev} | {sub} | {msg} |")
        lines.append("")

        # 4.x.6 Recommendations
        recs = _recommendations_for(root_subtype, root_device, iface_str)
        lines += [f"#### 4.{idx}.6  Recommendations", "", "| # | Action | Rationale |", "|---|---|---|"]
        for i_r, (action, rationale) in enumerate(recs, 1):
            lines.append(f"| {i_r} | **{action}** | {rationale} |")
        lines.append("")

    # 5. STANDALONE ALERTS
    lines += [
        "---",
        "",
        "## 5. Standalone Alerts",
        "",
        "> These events have **no proven causal chain**. Each is independent — not part of a cascading incident.",
        "",
    ]
    if not alert_incidents:
        lines += ["> No standalone alerts detected.", ""]
    else:
        lines += [
            "| Incident ID | Alert Type | Severity | Time (UTC) | Message | Action Required |",
            "|---|---|---|---|---|---|",
        ]
        for inc in alert_incidents:
            a_iid = inc.get("incident_id", "—")
            for e in inc.get("events", []):
                sub    = _humanize(e.get("normalized_subtype", e.get("subtype", "?")))
                sev    = e.get("severity", "info").capitalize()
                t      = _fmt_time(e.get("corrected_time") or e.get("event_time") or "")[:19]
                msg    = e.get("message", "")
                action = _alert_action(e.get("normalized_subtype", e.get("subtype", "")))
                lines.append(f"| {a_iid} | {sub} | {sev} | {t} | {msg} | {action} |")
        lines.append("")

    # 6. OPERATIONAL WORKFLOWS
    lines += [
        "---",
        "",
        "## 6. Operational Workflows",
        "",
        "> These are **normal, successful operations** — not incidents.",
        "",
    ]
    if not workflow_incidents:
        lines += ["> No operational workflows detected.", ""]
    else:
        lines += [
            "| Workflow ID | Event Type | Time (UTC) | Status | Action Required |",
            "|---|---|---|---|---|",
        ]
        for inc in workflow_incidents:
            w_iid  = inc.get("incident_id", "N/A")
            status = inc.get("status", "Successful")
            for e in inc.get("events", []):
                sub = _humanize(e.get("normalized_subtype", e.get("subtype", "?")))
                t   = _fmt_time(e.get("corrected_time") or e.get("event_time") or "")[:19]
                lines.append(f"| {w_iid} | {sub} | {t} | {status} | No |")
        lines.append("")

    # 7. ROUTINE INFORMATIONAL EVENTS
    lines += [
        "---",
        "",
        "## 7. Routine Informational Events",
        "",
        "> These events are **not actionable**. Included for completeness only.",
        "",
    ]
    if not noise_incidents:
        lines += ["> No routine events detected.", ""]
    else:
        lines += [
            "| Event Type | Time (UTC) | Device | Notes |",
            "|---|---|---|---|",
        ]
        for inc in noise_incidents:
            for e in inc.get("events", []):
                sub    = _humanize(e.get("normalized_subtype", e.get("subtype", "?")))
                t      = _fmt_time(e.get("corrected_time") or e.get("event_time") or "")[:19]
                dev    = e.get("device", "—")
                reason = _routine_reason(e.get("normalized_subtype", e.get("subtype", "")))
                lines.append(f"| {sub} | {t} | {dev} | {reason} |")
        lines.append("")

    # 8. RECOMMENDATIONS
    lines += [
        "---",
        "",
        "## 8. Recommendations",
        "",
        "| Priority | Action | Source |",
        "|---|---|---|",
    ]
    all_recs = []
    for inc in causal_incidents:
        root     = inc.get("root_cause") or {}
        root_sub = root.get("normalized_subtype") or root.get("subtype", "unknown")
        iid      = inc.get("incident_id", "N/A")
        for action, _ in _recommendations_for(root_sub, root.get("device", ""), ""):
            sev  = root.get("severity", "info").lower()
            prio = "Critical" if sev == "critical" else ("High" if sev in ("error", "warning") else "Medium")
            all_recs.append((prio, action, iid))
    for inc in alert_incidents:
        for e in inc.get("events", []):
            sub    = e.get("normalized_subtype", e.get("subtype", ""))
            sev    = e.get("severity", "info").lower()
            action = _alert_action(sub)
            prio   = "Critical" if sev == "critical" else "High"
            a_iid  = inc.get("incident_id", "Alert")
            all_recs.append((prio, action, a_iid))
    all_recs.append(("Low", "Enrich device vendor metadata for improved classification accuracy", "All"))
    all_recs.append(("Low", "Configure alerting for high root-score event subtypes", "All"))
    for prio, action, source in all_recs:
        lines.append(f"| {prio} | {action} | {source} |")
    lines.append("")

    # 9. INVESTIGATION CONCLUSION
    lines += ["---", "", "## 9. Investigation Conclusion", ""]
    if causal_incidents:
        lines.append(f"**Reconstructed Incidents ({n_reconstructed}):**")
        for inc in causal_incidents:
            iid    = inc.get("incident_id", "N/A")
            root   = inc.get("root_cause") or {}
            rtype  = _humanize(root.get("normalized_subtype") or root.get("subtype", "unknown"))
            status = inc.get("status", "Unknown")
            seq    = inc.get("causal_sequences", [])
            conf   = f"{int(max((s.get('total_confidence', 0) for s in seq), default=0) * 100)}%" if seq else "N/A"
            lines.append(f"- **{iid}** — Root Cause: {rtype} | Status: {status} | Confidence: {conf}")
        lines.append("")
    if alert_incidents:
        a_ids = ", ".join(i.get("incident_id", "?") for i in alert_incidents)
        lines.append(f"**Standalone Alerts ({n_alerts}):** {a_ids} — Independent events. See Section 5.")
        lines.append("")
    health = "Poor — active incidents detected" if active else ("Fair — incidents recovering" if recovering else "Stable")
    lines += [
        f"**Overall Network Health:** {health}",
        "",
        "**Remaining Uncertainties:**",
        "- Causality is inferred from temporal and contextual heuristics — not guaranteed proof.",
        "- Events with vendor = unknown may have reduced classification accuracy.",
        "",
    ]

    # 10. APPENDIX
    inc_ids    = [i.get("incident_id", "N/A") for i in causal_incidents]
    alert_iids = [i.get("incident_id", "?") for i in alert_incidents]
    lines += [
        "---",
        "",
        "## 10. Appendix",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Reconstructed Incident IDs** | {', '.join(inc_ids) if inc_ids else 'None'} |",
        f"| **Standalone Alert IDs** | {', '.join(alert_iids) if alert_iids else 'None'} |",
        f"| **Total Causal Links** | {total_links} |",
        f"| **Report Generated** | {now_str} |",
        "| **Log Reference Files** | normalized_events.json, timeline_output.json, causal_inference_output.json |",
        "| **Causality Method** | Temporal + contextual heuristics (DAG-graph-partitioned) |",
        "",
    ]

    output_path.write_text("\n".join(lines), encoding="utf-8")



# ── Helper functions for report generation ─────────────────────────────────

def _recommendations_for(root_subtype: str, device: str, iface: str) -> List[tuple]:
    """Return (action, rationale) pairs based on the root cause subtype."""
    s = root_subtype.lower()
    if "power_failure" in s or "psu" in s:
        return [
            ("Replace failed power supply immediately", "No power redundancy — one PSU left"),
            ("Monitor thermal sensors", "Fan overspeed may indicate thermal stress"),
            ("Schedule emergency maintenance", "On-site hardware replacement required"),
        ]
    elif "stp" in s or "topology_change" in s:
        return [
            ("Investigate STP root bridge stability", "Unexpected STP transitions risk L2/L3 disruption"),
            ("Enable STP BPDU Guard on access ports", "Prevents rogue devices triggering STP reconvergence"),
            ("Tune OSPF hello/dead intervals", "Reduces sensitivity to brief L2 flaps"),
        ]
    elif "ospf" in s or "bgp" in s:
        return [
            ("Restore routing adjacency", f"Verify physical connectivity and protocol timers on {device}"),
            ("Check interface stability", f"Interface {iface} may be causing routing instability"),
        ]
    elif "interface_down" in s or "link_down" in s:
        return [
            ("Inspect physical cable and transceiver", f"Port {iface} went down — check hardware"),
            ("Enable interface monitoring alerts", "Alert on port state changes to catch issues early"),
        ]
    elif "crc_error" in s:
        return [
            ("Replace cable or transceiver", "CRC errors indicate signal integrity problems"),
            ("Check port error counters", "Persistent CRC errors may require port replacement"),
        ]
    elif "ssh_brute" in s or "bruteforce" in s:
        return [
            ("Block source IP at perimeter firewall", "External IP targeting management plane"),
            ("Enable SSH rate limiting", "Limit failed login attempts per source"),
            ("Review SSH access control list", "Restrict SSH to trusted management IPs only"),
        ]
    elif "auth_failure" in s or "dot1x" in s:
        return [
            ("Review NAC/802.1X policy", "Authentication failure may indicate unauthorized device"),
            ("Audit recent login attempts", "Check if failure is a misconfigured client or attack"),
        ]
    elif "fan_failure" in s:
        return [
            ("Check cooling system", "Fan failure may lead to thermal shutdown"),
            ("Verify ambient temperature", "High ambient temp accelerates hardware degradation"),
        ]
    else:
        return [
            ("Investigate root cause device and interface", f"device={device}, interface={iface}"),
            ("Add monitoring alerts for this event type", f"subtype={root_subtype}"),
        ]


def _alert_action(subtype: str) -> str:
    """Return a short recommended action string for a standalone alert."""
    s = subtype.lower()
    if "ssh" in s and ("brute" in s or "login" in s):
        return "Block source IP at firewall immediately"
    elif "auth_failure" in s or "dot1x" in s:
        return "Review NAC policy and audit login attempts"
    elif "crc" in s:
        return "Inspect cable and transceiver"
    elif "interface_down" in s:
        return "Check physical connectivity"
    elif "transceiver" in s:
        return "Verify transceiver compatibility"
    elif "config_change" in s:
        return "Verify change matches approved change ticket"
    else:
        return "Review and investigate"


def _routine_reason(subtype: str) -> str:
    """Return a short explanation of why this event is routine."""
    s = subtype.lower()
    if "ntp" in s:
        return "Expected periodic time synchronization"
    elif "snmp" in s:
        return "Normal SNMP polling session teardown"
    elif "lldp" in s:
        return "Expected neighbor discovery"
    elif "interface_up" in s:
        return "Standard port coming online"
    elif "vlan" in s:
        return "Normal VLAN provisioning activity"
    elif "mac_auth" in s or "dot1x_logout" in s:
        return "Expected client authentication lifecycle"
    elif "bgp_established" in s or "bgp_session" in s:
        return "Routing session recovery — expected after flap"
    else:
        return "Classified as informational by causal engine"


def run_causal_from_timeline(timeline_incidents: List[Dict]) -> Dict:

    incident_results = []

    total_links = 0
    root_causes = []
    affected_devices = set()

    noise_incidents = []
    workflow_incidents = []
    alert_incidents = []
    
    for incident in timeline_incidents:

        # Stage 6 (causal inference) + Stage 7 (validate & split)
        results = analyze_and_validate(incident)

        for result in results:
            if result.get("classification") == "informational":
                noise_incidents.append(result)
                continue
            elif result.get("classification") == "operational_workflow":
                workflow_incidents.append(result)
                continue
            elif result.get("classification") == "standalone_alert":
                alert_incidents.append(result)
                continue
            incident_results.append(result)

            total_links += len(result.get("causal_links", []))

            root = result.get("root_cause")
            if root:
                root_causes.append(
                    {
                        "incident_id": result.get("incident_id"),
                        "event_uid": root.get("event_uid"),
                        "subtype": root.get("normalized_subtype"),
                        "device": root.get("device"),
                        "message": root.get("message"),
                        "score": root.get("root_score"),
                    }
                )

            # Collect affected devices from the result's events
            for event in incident.get("events", []):
                dev = event.get("device")
                if dev:
                    affected_devices.add(dev)

    return {
        "total_incidents": len(incident_results),
        "total_causal_links": total_links,
        "affected_devices": sorted(list(affected_devices)),
        "root_causes": root_causes,
        "incidents": incident_results,
        "noise_incidents": noise_incidents,
        "workflow_incidents": workflow_incidents,
        "alert_incidents": alert_incidents,
    }


def maybe_generate_llm_report(
    timeline_path: Path,
    causal_path: Path,
    output_path: Path,
    use_llm: bool,
) -> bool:
    if not use_llm:
        return False

    if not os.getenv("GEMINI_API_KEY"):
        return False

    cmd = [
        sys.executable,
        str(Path(__file__).parent / "network_incident_summarizer.py"),
        "--timeline",
        str(timeline_path),
        "--causal",
        str(causal_path),
        "--output",
        str(output_path),
    ]

    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def run_full_pipeline(input_path: Path, output_dir: Path, use_llm_report: bool = True) -> Dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    schema_output_path = output_dir / "schema_output.json"
    preprocessed_path = output_dir / "preprocessed_events.json"
    normalized_path = output_dir / "normalized_events.json"
    topology_path = output_dir / "topology_graph.json"
    timeline_path = output_dir / "timeline_output.json"
    causal_path = output_dir / "causal_inference_output.json"
    report_path = output_dir / "incident_report.md"
    visual_path = output_dir / "incident_visualization.html"

    # Stage 1: Log file -> schema conversion output
    _events, source_mode = parse_input_logs(input_path, schema_output_path, skip_schema_llm=not use_llm_report)

    # Stage 2: Schema output -> preprocessing output
    preprocessed_events = run_preprocessing_pipeline(
        str(schema_output_path),
        str(preprocessed_path),
    )
    if not preprocessed_events:
        raise ValueError("Preprocessing produced no valid events")

    # Keep normalized_events.json alias for compatibility with older consumers.
    normalized_payload = json.loads(
        json.dumps(preprocessed_events, default=json_serializable)
    )
    save_json(normalized_path, normalized_payload)

    # Stage 2: Implicit Topology Extraction (NEW)
    from preprocessing import restore_datetime_fields
    topo_events = restore_datetime_fields(
        json.loads(json.dumps(preprocessed_events, default=json_serializable))
    )
    topo = extract_topology(topo_events)
    save_topology(topo, topology_path)

    # Stages 3-5: Timeline reconstruction (temporal alignment + compatibility + Louvain)
    timeline_data = run_timeline_pipeline(str(preprocessed_path), str(timeline_path), topo=topo)

    # Stages 6-7: Causal inference with incident validation/splitting
    causal_summary = run_causal_from_timeline(timeline_data)
    save_json(causal_path, causal_summary)

    # Stage 5: Report and visualization generation
    if not maybe_generate_llm_report(timeline_path, causal_path, report_path, use_llm_report):
        generate_fallback_report(timeline_data, causal_summary, report_path)

    generate_visualization_html(timeline_data, visual_path)

    # Stage 6: PDF Report Generation
    pdf_path = output_dir / "incident_report.pdf"
    try:
        from generate_pdf_report import create_pdf_report
        create_pdf_report(timeline_path, causal_path, report_path, pdf_path)
        print(f"[OK] Saved PDF report to {pdf_path}")
        pdf_status = str(pdf_path)
    except Exception as e:
        print(f"[WARN] PDF generation failed: {e}")
        pdf_status = f"failed: {e}"

    return {
        "status": "success",
        "input": str(input_path),
        "mode": source_mode,
        "schema_output": str(schema_output_path),
        "preprocessed_events": str(preprocessed_path),
        "normalized_events": str(normalized_path),
        "timeline_output": str(timeline_path),
        "causal_output": str(causal_path),
        "report": str(report_path),
        "pdf_report": pdf_status,
        "visualization": str(visual_path),
        "actionable_incidents": len([i for i in timeline_data if i.get("is_incident")]),
        "operational_workflows": len([i for i in timeline_data if not i.get("is_incident")]),
        "total_clusters": len(timeline_data),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Integrated network incident pipeline")
    parser.add_argument("--input", required=True, help="Path to input log file (.txt/.log/.json)")
    parser.add_argument("--output-dir", default="pipeline_output", help="Output directory")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM report generation")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    result = run_full_pipeline(input_path, output_dir, use_llm_report=not args.no_llm)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
