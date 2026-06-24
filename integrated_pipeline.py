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
                    ("fan_failure",            ["fan tray", "fan failure", "fan stopped", "speed out of normal range", "fan tray failed"]),
                    ("fan_nominal",            ["speed nominal", "fan nominal"]),
                    ("thermal",              ["temperature critical", "thermal protection"]),
                    ("linecard_disabled",    ["linecard slot", "disabled due to"]),
                    ("crc_errors",           ["crc error", "excessive crc"]),
                    ("interface_down",       ["off-line", "offline", "link down", "is down", "operational status changed to down"]),
                    ("interface_up",         ["on-line", "online", "link up", "operational status changed to up"]),
                    ("stp_topology_change",  ["topology change", "mstp", "recalculating spanning tree", "spanning tree"]),
                    ("ospf_interface_down",  ["ptp to down"]),
                    ("ospf_interface_up",    ["down to ptp"]),
                    ("ospf_neighbor_down",   ["full to down"]),
                    ("ospf_neighbor_up",     ["down to full"]),
                    ("route_recalculation_started",   ["routing table recalculation started"]),
                    ("route_recalculation_completed", ["routing table recalculation completed"]),
                    ("routes_withdrawn",    ["routes withdrawn"]),
                    ("bgp_session_lost",     ["session lost", "session down", "hold timer expired"]),
                    ("bgp_session_established", ["session established"]),
                    ("route_withdrawal",     ["route withdrawal"]),
                    ("routes_relearned",     ["routes successfully relearned"]),
                    ("bgp",                  ["bgp"]),
                    ("ospf",                 ["ospf"]),
                    ("dot1x_logout",         ["logged out", "dot1x_logout"]),
                    ("dot1x_failure",        ["authentication failed"]),
                    ("port_blocked",         ["blocked due to repeated"]),
                    ("radius_failure",       ["radius server unreachable", "radius unreachable"]),
                    ("radius_recovered",     ["backup radius", "radius restored"]),
                    ("mac_auth_success",     ["authentication succeeded"]),
                    ("mac_auth",             ["mac-auth", "mac authentication"]),
                    ("ssh_source_blocked",   ["ssh source", "blocked after maximum"]),
                    ("ssh_bruteforce",       ["ssh login failed", "maximum attempts", "maximum failed attempts"]),
                    ("admin_auth_failure",   ["authentication failure for user", "authfail"]),
                    ("config_change",        ["configuration changed", "config_i", "configured from", "configuration saved"]),
                    ("lldp",                 ["lldp"]),
                    ("transceiver",         ["transceiver"]),
                    ("ntp",                 ["ntp"]),
                    ("snmp",                ["snmpd", "snmp"]),
                    # HPE 9300 / VXLAN / EVPN patterns — must be checked before generic "vlan"
                    ("tunnel_nexthop_delete", ["nexthop delete"]),
                    ("tunnel_nexthop_add",    ["nexthop add"]),
                    ("tunnel_activating",     ["forwarding_state is activating"]),
                    ("tunnel_operational",    ["forwarding_state is operational"]),
                    ("vtep_operational",      ["vtep-peer", "vtep_peer"]),
                    ("vni_create",            ["vni id", "vni_id"]),
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

                    # --- Detect subtype from content ---
                    chunk_lower = chunk.lower()
                    detected_subtype = "raw"
                    detected_type = "log"
                    for st, keywords in _SUBTYPE_RULES:
                        if any(kw in chunk_lower for kw in keywords):
                            detected_subtype = st
                            # Map to high-level type
                            if st in ("power_failure", "fan_failure", "fan_nominal", "thermal", "linecard_disabled"):
                                detected_type = "hardware"
                            elif st in ("crc_errors", "interface_down", "interface_up", "transceiver"):
                                detected_type = "physical_link"
                            elif st in ("stp_topology_change",):
                                detected_type = "topology"
                            elif st in ("ospf", "bgp", "ospf_interface_down", "ospf_interface_up", "ospf_neighbor_down", "ospf_neighbor_up", "route_recalculation_started", "route_recalculation_completed", "bgp_session_lost", "bgp_session_established", "route_withdrawal", "routes_relearned", "routes_withdrawn"):
                                detected_type = "routing"
                            elif st in ("dot1x_failure", "mac_auth", "mac_auth_success", "port_blocked"):
                                detected_type = "access_control"
                            elif st in ("ssh_bruteforce", "admin_auth_failure", "ssh_source_blocked", "acl_deny", "arp_spoofing", "mac_flap", "radius_recovered"):
                                detected_type = "security"
                            elif st in ("config_change",):
                                detected_type = "configuration"
                            elif st in ("lldp", "vlan"):
                                detected_type = "inventory"
                            elif st in ("ntp", "snmp"):
                                detected_type = "service"
                            elif st in ("tunnel_nexthop_delete", "tunnel_nexthop_add", "tunnel_activating", "tunnel_operational", "vtep_operational", "vni_create", "vxlan_interface"):
                                detected_type = "tunnel"
                            elif st in ("high_cpu", "high_memory", "queue_drop", "buffer_overflow"):
                                detected_type = "performance"
                            elif st in ("vrrp_state_change", "hsrp_state_change", "mlag_peer_down"):
                                detected_type = "high_availability"
                            elif st in ("ipsec_tunnel_down", "ike_failure"):
                                detected_type = "vpn"
                            elif st in ("pim_neighbor_down", "igmp_snooping_error"):
                                detected_type = "multicast"
                            break

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
    total_events = sum(len(i.get("events", [])) for i in timeline_incidents)
    total_links = causal_summary.get("total_causal_links", 0)
    roots = causal_summary.get("root_causes", [])
    devices = causal_summary.get("affected_devices", [])

    workflow_incidents = causal_summary.get("workflow_incidents", [])
    causal_incidents = causal_summary.get("incidents", [])
    report_incidents = causal_incidents if causal_incidents else (timeline_incidents if not workflow_incidents and not causal_summary.get("noise_incidents") else [])

    total_incidents = len(report_incidents)

    lines = [
        "# Network Incident Investigation Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Executive Summary",
        f"- Total incidents reconstructed: {total_incidents}",
        f"- Total events analyzed: {total_events}",
        f"- Total causal links inferred: {total_links}",
        f"- Affected devices: {', '.join(devices) if devices else 'N/A'}",
        "",
        "## Probable Initiating Triggers",
    ]

    valid_roots = [r for r in roots if r.get('score', 0) >= 0]
    if valid_roots:
        for root in valid_roots:
            lines.append(
        f"- Incident {root['incident_id']} "
        f"-> {root['subtype']} "
        f"(device={root['device']}, score={root['score']})"
    )
    else:
        lines.append("- No high-confidence root trigger was detected")

    lines.extend([
        "",
        "## Incident Overview",
    ])
    
    if not report_incidents:
        lines.append("- No actionable incidents detected.")
    
    for inc in report_incidents:
        root = inc.get("root_cause") or {}
        # Derive primary_issue from root cause subtype, then incident_type, then domain
        primary_issue = inc.get('summary', {}).get('primary_issue')
        if not primary_issue or primary_issue == 'unknown':
            primary_issue = root.get('normalized_subtype') or root.get('subtype')
        if not primary_issue or primary_issue == 'raw':
            primary_issue = inc.get('incident_type') or inc.get('classification', 'unclassified')
        lines.append(
            "- "
            f"{inc.get('incident_id', 'N/A')}: events={inc.get('event_count', len(inc.get('events', [])))}, "
            f"duration={inc.get('duration_sec', 0)}s, "
            f"primary_issue={primary_issue}"
        )

    lines.extend([
        "",
        "## Detailed Incident Chains",
    ])
    
    for inc in report_incidents:
        iid = inc.get('incident_id', 'N/A')
        duration = inc.get('duration_sec', 0)
        events = inc.get('events', [])
        failures = [e for e in events if not e.get('is_recovery')]
        recoveries = [e for e in events if e.get('is_recovery')]
        
        if not failures and not recoveries: continue
            
        lines.append(f"### {iid}")
        
        if failures:
            lines.append("**Failure Sequence:**")
            for e in failures:
                sub = e.get('normalized_subtype', e.get('subtype', 'unknown'))
                lines.append(f"- {sub} ({e.get('severity', 'info')})")
        
        if recoveries:
            lines.append("")
            lines.append("**Recovery Sequence:**")
            for e in recoveries:
                sub = e.get('normalized_subtype', e.get('subtype', 'unknown'))
                lines.append(f"- {sub} ({e.get('severity', 'info')})")
        
        status = inc.get('status', '')
        if status:
            lines.append(f"\n*Status: {status}*")
        lines.append(f"*Duration: {duration}s*\n")
        
    if workflow_incidents:
        lines.extend([
            "## Operational Workflows Detected",
            ""
        ])
        for inc in workflow_incidents:
            iid = inc.get('incident_id', 'N/A')
            events = inc.get('events', [])
            
            # Collapse repeated adjacent events for cleaner summary
            collapsed_events = []
            for e in events:
                sub = e.get('normalized_subtype', e.get('subtype', 'unknown'))
                sev = e.get('severity', 'info')
                evt_str = f"{sub} ({sev})"
                if collapsed_events and collapsed_events[-1]['str'] == evt_str:
                    collapsed_events[-1]['count'] += 1
                else:
                    collapsed_events.append({'str': evt_str, 'count': 1})
            
            lines.append(f"### Workflow: {iid}")
            lines.append("- **Status:** Successful")
            lines.append("- **Incident Detected:** No")
            lines.append("- **Sequence Summary:**")
            for item in collapsed_events:
                count_str = f" x{item['count']}" if item['count'] > 1 else ""
                lines.append(f"  - {item['str']}{count_str}")
            lines.append("")

    alert_incidents = causal_summary.get("alert_incidents", [])
    if alert_incidents:
        lines.extend([
            "## Standalone Alerts",
            "The following high-severity events were detected but do not appear to be part of a larger cascading incident:",
            ""
        ])
        for inc in alert_incidents:
            for e in inc.get('events', []):
                sub = e.get('normalized_subtype', e.get('subtype', 'unknown'))
                lines.append(f"- {e.get('device', 'unknown')}: {sub} ({e.get('severity', 'info')}) - {e.get('message', '')}")
        lines.append("")

    noise_incidents = causal_summary.get("noise_incidents", [])
    if noise_incidents:
        lines.extend([
            "## Routine & Unlinked Noise",
            "The following events were classified as non-actionable noise or routine informational activity:",
            ""
        ])
        for inc in noise_incidents:
            for e in inc.get('events', []):
                sub = e.get('normalized_subtype', e.get('subtype', 'unknown'))
                lines.append(f"- {e.get('device', 'unknown')}: {sub} ({e.get('severity', 'info')}) - {e.get('message', '')}")
        lines.append("")
        
    lines.extend([
        "## Confidence and Limitations",
        "- Causality is inferred from temporal and contextual heuristics, not strict proof.",
        "- Confidence increases when links have strong timing, device/interface alignment, and severity progression.",
        "",
        "## Recommendations",
        "- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.",
        "- Add monitoring alerts for repeated trigger subtypes and interface recurrence.",
        "- Validate inferred root causes with device-level diagnostics and config audit.",
    ])

    output_path.write_text("\n".join(lines), encoding="utf-8")


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
