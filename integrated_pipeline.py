import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from causalInference.causalInference import analyze_cluster_detailed
from preprocessing import (
    json_serializable,
    restore_datetime_fields,
    run_preprocessing_pipeline,
)
from schema_conversion.log_processor import LogProcessor
from timeline_reconstruction import run_pipeline as run_timeline_pipeline


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
            # Provide a simple, regex-free fallback that converts each non-empty
            # line/paragraph in the input text into a minimal event record so the
            # rest of the CRT pipeline can run offline.
            print("[WARN] Schema conversion produced 0 records — using fallback extractor")
            fallback = []
            try:
                # Attempt to use dateutil for fuzzy timestamp parsing if available
                try:
                    from dateutil import parser as date_parser  # type: ignore
                except Exception:
                    date_parser = None

                text = input_path.read_text(encoding="utf-8")
                # Split on blank lines to preserve multi-line log entries, fallback to lines
                chunks = [c.strip() for c in text.split("\n\n") if c.strip()]
                if not chunks:
                    chunks = [l.strip() for l in text.splitlines() if l.strip()]

                now_iso = datetime.now(timezone.utc).isoformat()

                for i, chunk in enumerate(chunks):
                    # Try to extract a timestamp from the chunk
                    event_time = None
                    if date_parser:
                        try:
                            parsed = date_parser.parse(chunk, fuzzy=True)
                            # ensure timezone-aware ISO format
                            if parsed.tzinfo is None:
                                parsed = parsed.replace(tzinfo=timezone.utc)
                            event_time = parsed.isoformat()
                        except Exception:
                            event_time = None

                    if not event_time:
                        event_time = now_iso

                    raw_event = {
                        "event": {
                            "event_uid": f"fallback-{i+1}",
                            "event_id": f"fallback-{i+1}",
                            "type": "log",
                            "subtype": "raw",
                            "severity": "info",
                            "message": chunk,
                        },
                        "device": {"hostname": "unknown"},
                        "network": {},
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
    total_links = causal_summary.get("num_causal_links", 0)
    roots = causal_summary.get("root_causes", [])
    devices = causal_summary.get("affected_devices", [])

    lines = [
        "# Network Incident Investigation Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Executive Summary",
        f"- Total incidents reconstructed: {len(timeline_incidents)}",
        f"- Total events analyzed: {total_events}",
        f"- Total causal links inferred: {total_links}",
        f"- Affected devices: {', '.join(devices) if devices else 'N/A'}",
        "",
        "## Probable Initiating Triggers",
    ]

    if roots:
        for root in roots:
            lines.append(f"- {root}")
    else:
        lines.append("- No high-confidence root trigger was detected")

    lines.extend([
        "",
        "## Incident Overview",
    ])

    for inc in timeline_incidents:
        root = inc.get("root_cause") or {}
        lines.append(
            "- "
            f"{inc.get('incident_id', 'N/A')}: events={len(inc.get('events', []))}, "
            f"duration={inc.get('duration_sec', 0)}s, "
            f"primary_issue={inc.get('summary', {}).get('primary_issue', root.get('subtype', 'unknown'))}"
        )

    lines.extend([
        "",
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
    incident_analyses = []
    all_links = []
    all_flows = []
    all_roots = []
    affected_devices = set()

    for incident in timeline_incidents:
        events = restore_datetime_fields(incident.get("events", []))
        links, root_event, flows = analyze_cluster_detailed(events, threshold=1.0)

        all_links.extend(links)
        all_flows.extend(flows)
        if root_event:
            all_roots.append(root_event.get("event_uid"))

        for event in events:
            device = event.get("device")
            if device:
                affected_devices.add(device)

        incident_analyses.append(
            {
                "incident_id": incident.get("incident_id"),
                "root_cause": root_event,
                "causal_links": links,
                "incident_flows": flows,
            }
        )

    result = {
        "num_incidents": len(timeline_incidents),
        "num_events": sum(len(inc.get("events", [])) for inc in timeline_incidents),
        "num_causal_links": len(all_links),
        "num_flows": len(all_flows),
        "root_causes": all_roots,
        "affected_devices": sorted(affected_devices),
        "causal_links": all_links,
        "incident_flows": all_flows,
        "incident_analyses": incident_analyses,
    }

    return json.loads(json.dumps(result, default=json_serializable))


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

    # Stage 3: Preprocessed events -> timeline reconstruction
    timeline_data = run_timeline_pipeline(str(preprocessed_path), str(timeline_path))

    # Causal inference is intentionally run from timeline output so flow is:
    # schema conversion -> preprocessing -> timeline reconstruction -> causal inference.
    # Stage 4: Timeline output -> causal inference with incident flows
    causal_summary = run_causal_from_timeline(timeline_data)
    save_json(causal_path, causal_summary)

    # Stage 5: Report and visualization generation
    if not maybe_generate_llm_report(timeline_path, causal_path, report_path, use_llm_report):
        generate_fallback_report(timeline_data, causal_summary, report_path)

    generate_visualization_html(timeline_data, visual_path)

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
        "visualization": str(visual_path),
        "incidents": len(timeline_data),
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
