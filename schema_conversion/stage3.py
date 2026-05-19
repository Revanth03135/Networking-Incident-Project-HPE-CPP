"""
STAGE 3 — Pipeline Output Formatter
-------------------------------------

Takes merged results from Stage1 and Stage2
and formats them according to the final schema.

Input: stage2_output.json
Output: output.json (overwritten each run)

Schema:
-------
{
  "event": {
    "event_uid": 1,  // Sequential line/log number
    "event_id": null,
    "type": "routing|security|system|...",
    "subtype": "bgp|ospf|...",
    "severity": "info|warning|error|critical",
    "message": "full original log"
  },
  "device": {
    "hostname": "device name",
    "ip": "IP address",
    "vendor": "Cisco|HPE|Aruba|...",
    "os": "IOS|AOS-CX|..."
  },
  "network": {
    "interface_id": "interface identifier",
    "vlan": null
  },
  "timestamps": {
    "event_time": "ISO timestamp"
  },
  "raw": {
    "message": "original log text"
  }
}
"""

import json
import sys
import argparse
from typing import List, Dict
from pathlib import Path


# ============================================================
# PROJECT ROOT PATH
# ============================================================

def get_project_root():
    """
    Get the project root directory
    Works regardless of where script is run from
    """
    # Get the directory of the schema_conversion folder
    schema_conversion_dir = Path(__file__).parent
    # Project root is parent of schema_conversion
    project_root = schema_conversion_dir.parent
    return project_root


PROJECT_ROOT = get_project_root()


def format_event_record(stage_data: Dict, line_number: int) -> Dict:
    """
    Transform stage1+stage2 combined data into final schema
    
    Args:
        stage_data: Combined stage1 and stage2 data
        line_number: Sequential log/line number (1-indexed)
    
    Input: {
        "timestamp": "...",
        "hostname": "...",
        "ip": "...",
        "vendor": "...",
        "os": "...",
        "core_message": "...",
        "raw_log": "...",
        "semantic_analysis": {
            "type": "...",
            "subtype": "...",
            "severity": "...",
            "interface_id": "..."
        }
    }
    """
    
    raw_log = stage_data.get("raw_log", "")
    core_message = stage_data.get("core_message", "")
    timestamp = stage_data.get("timestamp")
    hostname = stage_data.get("hostname")
    ip = stage_data.get("ip")
    vendor = stage_data.get("vendor") or "unknown"
    os = stage_data.get("os")
    
    semantic = stage_data.get("semantic_analysis", {})
    event_type = semantic.get("type") or "generic"
    subtype = semantic.get("subtype")
    severity = semantic.get("severity") or "info"
    interface_id = semantic.get("interface_id")
    
    return {
        "event": {
            "event_uid": line_number,
            "event_id": None,
            "type": event_type,
            "subtype": subtype,
            "severity": severity,
            "message": core_message
        },
        "device": {
            "hostname": hostname,
            "ip": ip,
            "vendor": vendor,
            "os": os
        },
        "network": {
            "interface_id": interface_id,
            "vlan": None
        },
        "timestamps": {
            "event_time": timestamp
        },
        "raw": {
            "message": raw_log
        }
    }


def process_stage2_output(
    stage2_file: str,
    output_file: str = "output.json"
) -> List[Dict]:
    """
    Read stage2 output and format for final pipeline
    
    Args:
        stage2_file: Path to stage2_output.json
        output_file: Output file path (default: output.json)
    
    Returns:
        List of formatted event records
    """
    
    # Load stage2 output
    try:
        with open(stage2_file, "r", encoding="utf-8") as f:
            stage2_data = json.load(f)
    except Exception as e:
        print(f"[FAIL] Error reading stage2 output: {e}")
        return []
    
    if not isinstance(stage2_data, list):
        print("[FAIL] Stage2 output must be a list")
        return []
    
    formatted_records = []
    
    for idx, entry in enumerate(stage2_data):
        
        try:
            formatted = format_event_record(entry, idx + 1)
            formatted_records.append(formatted)
            
        except Exception as e:
            print(f"[FAIL] Error formatting record {idx + 1}: {e}")
            # Add error record
            formatted_records.append({
                "error": str(e),
                "raw_entry": entry
            })
    
    # Save to output file (overwrite)
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(formatted_records, f, indent=2, ensure_ascii=False)
        
        print(f"[OK] Formatted {len(formatted_records)} records")
        print(f"[OK] Saved to: {output_file}")
        
    except Exception as e:
        print(f"[FAIL] Error saving output: {e}")
        return []
    
    return formatted_records


def print_summary(records: List[Dict]):
    """Print summary statistics"""
    
    total = len(records)
    with_error = sum(1 for r in records if "error" in r)
    success = total - with_error
    
    # Count by type
    type_counts = {}
    severity_counts = {}
    
    for r in records:
        if "error" not in r:
            event_type = r.get("event", {}).get("type")
            severity = r.get("event", {}).get("severity")
            
            if event_type:
                type_counts[event_type] = type_counts.get(event_type, 0) + 1
            
            if severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\n{'='*70}")
    print("STAGE 3 SUMMARY")
    print(f"{'='*70}")
    print(f"Total records:           {total}")
    print(f"Successfully formatted:  {success}")
    print(f"Errors:                  {with_error}")
    print(f"\nEvent types:")
    for event_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {event_type}: {count}")
    print(f"\nSeverities:")
    for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {severity}: {count}")
    print(f"{'='*70}\n")


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        description="Stage 3 - Pipeline Output Formatter"
    )
    
    parser.add_argument(
        "--input",
        type=str,
        default=str(PROJECT_ROOT / "stage2_output.json"),
        help=f"Input file from stage2 (default: {PROJECT_ROOT / 'stage2_output.json'})"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default=str(PROJECT_ROOT / "output.json"),
        help=f"Output file (default: {PROJECT_ROOT / 'output.json'})"
    )
    
    args = parser.parse_args()
    
    print(f"\n{'='*70}")
    print("STAGE 3: PIPELINE OUTPUT FORMATTER")
    print(f"{'='*70}")
    print(f"Input:   {args.input}")
    print(f"Output:  {args.output}\n")
    
    if not Path(args.input).exists():
        print(f"[FAIL] Error: Input file not found: {args.input}")
        sys.exit(1)
    
    records = process_stage2_output(args.input, args.output)
    
    if records:
        print_summary(records)
    else:
        print("[FAIL] No records were processed")
        sys.exit(1)
