"""
preprocessing.py — Shared preprocessing utilities.

Used by both timeline_reconstruction.py and causalInference.py.
Contains every step that was duplicated across those two files:
  - Event flattening
  - Timestamp normalisation
  - Clock-skew correction
  - Dynamic time-window calculation
"""

import json
import statistics
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


# =========================================================
# STRING NORMALISATION
# =========================================================

def normalize_string(s: str) -> str:
    """Lowercase, strip and collapse whitespace."""
    if not s:
        return ""
    return " ".join(s.lower().strip().split())


# =========================================================
# LOAD RAW DATA
# =========================================================

def load_data(filepath: str) -> List[Dict]:
    with open(filepath, "r", encoding="utf-8-sig") as f:
        raw = json.load(f)
    print(f"[LOAD]       OK {len(raw)} raw events loaded from '{filepath}'")
    return raw


# =========================================================
# FLATTEN EVENTS
# Unified superset schema (covers all fields from both files)
# =========================================================

def flatten_event(raw_event: Dict) -> Optional[Dict]:
    """
    Flatten one nested HPE event record into a flat dict.

    Source structure:
        { "event": {...}, "device": {...}, "network": {...},
          "timestamps": {...}, "raw": {...} }
    """
    try:
        ev  = raw_event.get("event",      {})
        dev = raw_event.get("device",     {})
        net = raw_event.get("network",    {})
        ts  = raw_event.get("timestamps", {})
        raw = raw_event.get("raw",        {})

        return {
            # event fields
            "event_uid":      ev.get("event_uid",  "unknown"),
            "event_id":       ev.get("event_id",   "unknown"),
            "type":           ev.get("type",        "unknown"),
            "subtype":        normalize_string(ev.get("subtype", "unknown")),
            "severity":       ev.get("severity",   "info").lower(),
            "message":        ev.get("message",    ""),
            # device fields
            "device":         dev.get("hostname",  "unknown"),
            "device_ip":      dev.get("ip",        dev.get("ip_address", "unknown")),
            "vendor":         dev.get("vendor",    "unknown"),
            "os":             dev.get("os",        "unknown"),
            # network fields
            "interface_id":   net.get("interface_id"),
            "vlan":           net.get("vlan"),
            "protocol":       net.get("protocol"),
            # timestamps (raw strings — parsed later)
            "event_time":     ts.get("event_time",     ""),
            "ingestion_time": ts.get("ingestion_time", ""),
            # raw log
            "raw_message":    raw.get("message", ""),
        }

    except Exception:
        return None


def flatten_events(raw: List[Dict]) -> List[Dict]:
    """Flatten a list of raw records, silently dropping any that fail."""
    events = [flatten_event(item) for item in raw]
    events = [e for e in events if e is not None]
    print(f"[FLATTEN]    OK {len(events)} events flattened")
    return events


# =========================================================
# TIMESTAMP NORMALISATION
# =========================================================

def normalize_timestamps(
    events: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:
    """
    Parse ISO-8601 timestamps in-place and strip microseconds.

    Returns:
        (valid_events, dropped_events)
    """
    valid   = []
    dropped = []

    for e in events:
        try:
            e["event_time"] = datetime.fromisoformat(
                e["event_time"].replace("Z", "+00:00")
            ).replace(microsecond=0)

            e["ingestion_time"] = datetime.fromisoformat(
                e["ingestion_time"].replace("Z", "+00:00")
            ).replace(microsecond=0)

            valid.append(e)

        except Exception as err:
            e["_parse_error"] = str(err)
            dropped.append(e)

    print(f"[TIMESTAMPS] OK {len(valid)} valid | XX {len(dropped)} dropped")
    return valid, dropped


# =========================================================
# CLOCK-SKEW CORRECTION
# =========================================================

def correct_clock_skew(events: List[Dict]) -> Dict[str, float]:
    """
    Compute per-device median skew (ingestion − event) and apply it in-place
    as a new field ``corrected_time``.

    Returns a dict of {device: median_skew_sec} for reference.
    """
    device_skews: Dict[str, List[float]] = defaultdict(list)

    for e in events:
        skew = (e["ingestion_time"] - e["event_time"]).total_seconds()
        e["raw_skew_sec"] = skew
        device_skews[e["device"]].append(skew)

    corrections: Dict[str, float] = {}

    for dev, skews in device_skews.items():
        med = statistics.median(skews)
        corrections[dev] = med
        print(f"[SKEW]       Device '{dev}' -> median skew: {med:+.2f}s")

    for e in events:
        correction = corrections[e["device"]]
        e["corrected_time"] = e["event_time"] + timedelta(seconds=correction)
        e["skew_corrected"]  = correction

    return corrections


# =========================================================
# DYNAMIC TIME-WINDOW
# =========================================================

def compute_dynamic_window(events: List[Dict]) -> float:
    """
    IQR-based dynamic clustering window.
    window = max(2.0, median_gap + 1.5 × IQR)
    """
    sorted_events = sorted(
        events,
        key=lambda x: x.get("corrected_time") or x.get("event_time"),
    )

    if len(sorted_events) < 2:
        print("[WINDOW]     WARN Too few events -> default window = 10s")
        return 10.0

    gaps = []
    for i in range(1, len(sorted_events)):
        t1  = sorted_events[i - 1].get("corrected_time") or sorted_events[i - 1].get("event_time")
        t2  = sorted_events[i    ].get("corrected_time") or sorted_events[i    ].get("event_time")
        gap = (t2 - t1).total_seconds()
        if gap >= 0:
            gaps.append(gap)

    if len(gaps) < 2:
        print("[WINDOW]     WARN Too few gaps -> default window = 10s")
        return 10.0

    gaps.sort()
    n          = len(gaps)
    q1         = gaps[n // 4]
    q3         = gaps[(3 * n) // 4]
    iqr        = q3 - q1
    median_gap = gaps[n // 2]
    window     = max(2.0, median_gap + 1.5 * iqr)

    print(f"[WINDOW]     OK median gap={median_gap:.2f}s | IQR={iqr:.2f}s")
    print(f"[WINDOW]     OK Dynamic clustering window={window:.2f}s")

    return window


# =========================================================
# JSON SERIALIZATION
# =========================================================

def json_serializable(obj):
    """Convert datetime objects to ISO format for JSON."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


# =========================================================
# MAIN PIPELINE & CLI
# =========================================================

def run_preprocessing_pipeline(
    input_path: str,
    output_path: str = "preprocessed_events.json"
) -> List[Dict]:
    """
    Full preprocessing pipeline:
    1. Load raw events
    2. Flatten events
    3. Normalize timestamps
    4. Correct clock skew
    5. Compute dynamic window
    6. Save to JSON
    
    Returns: Preprocessed events list
    """
    print("\n" + "═" * 60)
    print(" HPE PREPROCESSING PIPELINE ")
    print("═" * 60)

    # Step 1: Load
    raw = load_data(input_path)

    # Step 2: Flatten
    events = flatten_events(raw)

    if not events:
        print("[ERROR] No valid events after flattening")
        return []

    # Step 3: Normalize timestamps
    print("[TIMESTAMPS] Normalizing...")
    valid_events = []
    dropped = []
    for e in events:
        try:
            e["event_time"] = datetime.fromisoformat(
                e["event_time"].replace("Z", "+00:00")
            ).replace(microsecond=0)
            e["ingestion_time"] = datetime.fromisoformat(
                e["ingestion_time"].replace("Z", "+00:00")
            ).replace(microsecond=0)
            valid_events.append(e)
        except Exception as err:
            e["_parse_error"] = str(err)
            dropped.append(e)

    print(f"[TIMESTAMPS] ✔ {len(valid_events)} valid | ✗ {len(dropped)} dropped")

    # Step 4: Clock skew correction
    print("[SKEW]       Correcting clock skew...")
    correct_clock_skew(valid_events)

    # Step 5: Dynamic window
    print("[WINDOW]     Computing dynamic window...")
    window = compute_dynamic_window(valid_events)

    # Step 6: Save to JSON
    print(f"[OUTPUT]     Saving to '{output_path}'...")
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(valid_events, f, indent=2, default=json_serializable)
        print(f"[OUTPUT]     OK Successfully saved {len(valid_events)} events")
    except Exception as e:
        print(f"[ERROR]      Failed to save: {e}")
        return valid_events

    print("═" * 60)
    return valid_events


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="HPE Preprocessing Pipeline"
    )
    parser.add_argument(
        "input",
        nargs='?',
        help="Input JSON file path"
    )
    parser.add_argument(
        "-o", "--output",
        default="preprocessed_events.json",
        help="Output JSON file (default: preprocessed_events.json)"
    )

    args = parser.parse_args()

    # Prompt for input file if not provided
    input_file = args.input
    if not input_file:
        input_file = input("Enter input JSON file path (or filename): ").strip()
        if not input_file:
            print("[ERROR] Input file required")
            sys.exit(1)

    try:
        run_preprocessing_pipeline(input_file, args.output)
        print("\n✓ Preprocessing complete!")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)
