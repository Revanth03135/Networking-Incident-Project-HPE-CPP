import json
import statistics
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional
import argparse
import sys
import os


# =========================================================
# NORMALIZE SUBTYPE
# =========================================================

def _norm(subtype: str) -> str:
    return " ".join(subtype.lower().strip().split())


# =========================================================
# DATASET-ALIGNED CAUSAL MAP
# =========================================================

CAUSAL_MAP = {

    "arp": [
        "spanning_tree",
        "interface",
        "security",
        "stability"
    ],

    "spanning_tree": [
        "interface",
        "bgp"
    ],

    "interface": [
        "bgp",
        "security",
        "system"
    ],

    "bgp": [
        "bgp",
        "interface"
    ],

    "security": [
        "system"
    ],

    "stability": [
        "security",
        "interface"
    ],

    "system": [
        "interface"
    ]
}


# =========================================================
# STEP 1 — LOAD DATA
# =========================================================

def load_data(filepath):

    with open(filepath, "r", encoding="utf-8-sig") as f:
        raw = json.load(f)

    print(f"[LOAD]      ✔ {len(raw)} raw events loaded from '{filepath}'")

    return raw


# =========================================================
# STEP 2 — FLATTEN EVENTS
# =========================================================

def flatten_events(raw):

    events = []

    for item in raw:

        ev = item.get("event", {})
        dev = item.get("device", {})
        net = item.get("network", {})
        ts = item.get("timestamps", {})

        events.append({

            "id": ev.get("event_uid", "unknown"),

            "subtype": ev.get("subtype", "unknown"),

            "severity": ev.get("severity", "info"),

            "message": ev.get("message", ""),

            "device": dev.get("hostname", "unknown"),

            "device_ip": dev.get("ip_address"),

            "interface": net.get("interface_id"),

            "protocol": net.get("protocol"),

            "event_time": ts.get("event_time"),

            "ingestion_time": ts.get("ingestion_time")
        })

    print(f"[FLATTEN]   ✔ {len(events)} events flattened")

    return events


# =========================================================
# STEP 3 — NORMALIZE TIMESTAMPS
# =========================================================

def normalize_timestamps(events):

    valid = []
    dropped = []

    for e in events:

        try:

            e["event_time"] = datetime.fromisoformat(
                e["event_time"].replace("Z", "+00:00")
            )

            e["ingestion_time"] = datetime.fromisoformat(
                e["ingestion_time"].replace("Z", "+00:00")
            )

            # Normalize resolution (remove microseconds)
            e["event_time"] = e["event_time"].replace(microsecond=0)
            e["ingestion_time"] = e["ingestion_time"].replace(microsecond=0)

            valid.append(e)

        except Exception as err:

            e["_parse_error"] = str(err)
            dropped.append(e)

    print(
        f"[TIMESTAMPS] ✔ {len(valid)} valid | ✗ {len(dropped)} dropped"
    )

    return valid


# =========================================================
# STEP 4 — CLOCK SKEW CORRECTION
# =========================================================

def correct_clock_skew(events):

    device_skews = defaultdict(list)

    for e in events:

        skew = (
            e["ingestion_time"] - e["event_time"]
        ).total_seconds()

        e["raw_skew_sec"] = skew

        device_skews[e["device"]].append(skew)

    # median skew per device
    device_median_skew = {}

    for dev, skews in device_skews.items():

        med = statistics.median(skews)

        device_median_skew[dev] = med

        print(
            f"[SKEW]       Device '{dev}' → median skew: {med:+.2f}s"
        )

    # apply correction
    for e in events:

        correction = device_median_skew[e["device"]]

        e["corrected_time"] = (
            e["event_time"] + timedelta(seconds=correction)
        )

        e["skew_corrected"] = correction

    return events


# =========================================================
# STEP 5 — COMPUTE DYNAMIC WINDOW
# =========================================================

def compute_dynamic_window(events):

    sorted_events = sorted(
        events,
        key=lambda x: x["corrected_time"]
    )

    gaps = []

    for i in range(1, len(sorted_events)):

        gap = (
            sorted_events[i]["corrected_time"]
            - sorted_events[i - 1]["corrected_time"]
        ).total_seconds()

        if gap >= 0:
            gaps.append(gap)

    if len(gaps) < 2:

        window = 10

        print(
            f"[WINDOW]    ⚠ Too few gaps → default window = {window}s"
        )

        return window

    gaps.sort()

    n = len(gaps)

    q1 = gaps[n // 4]
    q3 = gaps[(3 * n) // 4]

    iqr = q3 - q1

    median_gap = gaps[n // 2]

    window = max(2.0, median_gap + 1.5 * iqr)

    print(
        f"[WINDOW]    ✔ median gap={median_gap:.2f}s | IQR={iqr:.2f}s"
    )

    print(
        f"[WINDOW]    ✔ Dynamic clustering window={window:.2f}s"
    )

    return window


# =========================================================
# STEP 6 — CLUSTER EVENTS
# =========================================================

def cluster_events(events, window_sec):

    sorted_events = sorted(
        events,
        key=lambda x: x["corrected_time"]
    )

    clusters = []

    current = [sorted_events[0]]

    for i in range(1, len(sorted_events)):

        gap = (
            sorted_events[i]["corrected_time"]
            - sorted_events[i - 1]["corrected_time"]
        ).total_seconds()

        if gap <= window_sec:

            current.append(sorted_events[i])

        else:

            clusters.append(current)

            current = [sorted_events[i]]

    clusters.append(current)

    print(
        f"[CLUSTER]   ✔ {len(clusters)} clusters formed"
    )

    return clusters


# =========================================================
# STEP 7 — DEDUPLICATION
# =========================================================

def deduplicate_cluster(cluster):

    seen = {}

    for e in cluster:

        key = (
            e["subtype"],
            e["device"],
            e["interface"]
        )

        if key in seen:

            existing = seen[key]

            existing["duplicate_count"] += 1

        else:

            e["duplicate_count"] = 1

            seen[key] = e

    return list(seen.values())


# =========================================================
# STEP 8 — CAUSAL RECONSTRUCTION
# =========================================================

def reconstruct_causal_chain(events):

    chains = []

    sorted_ev = sorted(
        events,
        key=lambda x: x["corrected_time"]
    )

    for i, cause_event in enumerate(sorted_ev):

        cause = _norm(cause_event["subtype"])

        possible_effects = CAUSAL_MAP.get(cause, [])

        for j in range(i + 1, len(sorted_ev)):

            effect_event = sorted_ev[j]

            effect = _norm(effect_event["subtype"])

            if effect in possible_effects:

                lag = (
                    effect_event["corrected_time"]
                    - cause_event["corrected_time"]
                ).total_seconds()

                same_device = (
                    cause_event["device"]
                    == effect_event["device"]
                )

                confidence = 0.9 if same_device else 0.6

                chains.append({

                    "cause_id": cause_event["id"],

                    "cause_subtype": cause_event["subtype"],

                    "cause_device": cause_event["device"],

                    "effect_id": effect_event["id"],

                    "effect_subtype": effect_event["subtype"],

                    "effect_device": effect_event["device"],

                    "lag_sec": round(lag, 2),

                    "confidence": confidence
                })

    return chains


# =========================================================
# STEP 9 — ROOT CAUSE
# =========================================================

def find_root_cause(events, chains):

    score = defaultdict(float)

    for link in chains:

        score[link["cause_id"]] += link["confidence"]

    if not score:

        return min(
            events,
            key=lambda x: x["corrected_time"]
        )

    top = max(score, key=score.get)

    for e in events:

        if e["id"] == top:
            return e

    return None


# =========================================================
# STEP 10 — BUILD INCIDENTS
# =========================================================

def build_incidents(clusters):

    incidents = []

    for idx, cluster in enumerate(clusters):

        deduped = deduplicate_cluster(cluster)

        chains = reconstruct_causal_chain(deduped)

        root = find_root_cause(deduped, chains)

        devices = list({
            e["device"]
            for e in deduped
        })

        start = min(
            e["corrected_time"]
            for e in deduped
        )

        end = max(
            e["corrected_time"]
            for e in deduped
        )

        duration = (
            end - start
        ).total_seconds()

        incident = {

            "incident_id": f"INC-{idx+1:04d}",

            "start_time": start,

            "end_time": end,

            "duration_sec": duration,

            "devices": devices,

            "events": sorted(
                deduped,
                key=lambda x: x["corrected_time"]
            ),

            "root_cause": root,

            "causal_chains": chains
        }

        incidents.append(incident)

        print(
            f"[INCIDENT]  {incident['incident_id']} | "
            f"{len(deduped)} events | "
            f"{len(chains)} causal links"
        )

    return incidents


# =========================================================
# STEP 11 — FINAL TIMELINE OUTPUT
# =========================================================

def print_timeline(incidents):

    print("\n" + "=" * 70)
    print("FINAL INCIDENT TIMELINE")
    print("=" * 70)

    for incident in incidents:

        print(f"\n🚨 {incident['incident_id']}")
        print("-" * 70)

        print(f"Start Time : {incident['start_time']}")
        print(f"End Time   : {incident['end_time']}")
        print(f"Duration   : {incident['duration_sec']} sec")

        print(
            f"Devices    : {', '.join(incident['devices'])}"
        )

        root = incident["root_cause"]

        if root:

            print("\n🔥 Root Cause:")

            print(
                f"   {root['subtype']} @ {root['device']}"
            )

        print("\n📌 Events Timeline:")

        for e in incident["events"]:

            dup = ""

            if e.get("duplicate_count", 1) > 1:

                dup = f" (x{e['duplicate_count']})"

            print(

                f"   [{e['corrected_time']}] "

                f"{e['device']} | "

                f"{e['subtype']} | "

                f"{e['message']}{dup}"
            )

        print("\n🔗 Causal Relationships:")

        if incident["causal_chains"]:

            for c in incident["causal_chains"]:

                print(

                    f"   {c['cause_subtype']} "

                    f"→ {c['effect_subtype']} "

                    f"(lag={c['lag_sec']}s, conf={c['confidence']})"
                )

        else:

            print("   No causal relationships found.")


# =========================================================
# SERIALIZATION
# =========================================================

def json_serializable(obj):

    if isinstance(obj, datetime):

        return obj.isoformat()

    raise TypeError


# =========================================================
# MAIN PIPELINE
# =========================================================

def run_pipeline(input_path, output_path="timeline_output.json"):

    print("\n" + "═" * 60)
    print(" HPE INCIDENT TIMELINE RECONSTRUCTION ENGINE ")
    print("═" * 60)

    raw = load_data(input_path)

    flat = flatten_events(raw)

    norm = normalize_timestamps(flat)

    corrected = correct_clock_skew(norm)

    window = compute_dynamic_window(corrected)

    clusters = cluster_events(corrected, window)

    print("\n[BUILD]     Building incidents...")

    incidents = build_incidents(clusters)

    print_timeline(incidents)

    # save json
    serializable = json.loads(
        json.dumps(
            incidents,
            default=json_serializable
        )
    )

    with open(output_path, "w", encoding="utf-8") as f:

        json.dump(serializable, f, indent=2)

    print(
        f"\n[OUTPUT]    ✔ Timeline written to '{output_path}'"
    )

    print("═" * 60)

    return serializable


# =========================================================
# CLI
# =========================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "input",
        help="Input JSON dataset"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="timeline_output.json"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input):

        print(f"[ERROR] File not found: {args.input}")

        sys.exit(1)

    run_pipeline(args.input, args.output)