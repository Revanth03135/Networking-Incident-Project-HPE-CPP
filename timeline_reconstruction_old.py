"""
timeline_reconstruction.py — HPE Incident Timeline Reconstruction Engine.

Responsibility: group events into incidents (clustering, deduplication,
incident metadata, timeline output).

Preprocessing (flatten / timestamps / skew / window) is handled by
preprocessing.py and imported here.

Causal analysis (graph building, scoring, root-cause detection, chain
extraction) is handled by causalInference.py.  build_incidents() calls
causalInference.analyze_cluster() for each deduped cluster instead of
maintaining its own CAUSAL_MAP and chain logic.
"""

import json
import statistics
import argparse
import sys
import os
from typing import Dict, List, Optional

# ── shared preprocessing ──────────────────────────────────────────────────────
from preprocessing import (
    load_data,
    flatten_events,
    normalize_timestamps,
    correct_clock_skew,
    compute_dynamic_window,
    json_serializable,
    restore_datetime_fields,
)

# ── CRT generation (LLM-based, lives in crt_generation.py) ──────────────────
from crt_generation import generate_crt_with_groq, get_last_crt_source, parse_crt_response



# =========================================================
# STEP 1 — CLUSTER EVENTS
# =========================================================

def cluster_events(events: List[Dict], window_sec: float) -> List[List[Dict]]:

    if not events:
        return []

    sorted_events = sorted(
        events,
        key=lambda x: x["corrected_time"],
    )

    clusters = []
    current  = [sorted_events[0]]

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

    print(f"[CLUSTER]    ✔ {len(clusters)} clusters formed")
    return clusters


# =========================================================
# STEP 2 — DEDUPLICATION
# =========================================================

def deduplicate_cluster(cluster: List[Dict]) -> List[Dict]:

    seen: Dict = {}

    for e in cluster:

        key = (e["subtype"], e["device"], e["interface_id"])

        if key in seen:
            seen[key]["duplicate_count"] += 1
        else:
            e["duplicate_count"] = 1
            seen[key] = e

    return list(seen.values())


# =========================================================
# STEP 3 — CONFIDENCE HELPERS
# (operate on the causal_links list returned by analyze_cluster)
# =========================================================

def compute_root_confidence(
    root:   Optional[Dict],
    chains: List[Dict],
) -> float:

    if not root or not chains:
        return 0.5

    outgoing = [
        c["confidence"]
        for c in chains
        if c["cause_id"] == root["event_uid"]
    ]

    if not outgoing:
        return 0.5

    return round(statistics.mean(outgoing), 2)


def compute_incident_confidence(
    events: List[Dict],
    chains: List[Dict],
) -> float:

    if not chains:
        return 0.45

    avg_chain_conf = statistics.mean(c["confidence"] for c in chains)

    duplicate_factor = min(
        1.0,
        sum(e.get("duplicate_count", 1) for e in events) / len(events),
    )

    confidence = 0.75 * avg_chain_conf + 0.25 * duplicate_factor

    return round(min(confidence, 1.0), 2)


def build_incident_summary(
    events: List[Dict],
    root:   Optional[Dict],
    related_event_ids: Optional[List] = None,
    unrelated_event_ids: Optional[List] = None,
) -> Dict:

    protocols = list({
        e["protocol"]
        for e in events
        if e.get("protocol")
    })

    return {
        "primary_issue":      root["subtype"] if root else "unknown",
        "affected_devices":   list({e["device"] for e in events}),
        "event_count":        len(events),
        "protocols":          protocols,
        "highest_severity":   max(e["severity"] for e in events),
        "related_event_ids":  related_event_ids or [],
        "unrelated_event_ids": unrelated_event_ids or [],
    }


# =========================================================
# STEP 4 — BUILD INCIDENTS
# Causal analysis is fully delegated to causalInference.analyze_cluster()
# =========================================================

def build_incidents(clusters: List[List[Dict]]) -> List[Dict]:

    incidents = []

    for idx, cluster in enumerate(clusters):

        deduped = deduplicate_cluster(cluster)
        incident_id = f"INC-{idx + 1:04d}"
        devices  = list({e["device"] for e in deduped})
        start    = min(e["corrected_time"] for e in deduped)
        end      = max(e["corrected_time"] for e in deduped)
        duration = (end - start).total_seconds()

        # ── CRT generation: LLM-based causal reasoning ──
        crt_result = generate_crt_with_groq(incident_id, deduped, start, end)
        crt_data = parse_crt_response(crt_result) if crt_result else None

        # Extract root cause and causal structure from CRT
        if crt_data:
            root_event_id = crt_data.get("root_cause_event_id")
            root = next(
                (e for e in deduped 
                 if str(e.get("event_uid") or e.get("event_id")) == str(root_event_id)),
                None
            )
            
            # Build causal_links from CRT causal_sequence
            causal_links = []
            causal_sequence = crt_data.get("causal_sequence", [])
            
            for step_idx, step in enumerate(causal_sequence):
                # Create links for direct consequences
                if step.get("role") == "direct_consequence":
                    # Find the previous root_cause in sequence
                    for prev_step in causal_sequence[:step_idx]:
                        if prev_step.get("role") == "root_cause":
                            causal_links.append({
                                "cause_id": prev_step.get("event_id"),
                                "effect_id": step.get("event_id"),
                                "confidence": 0.9  # High confidence from LLM
                            })
                            break
                elif step.get("role") == "indirect_consequence":
                    # Create link to previous consequence
                    for prev_step in reversed(causal_sequence[:step_idx]):
                        if prev_step.get("role") in ["root_cause", "direct_consequence"]:
                            causal_links.append({
                                "cause_id": prev_step.get("event_id"),
                                "effect_id": step.get("event_id"),
                                "confidence": 0.7  # Medium confidence for indirect
                            })
                            break
            
            incident_flows = []
            if causal_sequence:
                flow_path = [step.get("event_id") for step in causal_sequence 
                            if step.get("role") in ["root_cause", "direct_consequence", "indirect_consequence"]]
                if flow_path:
                    incident_flows = [flow_path]
            
            # Mark events by their role in CRT
            for event in deduped:
                event_id = str(event.get("event_uid") or event.get("event_id"))  # Convert to string
                event_step = next(
                    (s for s in causal_sequence if str(s.get("event_id")) == event_id),
                    None
                )
                if event_step:
                    role = event_step.get("role")
                    if role == "root_cause":
                        event["relation_label"] = "root"
                    elif role in ["direct_consequence", "indirect_consequence"]:
                        event["relation_label"] = "related"
                    else:
                        event["relation_label"] = "unrelated"
                else:
                    event["relation_label"] = "unrelated"
            
            root_confidence = {
                "high": 0.9,
                "medium": 0.6,
                "low": 0.3
            }.get(crt_data.get("root_cause_confidence", "medium"), 0.6)
        else:
            # Fallback when CRT fails
            root = None
            causal_links = []
            incident_flows = []
            causal_sequence = []
            root_confidence = 0.0
            
            for event in deduped:
                event["relation_label"] = "unknown"

        incident_confidence = compute_incident_confidence(deduped, causal_links)

        connected_ids = set()
        for link in causal_links:
            connected_ids.add(link.get("cause_id"))
            connected_ids.add(link.get("effect_id"))

        if root and root.get("event_uid") is not None:
            connected_ids.add(root.get("event_uid"))

        all_ids = [e.get("event_uid") for e in deduped if e.get("event_uid") is not None]
        related_ids = [eid for eid in all_ids if eid in connected_ids]
        unrelated_ids = [eid for eid in all_ids if eid not in connected_ids]

        summary = build_incident_summary(
            deduped,
            root,
            related_event_ids=related_ids,
            unrelated_event_ids=unrelated_ids,
        )

        incident = {
            "incident_id":   incident_id,
            "start_time":    start,
            "end_time":      end,
            "duration_sec":  duration,
            "devices":       devices,

            # ── enterprise metadata ──────────────────────────────
            "incident_confidence":  incident_confidence,
            "root_cause_confidence": root_confidence,
            "summary":              summary,
            "llm_guidance": {
                "causal_certainty":      get_last_crt_source(),
                "crt_source":            get_last_crt_source(),
                "recommended_language":  "probabilistic",
            },
            # ────────────────────────────────────────────────────

            "events": sorted(deduped, key=lambda x: x["corrected_time"]),
            "root_cause":    root,
            "causal_chains": causal_links,
            "incident_flows": incident_flows,
            "causal_sequence": causal_sequence,  # NEW: LLM-ordered sequence
        }
        
        # Add CRT metadata if available
        if crt_data:
            incident["crt_incident_summary"] = crt_data.get("incident_summary", "")
            incident["crt_recommendations"] = crt_data.get("recommendations", [])
            incident["crt_notes"] = crt_data.get("notes", "")

        incidents.append(incident)

        print(
            f"[INCIDENT]   {incident['incident_id']} | "
            f"{len(deduped)} events | "
            f"{len(causal_links)} causal links | "
            f"conf={incident_confidence} | "
            f"crt={get_last_crt_source()}"
        )

    return incidents


# =========================================================
# STEP 5 — PRINT TIMELINE
# =========================================================

def print_timeline(incidents: List[Dict]) -> None:

    print("\n" + "=" * 70)
    print("FINAL INCIDENT TIMELINE")
    print("=" * 70)

    for incident in incidents:

        print(f"\n🚨 {incident['incident_id']}")
        print("-" * 70)
        print(f"Start Time : {incident['start_time']}")
        print(f"End Time   : {incident['end_time']}")
        print(f"Duration   : {incident['duration_sec']} sec")
        # Filter out None values from devices list
        devices = [d if d else "Unknown" for d in incident['devices']]
        print(f"Devices    : {', '.join(devices)}")

        root = incident["root_cause"]

        if root:
            print("\n🔥 Root Cause:")
            print(f"   {root['subtype']} @ {root['device']}")

        print("\n📌 Events Timeline:")

        for e in incident["events"]:

            dup = (
                f" (x{e['duplicate_count']})"
                if e.get("duplicate_count", 1) > 1
                else ""
            )

            print(
                f"   [{e['corrected_time']}] "
                f"{e['device']} | "
                f"{e['subtype']} | "
                f"{e['message']}"
                f" [{e.get('relation_label', 'related')}]"
                f"{dup}"
            )

        related_ids = incident.get("summary", {}).get("related_event_ids", [])
        unrelated_ids = incident.get("summary", {}).get("unrelated_event_ids", [])
        if unrelated_ids:
            print("\n🧩 Within-window noise candidates:")
            print(f"   Related IDs  : {related_ids}")
            print(f"   Unrelated IDs: {unrelated_ids}")

        print("\n🔗 Causal Relationships:")

        if incident["causal_chains"]:
            for c in incident["causal_chains"]:
                # Get cause and effect event details
                cause_id = c.get("cause_id")
                effect_id = c.get("effect_id")
                
                cause_event = next(
                    (e for e in incident["events"] 
                     if e.get("event_uid") == cause_id or e.get("event_id") == cause_id),
                    None
                )
                effect_event = next(
                    (e for e in incident["events"] 
                     if e.get("event_uid") == effect_id or e.get("event_id") == effect_id),
                    None
                )
                
                if cause_event and effect_event:
                    cause_subtype = cause_event.get("subtype", "unknown")
                    effect_subtype = effect_event.get("subtype", "unknown")
                    confidence = c.get("confidence", 0.0)
                    print(f"   {cause_subtype} → {effect_subtype} (conf={confidence})")
        else:
            print("   No causal relationships found.")

        print("\n🧭 Incident Flow:")
        if incident.get("incident_flows"):
            primary_flow = incident["incident_flows"][0]
            # incident_flows now contains lists of event_ids
            if isinstance(primary_flow, list):
                flow_events = []
                for event_id in primary_flow:
                    event = next(
                        (e for e in incident["events"] 
                         if e.get("event_uid") == event_id or e.get("event_id") == event_id),
                        None
                    )
                    if event:
                        flow_events.append(f"{event.get('subtype', 'unknown')}@{event.get('device', 'unknown')}")
                if flow_events:
                    print(f"   {' -> '.join(flow_events)}")
                else:
                    print("   No coherent flow extracted.")
            else:
                print("   No coherent flow extracted.")
        else:
            print("   No coherent flow extracted.")


# =========================================================
# MAIN PIPELINE
# =========================================================


def run_pipeline(
    input_path:  str,
    output_path: str = "timeline_output.json",
):
    print("\n" + "═" * 60)
    print(" HPE INCIDENT TIMELINE RECONSTRUCTION ENGINE ")
    print("═" * 60)

    # 1. Load
    raw = load_data(input_path)

    # Check if already preprocessed (has corrected_time field)
    is_preprocessed = raw and isinstance(raw[0], dict) and "corrected_time" in raw[0]

    if is_preprocessed:
        print("[LOAD]       Already preprocessed format detected")
        norm = restore_datetime_fields(raw)
    else:
        # 2. Flatten  (preprocessing.py)
        flat = flatten_events(raw)

        # 3. Timestamps  (preprocessing.py)
        norm, _ = normalize_timestamps(flat)

        # 4. Clock-skew  (preprocessing.py)
        correct_clock_skew(norm)

    # 5. Dynamic window  (preprocessing.py)
    window = compute_dynamic_window(norm)

    # 6. Cluster events
    clusters = cluster_events(norm, window)

    # 7. Build incidents  (causal analysis via causalInference.analyze_cluster)
    print("\n[BUILD]      Building incidents...")
    incidents = build_incidents(clusters)

    # 8. Print
    print_timeline(incidents)

    # 9. Save JSON
    serializable = json.loads(
        json.dumps(incidents, default=json_serializable)
    )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)

    print(f"\n[OUTPUT]     ✔ Timeline written to '{output_path}'")
    print("═" * 60)

    return serializable


# =========================================================
# CLI
# =========================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs='?', default="preprocessed_events.json", help="Input JSON dataset (default: preprocessed_events.json)")
    parser.add_argument("-o", "--output", default="timeline_output.json")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[ERROR] File not found: {args.input}")
        sys.exit(1)

    run_pipeline(args.input, args.output)