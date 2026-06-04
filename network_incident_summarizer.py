"""
Enterprise Network Incident Summarizer
=====================================

Production-Oriented Enterprise RCA Summarizer

Uses:
    - timeline_output.json
    - causal_inference_output.json

Reads:
    GEMINI_API_KEY from .env

Key Improvements:
-----------------
- Safer RCA semantics
- Hallucination-resistant prompting
- Trigger vs symptom separation
- Confidence-aware causal filtering
- Ranked evidence selection
- Reduced noisy telemetry
- Enterprise-style operational summarization
"""

import os
import json
import argparse

from datetime import datetime, timezone
from collections import Counter

from dotenv import load_dotenv

try:
    import google.generativeai as genai
except Exception:
    genai = None


# =========================================================
# LOAD ENV
# =========================================================

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if genai is not None and not API_KEY:
    raise ValueError(
        "GEMINI_API_KEY missing in .env"
    )

if genai is not None and API_KEY:
    genai.configure(api_key=API_KEY)


# =========================================================
# CONFIG
# =========================================================

MODEL = "gemini-2.5-flash-lite"

TEMPERATURE = 0.1
TOP_P = 0.8
TOP_K = 20
MAX_OUTPUT_TOKENS = 4096

MIN_CAUSAL_CONFIDENCE = 0.8


# =========================================================
# EVENT CLASSIFICATION
# =========================================================

TRIGGER_EVENTS = {
    "link down",
    "bgp neighbor down",
    "authentication failure",
    "stp topology change"
}

PROPAGATION_EVENTS = {
    "packet drop",
    "arp request",
    "heartbeat"
}

RECOVERY_EVENTS = {
    "link up",
    "bgp neighbor up"
}


# =========================================================
# LOAD JSON
# =========================================================

def load_json(path):

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# =========================================================
# SEVERITY HELPERS
# =========================================================

SEVERITY_WEIGHT = {
    "info": 1,
    "warning": 2,
    "error": 3,
    "critical": 4
}


def normalize_severity(severity):

    if not severity:
        return "info"

    return str(severity).lower().strip()


# =========================================================
# EVENT GRAPH ANALYSIS
# =========================================================

def compute_event_graph_metrics(
    event_id,
    causal_links
):

    incoming = 0
    outgoing = 0
    confidence_sum = 0.0

    for link in causal_links:

        conf = float(
            link.get("confidence", 0)
        )

        if link.get("cause_id") == event_id:

            outgoing += 1
            confidence_sum += conf

        if link.get("effect_id") == event_id:

            incoming += 1

    return {

        "incoming": incoming,

        "outgoing": outgoing,

        "confidence_sum":
            round(confidence_sum, 2)
    }


# =========================================================
# EVENT ROLE CLASSIFICATION
# =========================================================

def derive_event_role(event, metrics):

    subtype = (
        event.get("subtype", "")
        .lower()
        .strip()
    )

    incoming = metrics["incoming"]
    outgoing = metrics["outgoing"]
    confidence = metrics["confidence_sum"]

    # -------------------------------------------------
    # RECOVERY EVENTS
    # -------------------------------------------------

    if subtype in RECOVERY_EVENTS:
        return "recovery_indicator"

    # -------------------------------------------------
    # HIGH CONFIDENCE TRIGGERS
    # -------------------------------------------------

    if (
        subtype in TRIGGER_EVENTS
        and outgoing >= 2
        and confidence >= 1.5
    ):
        return "probable_trigger"

    # -------------------------------------------------
    # PROPAGATION EVENTS
    # -------------------------------------------------

    if outgoing >= 2:
        return "propagation_event"

    # -------------------------------------------------
    # DOWNSTREAM IMPACT
    # -------------------------------------------------

    if incoming >= 2:
        return "downstream_impact"

    # -------------------------------------------------
    # SUPPORTING SIGNAL
    # -------------------------------------------------

    return "supporting_signal"


# =========================================================
# INCIDENT SEVERITY
# =========================================================

def derive_incident_severity(
    events,
    links,
    chains,
    devices
):

    critical = 0
    errors = 0

    for e in events:

        sev = normalize_severity(
            e.get("severity")
        )

        if sev == "critical":
            critical += 1

        elif sev == "error":
            errors += 1

    chain_depth = max(
        [len(c) for c in chains],
        default=0
    )

    score = (
        critical * 12
        + errors * 6
        + len(links) * 3
        + chain_depth * 4
        + len(devices) * 5
    )

    score = min(score, 100)

    if score >= 80:
        label = "Critical"

    elif score >= 60:
        label = "High"

    elif score >= 30:
        label = "Medium"

    else:
        label = "Low"

    return score, label


# =========================================================
# RCA CONFIDENCE
# =========================================================

def derive_rca_confidence(links):

    if not links:
        return "Low"

    avg = sum(
        l["confidence"]
        for l in links
    ) / len(links)

    if avg >= 2.0:
        return "Moderate-High"

    if avg >= 1.2:
        return "Moderate"

    return "Low"


# =========================================================
# AGGREGATION FUNCTIONS
# =========================================================

def aggregate_event_types(events):

    counter = Counter()

    for e in events:

        ev = e.get("event_type")

        if ev:
            counter[ev] += 1

    return dict(counter)


def aggregate_device_impact(events):

    counter = Counter()

    for e in events:

        dev = e.get("device")

        if dev:
            counter[dev] += 1

    return dict(counter)


def derive_primary_patterns(event_stats):

    patterns = []

    if event_stats.get("link down", 0) >= 3:
        patterns.append("link_instability")

    if event_stats.get("bgp neighbor down", 0) >= 3:
        patterns.append("routing_instability")

    if event_stats.get("stp topology change", 0) >= 3:
        patterns.append("layer2_reconvergence")

    if event_stats.get("authentication failure", 0) >= 3:
        patterns.append("authentication_disruption")

    if event_stats.get("packet drop", 0) >= 3:
        patterns.append("forwarding_instability")

    return patterns


# =========================================================
# EVIDENCE RANKING
# =========================================================

def rank_incident_evidence(events):

    ranked = []

    for e in events:

        metrics = e["graph_metrics"]

        score = (
            metrics["outgoing"] * 4
            + metrics["incoming"] * 2
            + metrics["confidence_sum"] * 5
        )

        ranked.append((score, e))

    ranked.sort(
        key=lambda x: x[0],
        reverse=True
    )

    return [e for _, e in ranked[:10]]


# =========================================================
# BUILD TRIGGER SUMMARY
# =========================================================

def build_trigger_summary(events):

    trigger_counter = Counter()

    for e in events:

        if e["role"] == "probable_trigger":

            trigger_counter[
                e["event_type"]
            ] += 1

    return dict(
        trigger_counter.most_common(5)
    )


# =========================================================
# GLOBAL ANALYTICS
# =========================================================

def build_global_summary(cleaned_incidents):

    total_event_stats = Counter()
    total_device_stats = Counter()
    total_trigger_stats = Counter()

    severity_counter = Counter()

    for inc in cleaned_incidents:

        severity_counter[
            inc["incident_severity"]
        ] += 1

        total_event_stats.update(
            inc.get("event_statistics", {})
        )

        total_device_stats.update(
            inc.get("device_impact", {})
        )

        total_trigger_stats.update(
            inc.get("trigger_summary", {})
        )

    return {

        "severity_distribution":
            dict(severity_counter),

        "top_event_types":
            dict(
                total_event_stats.most_common(10)
            ),

        "most_impacted_devices":
            dict(
                total_device_stats.most_common(10)
            ),

        "top_trigger_candidates":
            dict(
                total_trigger_stats.most_common(10)
            )
    }


# =========================================================
# BUILD PAYLOAD
# =========================================================

def build_payload(
    timeline_data,
    causal_data
):

    # -------------------------------------------------
    # TIMELINE NORMALIZATION
    # -------------------------------------------------

    if isinstance(timeline_data, list):

        incidents = timeline_data

    elif isinstance(timeline_data, dict):

        incidents = timeline_data.get(
            "incidents",
            []
        )

    else:

        raise ValueError(
            "Unsupported timeline_output structure"
        )

    # -------------------------------------------------
    # CAUSAL NORMALIZATION
    # -------------------------------------------------

    causal_links = []
    causal_chains = []

    if isinstance(causal_data, dict):

        causal_links = causal_data.get(
            "causal_links",
            []
        )

        causal_chains = causal_data.get(
            "chains",
            causal_data.get(
                "causal_chains",
                []
            )
        )

    elif isinstance(causal_data, list):

        causal_links = causal_data

    else:

        raise ValueError(
            "Unsupported causal structure"
        )

    # -------------------------------------------------
    # PROCESS INCIDENTS
    # -------------------------------------------------

    cleaned_incidents = []

    for inc in incidents:

        incident_id = inc.get(
            "incident_id"
        )

        events = inc.get(
            "events",
            []
        )

        cleaned_events = []

        # -------------------------------------------------
        # EVENT PROCESSING
        # -------------------------------------------------

        for e in events:

            event_id = (
                e.get("id")
                or e.get("event_uid")
            )

            metrics = compute_event_graph_metrics(
                event_id,
                causal_links
            )

            role = derive_event_role(
                e,
                metrics
            )

            cleaned_events.append({

                "event_id":
                    event_id,

                "timestamp":
                    e.get("corrected_time")
                    or e.get("time"),

                "device":
                    e.get("device"),

                "interface":
                    e.get("interface"),

                "event_type":
                    e.get("subtype"),

                "severity":
                    e.get("severity"),

                "role":
                    role,

                "graph_metrics":
                    metrics
            })

        # -------------------------------------------------
        # INCIDENT EVENT IDS
        # -------------------------------------------------

        incident_event_ids = {

            e["event_id"]
            for e in cleaned_events
        }

        # -------------------------------------------------
        # MATCH LINKS
        # -------------------------------------------------

        incident_links = []

        for link in causal_links:

            confidence = float(
                link.get("confidence", 0)
            )

            if confidence < MIN_CAUSAL_CONFIDENCE:
                continue

            cause_id = link.get("cause_id")
            effect_id = link.get("effect_id")

            if (
                cause_id in incident_event_ids
                and
                effect_id in incident_event_ids
            ):

                incident_links.append({

                    "cause":
                        cause_id,

                    "effect":
                        effect_id,

                    "cause_type":
                        link.get("cause_subtype"),

                    "effect_type":
                        link.get("effect_subtype"),

                    "lag_seconds":
                        link.get("lag_sec"),

                    "confidence":
                        round(confidence, 2)
                })

        # -------------------------------------------------
        # MATCH CHAINS
        # -------------------------------------------------

        incident_chains = []

        for chain in causal_chains:

            if isinstance(chain, list):

                if all(
                    eid in incident_event_ids
                    for eid in chain
                ):
                    incident_chains.append(chain)

        # -------------------------------------------------
        # SEVERITY
        # -------------------------------------------------

        severity_score, incident_severity = (
            derive_incident_severity(
                cleaned_events,
                incident_links,
                incident_chains,
                inc.get("devices", [])
            )
        )

        # -------------------------------------------------
        # PROPAGATION DEPTH
        # -------------------------------------------------

        propagation_depth = max(
            [len(c) for c in incident_chains],
            default=0
        )

        # -------------------------------------------------
        # AGGREGATION
        # -------------------------------------------------

        event_stats = aggregate_event_types(
            cleaned_events
        )

        device_impact = aggregate_device_impact(
            cleaned_events
        )

        patterns = derive_primary_patterns(
            event_stats
        )

        trigger_summary = build_trigger_summary(
            cleaned_events
        )

        # -------------------------------------------------
        # BUILD INCIDENT
        # -------------------------------------------------

        cleaned_incidents.append({

            "incident_id":
                incident_id,

            "incident_window": {

                "start":
                    inc.get("start_time"),

                "end":
                    inc.get("end_time"),

                "duration_seconds":
                    inc.get("duration_sec")
            },

            "devices":
                inc.get("devices", []),

            "incident_severity":
                incident_severity,

            "severity_score":
                severity_score,

            "rca_confidence":
                derive_rca_confidence(
                    incident_links
                ),

            "propagation_depth":
                propagation_depth,

            "event_statistics":
                event_stats,

            "device_impact":
                device_impact,

            "primary_patterns":
                patterns,

            "trigger_summary":
                trigger_summary,

            "important_events":
                rank_incident_evidence(
                    cleaned_events
                ),

            "causal_links":
                incident_links[:20],

            "chain_statistics": {

                "total_chains":
                    len(incident_chains),

                "max_depth":
                    propagation_depth
            }
        })

    # -------------------------------------------------
    # GLOBAL SUMMARY
    # -------------------------------------------------

    global_summary = build_global_summary(
        cleaned_incidents
    )

    return {

        "report_generated":
            datetime.now(
                timezone.utc
            ).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),

        "total_incidents":
            len(cleaned_incidents),

        "global_summary":
            global_summary,

        "incidents":
            cleaned_incidents
    }


# =========================================================
# SYSTEM PROMPT
# =========================================================

SYSTEM_PROMPT = """
You are an enterprise SRE and
network incident investigator.

Generate a concise,
evidence-grounded
Network Incident Investigation Report.

STRICT RULES:

1. Use ONLY supplied evidence.
2. Never invent topology,
   hardware failures,
   protocol mechanisms,
   congestion,
   overload,
   or environmental causes.
3. Distinguish clearly between:
   - observed events
   - inferred relationships
   - hypotheses
4. Temporal correlation alone
   does NOT prove causality.
5. Never claim
   'confirmed root cause'
   unless explicitly proven.
6. Prefer probabilistic wording:
   - probable
   - inferred
   - correlated
   - observed
   - suggestive
7. Treat:
   - packet drops
   - ARP requests
   - heartbeat events
   as supporting telemetry
   unless strongly linked.
8. Treat:
   - link down
   - bgp neighbor down
   - authentication failure
   as probable trigger candidates.
9. Avoid speculative explanations.
10. Avoid repetitive incident dumps.
11. Summarize operational patterns.
12. Mention uncertainty explicitly.
13. Focus on operationally useful insights.
14. Keep language concise and professional.
15. Never overstate confidence.
"""


# =========================================================
# BUILD PROMPT
# =========================================================

def build_prompt(payload):

    return f"""
Generate an enterprise-grade
Network Incident Investigation Report.

Required Sections:

1. Executive Summary
2. Incident Overview
3. Major Operational Phases
4. Root Cause Analysis
5. Major Causal Patterns
6. Impact Assessment
7. Confidence & Limitations
8. Recommendations

IMPORTANT:

- DO NOT describe every incident individually.
- Group repetitive incidents.
- Summarize operational patterns.
- Use aggregate statistics.
- Mention dominant event types only.
- Mention dominant affected devices only.
- Focus on recurring failure patterns.
- Keep the report concise.
- Avoid repetitive timelines.
- Separate probable triggers from symptoms.
- Never use:
    - Confirmed Root Cause
    - Proven Cause
- Use:
    - Probable Initiating Triggers
    - Inferred Causal Patterns
    - Supporting Evidence

INPUT DATA:

{json.dumps(payload, indent=2)}
"""


# =========================================================
# GENERATE REPORT
# =========================================================

def generate_report(prompt, payload=None):

    if genai is None:
        return build_fallback_report(payload)

    model = genai.GenerativeModel(

        model_name=MODEL,

        system_instruction=SYSTEM_PROMPT
    )

    response = model.generate_content(

        prompt,

        generation_config={

            "temperature":
                TEMPERATURE,

            "top_p":
                TOP_P,

            "top_k":
                TOP_K,

            "max_output_tokens":
                MAX_OUTPUT_TOKENS
        }
    )

    return response.text


def build_fallback_report(payload):

    if not isinstance(payload, dict):
        payload = {"cleaned_incidents": []}

    incidents = payload.get("cleaned_incidents", [])
    total_incidents = len(incidents)
    total_events = sum(len(inc.get("important_events", [])) for inc in incidents)
    total_links = sum(len(inc.get("causal_links", [])) for inc in incidents)

    top_devices = Counter()
    top_patterns = Counter()
    for inc in incidents:
        for device in inc.get("devices", []):
            top_devices[device] += 1
        for pattern in inc.get("primary_patterns", []):
            top_patterns[pattern] += 1

    lines = [
        "# Enterprise Network Incident Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Executive Summary",
        f"- Total incidents reconstructed: {total_incidents}",
        f"- Total important events analyzed: {total_events}",
        f"- Total causal links inferred: {total_links}",
        f"- Dominant devices: {', '.join(device for device, _ in top_devices.most_common(5)) or 'N/A'}",
        "",
        "## Major Operational Phases",
    ]

    for inc in incidents[:5]:
        lines.append(
            f"- {inc.get('incident_id')}: severity={inc.get('incident_severity', 'unknown')}, rca_confidence={inc.get('rca_confidence', 0)}"
        )

    lines.extend([
        "",
        "## Root Cause Analysis",
    ])

    for inc in incidents[:5]:
        root_events = inc.get("important_events", [])[:1]
        if root_events:
            root = root_events[0]
            lines.append(
                f"- {inc.get('incident_id')}: probable trigger at {root.get('device', 'unknown')} ({root.get('event_type', 'unknown')})"
            )

    lines.extend([
        "",
        "## Major Causal Patterns",
    ])

    for pattern, count in top_patterns.most_common(5):
        lines.append(f"- {pattern}: {count}")

    lines.extend([
        "",
        "## Confidence & Limitations",
        "- Gemini SDK is unavailable in this environment, so this report was generated deterministically.",
        "- Causality still reflects the timeline and causal inference outputs.",
        "",
        "## Recommendations",
        "- Validate the root-linked devices first.",
        "- Correlate downstream symptoms with the inferred trigger window.",
    ])

    return "\n".join(lines)


# =========================================================
# SAVE REPORT
# =========================================================

def save_report(
    report,
    output_path
):

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(report)

    print(
        f"[OK] Report saved: {output_path}"
    )


# =========================================================
# MAIN
# =========================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--timeline",
        default="timeline_output.json"
    )

    parser.add_argument(
        "--causal",
        default="causal_inference_output.json"
    )

    parser.add_argument(
        "--output",
        default=(
            "enterprise_network_report_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        )
    )

    args = parser.parse_args()

    print("=" * 60)
    print(" Enterprise Network Incident Summarizer ")
    print("=" * 60)

    # -------------------------------------------------
    # LOAD DATA
    # -------------------------------------------------

    timeline_data = load_json(
        args.timeline
    )

    causal_data = load_json(
        args.causal
    )

    print(
        "[OK] Timeline and causal data loaded"
    )

    # -------------------------------------------------
    # BUILD PAYLOAD
    # -------------------------------------------------

    payload = build_payload(
        timeline_data,
        causal_data
    )

    print(
        "[OK] Enterprise RCA payload constructed"
    )

    # -------------------------------------------------
    # BUILD PROMPT
    # -------------------------------------------------

    prompt = build_prompt(payload)

    # -------------------------------------------------
    # GENERATE REPORT
    # -------------------------------------------------

    print(
        "[INFO] Generating report with Gemini..."
    )

    report = generate_report(prompt, payload)

    # -------------------------------------------------
    # SAVE REPORT
    # -------------------------------------------------

    save_report(
        report,
        args.output
    )

    print(
        "[DONE] Enterprise report generation completed"
    )


# =========================================================
# ENTRY
# =========================================================

if __name__ == "__main__":

    main()