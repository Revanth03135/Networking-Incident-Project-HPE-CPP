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
    import google.generativeai as genai  # type: ignore[import-untyped]
except Exception:
    genai = None  # type: ignore[assignment]

genai = genai  # re-export to satisfy static analysis




load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if genai is not None and not API_KEY:
    raise ValueError(
        "GEMINI_API_KEY missing in .env"
    )

if genai is not None and API_KEY:
    genai.configure(api_key=API_KEY)



MODEL = "gemini-2.5-flash-lite"

TEMPERATURE = 0.1
TOP_P = 0.8
TOP_K = 20
MAX_OUTPUT_TOKENS = 4096

MIN_CAUSAL_CONFIDENCE = 0.6  # Accept links >= 0.60; causalInference scores range 0.0-0.99




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

        if link.get("source_event_uid") == event_id:

            outgoing += 1
            confidence_sum += conf

        if link.get("target_event_uid") == event_id:

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
    """Return a confidence label based on average link confidence (0.0–1.0 scale)."""
    if not links:
        return "Low"

    avg = sum(
        float(l.get("confidence", 0))
        for l in links
    ) / len(links)

    # confidence values are 0.0–1.0 (e.g. 0.99, 0.85, 0.70)
    if avg >= 0.85:
        return "High"

    if avg >= 0.65:
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
    # The causal output from causalInference.py has this structure:
    # {
    #   "total_incidents": N,
    #   "total_causal_links": N,
    #   "root_causes": [...],
    #   "incidents": [
    #     { "incident_id": "INC-0001", "causal_links": [...], "root_cause": {...}, ... }
    #   ]
    # }
    # We index per-incident data by incident_id for fast lookup.

    # Build per-incident causal data index
    causal_by_inc = {}  # incident_id -> causal incident dict
    if isinstance(causal_data, dict):
        for ci in causal_data.get("incidents", []):
            iid = ci.get("incident_id")
            if iid:
                causal_by_inc[iid] = ci
    elif isinstance(causal_data, list):
        # Legacy flat list of links
        for link in causal_data:
            pass  # handled below as flat fallback

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

        # Resolve per-incident causal data early so event processing can use it
        causal_inc = causal_by_inc.get(incident_id, {})
        raw_links = causal_inc.get("causal_links", [])

        for e in events:

            event_id = (
                e.get("id")
                or e.get("event_uid")
            )

            metrics = compute_event_graph_metrics(
                event_id,
                raw_links
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
        # MATCH LINKS from per-incident causal data
        # -------------------------------------------------
        # Field mapping from causalInference.py output:
        #   source_event_uid / target_event_uid  (not cause_id/effect_id)
        #   source_subtype / target_subtype       (not cause_subtype/effect_subtype)
        #   lag_seconds                           (not lag_sec)


        incident_links = []

        for link in raw_links:

            confidence = float(link.get("confidence", 0))
            # Accept all links with confidence >= MIN_CAUSAL_CONFIDENCE
            if confidence < MIN_CAUSAL_CONFIDENCE:
                continue

            cause_id = link.get("source_event_uid")
            effect_id = link.get("target_event_uid")

            incident_links.append({
                "cause": cause_id,
                "effect": effect_id,
                "cause_type": link.get("source_subtype"),
                "effect_type": link.get("target_subtype"),
                "lag_seconds": link.get("lag_seconds"),
                "confidence": round(confidence, 2),
                "reason": link.get("reason", ""),
            })

        # Also pull causal_sequences as chains
        incident_chains = []
        for seq in causal_inc.get("causal_sequences", []):
            steps = seq.get("steps", [])
            if len(steps) >= 2:
                incident_chains.append([s.get("event_uid") for s in steps])

        # Pull root_cause from causal engine for this incident
        causal_root = causal_inc.get("root_cause") or {}

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
                "start": inc.get("start_time"),
                "end": inc.get("end_time"),
                "duration_seconds": inc.get("duration_sec")
            },

            "total_events": len(events),

            "devices":
                inc.get("devices", []),

            "incident_severity":
                incident_severity,

            "severity_score":
                severity_score,

            "rca_confidence":
                derive_rca_confidence(incident_links),

            # Root cause from causal engine (enriched)
            "root_cause": {
                "subtype": causal_root.get("normalized_subtype") or causal_root.get("subtype"),
                "device": causal_root.get("device"),
                "message": causal_root.get("message"),
                "severity": causal_root.get("severity"),
                "score": causal_root.get("root_score"),
                "domain": causal_root.get("normalized_domain"),
                "interface": causal_root.get("interface_id"),
                "timestamp": causal_root.get("corrected_time") or causal_root.get("event_time"),
            } if causal_root else None,

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
                rank_incident_evidence(cleaned_events),

            "causal_links":
                incident_links[:20],

            "chain_statistics": {
                "total_chains": len(incident_chains),
                "max_depth": propagation_depth
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
You are a senior network SRE and infrastructure incident analyst at an enterprise NOC.

Your task is to generate a professional, evidence-grounded Network Incident Investigation Report
that a network engineer can use to triage and remediate real infrastructure failures.

STRICT RULES:

1. Use ONLY the supplied JSON evidence. Never invent facts.
2. Distinguish clearly between: observed events | inferred relationships | hypotheses.
3. Temporal correlation alone does NOT prove causality.
4. Prefer probabilistic language: probable, inferred, correlated, observed, suggestive.
5. Never claim 'confirmed root cause' unless explicitly proven by data.
6. Avoid speculation. Avoid repetitive event dumps.
7. Focus on operationally useful, device-specific insights.
8. Language must be concise, professional, and actionable.

NETWORK DOMAIN CLASSIFICATION (use exactly these labels):
- Layer 0 - Hardware: Power supply (PSU), Fan, Temperature alarms
- Layer 1 - Physical: CRC errors, Interface down/up, Transceiver faults, Cable faults
- Layer 2 - Switching: STP topology change, VLAN, LLDP, 802.1X, MAC-auth
- Layer 3 - Routing: OSPF neighbor change, BGP session down, Route flap
- Layer 4 - Security: SSH brute-force, Admin auth failure, ACL violations
- Layer 4 - Management: SNMP, NTP, Configuration changes

ROOT CAUSE PRIORITY (from most to least likely):
  Layer 0 Hardware > Layer 1 Physical > Layer 3 Routing > Layer 2 Switching >
  Layer 4 Management > Layer 4 Security

SECURITY NOTE: SSH brute-force and authentication failures are almost NEVER the
infrastructure root cause. They are either independent noise or a consequence of
service disruption. Do NOT list them as root cause unless there is zero physical
evidence and they directly correlate with outage timing.

ACTIONABLE RECOMMENDATIONS MUST:
- Reference specific device names, port IDs, or interface IDs from the data.
- Be actionable by a network engineer right now (e.g. check cable on port 1/1/2,
  replace PSU-2, verify OSPF neighbor config, rotate SSH keys).
- NOT be generic advisories (e.g. 'monitor the network', 'check logs').
"""


# =========================================================
# BUILD PROMPT
# =========================================================




def extract_top_causal_chain(payload):
    """Extract the longest/most impactful causal chain string for the report."""
    best_chain = None
    best_len = 0
    for inc in payload.get("incidents", []):
        # The payload incidents come from build_payload() in network_incident_summarizer
        # which does not carry causal_sequences. We rely on causal_links ordering.
        links = inc.get("causal_links", [])
        if links and len(links) > best_len:
            best_len = len(links)
            best_chain = links
    if best_chain:
        # Build a readable arrow chain from the top-confidence links
        sorted_links = sorted(best_chain, key=lambda l: l.get("confidence", 0), reverse=True)
        seen = []
        for l in sorted_links[:6]:
            cause = l.get("cause_type") or "?"
            effect = l.get("effect_type") or "?"
            if cause not in seen:
                seen.append(cause)
            if effect not in seen:
                seen.append(effect)
        return " -> ".join(seen) if seen else "N/A"
    return "N/A"


def build_prompt(payload):
    top_chain = extract_top_causal_chain(payload)
    global_summary = payload.get("global_summary", {})
    
    total_incidents = len(payload.get("incidents", []))
    total_events = sum(inc.get("total_events", len(inc.get("important_events", []))) for inc in payload.get("incidents", []))

    return f"""
Generate an enterprise-grade Network Incident Investigation Report using EXACTLY the 6 sections below.
Base every claim on the INPUT DATA provided at the end.

---
### SECTION 1: Executive Summary
Write 3-5 sentences covering:
- Total incidents ({total_incidents}) and EXACTLY {total_events} total events recorded in logs. Do not report a different number of events.
- Overall incident severity
- Primary operational impact on the network

### SECTION 2: Root Cause / Initiating Event Analysis
Select the MOST PROBABLE root cause (for incidents) or initiating event (for workflows) following this priority:
  Layer 0 Hardware > Layer 1 Physical > Layer 3 Routing > Layer 2 Switching > Security

For each incident/workflow:
- State the probable root cause or initiating event (device, port, subtype, timestamp)
- Clearly state if this is an "Initiating Event" (for routine operational workflows) or a "Root Cause" (for unexpected network incidents).
- Assign a Confidence % based on causal link count and confidence scores:
  - High confidence (>75%): strong causal chain + multiple correlated events
  - Medium confidence (50-75%): partial causal chain, same device/port
  - Low confidence (<50%): temporal correlation only

DO NOT select SSH brute-force or auth failures as root cause if any hardware or physical event is present.

### SECTION 3: Top Causal Chain
Highlight the most impactful event propagation sequence observed:
Detected chain: {top_chain}

Format as:
[Event A] -> [Event B] -> [Event C] -> ...
With a 1-sentence explanation of each propagation step.

### SECTION 4: Impact Assessment
- Which devices/interfaces were impacted?
- Which network layer was most disrupted?
- Estimated blast radius (how many downstream systems affected)?

### SECTION 5: Confidence and Limitations
- State the overall RCA confidence level (High/Medium/Low) with a percentage
- List any data gaps or uncertainty factors

### SECTION 6: Actionable Recommendations
Provide 5-8 specific, device-level remediation steps. Each recommendation MUST:
- Name the specific device or interface (from the data)
- State the exact action to take (not generic advice)
- Reference the event that triggered this recommendation

Examples of GOOD recommendations:
  - Check port 1/1/2 on [device] for cable fault or SFP degradation (triggered by CRC errors)
  - Replace PSU-2 on [device] and verify redundant power path is active
  - Verify OSPF neighbor configuration between [device-A] and [device-B]

Examples of BAD recommendations (do NOT use):
  - Monitor the network
  - Review logs regularly
  - Implement better security
---

INPUT DATA:

{json.dumps(payload, indent=2)}
"""


# =========================================================
# HELPER LLM APIS FOR FALLBACK
# =========================================================

def call_groq_api(prompt, system_prompt, api_key):
    import requests
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    # Try llama-3.3-70b-versatile first, fall back to llama-3.1-8b-instant
    for model in ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": 2048
        }
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            else:
                print(f"[WARN] Groq model {model} failed with status {response.status_code}: {response.text}")
        except Exception as e:
            print(f"[WARN] Groq model {model} failed with exception: {e}")
    return None


def call_ollama_api(prompt, system_prompt):
    import requests
    import re
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
    ollama_model = os.getenv("OLLAMA_MODEL", "gemma3:1b")
    
    combined_prompt = f"{system_prompt}\n\nUser request: Generate the report for this data:\n{prompt}"
    payload = {
        "model": ollama_model,
        "prompt": combined_prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 2048
        }
    }
    try:
        response = requests.post(ollama_url, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json().get("response", "").strip()
            # Handle and remove reasoning think tags if they exist
            if "<think>" in result:
                result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL).strip()
            return result
        else:
            print(f"[WARN] Ollama API failed with status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[WARN] Ollama API failed with exception: {e}")
    return None


# =========================================================
# GENERATE REPORT
# =========================================================

def generate_report(prompt, payload=None):
    # Tier 1: Gemini API
    if genai is not None and API_KEY:
        print("[INFO] Attempting report generation using Gemini API...")
        try:
            try:
                model = genai.GenerativeModel(
                    model_name=MODEL,
                    system_instruction=SYSTEM_PROMPT
                )
                prompt_with_sys = prompt
            except TypeError:
                # Fallback for older google-generativeai versions (like 0.3.2)
                model = genai.GenerativeModel(
                    model_name=MODEL
                )
                prompt_with_sys = f"{SYSTEM_PROMPT}\n\n{prompt}"

            response = model.generate_content(
                prompt_with_sys,
                generation_config={
                    "temperature": TEMPERATURE,
                    "top_p": TOP_P,
                    "top_k": TOP_K,
                    "max_output_tokens": MAX_OUTPUT_TOKENS
                }
            )
            if response.text:
                print("[OK] Successfully generated report using Gemini API!")
                return response.text
        except Exception as e:
            print(f"[WARN] Gemini API failed: {e}")

    # Tier 2: Groq API
    groq_key = os.getenv("GROQ_API")
    if groq_key:
        print("[INFO] Attempting report generation using Groq API...")
        groq_report = call_groq_api(prompt, SYSTEM_PROMPT, groq_key)
        if groq_report:
            print("[OK] Successfully generated report using Groq API!")
            return groq_report

    # Tier 3: Local Ollama
    print("[INFO] Attempting report generation using local Ollama model...")
    ollama_report = call_ollama_api(prompt, SYSTEM_PROMPT)
    if ollama_report:
        print("[OK] Successfully generated report using local Ollama!")
        return ollama_report

    # Tier 4: Local structured rule-based template
    print("[WARN] All LLM APIs failed. Falling back to local structured template generator.")
    return build_fallback_report(payload)


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
        "## Root Cause / Initiating Event Analysis",
    ])

    for inc in incidents[:5]:
        root_events = inc.get("important_events", [])[:1]
        if root_events:
            root = root_events[0]
            is_wf = inc.get('incident_id', '').startswith("WORKFLOW")
            prefix = "Workflow" if is_wf else "Incident"
            label = "initiating event" if is_wf else "probable root cause"
            lines.append(
                f"- {prefix} {inc.get('incident_id')}: {label} at {root.get('device', 'unknown')} ({root.get('event_type', 'unknown')})"
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