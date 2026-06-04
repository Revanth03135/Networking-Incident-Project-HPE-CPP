"""
crt_generation.py — CRT (Causal Reasoning and Timeline) generation using Groq LLM.

Responsibility: Take deduplicated events from timeline reconstruction and use
Groq LLM to generate a causal sequence with root cause analysis and step-by-step
reasoning.

This replaces the deterministic graph-based causal inference, delegating all
causality reasoning to the LLM.
"""

# -*- coding: utf-8 -*-
import sys
import io

# Configure UTF-8 encoding for stdout (fixes Windows encoding issues)
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import json
import requests
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

# Global state to track last refinement source
LAST_CRT_SOURCE = None

def get_last_crt_source() -> str:
    """Return the source of last CRT generation (groq_rest, groq_sdk, or none)."""
    global LAST_CRT_SOURCE
    return LAST_CRT_SOURCE or "none"

def _get_groq_api_key() -> Optional[str]:
    """Retrieve Groq API key from environment variables."""
    return os.getenv("GROQ_API") or os.getenv("GROQ_API_KEY")

def _json_extract(text: str) -> Optional[Dict]:
    """Extract JSON from response text, handling markdown backticks."""
    try:
        # Remove markdown backticks if present
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        
        text = text.strip()
        
        # Try to find JSON object boundaries
        # Find first { and last }
        start_idx = text.find("{")
        end_idx = text.rfind("}")
        
        if start_idx >= 0 and end_idx > start_idx:
            text = text[start_idx:end_idx+1]
        
        return json.loads(text)
    except json.JSONDecodeError as e:
        logging.error(f"[CRT] JSON parsing failed at line {e.lineno}: {e.msg}")
        logging.debug(f"[CRT] Attempted to parse: {text[:300]}")
        return None
    except Exception as e:
        logging.error(f"[CRT] JSON extraction failed: {e}")
        return None

def build_groq_crt_payload(
    incident_id: str,
    deduped_events: List[Dict],
    start_time: datetime,
    end_time: datetime
) -> Dict[str, Any]:
    """
    Build Groq payload from deduplicated events.
    
    Args:
        incident_id: Incident identifier (e.g., "INC-0001")
        deduped_events: List of deduplicated events from timeline clustering
        start_time: Incident start time
        end_time: Incident end time
    
    Returns:
        Dictionary payload ready to send to Groq
    """
    
    # Normalize timestamps for JSON serialization
    events_for_groq = []
    for e in deduped_events:
        # Get timestamp (corrected_time is preferred, fallback to event_time)
        ts = e.get("corrected_time") or e.get("event_time")
        if isinstance(ts, datetime):
            ts_str = ts.isoformat()
        else:
            ts_str = str(ts)
        
        evt = {
            "event_id": str(e.get("event_uid", e.get("event_id", "unknown"))),
            "timestamp": ts_str,
            "device": e.get("device", "unknown"),
            "type": e.get("type", "unknown"),
            "subtype": e.get("subtype", "unknown"),
            "severity": e.get("severity", "info"),
            "message": e.get("message", ""),
            "interface_id": e.get("interface_id"),
            "protocol": e.get("protocol"),
        }
        events_for_groq.append(evt)
    
    # Build context summary from events
    event_types = {}
    severities = {}
    protocols = set()
    
    for e in deduped_events:
        subtype = e.get("subtype", "unknown")
        event_types[subtype] = event_types.get(subtype, 0) + 1
        
        severity = e.get("severity", "info").lower()
        severities[severity] = severities.get(severity, 0) + 1
        
        if e.get("protocol"):
            protocols.add(e.get("protocol"))
    
    # Calculate duration
    if isinstance(start_time, datetime) and isinstance(end_time, datetime):
        duration_sec = (end_time - start_time).total_seconds()
        start_str = start_time.isoformat()
        end_str = end_time.isoformat()
    else:
        duration_sec = 0
        start_str = str(start_time)
        end_str = str(end_time)
    
    # Build payload
    payload = {
        "incident_id": incident_id,
        "time_range": {
            "start": start_str,
            "end": end_str,
            "duration_sec": round(duration_sec, 2)
        },
        "event_count": len(deduped_events),
        "unique_devices": len(set(e.get("device") for e in deduped_events if e.get("device"))),
        "devices": sorted(list(set(e.get("device") for e in deduped_events if e.get("device")))),
        
        "events": events_for_groq,
        
        "context": {
            "event_types": event_types,
            "severity_distribution": severities,
            "protocols_involved": sorted(list(protocols)),
        }
    }
    
    return payload

def generate_crt_with_groq(
    incident_id: str,
    deduped_events: List[Dict],
    start_time: datetime,
    end_time: datetime
) -> Optional[Dict]:
    """
    Call Groq LLM to generate CRT (Causal Reasoning and Timeline) sequence.
    
    Args:
        incident_id: Incident identifier
        deduped_events: Deduplicated events from timeline clustering
        start_time: Incident start time
        end_time: Incident end time
    
    Returns:
        Dictionary with CRT results or None if generation fails
    """
    global LAST_CRT_SOURCE
    
    api_key = _get_groq_api_key()
    if not api_key:
        logging.warning("[CRT] No Groq API key found, CRT generation skipped")
        LAST_CRT_SOURCE = "none"
        return None
    
    payload = build_groq_crt_payload(incident_id, deduped_events, start_time, end_time)
    
    # System prompt: Define role and task for Groq
    system_prompt = """You are a network incident analyst specializing in root cause analysis.
Your task is to analyze network events and generate a Causal Reasoning and Timeline (CRT) sequence.

For each incident:
1. Identify which event triggered the incident (root cause)
2. Trace which events were direct consequences of the root cause
3. Identify which events are coincidental or unrelated (noise)
4. Order events by causal dependency (not chronological order)
5. Provide confidence level and explanations for your reasoning

Return ONLY valid JSON. No markdown, no code blocks, no explanations outside JSON."""

    # User prompt: Provide incident data and task
    user_prompt = f"""Analyze this network incident and generate a causal sequence:

Incident: {payload['incident_id']}
Duration: {payload['time_range']['duration_sec']}s
Total Events: {payload['event_count']}
Devices Involved: {', '.join(payload['devices'])}
Event Type Distribution: {payload['context']['event_types']}
Severity Distribution: {payload['context']['severity_distribution']}
Protocols Involved: {', '.join(payload['context']['protocols_involved']) if payload['context']['protocols_involved'] else 'none'}

Events (in chronological order):
"""
    
    # Add events to prompt
    for i, e in enumerate(payload['events'], 1):
        user_prompt += f"\n{i}. [{e['timestamp']}] {e['device']} | {e['subtype']}"
        if e.get('message'):
            user_prompt += f" | {e['message']}"
    
    # Add output format specification
    user_prompt += """

Generate a JSON response with this structure:
{
  "root_cause_event_id": "<event_id of the root cause>",
  "root_cause_summary": "<one-line summary of what caused the incident>",
  "root_cause_confidence": "high|medium|low",
  "causal_sequence": [
    {
      "step": 1,
      "event_id": "<event_id>",
      "role": "root_cause|direct_consequence|indirect_consequence|concurrent_unrelated",
      "description": "<what happened in this event>",
      "reason": "<why this event has this role>"
    },
    ...more events...
  ],
  "incident_summary": "<2-3 sentence narrative of the incident and how it propagated>",
  "recommendations": ["<action 1>", "<action 2>", "..."],
  "notes": "<any uncertainties or caveats about the analysis>"
}"""
    
    try:
        logging.info(f"[CRT] Calling Groq for {incident_id}...")
        
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1,  # Low randomness for consistent reasoning
                "max_tokens": 2000
            },
            timeout=30
        )
        
        if response.status_code != 200:
            logging.error(f"[CRT] Groq API returned {response.status_code}")
            LAST_CRT_SOURCE = "none"
            return None
        
        result = response.json()
        groq_response = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        if not groq_response:
            logging.error("[CRT] Groq returned empty response")
            LAST_CRT_SOURCE = "none"
            return None
        
        # Log raw response for debugging
        logging.debug(f"[CRT] Raw response (first 500 chars): {groq_response[:500]}")
        
        # Save raw response to file for inspection
        try:
            with open("pipeline_output/crt_raw_response.txt", "w", encoding="utf-8") as f:
                f.write(groq_response)
        except:
            pass
        
        # Extract JSON from response
        crt_data = _json_extract(groq_response)
        if not crt_data:
            logging.error("[CRT] Failed to parse Groq response as JSON")
            logging.debug(f"[CRT] Response was: {groq_response[:500]}")
            LAST_CRT_SOURCE = "none"
            return None
        
        LAST_CRT_SOURCE = "groq_rest"
        logging.info(f"[CRT] ✓ Generated CRT for {incident_id}")
        return crt_data
    
    except requests.exceptions.RequestException as e:
        logging.error(f"[CRT] Request failed: {e}")
        LAST_CRT_SOURCE = "none"
        return None
    except Exception as e:
        logging.error(f"[CRT] Unexpected error: {e}")
        LAST_CRT_SOURCE = "none"
        return None

def parse_crt_response(crt_data: Dict) -> Optional[Dict]:
    """
    Validate and normalize CRT response from Groq.
    
    Args:
        crt_data: Dictionary returned from generate_crt_with_groq()
    
    Returns:
        Validated CRT data or None if invalid
    """
    
    if not crt_data:
        return None
    
    # Validate required fields
    required_fields = [
        "root_cause_event_id",
        "root_cause_summary",
        "causal_sequence",
        "incident_summary"
    ]
    
    for field in required_fields:
        if field not in crt_data or not crt_data[field]:
            logging.warning(f"[CRT] Missing required field: {field}")
            return None
    
    # Validate causal_sequence is a list
    if not isinstance(crt_data.get("causal_sequence"), list):
        logging.error("[CRT] causal_sequence must be a list")
        return None
    
    if not crt_data["causal_sequence"]:
        logging.error("[CRT] causal_sequence is empty")
        return None
    
    # Validate each step in sequence
    for step in crt_data["causal_sequence"]:
        if not isinstance(step, dict):
            logging.error("[CRT] causal_sequence items must be dictionaries")
            return None
        
        required_step_fields = ["event_id", "role", "description"]
        for field in required_step_fields:
            if field not in step:
                logging.warning(f"[CRT] Missing step field: {field}")
                return None
    
    return crt_data

def enrich_incidents_with_crt(
    incidents: List[Dict],
    crt_results: List[Optional[Dict]]
) -> List[Dict]:
    """
    Merge CRT results back into incident objects.
    
    Args:
        incidents: List of incidents from timeline reconstruction
        crt_results: List of CRT results from generate_crt_with_groq()
    
    Returns:
        Incidents enriched with CRT causal_sequence and metadata
    """
    
    for incident, crt_data in zip(incidents, crt_results):
        if crt_data:
            # Add causal_sequence to incident
            incident["causal_sequence"] = crt_data.get("causal_sequence", [])
            incident["crt_incident_summary"] = crt_data.get("incident_summary", "")
            incident["crt_recommendations"] = crt_data.get("recommendations", [])
            incident["crt_notes"] = crt_data.get("notes", "")
            
            # Update root cause if Groq identified one
            root_event_id = crt_data.get("root_cause_event_id")
            if root_event_id:
                root_event = next(
                    (e for e in incident.get("events", [])
                     if e.get("event_uid") == root_event_id or e.get("event_id") == root_event_id),
                    None
                )
                if root_event:
                    incident["root_cause"] = root_event
                    incident["root_cause_confidence"] = {
                        "high": 0.9,
                        "medium": 0.6,
                        "low": 0.3
                    }.get(crt_data.get("root_cause_confidence", "medium"), 0.6)
            
            # Update llm_guidance
            if "llm_guidance" not in incident:
                incident["llm_guidance"] = {}
            incident["llm_guidance"]["causal_certainty"] = "groq_rest"
            incident["llm_guidance"]["crt_source"] = "groq_rest"
        else:
            # Fallback: mark as no LLM guidance
            if "llm_guidance" not in incident:
                incident["llm_guidance"] = {}
            incident["llm_guidance"]["causal_certainty"] = "none"
            incident["llm_guidance"]["crt_source"] = "none"
    
    return incidents
