import json
import requests
from pathlib import Path
import re 

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


class CoreMessageSemanticAnalyzer:
    """
    STAGE 2 — Semantic Event Analyzer

    Input:
    ------
    Core semantic message from Stage-1 extractor.

    Responsibilities:
    -----------------
    - Determine event type
    - Determine subtype
    - Determine severity
    - Extract interface_id if explicitly present

    IMPORTANT:
    ----------
    - No hallucinations
    - No unsupported assumptions
    - Only infer directly supported semantics
    """

    def __init__(
        self,
        model=None,
        ollama_url=None
    ):
        import os
        from dotenv import load_dotenv
        load_dotenv()
        
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
        self.ollama_url = ollama_url or os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")

        # ----------------------------------------------------
        # Allowed schema enums
        # ----------------------------------------------------

        self.allowed_types = [

            "routing",
            "security",
            "system",
            "interface",
            "overlay",
            "fabric",
            "storage",
            "orchestration",
            "time",
            "generic"
            
        ]
        self.allowed_subtypes = [
            "bgp", "bgp session down", "bgp neighbor down",
            "ospf", "ospf neighbor down", "ospf adjacency lost",
            "interface", "interface flap", "interface down", "link down",
            "arp", "spanning_tree", "routing", "packet_drop",
            "cpu", "cpu high", "memory", "system", "security",
            "authentication_failure", "dns", "generic"
        ]
        self.allowed_severities = [

            "info",
            "warning",
            "error",
            "critical"
        ]

    # ========================================================
    # MAIN ANALYSIS
    # ========================================================

    def analyze(self, core_message):

        try:
            prompt = self.build_prompt(core_message)

            result = self.call_llm(prompt)

            validated = self.validate(result)

            return validated
            
        except Exception as e:
            print(f"[ERROR] Analysis failed for '{core_message[:80]}': {type(e).__name__}: {e}")
            raise

    def is_valid_canonical_event(self, value):

        if not value:
            return False

        return bool(
            re.fullmatch(
                r"[a-z0-9_]+",
                value
            )
        )

    # ========================================================
    # PROMPT
    # ========================================================

    def build_prompt(self, core_message):

        return f"""
You are a distributed systems semantic event analyzer.

Your task:
------------
Analyze ONLY the provided core semantic message.

Determine:

1. type
2. subtype
3. severity
4. interface_id
5. event_object
6. event_action
7. canonical_event_msg

Return ONLY valid JSON.

STRICT RULES
------------
1. Return ONLY valid JSON.
2. No markdown.
3. No explanation.
4. No comments.
5. No hallucinations.
6. Do NOT invent protocol names.
7. Do NOT invent interfaces.
8. Do NOT infer vendors.
9. If uncertain return null.
10.Use only information directly supported by the message.
11.Choose the closest match from the allowed_subtypes list.
ALLOWED TYPES
------------
routing
security
system
interface
overlay
fabric
storage
orchestration
time
generic

ALLOWED SEVERITIES
------------
info
warning
error
critical

FIELD DEFINITIONS
------------

type:
High-level operational domain.

Examples:

BGP
OSPF
ISIS
→ routing

Authentication
VPN
IPSec
SSH
LDAP
→ security

CPU
Memory
Power
Fan
Temperature
→ system

Physical interfaces
Ports
VLANs
Link state
→ interface

VXLAN
EVPN
Overlay tunnels
→ overlay

STP
MSTP
Topology
LLDP
→ fabric

Databases
Replication
Storage clusters
→ storage

Kubernetes
Containers
Pods
→ orchestration

NTP
Clock synchronization
→ time

Unknown events
→ generic

subtype:
Normalized subsystem.

Examples:

bgp
ospf
isis
stp
mstp
vxlan
evpn
vpn
authentication
ssh
dns
ntp
cpu
memory
power
fan
temperature
replication
database
configuration
transceiver
topology
interface

severity:
Operational impact.

info:
Normal state changes.

warning:
Degradation.
Threshold exceeded.
Link flap.
CRC errors.

error:
Operation failed.

critical:
Severe outage.
Power failure.
Storage failure.
Major service loss.

interface_id:
Extract ONLY if explicitly present.

Examples:

Ethernet1/1
Port 1/1/1
VLAN 10
Vxlan1
Tunnel 7.7.7.7

If absent:
null

IMPORTANT PROTOCOL RULE
-----------------------

Never infer protocol names.

Examples:

"connection closed"

DO NOT ASSUME:

bgp
ospf
vxlan
ssh

Use:

type = generic

unless protocol is explicitly mentioned.

EVENT SEMANTICS
---------------

Determine the operational action.

Allowed event_action values:

up
down
created
deleted
inserted
removed
failure
restored
high
low
warning
success
logout
login
detected
changed
discovered
lost
established
closed
flapping
degraded

Examples:

Interface down
→ down

Interface up
→ up

VLAN created
→ created

VLAN deleted
→ deleted

Transceiver inserted
→ inserted

Transceiver removed
→ removed

Power supply failed
→ failure

Power restored
→ restored

CPU utilization high
→ high

Authentication successful
→ success

Client logged out
→ logout

Topology change detected
→ changed

LLDP neighbor discovered
→ discovered

event_object
------------

Determine the normalized object affected.

Examples:

interface
vlan
bgp_neighbor
ospf_neighbor
vxlan_tunnel
power_supply
fan
cpu
memory
authentication
configuration
topology
transceiver
dns
ntp
database_replication
connection

canonical_event_msg
--------------------

Generate:

<object>_<action>

Rules:

1. lowercase only
2. underscores only
3. no spaces
4. no IP addresses
5. no interface names
6. no timestamps
7. no vendor names
8. deterministic naming

Examples:

interface_down

interface_up

vlan_created

vlan_deleted

bgp_neighbor_down

bgp_neighbor_up

ospf_neighbor_down

ospf_neighbor_up

vxlan_tunnel_down

vxlan_tunnel_up

power_supply_failure

power_supply_restored

fan_failure

fan_restored

cpu_high

memory_high

authentication_failure

authentication_success

authentication_logout

configuration_changed

topology_changed

transceiver_inserted

transceiver_removed

database_replication_failure

database_replication_lag_high

dns_resolution_failure

ntp_sync_lost

ntp_sync_restored

NORMALIZATION EXAMPLES
----------------------

INPUT:
Interface Ethernet1/1 went down

OUTPUT:

{{
  "type":"interface",
  "subtype":"interface",
  "severity":"warning",
  "interface_id":"Ethernet1/1",
  "event_object":"interface",
  "event_action":"down",
  "canonical_event_msg":"interface_down"
}}

INPUT:
Port Ethernet1/1 lost carrier

OUTPUT:

{{
  "type":"interface",
  "subtype":"interface",
  "severity":"warning",
  "interface_id":"Ethernet1/1",
  "event_object":"interface",
  "event_action":"down",
  "canonical_event_msg":"interface_down"
}}

INPUT:
Ethernet1/1 operationally disabled

OUTPUT:

{{
  "type":"interface",
  "subtype":"interface",
  "severity":"warning",
  "interface_id":"Ethernet1/1",
  "event_object":"interface",
  "event_action":"down",
  "canonical_event_msg":"interface_down"
}}

INPUT:
BGP session lost

OUTPUT:

{{
  "type":"routing",
  "subtype":"bgp",
  "severity":"warning",
  "interface_id":null,
  "event_object":"bgp_neighbor",
  "event_action":"down",
  "canonical_event_msg":"bgp_neighbor_down"
}}

INPUT:
Power supply failure detected

OUTPUT:

{{
  "type":"system",
  "subtype":"power",
  "severity":"critical",
  "interface_id":null,
  "event_object":"power_supply",
  "event_action":"failure",
  "canonical_event_msg":"power_supply_failure"
}}

INPUT:
VLAN 10 created

OUTPUT:

{{
  "type":"interface",
  "subtype":"vlan",
  "severity":"info",
  "interface_id":"VLAN 10",
  "event_object":"vlan",
  "event_action":"created",
  "canonical_event_msg":"vlan_created"
}}

INPUT:
Client logged out

OUTPUT:

{{
  "type":"security",
  "subtype":"authentication",
  "severity":"info",
  "interface_id":null,
  "event_object":"authentication",
  "event_action":"logout",
  "canonical_event_msg":"authentication_logout"
}}

INPUT:
Connection closed

OUTPUT:

{{
  "type":"generic",
  "subtype":"connection",
  "severity":"info",
  "interface_id":null,
  "event_object":"connection",
  "event_action":"closed",
  "canonical_event_msg":"connection_closed"
}}

DETERMINISM REQUIREMENT
-----------------------

If two messages describe the same operational meaning,
they MUST produce exactly the same:

event_object
event_action
canonical_event_msg

Examples:

"Interface down"
"Link failure"
"Port lost carrier"

ALL MUST RETURN:

event_object = interface
event_action = down
canonical_event_msg = interface_down

Examples:

"BGP session closed"
"BGP neighbor lost"
"Neighbor adjacency dropped"

ALL MUST RETURN:

event_object = bgp_neighbor
event_action = down
canonical_event_msg = bgp_neighbor_down

Examples:

"Power supply failure"
"PSU fault"
"Power module failure"

ALL MUST RETURN:

event_object = power_supply
event_action = failure
canonical_event_msg = power_supply_failure

NOW ANALYZE THIS CORE MESSAGE:

{core_message}"""

    # ========================================================
    # LLM CALL
    # ========================================================

    def call_llm(self, prompt):

        payload = {

            "model": self.model,

            "prompt": prompt,

            "stream": False,

            "options": {

    "temperature": 0,
    "top_p": 0.01,
    "repeat_penalty": 1.0,
    "num_predict": 256
}
        }

        try:
            response = requests.post(
                self.ollama_url,
                json=payload,
                timeout=1800
            )

            response.raise_for_status()

            result = response.json()["response"].strip()

            # Cleanup markdown code blocks if present
            result = result.replace("```json", "")
            result = result.replace("```", "")
            result = result.strip()

            return json.loads(result)
            
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse LLM response as JSON: {e}")
            raise
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] LLM API request failed: {e}")
            raise
        except Exception as e:
            print(f"[ERROR] Unexpected error in LLM call: {type(e).__name__}: {e}")
            raise

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate(self, result):

        validated = {

    "type": None,
    "subtype": None,
    "severity": None,
    "interface_id": None,
    "canonical_event_msg": None
}

        # TYPE VALIDATION
        if result.get("type") in self.allowed_types:
            validated["type"] = result["type"]

        # SEVERITY VALIDATION
        if result.get("severity") in self.allowed_severities:
            validated["severity"] = result["severity"]

        # SAFE COPY
        if result.get("subtype"):
            validated["subtype"] = result["subtype"]

        if result.get("interface_id"):
            validated["interface_id"] = result["interface_id"]

        # Normalize empty values
        for k, v in validated.items():
            if v in ["", "null", "None"]:
                validated[k] = None

        # Validate canonical event message
        if self.is_valid_canonical_event(result.get("canonical_event_msg")):
            validated["canonical_event_msg"] = result["canonical_event_msg"]
    
        return validated


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="Stage 2 - Semantic Analysis")
    parser.add_argument("--input", type=str, help="Input JSON file from stage1")
    parser.add_argument("--output", type=str, default=str(PROJECT_ROOT / "stage2_output.json"), help=f"Output JSON file (default: {PROJECT_ROOT / 'stage2_output.json'})")
    parser.add_argument("--single-log", action="store_true", help="Return semantic analysis only (used by log_processor.py)")
    args = parser.parse_args()

    if not args.input:
        print("Error: --input argument required (stage1 output JSON)")
        exit(1)

    analyzer = CoreMessageSemanticAnalyzer()

    # Load stage1 output
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            stage1_results = json.load(f)
    except Exception as e:
        print(f"Error reading input file: {e}")
        exit(1)

    results = []

    for idx, entry in enumerate(stage1_results, 1):

        core_msg = entry.get("core_message")

        if not core_msg:
            print(f"\nSkipping entry {idx}: No core_message")
            if args.single_log:
                results.append({
                    "error": "No core_message"
                })
            else:
                results.append({
                    **entry,
                    "semantic_analysis": None,
                    "error": "No core_message"
                })
            continue

        print(f"\nAnalyzing entry {idx}: {core_msg[:60]}...")

        try:

            analysis = analyzer.analyze(core_msg)

            if args.single_log:
                # Return only the semantic analysis
                results.append(analysis)
            else:
                # Return full result with semantic_analysis
                result = {
                    **entry,
                    "semantic_analysis": analysis
                }
                results.append(result)

            print(f"[OK] Success - Type: {analysis.get('type')}")

        except Exception as e:

            print(f"[FAIL] Error: {e}")
            if args.single_log:
                results.append({
                    "error": str(e)
                })
            else:
                results.append({
                    **entry,
                    "semantic_analysis": None,
                    "error": str(e)
                })

    # Save results
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved {len(results)} results to {args.output}")