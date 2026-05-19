import json
import requests
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
        model="qwen2.5:14b",
        ollama_url="http://localhost:11434/api/generate"
    ):

        self.model = model
        self.ollama_url = ollama_url

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

        prompt = self.build_prompt(core_message)

        result = self.call_llm(prompt)

        validated = self.validate(result)

        return validated

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

STRICT RULES:
------------
1. Return ONLY valid JSON
2. No markdown
3. No explanation
4. Do NOT hallucinate
5. Do NOT invent values
6. If uncertain, return null 
7. interface_id must ONLY be extracted if explicitly present
8. Severity must reflect actual operational impact
9. Do NOT assume all DOWN events are critical
10. Do NOT infer vendor/platform

ALLOWED TYPES:
------------
- routing
- security
- system
- interface
- overlay
- fabric
- storage
- orchestration
- time
- generic

ALLOWED SEVERITIES:
------------
- info
- warning
- error
- critical

FIELD DEFINITIONS:
------------

type:
High-level operational domain.

Examples:
- BGP/OSPF -> routing
- VPN/IPSec -> security
- CPU/Fan/Power -> system
- Interface/VLAN/VXLAN -> interface
- EVPN/VXLAN overlays -> overlay
- Cassandra/Gossip -> storage
- Kubernetes/Pods -> orchestration

subtype:
Normalized operational subsystem or protocol label.

Examples:
- bgp
- ospf
- mstp
- vxlan
- evpn
- vpn
- dns
- ntp
- ldap
- ssh
- cpu
- memory
- fan
- power
- telemetry
- replication
- database
- api
- interface
- topology
- latency
- kubernetes
- authentication
- configuration
- transceiver

severity:
Operational impact level.

Guidelines:
- informational state -> info
- transient degradation -> warning
- failed operation -> error
- severe outage/data-path failure -> critical

interface_id:
Extract ONLY if explicitly present.

Examples:
- vxlan 1
- Ethernet1/1
- VLAN 20
- Tunnel 7.7.7.7

If no explicit interface exists:
return null.

OUTPUT SCHEMA:
------------
{{
  "type": null,
  "subtype": null,
  "severity": null,
  "interface_id": null
}}

EXAMPLES:
------------

INPUT:
neighbor 10.10.1.2 Down Interface flap

OUTPUT:
{{
  "type": "routing",
  "subtype": "bgp",
  "severity": "warning",
  "interface_id": null
}}

INPUT:
Tunnel 7.7.7.7 forwarding_state is operational

OUTPUT:
{{
  "type": "overlay",
  "subtype": "vxlan",
  "severity": "info",
  "interface_id": "Tunnel 7.7.7.7"
}}

INPUT:
OSPF neighbor 192.168.2.1 on VLAN 20 changed state from FULL to DOWN

OUTPUT:
{{
  "type": "routing",
  "subtype": "ospf",
  "severity": "warning",
  "interface_id": "VLAN 20"
}}

INPUT:
Power supply PSU-2 failure detected

OUTPUT:
{{
  "type": "system",
  "subtype": "power",
  "severity": "critical",
  "interface_id": null
}}

INPUT:
failed to setup network for sandbox 3f2a91 because BGP session unexpectedly closed

OUTPUT:
{{
  "type": "orchestration",
  "subtype": "kubernetes",
  "severity": "error",
  "interface_id": null
}}

NOW ANALYZE THIS CORE MESSAGE:
------------
{core_message}
"""

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

                "top_p": 0.1,

                "repeat_penalty": 1.0,

                "num_predict": 256
            }
        }

        response = requests.post(
            self.ollama_url,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        result = response.json()["response"].strip()

        # ----------------------------------------------------
        # Cleanup
        # ----------------------------------------------------

        result = result.replace("```json", "")
        result = result.replace("```", "")
        result = result.strip()

        return json.loads(result)

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate(self, result):

        validated = {

            "type": None,
            "subtype": None,
            "severity": None,
            "interface_id": None
        }

        # ----------------------------------------------------
        # TYPE VALIDATION
        # ----------------------------------------------------

        if result.get("type") in self.allowed_types:
            validated["type"] = result["type"]

        # ----------------------------------------------------
        # SEVERITY VALIDATION
        # ----------------------------------------------------

        if result.get("severity") in self.allowed_severities:
            validated["severity"] = result["severity"]

        # ----------------------------------------------------
        # SAFE COPY
        # ----------------------------------------------------

        if result.get("subtype"):
            validated["subtype"] = result["subtype"]

        if result.get("interface_id"):
            validated["interface_id"] = result["interface_id"]

        # ----------------------------------------------------
        # Normalize empty values
        # ----------------------------------------------------

        for k, v in validated.items():

            if v in ["", "null", "None"]:
                validated[k] = None

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