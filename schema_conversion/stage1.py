import json
import re
import requests
from dateutil import parser as dtparser
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


class FewShotLLMLogExtractor:
    """
    Minimal LLM-based semantic log extractor
    with controlled few-shot prompting.

    Extracted fields:
    -----------------
    - timestamp
    - hostname
    - ip
    - vendor
    - os
    - core_message
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

        # =====================================================
        # TIMESTAMP PATTERNS
        # =====================================================

        self.timestamp_patterns = [

            # ISO8601
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T[^\s]+)',

            # Syslog style
            r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})'
        ]

        # =====================================================
        # FEW-SHOT EXAMPLES
        # =====================================================

        self.examples = [

            {
                "input": (
                    "2026-04-03T09:58:04Z "
                    "CORE-RTR-W1 Cisco-IOS "
                    "%BGP-5-ADJCHANGE: "
                    "neighbor 10.10.1.2 Down Interface flap"
                ),

                "output": {
                    "timestamp": "2026-04-03T09:58:04+00:00",
                    "hostname": "CORE-RTR-W1",
                    "ip": None,
                    "vendor": "Cisco",
                    "os": "IOS",
                    "core_message":
                        "neighbor 10.10.1.2 Down Interface flap"
                }
            },

            {
                "input": (
                    "2026-04-03T09:58:05Z "
                    "MONITOR-NODE-01 Linux kernel: "
                    "CPU utilization exceeded 85% "
                    "for 120 seconds"
                ),

                "output": {
                    "timestamp": "2026-04-03T09:58:05+00:00",
                    "hostname": "MONITOR-NODE-01",
                    "ip": None,
                    "vendor": "Linux",
                    "os": "Linux",
                    "core_message":
                        "CPU utilization exceeded 85% "
                        "for 120 seconds"
                }
            },

            {
                "input": (
                    "2026-04-07T08:20:39.861162+00:00 "
                    "9300 ops-switchd[1489]: "
                    "Event|8120|LOG_INFO|AMM|1/1|"
                    "Tunnel 7.7.7.7 "
                    "forwarding_state is operational"
                ),

                "output": {
                    "timestamp":
                        "2026-04-07T08:20:39.861162+00:00",
                    "hostname": "9300",
                    "ip": None,
                    "vendor": "Aruba",
                    "os": "AOS-CX",
                    "core_message":
                        "Tunnel 7.7.7.7 "
                        "forwarding_state is operational"
                }
            },

            {
                "input": (
                    "May 14 14:43:10 "
                    "192.168.1.104 "
                    "hpe-routing[645]: "
                    "[ospf.warn] "
                    "OSPF neighbor 192.168.2.1 "
                    "on VLAN 20 changed state "
                    "from FULL to DOWN"
                ),

                "output": {
                    "timestamp":
                        "2026-05-14T14:43:10",
                    "hostname": "192.168.1.104",
                    "ip": "192.168.1.104",
                    "vendor": "HPE",
                    "os": "AOS-CX",
                    "core_message":
                        "OSPF neighbor 192.168.2.1 "
                        "on VLAN 20 changed state "
                        "from FULL to DOWN"
                }
            }
        ]

    # =========================================================
    # MAIN EXTRACTION
    # =========================================================

    def extract(self, raw_log):

        # -----------------------------------------------------
        # STEP 1 — TIMESTAMP EXTRACTION
        # -----------------------------------------------------

        timestamp = self.extract_timestamp(raw_log)

        # -----------------------------------------------------
        # STEP 2 — BUILD PROMPT
        # -----------------------------------------------------

        prompt = self.build_prompt(
            raw_log,
            timestamp
        )

        # -----------------------------------------------------
        # STEP 3 — CALL LLM
        # -----------------------------------------------------

        result = self.call_llm(prompt)

        # -----------------------------------------------------
        # STEP 4 — VALIDATE OUTPUT
        # -----------------------------------------------------

        validated = self.validate_output(
            result,
            timestamp,
            raw_log
        )

        return validated

    # =========================================================
    # TIMESTAMP EXTRACTION
    # =========================================================

    def extract_timestamp(self, raw_log):

        for pattern in self.timestamp_patterns:

            match = re.match(pattern, raw_log)

            if match:

                ts = match.group("timestamp")

                try:
                    return dtparser.parse(ts).isoformat()

                except Exception:
                    return ts

        return None

    # =========================================================
    # BUILD PROMPT
    # =========================================================

    def build_prompt(self, raw_log, timestamp):

        examples_text = ""

        for ex in self.examples:

            examples_text += f"""

INPUT:
{ex['input']}

OUTPUT:
{json.dumps(ex['output'], indent=2)}

"""

        prompt = f"""
You are an advanced network log semantic extraction engine.

Your task:
------------
Extract ONLY these fields:

1. hostname
2. ip
3. vendor
4. os
5. core_message

The timestamp is already extracted separately.

STRICT RULES:
------------
1. Return ONLY valid JSON
2. No markdown
3. No explanation
4. Missing values must be null
5. Do NOT invent values
6. Preserve semantic meaning exactly
7. Remove:
   - timestamps
   - daemon names
   - metadata prefixes
   - logging headers
   - event formatting tokens
8. core_message must contain ONLY the actual event description

FIELD DEFINITIONS:
------------

hostname:
- primary device/source identifier
- can be hostname or device IP
- examples:
  CORE-RTR-W1
  MONITOR-NODE-01
  9300
  192.168.1.104

OUTPUT SCHEMA:
------------
{{
  "timestamp": "{timestamp}",
  "hostname": null,
  "ip": null,
  "vendor": null,
  "os": null,
  "core_message": null
}}

EXAMPLES:
------------
{examples_text}

NOW PROCESS THIS LOG:
------------
{raw_log}
"""

        return prompt

    # =========================================================
    # CALL LLM
    # =========================================================

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
            timeout=1800
        )

        response.raise_for_status()

        result = response.json()["response"].strip()

        # -----------------------------------------------------
        # CLEANUP
        # -----------------------------------------------------

        result = result.replace("```json", "")
        result = result.replace("```", "")
        result = result.strip()

        return json.loads(result)

    # =========================================================
    # VALIDATION
    # =========================================================

    def validate_output(
        self,
        result,
        timestamp,
        raw_log
    ):

        validated = {

            "timestamp": timestamp,
            "hostname": None,
            "ip": None,
            "vendor": None,
            "os": None,
            "core_message": None,
            "raw_log": raw_log
        }

        for field in [
            "hostname",
            "ip",
            "vendor",
            "os",
            "core_message"
        ]:

            if field in result:
                validated[field] = result[field]

        # -----------------------------------------------------
        # NORMALIZE EMPTY VALUES
        # -----------------------------------------------------

        for k, v in validated.items():

            if v in ["", "null", "None"]:
                validated[k] = None

        return validated


# =============================================================
# TESTING
# =============================================================

if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="Stage 1 - Log Extraction")
    parser.add_argument("--logs", type=str, help="Input logs file or JSON file")
    parser.add_argument("--output", type=str, default=str(PROJECT_ROOT / "stage1_output.json"), help=f"Output JSON file (default: {PROJECT_ROOT / 'stage1_output.json'})")
    parser.add_argument("--single-log", action="store_true", help="Process file as single log (used by log_processor.py)")
    args = parser.parse_args()

    extractor = FewShotLLMLogExtractor()

    # Read logs from file
    if not args.logs:
        print("Error: --logs argument required")
        exit(1)

    logs = []
    try:
        if args.logs.endswith('.json'):
            with open(args.logs, "r", encoding="utf-8") as f:
                data = json.load(f)
                logs = data if isinstance(data, list) else [data]
        else:
            with open(args.logs, "r", encoding="utf-8") as f:
                logs = f.readlines()
    except Exception as e:
        print(f"Error reading file: {e}")
        exit(1)

    results = []

    for idx, log in enumerate(logs, 1):

        log = log.strip()
        if not log:
            continue

        print(f"\nProcessing log {idx}...")

        try:

            result = extractor.extract(log)

            results.append(result)

            print("[OK] Success")

        except Exception as e:

            print(f"[FAIL] Error: {e}")
            results.append({
                "raw_log": log,
                "error": str(e)
            })

    # Save results
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved {len(results)} results to {args.output}")