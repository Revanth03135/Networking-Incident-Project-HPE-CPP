import json
import hashlib
import requests
import re
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


class SemanticTemplateGenerator:
    """
    LLM-based Semantic Template Generator

    Responsibilities:
    -----------------
    1. Detect dynamic semantic entities
    2. Generate canonical semantic template
    3. Generate regex from template
    4. Create template fingerprint
    """

    def __init__(
        self,
        model="qwen2.5:14b",
        ollama_url="http://localhost:11434/api/generate"
    ):

        self.model = model
        self.ollama_url = ollama_url

        # ====================================================
        # PLACEHOLDER → REGEX MAP
        # ====================================================

        # ============================================================
# UPDATED PLACEHOLDER → REGEX MAP
# ============================================================

        self.placeholder_regex = {

    "<IP>":
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)",

    "<VLAN>":
        r"(?P<vlan>\d+)",

    "<MAC>":
        r"(?P<mac>[0-9a-fA-F:]{17})",

    # --------------------------------------------------------
    # FIXED IFACE REGEX
    # Supports:
    # 1/1/1
    # Gi0/1
    # xe-0/0/0
    # Port-channel1
    # Po10
    # lag100
    # eth0
    # --------------------------------------------------------

    "<IFACE>":
    r"(?P<interface>[A-Za-z][A-Za-z0-9_\-\/\. ]*)",
    # --------------------------------------------------------
    # NEW SEMANTIC PLACEHOLDER
    # --------------------------------------------------------

    "<INSTANCE_ID>":
    r"(?P<instance_id>\d+)",

"<PROCESS_ID>":
    r"(?P<process_id>\d+)",

"<VNI_ID>":
    r"(?P<vni_id>\d+)",


"<VLAN>":
    r"(?P<vlan>\d+)",

"<COUNT>":
    r"(?P<count>\d+)",

"<PERCENT>":
    r"(?P<percent>\d+)",

"<DURATION>":
    r"(?P<duration>\d+)",

"<SECONDS>":
    r"(?P<seconds>\d+)",

"<VPN_NAME>":
    r"(?P<vpn_name>[A-Za-z0-9_.-]+)",

"<AGGREGATE>":
    r"(?P<aggregate>[A-Za-z0-9_.-]+)",

"<NAMESPACE>":
    r"(?P<namespace>[A-Za-z0-9_.-]+)",

"<SERVICE>":
    r"(?P<service>[A-Za-z0-9_.-]+)",

"<FQDN>":
    r"(?P<fqdn>[A-Za-z0-9_.-]+)",


    "<USER>":
        r"(?P<user>[A-Za-z0-9_.-]+)",
    
    "<LACP_STATE>" : r"(?P<lacp_state>[A-Z]+)"
}

    # ========================================================
    # MAIN ENTRY
    # ========================================================

    def generate(self, core_message):

        # ----------------------------------------------------
        # STEP 1 — LLM ENTITY DETECTION
        # ----------------------------------------------------

        llm_output = self.detect_entities(core_message)

        # ----------------------------------------------------
        # STEP 2 — GENERATE TEMPLATE
        # ----------------------------------------------------

        template = self.build_template(
            core_message,
            llm_output["dynamic_entities"]
        )

        # ----------------------------------------------------
        # STEP 3 — GENERATE REGEX
        # ----------------------------------------------------

        regex_pattern = self.generate_regex(template)

        # ----------------------------------------------------
        # STEP 4 — TEMPLATE HASH
        # ----------------------------------------------------

        template_hash = hashlib.sha256(
            template.encode()
        ).hexdigest()

        return {

            "core_message": core_message,

            "template": template,

            "template_hash": template_hash,

            "dynamic_entities":
                llm_output["dynamic_entities"],

            "regex_pattern": regex_pattern
        }

    # ========================================================
    # LLM ENTITY DETECTION
    # ========================================================

    def detect_entities(self, core_message):

        prompt = f"""
You are a semantic log template mining engine.

Your task:
------------
Analyze the core semantic log message.

Identify ONLY dynamic semantic entities.

STRICT RULES:
------------
1. Return ONLY valid JSON
2. No markdown
3. No explanation
4. Do NOT hallucinate
5. Preserve operational semantics
6. Only mark values that can vary across logs
7. Do NOT replace operational states like:
   - DOWN
   - UP
   - FULL
   - EXSTART
   - operational
   - failed

DYNAMIC ENTITY TYPES:
------------
- IP: IPv4 address (192.168.1.1)
- VLAN: VLAN ID (numeric)
- MAC: MAC address
- IFACE: Interface name (Gi0/1, eth0, 1/1/1)
- PROCESS_ID: Process/thread ID
- INSTANCE_ID: Instance or index number
- VNI_ID: VXLAN VNI ID
- DURATION: Time duration in seconds (use when describing time intervals)
- SECONDS: Time measurement (use for duration values)
- PERCENT: Percentage value
- VPN_NAME: Named VPN tunnel
- AGGREGATE: Named aggregate or keyword (NOT numeric)
- NAMESPACE: Named namespace or context
- SERVICE: Named service
- FQDN: Fully qualified domain name
- USER: Username
- NUM: Generic number (hardware part numbers, etc.) 


OUTPUT FORMAT:
------------
{{
  "dynamic_entities": [
    {{
      "value": "...",
      "placeholder": "<IP>"
    }}
  ]
}}

EXAMPLES:
------------

INPUT:
Instance 0: Port 1/1/1 changed state from LEARNING to FORWARDING

OUTPUT:
{{
  "dynamic_entities": [
    {{
      "value": "0",
      "placeholder": "<INSTANCE_ID>"
    }},
    {{
      "value": "1/1/1",
      "placeholder": "<IFACE>"
    }}
  ]
}}


INPUT:
OSPF neighbor 192.168.2.1 on VLAN 20 changed state from FULL to DOWN

OUTPUT:
{{
  "dynamic_entities": [
    {{
      "value": "192.168.2.1",
      "placeholder": "<IP>"
    }},
    {{
      "value": "20",
      "placeholder": "<VLAN>"
    }}
  ]
}}

INPUT:
Interface GigabitEthernet0/1 changed state to down

OUTPUT:
{{
  "dynamic_entities": [
    {{
      "value": "GigabitEthernet0/1",
      "placeholder": "<IFACE>"
    }}
  ]
}}

INPUT:
Power supply PSU-2 failure detected

OUTPUT:
{{
  "dynamic_entities": [
    {{
      "value": "PSU-2",
      "placeholder": "<NUM>"
    }}
  ]
}}

INPUT:
CPU utilization exceeded 85% for 120 seconds

OUTPUT:
{{
  "dynamic_entities": [
    {{
      "value": "85",
      "placeholder": "<PERCENT>"
    }},
    {{
      "value": "120",
      "placeholder": "<DURATION>"
    }}
  ]
}}

INPUT:
Interface down for 45 seconds

OUTPUT:
{{
  "dynamic_entities": [
    {{
      "value": "45",
      "placeholder": "<SECONDS>"
    }}
  ]
}}

NOW PROCESS THIS MESSAGE:
------------
{core_message}
"""

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

        result = result.replace("```json", "")
        result = result.replace("```", "")
        result = result.strip()

        parsed = json.loads(result)

        return parsed

    # ========================================================
    # BUILD TEMPLATE
    # ========================================================

    def build_template(
        self,
        core_message,
        dynamic_entities
    ):

        template = core_message

        # ----------------------------------------------------
        # LONGEST FIRST
        # Prevent partial replacement conflicts
        # ----------------------------------------------------

        dynamic_entities = sorted(
            dynamic_entities,
            key=lambda x: len(x["value"]),
            reverse=True
        )

        for entity in dynamic_entities:

            value = entity["value"]

            placeholder = entity["placeholder"]

            template = template.replace(
                value,
                placeholder,
                1  # Replace only first occurrence to handle duplicates properly
            )

        # ====================================================
        # HANDLE DUPLICATE PLACEHOLDERS
        # ====================================================
        # If same placeholder appears multiple times, make them unique
        # e.g., <PERCENT> → <PERCENT>, <PERCENT_2>, <PERCENT_3>...
        
        placeholder_counts = {}
        result_template = template
        
        # Find all placeholder patterns
        import re as regex_module
        placeholders_found = regex_module.findall(r'<[A-Z_]+>', template)
        
        # Track occurrences and make duplicates unique
        for placeholder in placeholders_found:
            if placeholder not in placeholder_counts:
                placeholder_counts[placeholder] = 0
            placeholder_counts[placeholder] += 1
        
        # If any placeholder appears more than once, make subsequent ones unique
        current_counts = {}
        for placeholder in placeholders_found:
            if placeholder_counts[placeholder] > 1:
                if placeholder not in current_counts:
                    current_counts[placeholder] = 1
                else:
                    current_counts[placeholder] += 1
                    # Replace Nth occurrence with unique version
                    unique_placeholder = f"{placeholder[:-1]}__{current_counts[placeholder]}>"
                    result_template = result_template.replace(placeholder, unique_placeholder, 1)
        
        return result_template

    # ========================================================
    # GENERATE REGEX
    # ========================================================

    def generate_regex(self, template):

        regex = re.escape(template)

        # ====================================================
        # Replace placeholders with regex patterns
        # Handle both regular and unique (counted) placeholders
        # ====================================================

        for placeholder, pattern in self.placeholder_regex.items():

            escaped_placeholder = re.escape(placeholder)

            # Standard placeholder (e.g., <IP>)
            regex = regex.replace(
                escaped_placeholder,
                pattern
            )
            
            # Handle duplicate/unique versions (e.g., <PERCENT__2>)
            # Extract base placeholder name (e.g., PERCENT from <PERCENT__2>)
            base_placeholder = placeholder[1:-1]  # Remove < and >
            
            # Find all variants like <PERCENT__2>, <PERCENT__3>, etc.
            import re as regex_module
            unique_variants = regex_module.findall(
                f'{re.escape(placeholder[:-1])}__\\d+>',
                template
            )
            
            for variant in set(unique_variants):
                # Extract the counter number
                counter = variant.split('__')[1].rstrip('>')
                
                # Create unique group name (e.g., percent_2)
                base_name = pattern.split('(?P<')[1].split('>')[0]
                unique_group_name = f"{base_name}_{counter}"
                
                # Create unique pattern
                unique_pattern = pattern.replace(
                    f"(?P<{base_name}",
                    f"(?P<{unique_group_name}"
                )
                
                escaped_variant = re.escape(variant)
                regex = regex.replace(escaped_variant, unique_pattern)

        regex = "^" + regex + "$"

        return regex


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    import argparse
    
    parser = argparse.ArgumentParser(description="Template Generator")
    parser.add_argument("--input", type=str, help="Input JSON file with core_messages")
    parser.add_argument("--output", type=str, default=str(PROJECT_ROOT / "template1_output.json"), help=f"Output JSON file (default: {PROJECT_ROOT / 'template1_output.json'})")
    parser.add_argument("--single-log", action="store_true", help="Process single log mode (used by log_processor.py)")
    args = parser.parse_args()
    
    # Load core_messages
    if args.input:
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                stage1_data = json.load(f)
            
            core_messages = []
            if isinstance(stage1_data, list):
                core_messages = [
                    entry.get("core_message") if isinstance(entry, dict) else entry
                    for entry in stage1_data
                    if (entry.get("core_message") if isinstance(entry, dict) else entry)
                ]
            
            if not core_messages:
                print("No core_messages found in input file")
                exit(1)
                
        except FileNotFoundError:
            print("Error: Input file not found")
            exit(1)
        except json.JSONDecodeError:
            print("Error: Invalid JSON in input file")
            exit(1)
    else:
        # Load core_messages from stage1_output.json in project root
        default_input = PROJECT_ROOT / "stage1_output.json"
        try:
            with open(default_input, "r", encoding="utf-8") as f:
                stage1_data = json.load(f)
            
            core_messages = []
            if isinstance(stage1_data, list):
                core_messages = [
                    entry.get("core_message")
                    for entry in stage1_data
                    if entry.get("core_message")
                ]
            
            if not core_messages:
                print("No core_messages found in stage1_output.json")
                exit(1)
                
        except FileNotFoundError:
            print(f"Error: stage1_output.json not found at {default_input}")
            exit(1)
        except json.JSONDecodeError:
            print("Error: Invalid JSON in stage1_output.json")
            exit(1)

    generator = SemanticTemplateGenerator()

    results = []

    for idx, msg in enumerate(core_messages, 1):

        if not args.single_log:
            print("\n" + "=" * 100)
            print(f"TEMPLATE {idx}")
            print("=" * 100)

        try:

            result = generator.generate(msg)

            if not args.single_log:
                print(json.dumps(result, indent=2))
            
            results.append(result)

        except Exception as e:

            if not args.single_log:
                print(f"ERROR: {e}")
            results.append({
                "error": str(e),
                "core_message": msg
            })

    # Save results to output file
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        if not args.single_log:
            print("\n" + "=" * 100)
            print(f"[OK] Saved {len(results)} templates to {args.output}")
            print("=" * 100)
        
    except Exception as e:
        print(f"[FAIL] Error saving to {args.output}: {e}")