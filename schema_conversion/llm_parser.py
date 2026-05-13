import json
import hashlib
from pathlib import Path

import ollama


# =========================================================
# CONFIG
# =========================================================

MODEL_NAME = "qwen:7b"

INPUT_LOG_FILE = None

OUTPUT_FILE = "parsed_output.jsonl"

MAX_LOG_LENGTH = 5000


# =========================================================
# FEW-SHOT EXAMPLES
# =========================================================

EXAMPLES = """
==================================================
EXAMPLE 1
==================================================

RAW LOG:
2026-04-03T09:58:11Z CORE-RTR-01 Cisco-IOS %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down

OUTPUT:
{
  "type": "interface",
  "subtype": "link",
  "severity": "error",
  "message": "Interface down",
  "hostname": "CORE-RTR-01",
  "ip": null,
  "vendor": "cisco",
  "os": "Cisco-IOS",
  "interface_id": "GigabitEthernet0/1",
  "vlan": null,
  "event_time": "2026-04-03T09:58:11Z"
}

==================================================
EXAMPLE 2
==================================================

RAW LOG:
2026-04-03T09:58:20Z CORE-RTR-01 Cisco-IOS %OSPF-5-ADJCHG: Process 1, Nbr 10.10.10.2 on GigabitEthernet0/1 from FULL to DOWN

OUTPUT:
{
  "type": "routing",
  "subtype": "ospf",
  "severity": "info",
  "message": "OSPF neighbor down",
  "hostname": "CORE-RTR-01",
  "ip": "10.10.10.2",
  "vendor": "cisco",
  "os": "Cisco-IOS",
  "interface_id": "GigabitEthernet0/1",
  "vlan": null,
  "event_time": "2026-04-03T09:58:20Z"
}

==================================================
EXAMPLE 3
==================================================

RAW LOG:
2026-04-03T09:59:00Z CORE-RTR-01 Cisco-IOS %BGP-5-ADJCHANGE: neighbor 192.168.254.2 Down Interface flap

OUTPUT:
{
  "type": "routing",
  "subtype": "bgp",
  "severity": "info",
  "message": "BGP neighbor down",
  "hostname": "CORE-RTR-01",
  "ip": "192.168.254.2",
  "vendor": "cisco",
  "os": "Cisco-IOS",
  "interface_id": null,
  "vlan": null,
  "event_time": "2026-04-03T09:59:00Z"
}

==================================================
EXAMPLE 4
==================================================

RAW LOG:
2026-04-03T09:59:24Z DIST-SW-01 ArubaOS-Switch Port 1/1/48 is now on-line

OUTPUT:
{
  "type": "interface",
  "subtype": "link",
  "severity": "info",
  "message": "Interface up",
  "hostname": "DIST-SW-01",
  "ip": null,
  "vendor": "aruba",
  "os": "ArubaOS-Switch",
  "interface_id": "1/1/48",
  "vlan": null,
  "event_time": "2026-04-03T09:59:24Z"
}

==================================================
EXAMPLE 5
==================================================

RAW LOG:
2026-04-03T10:05:00Z ARISTA-SW-01 Arista-EOS TRANSCEIVER-3-ALARM: Ethernet1 optical power below threshold

OUTPUT:
{
  "type": "hardware",
  "subtype": "transceiver",
  "severity": "error",
  "message": "Optical power below threshold",
  "hostname": "ARISTA-SW-01",
  "ip": null,
  "vendor": "arista",
  "os": "Arista-EOS",
  "interface_id": "Ethernet1",
  "vlan": null,
  "event_time": "2026-04-03T10:05:00Z"
}
"""


# =========================================================
# HELPERS
# =========================================================

def generate_uid(raw_log: str):
    return hashlib.sha1(raw_log.encode()).hexdigest()


def build_prompt(raw_log: str):

    return f"""
You are an expert network log parser.

Convert the RAW LOG into structured JSON.

STRICT RULES:
1. Return ONLY valid JSON.
2. Do NOT explain anything.
3. Use null for missing fields.
4. Keep subtype short and canonical.
5. Do NOT invent fields.
6. Preserve exact interface names.
7. Preserve exact hostname.
8. Preserve exact timestamp.
9. Vendor names should be lowercase.
10. Do NOT add extra fields.

Allowed type values:
- interface
- routing
- security
- hardware
- system

Allowed severity values:
- info
- warning
- error
- critical

Schema format:

{{
  "type": "string",
  "subtype": "string",
  "severity": "string",
  "message": "string",
  "hostname": "string or null",
  "ip": "string or null",
  "vendor": "string or null",
  "os": "string or null",
  "interface_id": "string or null",
  "vlan": "string or null",
  "event_time": "string or null"
}}

{EXAMPLES}

==================================================
NOW PARSE THIS LOG
==================================================

RAW LOG:
{raw_log}
"""


def extract_json(text):

    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1:
        raise ValueError("No JSON found")

    json_text = text[start:end + 1]

    return json.loads(json_text)


def normalize_schema(schema, raw_log):

    schema["event_uid"] = generate_uid(raw_log)

    schema["event_id"] = None

    schema["raw_message"] = raw_log

    required_fields = [
        "event_uid",
        "event_id",
        "type",
        "subtype",
        "severity",
        "message",
        "hostname",
        "ip",
        "vendor",
        "os",
        "interface_id",
        "vlan",
        "event_time",
        "raw_message"
    ]

    for field in required_fields:
        if field not in schema:
            schema[field] = None

    return schema


def save_output(schema):

    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(schema) + "\n")


# =========================================================
# MAIN PARSER
# =========================================================

def parse_log(raw_log):

    if len(raw_log) > MAX_LOG_LENGTH:
        raise ValueError("Log too large")

    prompt = build_prompt(raw_log)

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    llm_output = response["message"]["content"]

    parsed = extract_json(llm_output)
    parsed["raw_message"] = raw_log
    normalized = normalize_schema(parsed, raw_log)

    return normalized


# =========================================================
# FINAL OUTPUT GENERATOR
# =========================================================

FINAL_OUTPUT_FILE = "output.json"


def generate_final_output():

    final_records = []

    parsed_path = Path(OUTPUT_FILE)

    if not parsed_path.exists():
        print("parsed_output.jsonl not found")
        return

    with open(parsed_path, "r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            record = json.loads(line)

            raw_message = record.get("raw_message", "")

            final_schema = {

                "event_uid": generate_uid(raw_message),

                "event_id": None,

                "type": record.get("type"),

                "subtype": record.get("subtype"),

                "severity": record.get("severity"),

                "message": record.get("message"),

                "hostname": record.get("hostname"),

                "ip": record.get("ip"),

                "vendor": record.get("vendor"),

                "os": record.get("os"),

                "interface_id": record.get("interface_id"),

                "vlan": record.get("vlan"),

                "event_time": record.get("event_time"),

                "raw": {
                    "message": raw_message
                }
            }

            final_records.append(final_schema)

    with open(FINAL_OUTPUT_FILE, "w", encoding="utf-8") as f:

        json.dump(final_records, f, indent=2)

    print("\nFinal output generated")
    print(f"Saved to: {FINAL_OUTPUT_FILE}")

# =========================================================
# MAIN EXECUTION
# =========================================================

def main(input_log_file=None):

    if input_log_file is None:

        input_log_file = input(
            "Enter log file path: "
        ).strip()

    input_path = Path(input_log_file)

    if not input_path.exists():
        print("Input file not found")
        return

    total = 0
    success = 0
    failed = 0

    with open(input_path, "r", encoding="utf-8") as f:

        for line in f:

            raw_log = line.strip()

            if not raw_log:
                continue

            total += 1

            print(f"Processing log #{total}")

            try:

                parsed_schema = parse_log(raw_log)

                save_output(parsed_schema)

                success += 1

                print("SUCCESS")

            except Exception as e:

                failed += 1

                print("FAILED")
                print(e)

    print("\n======================")
    print("PROCESS COMPLETE")
    print("======================")
    print(f"Total Logs : {total}")
    print(f"Success    : {success}")
    print(f"Failed     : {failed}")
    print(f"Saved To   : {OUTPUT_FILE}")
    generate_final_output()

if __name__ == "__main__":
    main()