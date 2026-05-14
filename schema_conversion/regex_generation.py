#regex_generation.py
import json
import re
import hashlib
import sys
from pathlib import Path

import ollama

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# =========================================================
# CONFIG
# =========================================================

REGEX_STORE_FILE = project_root / "schema_conversion" / "regex_patterns.json"

LLM_MODEL = "qwen:7b"


# =========================================================
# FIELD PLACEHOLDERS
# =========================================================

FIELD_PATTERNS = {

    "event_time": {
        "placeholder": "<EVENT_TIME>",
        "regex": r"(?P<event_time>\S+)"
    },

    "hostname": {
        "placeholder": "<HOSTNAME>",
        "regex": r"(?P<hostname>\S+)"
    },

    "ip": {
        "placeholder": "<IP>",
        "regex": r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    },

    "interface_id": {
        "placeholder": "<INTERFACE>",
        "regex": r"(?P<interface_id>\S+)"
    },

    "vlan": {
        "placeholder": "<VLAN>",
        "regex": r"(?P<vlan>\d+)"
    }
}


# =========================================================
# HELPERS
# =========================================================

def generate_pattern_id(log_text):

    return hashlib.sha1(
        log_text.encode()
    ).hexdigest()[:16]


def load_existing_patterns():

    path = Path(REGEX_STORE_FILE)

    if not path.exists():
        return []

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except Exception:

        return []


def save_patterns(patterns):

    with open(
        REGEX_STORE_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            patterns,
            f,
            indent=2
        )


# =========================================================
# DETERMINISTIC REGEX GENERATION
# =========================================================

def create_regex_pattern(
    raw_log,
    schema
):

    template = raw_log

    replacements = []

    for field, config in FIELD_PATTERNS.items():

        value = schema.get(field)

        if not value:
            continue

        placeholder = config["placeholder"]

        regex_group = config["regex"]

        if str(value) in template:

            template = template.replace(
                str(value),
                placeholder
            )

            replacements.append(
                (
                    placeholder,
                    regex_group
                )
            )

    escaped = re.escape(template)

    for placeholder, regex_group in replacements:

        escaped_placeholder = re.escape(
            placeholder
        )

        escaped = escaped.replace(
            escaped_placeholder,
            regex_group
        )

    escaped = escaped.replace(
        r"\ ",
        r"\s+"
    )

    return escaped


# =========================================================
# VALIDATION
# =========================================================

def validate_regex(
    regex_pattern,
    raw_log
):

    try:

        compiled = re.compile(regex_pattern)

        match = compiled.search(raw_log)

        return match is not None

    except Exception:

        return False


# =========================================================
# LLM BACKUP GENERATOR
# =========================================================

def build_llm_prompt(
    raw_log,
    schema
):

    return f"""
You are an expert regex generator for network logs.

Generate ONLY a valid Python regex pattern.

STRICT RULES:
1. Return ONLY the regex.
2. Use named capture groups.
3. Regex must match the original log.
4. Do NOT explain anything.
5. Use Python regex syntax only.

RAW LOG:
{raw_log}

SCHEMA:
{json.dumps(schema, indent=2)}

Expected named fields:
- event_time
- hostname
- ip
- interface_id
- vlan
"""


def llm_generate_regex(
    raw_log,
    schema
):

    prompt = build_llm_prompt(
        raw_log,
        schema
    )

    response = ollama.chat(
        model=LLM_MODEL,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    regex_pattern = response[
        "message"
    ]["content"].strip()

    regex_pattern = regex_pattern.replace(
        "```regex",
        ""
    )

    regex_pattern = regex_pattern.replace(
        "```",
        ""
    )

    regex_pattern = regex_pattern.strip()

    return regex_pattern


# =========================================================
# MAIN REGEX GENERATOR
# =========================================================

def generate_regex_with_backup(
    raw_log,
    schema
):

    # ============================================
    # TRY DETERMINISTIC GENERATION
    # ============================================

    deterministic_regex = create_regex_pattern(
        raw_log,
        schema
    )

    valid = validate_regex(
        deterministic_regex,
        raw_log
    )

    if valid:

        return deterministic_regex, "deterministic"

    # ============================================
    # FALLBACK TO LLM
    # ============================================

    print(
        "Deterministic regex failed -> LLM fallback"
    )

    llm_regex = llm_generate_regex(
        raw_log,
        schema
    )

    llm_valid = validate_regex(
        llm_regex,
        raw_log
    )

    if not llm_valid:

        raise ValueError(
            "LLM regex generation failed"
        )

    return llm_regex, "llm"


# =========================================================
# STORE PATTERN
# =========================================================

def store_pattern(
    raw_log,
    schema
):

    regex_pattern, source = generate_regex_with_backup(
        raw_log,
        schema
    )

    pattern_record = {

        "pattern_id": generate_pattern_id(
            raw_log
        ),

        "regex_pattern": regex_pattern,

        "type": schema.get("type"),

        "subtype": schema.get("subtype"),

        "severity": schema.get("severity"),

        "vendor": schema.get("vendor"),

        "event_id": schema.get("event_id"),

        "fields": [

            field

            for field in FIELD_PATTERNS

            if schema.get(field) is not None
        ],

        "example_log": raw_log,

        "generation_source": source
    }

    patterns = load_existing_patterns()

    existing_regex = {

        p["regex_pattern"]

        for p in patterns
    }

    if regex_pattern not in existing_regex:

        patterns.append(pattern_record)

        save_patterns(patterns)

        print(
            f"Regex stored ({source})"
        )

    else:

        print("Pattern already exists")

    return pattern_record


# =========================================================
# TEST
# =========================================================

if __name__ == "__main__":

    raw_log = input(
        "Enter raw log:\n"
    ).strip()

    schema_input = input(
        "\nEnter schema JSON:\n"
    ).strip()

    schema = json.loads(schema_input)

    result = store_pattern(
        raw_log,
        schema
    )

    print("\nGenerated Pattern:\n")

    print(
        json.dumps(
            result,
            indent=2
        )
    )