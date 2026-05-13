import json
import re
import sys
from pathlib import Path
import hashlib

# =========================================================
# ADD PROJECT ROOT
# =========================================================

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# =========================================================
# IMPORTS
# =========================================================

from schema_conversion.rag_module.schema_convertor.rag_model.Core_RAG.retriever import (
    RAGRetriever
)

from schema_conversion.llm_parser import (
    parse_log
)

from schema_conversion.regex_generation import (
    store_pattern
)


# =========================================================
# CONFIG
# =========================================================

OUTPUT_FILE = r"C:\Users\kavin\Documents\Networking-Incident-Project-HPE-CPP-main\output.json"

REGEX_FILE = r"C:\Users\kavin\Documents\Networking-Incident-Project-HPE-CPP-main\schema_conversion\regex_patterns.json"

MIN_CONFIDENCE_SCORE = 0.60


# =========================================================
# LOAD EXISTING OUTPUT
# =========================================================

def load_existing_output():

    output_path = Path(OUTPUT_FILE)

    if not output_path.exists():
        return []

    try:

        with open(
            output_path,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except Exception:

        return []


# =========================================================
# SAVE OUTPUT
# =========================================================

def save_output(records):

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            records,
            f,
            indent=2
        )


def generate_uid(raw_log):

    return hashlib.sha1(
        raw_log.encode()
    ).hexdigest()


# =========================================================
# LOAD REGEX PATTERNS
# =========================================================

def load_regex_patterns():

    path = Path(REGEX_FILE)

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


# =========================================================
# REGEX MATCHER
# =========================================================

def regex_match_log(
    raw_log,
    regex_patterns
):

    for pattern in regex_patterns:

        try:

            regex = pattern.get(
                "regex_pattern"
            )

            if not regex:
                continue

            match = re.search(
                regex,
                raw_log
            )

            if not match:
                continue

            extracted = match.groupdict()

            schema = {

                "event_uid": generate_uid(raw_log),

                "event_id": pattern.get(
                    "event_id"
                ),

                "type": pattern.get(
                    "type"
                ),

                "subtype": pattern.get(
                    "subtype"
                ),

                "severity": pattern.get(
                    "severity"
                ),

                "message": raw_log,

                "hostname": extracted.get(
                    "hostname"
                ),

                "ip": extracted.get(
                    "ip"
                ),

                "vendor": pattern.get(
                    "vendor"
                ),

                "os": None,

                "interface_id": extracted.get(
                    "interface_id"
                ),

                "vlan": extracted.get(
                    "vlan"
                ),

                "event_time": extracted.get(
                    "event_time"
                ),

                "raw": {
                    "message": raw_log
                }
            }

            return schema

        except Exception:

            continue

    return None


# =========================================================
# NORMALIZE RAG OUTPUT
# =========================================================

def normalize_rag_output(rag_result):

    if not rag_result.get("match_found"):
        return None

    confidence_score = rag_result.get(
        "confidence_score",
        0.0
    )

    if confidence_score < MIN_CONFIDENCE_SCORE:
        return None

    schema = rag_result.get("schema")

    if not schema:
        return None

    return schema


# =========================================================
# MAIN
# =========================================================

def main():

    input_file = input(
        "Enter log file path: "
    ).strip()

    input_path = Path(input_file)

    if not input_path.exists():

        print("Input file not found")

        return

    print("\n================================")
    print("LOADING COMPONENTS")
    print("================================\n")

    retriever = RAGRetriever()

    regex_patterns = load_regex_patterns()

    print(
        f"Loaded {len(regex_patterns)} regex patterns"
    )

    print("Retriever loaded successfully\n")

    existing_records = load_existing_output()

    total = 0

    regex_success = 0

    rag_success = 0

    llm_success = 0

    failed = 0

    with open(
        input_path,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            raw_log = line.strip()

            if not raw_log:
                continue

            total += 1

            print(f"\nProcessing log #{total}")

            try:

                # ====================================
                # REGEX MATCH LAYER
                # ====================================

                regex_schema = regex_match_log(
                    raw_log,
                    regex_patterns
                )

                if regex_schema is not None:

                    existing_records.append(
                        regex_schema
                    )

                    regex_success += 1

                    print("REGEX SUCCESS")

                    continue

                # ====================================
                # RAG LAYER
                # ====================================

                rag_result = retriever.search(
                    raw_log=raw_log,
                    top_k=3
                )

                normalized = normalize_rag_output(
                    rag_result
                )

                if normalized is not None:

                    existing_records.append(
                        normalized
                    )

                    try:

                        store_pattern(
                            raw_log=raw_log,
                            schema=normalized
                        )

                    except Exception as regex_error:

                        print(
                            "Regex generation failed:",
                            regex_error
                        )

                    rag_success += 1

                    print("RAG SUCCESS")

                    print(
                        "Confidence:",
                        rag_result.get(
                            "confidence"
                        )
                    )

                    print(
                        "Score:",
                        rag_result.get(
                            "confidence_score"
                        )
                    )

                    continue

                # ====================================
                # LLM FALLBACK
                # ====================================

                print(
                    "RAG FAILED -> LLM FALLBACK"
                )

                llm_schema = parse_log(
                    raw_log
                )

                existing_records.append(
                    llm_schema
                )

                try:

                    store_pattern(
                        raw_log=raw_log,
                        schema=llm_schema
                    )

                except Exception as regex_error:

                    print(
                        "Regex generation failed:",
                        regex_error
                    )

                llm_success += 1

                print("LLM SUCCESS")

            except Exception as e:

                failed += 1

                print("FAILED")
                print(e)

    save_output(existing_records)

    print("\n================================")
    print("PROCESS COMPLETE")
    print("================================")

    print(f"Total Logs    : {total}")

    print(f"Regex Success : {regex_success}")

    print(f"RAG Success   : {rag_success}")

    print(f"LLM Success   : {llm_success}")

    print(f"Failed        : {failed}")

    print(f"Saved To      : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()