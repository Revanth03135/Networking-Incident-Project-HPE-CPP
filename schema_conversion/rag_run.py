import json
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from schema_conversion.rag_module.schema_convertor.rag_model.Core_RAG.retriever import RAGRetriever


# =========================================================
# CONFIG
# =========================================================

OUTPUT_FILE = "output.json"


# =========================================================
# LOAD EXISTING OUTPUT
# =========================================================

def load_existing_output():

    output_path = Path(OUTPUT_FILE)

    if not output_path.exists():
        return []

    try:

        with open(output_path, "r", encoding="utf-8") as f:
            return json.load(f)

    except:
        return []


# =========================================================
# SAVE OUTPUT
# =========================================================

def save_output(records):

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


# =========================================================
# NORMALIZE RAG OUTPUT
# =========================================================

def normalize_rag_output(rag_result, raw_log):

    results = rag_result.get("results", [])

    if not results:
        return None

    top = results[0]

    normalized = {

        "event_uid": None,

        "event_id": top.get("event_id"),

        "type": top.get("category"),

        "subtype": top.get("message_template"),

        "severity": top.get("severity"),

        "message": top.get("description"),

        "hostname": None,

        "ip": None,

        "vendor": top.get("vendor"),

        "os": None,

        "interface_id": None,

        "vlan": None,

        "event_time": None,

        "raw": {
            "message": raw_log
        }
    }

    return normalized


# =========================================================
# MAIN
# =========================================================

def main():

    input_file = input("Enter log file path: ").strip()

    input_path = Path(input_file)

    if not input_path.exists():
        print("Input file not found")
        return

    retriever = RAGRetriever()

    existing_records = load_existing_output()

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

                rag_result = retriever.search(
                    raw_log=raw_log,
                    top_k=1
                )

                normalized = normalize_rag_output(
                    rag_result,
                    raw_log
                )

                if normalized is None:

                    failed += 1

                    print("No match found")

                    continue

                existing_records.append(normalized)

                success += 1

                print("SUCCESS")

            except Exception as e:

                failed += 1

                print("FAILED")
                print(e)

    save_output(existing_records)

    print("\n==========================")
    print("PROCESS COMPLETE")
    print("==========================")
    print(f"Total Logs : {total}")
    print(f"Success    : {success}")
    print(f"Failed     : {failed}")
    print(f"Saved To   : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()