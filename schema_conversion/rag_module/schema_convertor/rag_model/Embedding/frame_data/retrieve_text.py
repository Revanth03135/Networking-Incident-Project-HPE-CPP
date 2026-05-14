from typing import Dict, List


def build_retrieval_text(record: Dict) -> str:
    """
    Convert a KB record into embedding text.
    """

    parts: List[str] = []

    # ----------------------------
    # Core identity
    # ----------------------------
    parts.append(f"Vendor: {record.get('vendor')}")
    
    if record.get("product_family"):
        parts.append(f"Product Family: {record['product_family']}")

    parts.append(f"Event ID: {record.get('event_id')}")

    # ----------------------------
    # Metadata
    # ----------------------------
    if record.get("category"):
        parts.append(f"Category: {record['category']}")

    if record.get("severity"):
        parts.append(f"Severity: {record['severity']}")

    # ----------------------------
    # MOST IMPORTANT FIELD
    # ----------------------------
    if record.get("message_template"):
        parts.append(f"Message Template: {record['message_template']}")

    # ----------------------------
    # Description (weighted)
    # ----------------------------
    description = record.get("description")
    if description:
        if record.get("description_source") == "generated":
            parts.append(f"Description (generated): {description}")
        else:
            parts.append(f"Description: {description}")

    # ----------------------------
    # Optional: Recommended action
    # ----------------------------
    if record.get("recommended_action"):
        parts.append(f"Recommended Action: {record['recommended_action']}")

    # ----------------------------
    # Optional: placeholders (low weight)
    # ----------------------------
    if record.get("placeholders"):
        placeholders_str = ", ".join(record["placeholders"])
        parts.append(f"Dynamic Fields: {placeholders_str}")

    # ----------------------------
    # Final text
    # ----------------------------
    return "\n".join(parts)


# ----------------------------
# Bulk builder
# ----------------------------

def build_all_retrieval_texts(records: List[Dict]) -> List[Dict]:
    """
    Add retrieval_text field to all records.
    """
    output = []

    for record in records:
        rec = dict(record)
        rec["retrieval_text"] = build_retrieval_text(rec)
        output.append(rec)

    return output


# ----------------------------
# File integration
# ----------------------------

import json


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    from pathlib import Path
    
    input_path = str(Path(__file__).parent.parent / "filter_data" / "output" / "filtered_event_kb.json")
    output_path = "retrieval_ready_kb.json"

    records = load_json(input_path)
    enriched = build_all_retrieval_texts(records)

    save_json(output_path, enriched)

    print(f"Generated retrieval texts for {len(enriched)} records")


if __name__ == "__main__":
    main()