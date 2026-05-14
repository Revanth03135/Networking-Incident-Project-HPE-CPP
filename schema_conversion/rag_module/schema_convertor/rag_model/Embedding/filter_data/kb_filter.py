import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


# ----------------------------
# Config
# ----------------------------

HARD_EXCLUDE_FLAGS = {
    "description_section_bleed",
}

SOFT_LOW_TRUST_FLAGS = {
    "synthetic_description",
}

MIN_REQUIRED_FIELDS = [
    "record_id",
    "vendor",
    "event_id",
    "message_template",
]

OUTPUT_FIELDS = [
    "record_id",
    "vendor",
    "source_type",
    "event_id",
    "category",
    "severity",
    "message_template",
    "description",
    "recommended_action",
    "facility",
    "product_family",
    "placeholders",
    "description_source",
    "quality_flags",
    "raw_source_text",
    "trust_score",
]


# ----------------------------
# Helpers
# ----------------------------

def clean_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)

    value = value.replace("\u00ad", "")
    value = value.replace("\uf0b7", " ")
    value = value.strip()
    value = re.sub(r"\s+", " ", value)
    return value or None


def clean_multiline_text(value: Any) -> Optional[str]:
    """
    Keep line breaks if present, but normalize repeated whitespace.
    Useful for raw_source_text.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)

    value = value.replace("\u00ad", "")
    value = value.replace("\uf0b7", " ")
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    value = value.strip()
    return value or None


def ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out = []
        seen = set()
        for item in value:
            s = clean_text(item)
            if not s:
                continue
            k = s.lower()
            if k not in seen:
                seen.add(k)
                out.append(s)
        return out
    s = clean_text(value)
    return [s] if s else []


def has_required_fields(record: Dict[str, Any]) -> bool:
    for field in MIN_REQUIRED_FIELDS:
        val = record.get(field)
        if val is None:
            return False
        if isinstance(val, str) and not val.strip():
            return False
    return True


def is_low_value_message(message_template: Optional[str]) -> bool:
    if not message_template:
        return True

    msg = clean_text(message_template)
    if not msg:
        return True

    # separator-only / punctuation-only junk
    if re.fullmatch(r"[-_=.#* ]+", msg):
        return True

    # very weak generic rows to avoid indexing noise
    weak_literals = {
        "entity enabled",
        "initialization failed",
        "unknown var type",
    }
    if msg.lower() in weak_literals:
        return True

    return False


def normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize one KB record into a consistent shape.
    """
    normalized = {
        "record_id": clean_text(record.get("record_id")),
        "vendor": (clean_text(record.get("vendor")) or "").lower(),
        "source_type": clean_text(record.get("source_type")) or "event_template",
        "event_id": clean_text(record.get("event_id")),
        "category": clean_text(record.get("category")),
        "severity": clean_text(record.get("severity")),
        "message_template": clean_text(record.get("message_template")),
        "description": clean_text(record.get("description")),
        "recommended_action": clean_text(record.get("recommended_action")),
        "facility": clean_text(record.get("facility")),
        "product_family": clean_text(record.get("product_family")),
        "placeholders": ensure_list(record.get("placeholders")),
        "description_source": clean_text(record.get("description_source")),
        "quality_flags": ensure_list(record.get("quality_flags")),
        "raw_source_text": clean_multiline_text(record.get("raw_source_text")),
    }

    normalized["trust_score"] = compute_trust_score(normalized)
    return normalized


def compute_trust_score(record: Dict[str, Any]) -> float:
    """
    Initial trust score for later reranking.
    """
    score = 1.0

    flags = set(record.get("quality_flags", []))
    description_source = (record.get("description_source") or "").lower()

    if description_source == "generated":
        score -= 0.20

    if flags & SOFT_LOW_TRUST_FLAGS:
        score -= 0.15

    # If there is no description, slight penalty but keep it usable
    if not record.get("description"):
        score -= 0.10

    # If no raw source text, slight penalty
    if not record.get("raw_source_text"):
        score -= 0.05

    # Clamp
    score = max(0.0, min(1.0, score))
    return round(score, 2)


def should_exclude(record: Dict[str, Any]) -> Optional[str]:
    """
    Return exclusion reason, or None if record should be kept.
    """
    if record.get("source_type") != "event_template":
        return "non_event_template"

    if not has_required_fields(record):
        return "missing_required_fields"

    flags = set(record.get("quality_flags", []))
    if flags & HARD_EXCLUDE_FLAGS:
        return "hard_exclude_quality_flag"

    if is_low_value_message(record.get("message_template")):
        return "low_value_message"

    return None


# ----------------------------
# Main filtering logic
# ----------------------------

def filter_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Filter and normalize KB records.

    Returns:
        {
            "kept_records": [...],
            "excluded_records": [...],
            "stats": {...}
        }
    """
    kept_records: List[Dict[str, Any]] = []
    excluded_records: List[Dict[str, Any]] = []

    stats = {
        "input_count": len(records),
        "kept_count": 0,
        "excluded_count": 0,
        "excluded_by_reason": {},
        "vendor_counts": {},
    }

    for raw_record in records:
        rec = normalize_record(raw_record)
        reason = should_exclude(rec)

        if reason is not None:
            excluded_entry = {
                "record_id": rec.get("record_id"),
                "vendor": rec.get("vendor"),
                "event_id": rec.get("event_id"),
                "reason": reason,
                "quality_flags": rec.get("quality_flags", []),
                "message_template": rec.get("message_template"),
            }
            excluded_records.append(excluded_entry)
            stats["excluded_by_reason"][reason] = stats["excluded_by_reason"].get(reason, 0) + 1
            continue

        kept_records.append({k: rec.get(k) for k in OUTPUT_FIELDS})

        vendor = rec.get("vendor") or "unknown"
        stats["vendor_counts"][vendor] = stats["vendor_counts"].get(vendor, 0) + 1

    stats["kept_count"] = len(kept_records)
    stats["excluded_count"] = len(excluded_records)

    return {
        "kept_records": kept_records,
        "excluded_records": excluded_records,
        "stats": stats,
    }


# ----------------------------
# File IO helpers
# ----------------------------

def load_json_file(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list")
    return data


def save_json_file(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ----------------------------
# CLI entrypoint
# ----------------------------

def main(
    input_path: str = None,
    filtered_output_path: str = "filtered_event_kb.json",
    excluded_output_path: str = "excluded_event_kb.json",
    stats_output_path: str = "filter_stats.json",
    
) -> None:
    if input_path is None:
        input_path = str(Path(__file__).parent.parent.parent / "PreRequirementSteps" / "template_normalizer" / "unified_event_kb.json")
    records = load_json_file(input_path)
    result = filter_records(records)

    save_json_file(filtered_output_path, result["kept_records"])
    save_json_file(excluded_output_path, result["excluded_records"])
    save_json_file(stats_output_path, result["stats"])

    print("KB filtering complete")
    print(f"Input records     : {result['stats']['input_count']}")
    print(f"Kept records      : {result['stats']['kept_count']}")
    print(f"Excluded records  : {result['stats']['excluded_count']}")
    print("\nExcluded by reason:")
    for reason, count in sorted(result["stats"]["excluded_by_reason"].items()):
        print(f"  - {reason}: {count}")

    print("\nVendor counts:")
    for vendor, count in sorted(result["stats"]["vendor_counts"].items()):
        print(f"  - {vendor}: {count}")


if __name__ == "__main__":
    main()