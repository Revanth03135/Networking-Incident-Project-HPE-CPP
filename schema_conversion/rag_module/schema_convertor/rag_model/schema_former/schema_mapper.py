import hashlib
from typing import Dict, Any, Optional

from schema_conversion.rag_module.schema_convertor.rag_model.schema_former.schema_mapping import TYPE_MAPPING, SUBTYPE_MAPPING, SEVERITY_MAPPING, PLACEHOLDER_TO_SCHEMA


def normalize_severity(severity: Optional[str]) -> str:
    if not severity:
        return "info"
    return SEVERITY_MAPPING.get(severity.strip().lower(), "info")


def normalize_type(category: Optional[str]) -> str:
    if not category:
        return "system"
    return TYPE_MAPPING.get(category.strip().lower(), "system")


def normalize_subtype(category: Optional[str]) -> str:
    if not category:
        return "generic"
    return SUBTYPE_MAPPING.get(category.strip().lower(), category.strip().lower())


def generate_event_uid(vendor: str, event_id: str, event_time: str, raw_message: str) -> str:
    key = f"{vendor}|{event_id}|{event_time}|{raw_message}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def map_extracted_fields(extracted: Dict[str, str]) -> Dict[str, Any]:
    mapped = {
        "hostname": None,
        "ip": None,
        "interface_id": None,
        "vlan": None,
    }

    for key, value in extracted.items():
        original_name = key.replace("_", " ").upper()

        for source_name, target_name in PLACEHOLDER_TO_SCHEMA.items():
            safe_source = source_name.replace(" ", "_").replace("/", "_").replace("-", "_")
            if key.upper() == safe_source.upper():
                mapped[target_name] = value
                break

    return mapped