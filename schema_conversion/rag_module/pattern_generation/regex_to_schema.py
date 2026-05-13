import hashlib
from typing import Dict, Any


def generate_event_uid(vendor: str, event_id: str, event_time: str, raw_message: str) -> str:
    key = f"{vendor}|{event_id}|{event_time}|{raw_message}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def map_extracted_fields(
    extracted: Dict[str, str],
    placeholder_map: Dict[str, str]
) -> Dict[str, Any]:
    mapped = {
        "hostname": None,
        "ip": None,
        "interface_id": None,
        "vlan": None,
    }

    for key, value in extracted.items():
        original_key = key.upper()
        for src_name, target_name in placeholder_map.items():
            safe_src = (
                src_name.replace(" ", "_")
                .replace("-", "_")
                .replace("/", "_")
                .upper()
            )
            if original_key == safe_src:
                mapped[target_name] = value
                break

    return mapped


def regex_match_to_schema(
    raw_log: Dict[str, Any],
    pattern_match: Dict[str, Any]
) -> Dict[str, Any]:
    extracted = pattern_match.get("extracted", {})
    placeholder_map = pattern_match.get("placeholder_map", {})
    schema_defaults = pattern_match.get("schema_defaults", {})

    mapped_fields = map_extracted_fields(extracted, placeholder_map)

    vendor = pattern_match["vendor"]
    event_id = str(pattern_match["event_id"])
    event_time = raw_log["event_time"]
    raw_message = raw_log["message"]

    return {
        "event_uid": generate_event_uid(vendor, event_id, event_time, raw_message),
        "event_id": event_id,
        "type": schema_defaults.get("type", "system"),
        "subtype": schema_defaults.get("subtype", "generic"),
        "severity": schema_defaults.get("severity", "info"),
        "message": raw_message,
        "hostname": raw_log.get("hostname"),
        "ip": raw_log.get("ip") or mapped_fields.get("ip"),
        "vendor": vendor,
        "os": schema_defaults.get("os"),
        "interface_id": mapped_fields.get("interface_id"),
        "vlan": mapped_fields.get("vlan"),
        "event_time": event_time,
        "raw": {
            "message": raw_message
        }
    }