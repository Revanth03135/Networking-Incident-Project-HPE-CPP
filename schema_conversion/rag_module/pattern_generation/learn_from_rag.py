from typing import Dict, Any
from pathlib import Path
from schema_conversion.rag_module.pattern_generation.pattern_generator import template_to_regex
from schema_conversion.rag_module.pattern_generation.pattern_store import PatternStore

# Import config
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "schema_convertor" / "rag_module"))
from config import PATTERN_REGISTRY_PATH


PLACEHOLDER_TO_SCHEMA = {
    "PORT_NAME": "interface_id",
    "PORT_NUM": "interface_id",
    "LPORT": "interface_id",
    "RULE_ID": "interface_id",
    "POLICY_NAME": "interface_id",
    "VLAN_ID": "vlan",
    "VLAN_NAME": "vlan",
    "IP_ADDRESS": "ip",
    "SRC_IP": "ip",
    "DST_IP": "ip",
    "SERVER_ADDRESS": "ip",
    "inside_address": "ip",
    "outside_address": "ip",
    "source_address": "ip",
    "dest_address": "ip",
    "interface_name": "interface_id",
}


def derive_schema_defaults(rag_result: Dict[str, Any]) -> Dict[str, Any]:
    category = (rag_result.get("category") or "").lower()
    severity = (rag_result.get("severity") or "info").lower()

    type_mapping = {
        "802.1x": "authentication",
        "authentication": "authentication",
        "aaa": "authentication",
        "acl": "security",
        "access control": "security",
        "activate": "system",
        "accounting": "system",
        "interface": "interface",
        "connection": "security",
    }

    subtype_mapping = {
        "802.1x": "802.1x",
        "authentication": "authentication",
        "aaa": "aaa",
        "acl": "acl",
        "access control": "acl",
        "activate": "activate",
        "accounting": "accounting",
        "interface": "interface",
        "connection": "connection",
    }

    severity_mapping = {
        "information": "info",
        "informational": "info",
        "info": "info",
        "warning": "warning",
        "error": "error",
        "critical": "critical",
        "fatal": "critical",
        "alert": "critical",
        "emergency": "critical",
    }

    normalized_type = type_mapping.get(category, "system")
    normalized_subtype = subtype_mapping.get(category, category if category else "generic")
    normalized_severity = severity_mapping.get(severity, "info")

    return {
        "type": normalized_type,
        "subtype": normalized_subtype,
        "severity": normalized_severity,
        "vendor": rag_result.get("vendor"),
        "os": rag_result.get("product_family"),
    }


def build_pattern_from_rag(rag_result: Dict[str, Any]) -> Dict[str, Any]:
    template = rag_result["message_template"]

    return {
        "pattern_id": f"{rag_result['vendor']}_{rag_result['event_id']}",
        "vendor": rag_result["vendor"],
        "event_id": str(rag_result["event_id"]),
        "message_template": template,
        "regex": template_to_regex(template),
        "placeholder_map": PLACEHOLDER_TO_SCHEMA,
        "schema_defaults": derive_schema_defaults(rag_result),
        "trust_score": float(rag_result.get("trust_score", 1.0)),
        "created_from": "rag",
        "usage_count": 0,
    }


def store_pattern_from_rag(
    rag_result: Dict[str, Any],
    store_path: str = None
) -> Dict[str, Any]:
    # Use config default if not provided
    if store_path is None:
        store_path = str(PATTERN_REGISTRY_PATH)
    pattern = build_pattern_from_rag(rag_result)
    store = PatternStore(store_path)
    store.add_or_update(pattern)
    return pattern


if __name__ == "__main__":
    rag_result = {
        "vendor": "aruba",
        "event_id": "429",
        "category": "802.1x",
        "severity": "Information",
        "message_template": "Port <PORT_NAME>-re-auth timeout <TIME> too short.",
        "product_family": "ArubaOS-Switch",
        "trust_score": 1.0,
    }

    pattern = store_pattern_from_rag(rag_result)
    print("Stored pattern:")
    print(pattern)