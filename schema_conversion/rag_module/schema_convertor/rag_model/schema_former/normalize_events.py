from typing import Dict, Any

from schema_conversion.rag_module.schema_convertor.rag_model.schema_former.schema_mapper import (
    normalize_type,
    normalize_subtype,
    normalize_severity,
    generate_event_uid,
    map_extracted_fields,
)
from schema_conversion.rag_module.schema_convertor.rag_model.schema_former.template_extractor import extract_template_values


def normalize_event(
    raw_log: Dict[str, Any],
    rag_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    raw_log example:
    {
        "event_time": "2026-04-03T10:20:11Z",
        "hostname": "sw1",
        "ip": None,
        "message": "Port 1/1/10-re-auth timeout 30 too short."
    }

    rag_result example:
    {
        "vendor": "aruba",
        "event_id": "429",
        "category": "802.1x",
        "severity": "Information",
        "message_template": "Port <PORT_NAME>-re-auth timeout <TIME> too short.",
        "product_family": "ArubaOS-Switch"
    }
    """
    vendor = rag_result.get("vendor")
    event_id = str(rag_result.get("event_id"))
    category = rag_result.get("category")
    severity = rag_result.get("severity")
    template = rag_result.get("message_template")
    product_family = rag_result.get("product_family")

    raw_message = raw_log.get("message")
    event_time = raw_log.get("event_time")
    hostname = raw_log.get("hostname")
    ip = raw_log.get("ip")

    extracted = extract_template_values(template, raw_message) if template and raw_message else {}
    mapped_fields = map_extracted_fields(extracted)

    final_ip = ip or mapped_fields.get("ip")
    interface_id = mapped_fields.get("interface_id")
    vlan = mapped_fields.get("vlan")

    normalized = {
        "event_uid": generate_event_uid(vendor, event_id, event_time, raw_message),
        "event_id": event_id,
        "type": normalize_type(category),
        "subtype": normalize_subtype(category),
        "severity": normalize_severity(severity),
        "message": raw_message,
        "hostname": hostname,
        "ip": final_ip,
        "vendor": vendor,
        "os": product_family,
        "interface_id": interface_id,
        "vlan": vlan,
        "event_time": event_time,
        "raw": {
            "message": raw_message
        }
    }

    return normalized