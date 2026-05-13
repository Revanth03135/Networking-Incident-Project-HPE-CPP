"""
normalize_events.py
-------------------
Normalizes Aruba (parser output) and Cisco event records into a unified KB schema.

KB Schema:
{
    "record_id":          str,
    "vendor":             str,
    "source_type":        "event_template" | "logging_metadata",
    "event_id":           str | None,
    "category":           str | None,
    "severity":           str | None,
    "message_template":   str | None,
    "description":        str | None,
    "recommended_action": str | None,
    "facility":           str | None,
    "product_family":     str | None,
    "placeholders":       list[str],
    "description_source": "pdf" | "generated" | "source",
    "quality_flags":      list[str],
    "raw_source_text":    str
}

Fix history
-----------
Round 1:  message_template key, raw_source_text not re-serialized,
          record_id no trailing _, placeholder separation by vendor.
Round 2:  Cisco source_type corrected, Aruba section-bleed stripped,
          description-drift flagged, synthetic description labelled,
          Cisco placeholder extraction made conservative,
          Cisco category inferred from message content when weak.
"""

import json
import re
import uuid
from pathlib import Path

# ─────────────────────────────────────────────
# Paths  –  adjust as needed
# ─────────────────────────────────────────────
ARUBA_FILE  = Path(r"D:\NetworkIncident-HPE\aruba_event_records.json")
CISCO_FILE  = Path(r"D:\NetworkIncident-HPE\cisco_event_records.json")
OUTPUT_FILE = Path(r"D:\NetworkIncident-HPE\unified_event_kb.json")


# ═══════════════════════════════════════════════════════════════════════
# FIX 1 (Cisco source_type)
# Every Cisco record that has a message_template + description is a real
# event-template, not just logging metadata.
# ═══════════════════════════════════════════════════════════════════════

def classify_cisco_source_type(rec: dict) -> str:
    """
    Return 'event_template' when the record contains a real message template
    with explanation text; 'logging_metadata' otherwise.
    """
    has_template    = bool((rec.get("message_template") or "").strip())
    has_description = bool((rec.get("description") or "").strip())
    has_action      = bool((rec.get("recommended_action") or "").strip())
    # A record is a proper event template when it carries at least
    # message + one of {description, recommended_action}.
    if has_template and (has_description or has_action):
        return "event_template"
    return "logging_metadata"


# ═══════════════════════════════════════════════════════════════════════
# FIX 2 (Aruba section-bleed in descriptions)
# Chapter / section headings that bleed into description text.
# ═══════════════════════════════════════════════════════════════════════

# Patterns that indicate section-heading text leaked into description
_SECTION_BLEED_RE = re.compile(
    r"(Switch\s+\d+[\.\d]*\s+\w+\s+Events"          # "Switch 16.09 Accounting Events"
    r"|The following are the events related to\b"    # standard chapter opener
    r"|\b\w[\w\s]+Events\b"                          # "ACL Events", "Activate Events", etc.
    r"|ArubaOS[\w\s\-]*Guide"                        # doc title leaking in
    r"|\bAddress Manager Events\b"
    r"|\bChapter\s+\d+\b)",
    re.IGNORECASE,
)

def strip_section_bleed(description: str | None) -> tuple[str | None, bool]:
    """
    Remove section-heading fragments from the end of a description.
    Returns (cleaned_description, was_modified).
    """
    if not description:
        return description, False

    # Split at the first occurrence of a bleed pattern
    m = _SECTION_BLEED_RE.search(description)
    if not m:
        return description, False

    cleaned = description[: m.start()].strip().rstrip(".,;:")
    return (cleaned if cleaned else None), True


# ═══════════════════════════════════════════════════════════════════════
# FIX 3 (Aruba description-drift detection)
# Category keywords that strongly suggest a description belongs to a
# different event family.
# ═══════════════════════════════════════════════════════════════════════

_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "802.1x":           ["eap", "supplicant", "authenticat", "radius", "802.1x"],
    "Accounting":       ["accounting", "radius", "session", "start", "stop"],
    "ACL":              ["acl", "access list", "access-list", "ace", "permit", "deny"],
    "Activate":         ["activate", "provision", "nms", "software update"],
    "Address Manager":  ["address manager", "ipam", "dhcp"],
    "Spanning Tree":    ["bpdu", "topology", "stp", "rstp", "spanning"],
    "VLAN":             ["vlan", "trunk", "tagged", "untagged"],
    "VxLAN Tunnel":     ["vxlan", "tunnel", "encapsul", "decapsul"],
}

def detect_description_drift(
    category: str | None,
    description: str | None,
) -> bool:
    """
    Return True when the description contains keywords strongly associated
    with a *different* category than the record's own category.
    """
    if not category or not description:
        return False

    desc_lower = description.lower()
    own_keywords = _CATEGORY_KEYWORDS.get(category, [])

    # Check if the description's dominant keywords belong to a different category
    for other_cat, keywords in _CATEGORY_KEYWORDS.items():
        if other_cat == category:
            continue
        foreign_hits = sum(1 for kw in keywords if kw in desc_lower)
        own_hits     = sum(1 for kw in own_keywords if kw in desc_lower)
        if foreign_hits >= 2 and foreign_hits > own_hits:
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════
# FIX 5 (Cisco placeholder extraction – conservative)
# Only treat tokens as placeholders when they look like symbolic variable
# names: lower_snake_case of 2+ parts, or MixedCase identifiers that
# appear mid-sentence (not standalone static words like DOWN, OK, PRIMARY).
# ═══════════════════════════════════════════════════════════════════════

# Static words that appear in Cisco messages but are NOT placeholders
_CISCO_STATIC_WORDS = {
    "DOWN", "UP", "OK", "PRIMARY", "SECONDARY", "IN", "OUT",
    "TCP", "UDP", "IP", "ICMP", "ACL", "NAT", "VPN", "ASA",
    "PIX", "FWSM", "IDS", "IPS", "SSL", "TLS", "GRE", "OSPF",
    "BGP", "EIGRP", "RIP", "STP", "HSRP", "VRRP", "AAA",
}

def extract_placeholders_cisco(template: str | None) -> list[str]:
    """
    Conservative Cisco placeholder extraction.

    Accepted forms (after stripping the %PRODUCT-N-ID: prefix):
      • lower_snake_case with 2+ segments  → likely a variable  (src_addr, reason_text)
      • MixedCase identifiers              → likely a variable  (srcAddr, ifName)

    Rejected:
      • ALL_CAPS words in the static-words blocklist
      • Single-word ALL_CAPS that read as status literals (DOWN, UP, OK …)
    """
    if not template:
        return []

    # Strip the Cisco message-id prefix
    body = re.sub(r"%[\w|]+-\d+-\d+:\s*", "", template)

    placeholders = []

    # 1. snake_case variables: at least one underscore, all lowercase segments
    snake = re.findall(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b", body)
    placeholders.extend(snake)

    # 2. MixedCase (camelCase / PascalCase) identifiers that are not in the
    #    static blocklist and contain both upper and lower chars
    mixed = re.findall(r"\b([A-Z][a-z][A-Za-z0-9]*|[a-z]+[A-Z][A-Za-z0-9]*)\b", body)
    placeholders.extend(mixed)

    # 3. ALL_CAPS only if NOT in the static blocklist
    allcaps = re.findall(r"\b([A-Z][A-Z0-9_]{2,})\b", body)
    for tok in allcaps:
        if tok not in _CISCO_STATIC_WORDS:
            placeholders.append(tok)

    return list(dict.fromkeys(placeholders))   # deduplicate, preserve order


# ═══════════════════════════════════════════════════════════════════════
# FIX 6 (Cisco category inference from message content)
# When the stored category is None or seems generic, try to infer a
# better one from the message template text.
# ═══════════════════════════════════════════════════════════════════════

_CISCO_CATEGORY_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"failover|standby|active unit",          re.I), "High Availability"),
    (re.compile(r"deny|permit|access.list|access-list",   re.I), "Access Control"),
    (re.compile(r"connection|conn |built |teardown",      re.I), "Connection"),
    (re.compile(r"crypto|ipsec|isakmp|vpn|tunnel",        re.I), "VPN"),
    (re.compile(r"nat |xlate|translation",                re.I), "NAT"),
    (re.compile(r"aaa|authentication|authorization|accounting", re.I), "AAA"),
    (re.compile(r"interface|link (up|down)|line protocol",re.I), "Interface"),
    (re.compile(r"routing|route |ospf|bgp|eigrp|rip\b",  re.I), "Routing"),
    (re.compile(r"memory|cpu|resource|threshold",         re.I), "System Resource"),
    (re.compile(r"login|logout|privilege|enable",         re.I), "Authentication"),
    (re.compile(r"snmp|syslog|logging",                   re.I), "Management"),
    (re.compile(r"password|encryption|master.key",        re.I), "Security"),
    (re.compile(r"url|http|web",                          re.I), "Web"),
    (re.compile(r"dns|domain.name|resolve",               re.I), "DNS"),
]

# Categories that are too vague to keep as-is
_WEAK_CISCO_CATEGORIES = {None, "", "Interface"}   # expand as needed

def infer_cisco_category(stored_category: str | None, message_template: str | None) -> str | None:
    """
    Return a better category when the stored one is weak/missing,
    inferred by matching the message template against content rules.
    The original category is kept if it's specific enough.
    """
    if stored_category and stored_category not in _WEAK_CISCO_CATEGORIES:
        return stored_category

    if not message_template:
        return stored_category

    for pattern, label in _CISCO_CATEGORY_RULES:
        if pattern.search(message_template):
            return label

    return stored_category   # return original if nothing matched


# ═══════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════

def clean_text(value) -> str | None:
    """Collapse whitespace; return None if result is empty."""
    if not value:
        return None
    cleaned = " ".join(str(value).split()).strip()
    return cleaned if cleaned else None


def extract_placeholders_aruba(template: str | None) -> list[str]:
    """Extract <TOKEN> style placeholders from an Aruba message template."""
    if not template:
        return []
    return re.findall(r"<([^<>]+)>", template)


def infer_facility_cisco(template: str | None) -> str | None:
    """Syslog facility from the numeric severity level in the Cisco prefix."""
    if not template:
        return None
    m = re.search(r"%[\w|]+-(\d+)-\d+:", template)
    return f"syslog-level-{m.group(1)}" if m else None


def build_record_id(prefix: str, event_id: str | None, suffix: str | None = None) -> str:
    """Clean record_id with no trailing underscores."""
    if not event_id:
        return f"{prefix}_{uuid.uuid4().hex[:8]}"
    parts = [prefix, event_id]
    if suffix:
        parts.append(suffix)
    return "_".join(parts)


# ═══════════════════════════════════════════════════════════════════════
# Aruba normalizer
# ═══════════════════════════════════════════════════════════════════════

def normalize_aruba(records: list) -> list:
    normalized = []

    for rec in records:
        event_id = clean_text(str(rec.get("event_id", ""))) or None
        category = clean_text(rec.get("category"))
        severity = clean_text(rec.get("severity"))

        # message_template – correct key from parser output
        message_template = clean_text(rec.get("message_template"))
        if not message_template:          # last-resort: scan raw_source_text
            rst = rec.get("raw_source_text", "")
            m = re.search(r'"message_template"\s*:\s*"([^"]+)"', rst)
            if m:
                message_template = clean_text(m.group(1))

        # Raw description from parser
        raw_description = clean_text(rec.get("description"))

        # FIX 4 – synthetic description label
        is_synthetic = (
            raw_description is not None
            and re.search(r"\[.*?\]\s*Event indicating:", raw_description) is not None
        )
        description_source = "generated" if is_synthetic else (
            "pdf" if raw_description else "generated"
        )

        # FIX 2 – strip section-bleed from description
        description, bleed_found = strip_section_bleed(raw_description)

        # FIX 3 – detect description drift
        drift_found = detect_description_drift(category, description)

        # Build quality flags
        quality_flags: list[str] = []
        if bleed_found:
            quality_flags.append("description_section_bleed")
        if drift_found:
            quality_flags.append("description_drift")
        if is_synthetic:
            quality_flags.append("synthetic_description")
        if not message_template:
            quality_flags.append("missing_message_template")

        record_id       = build_record_id("aruba", event_id)
        raw_source_text = rec.get("raw_source_text") or ""

        placeholders = (
            rec.get("placeholders")
            or extract_placeholders_aruba(message_template)
        )

        normalized.append({
            "record_id":          record_id,
            "vendor":             "aruba",
            "source_type":        "event_template",
            "event_id":           event_id,
            "category":           category,
            "severity":           severity,
            "message_template":   message_template,
            "description":        description,
            "recommended_action": None,
            "facility":           None,
            "product_family":     clean_text(rec.get("product_family")) or "ArubaOS-Switch",
            "placeholders":       placeholders,
            "description_source": description_source,
            "quality_flags":      quality_flags,
            "raw_source_text":    raw_source_text,
        })

    return normalized


# ═══════════════════════════════════════════════════════════════════════
# Cisco normalizer
# ═══════════════════════════════════════════════════════════════════════

def normalize_cisco(records: list) -> list:
    normalized = []

    for rec in records:
        record_id          = rec.get("record_id") or build_record_id("cisco", None)
        event_id           = clean_text(str(rec.get("event_id", ""))) or None
        severity           = clean_text(rec.get("severity"))
        message_template   = clean_text(rec.get("message_template"))
        description        = clean_text(rec.get("description"))
        recommended_action = clean_text(rec.get("recommended_action"))
        product_family     = clean_text(rec.get("product_family"))
        raw_source_text    = rec.get("raw_source_text") or json.dumps(rec, ensure_ascii=False)

        # FIX 1 – correct source_type based on record content
        source_type = classify_cisco_source_type(rec)

        # FIX 6 – improve weak/missing categories
        stored_category = clean_text(rec.get("category"))
        category = infer_cisco_category(stored_category, message_template)

        quality_flags: list[str] = []
        if category != stored_category and stored_category is not None:
            quality_flags.append(f"category_inferred_from:{stored_category}")

        # FIX 5 – conservative placeholder extraction
        provided     = rec.get("placeholders") or []
        inferred     = extract_placeholders_cisco(message_template)
        placeholders = list(dict.fromkeys(provided + inferred))

        normalized.append({
            "record_id":          record_id,
            "vendor":             "cisco",
            "source_type":        source_type,
            "event_id":           event_id,
            "category":           category,
            "severity":           severity,
            "message_template":   message_template,
            "description":        description,
            "recommended_action": recommended_action,
            "facility":           infer_facility_cisco(message_template),
            "product_family":     product_family,
            "placeholders":       placeholders,
            "description_source": "source",
            "quality_flags":      quality_flags,
            "raw_source_text":    raw_source_text,
        })

    return normalized


# ═══════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════

REQUIRED_KEYS = {
    "record_id", "vendor", "source_type", "event_id", "category",
    "severity", "message_template", "description", "recommended_action",
    "facility", "product_family", "placeholders", "raw_source_text",
    "description_source", "quality_flags",
}

VALID_SOURCE_TYPES = {"event_template", "logging_metadata"}


def validate(records: list) -> int:
    issues = 0
    flag_summary: dict[str, int] = {}

    for i, rec in enumerate(records):
        rid = rec.get("record_id", f"#{i}")

        missing = REQUIRED_KEYS - set(rec.keys())
        if missing:
            print(f"[WARN] {rid} - missing keys: {missing}")
            issues += 1

        if not rec.get("message_template"):
            print(f"[WARN] {rid} - message_template is null/empty")
            issues += 1

        if rec.get("record_id", "").endswith("_"):
            print(f"[WARN] {rid} - record_id has trailing underscore")
            issues += 1

        rst = rec.get("raw_source_text", "")
        if isinstance(rst, str) and rst.startswith('{"') and '"record_id"' in rst:
            print(f"[WARN] {rid} - raw_source_text appears to be re-serialized JSON")
            issues += 1

        if rec.get("source_type") not in VALID_SOURCE_TYPES:
            print(f"[WARN] {rid} - invalid source_type: {rec.get('source_type')}")
            issues += 1

        for flag in rec.get("quality_flags", []):
            flag_summary[flag] = flag_summary.get(flag, 0) + 1

    print("\nQuality flag summary:")
    if flag_summary:
        for flag, count in sorted(flag_summary.items()):
            print(f"  {flag}: {count} record(s)")
    else:
        print("  (none)")

    return issues


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("Loading Aruba events ...")
    aruba_raw = json.loads(ARUBA_FILE.read_text(encoding="utf-8"))

    print("Loading Cisco events ...")
    cisco_raw = json.loads(CISCO_FILE.read_text(encoding="utf-8"))

    print(f"  Aruba records : {len(aruba_raw)}")
    print(f"  Cisco records : {len(cisco_raw)}")

    print("Normalizing Aruba ...")
    aruba_normalized = normalize_aruba(aruba_raw)

    print("Normalizing Cisco ...")
    cisco_normalized = normalize_cisco(cisco_raw)

    combined = aruba_normalized + cisco_normalized
    print(f"Total normalized records : {len(combined)}")

    # ── source_type distribution report ──────────────────────────────────
    from collections import Counter
    st_counts = Counter(
        f"{r['vendor']}:{r['source_type']}" for r in combined
    )
    print("\nSource-type distribution:")
    for label, count in sorted(st_counts.items()):
        print(f"  {label}: {count}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(combined, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nOutput written -> {OUTPUT_FILE}")

    print("\nRunning validation ...")
    issues = validate(combined)
    if issues == 0:
        print("\nValidation passed - all records are clean.")
    else:
        print(f"\nValidation finished with {issues} issue(s).")


if __name__ == "__main__":
    main()