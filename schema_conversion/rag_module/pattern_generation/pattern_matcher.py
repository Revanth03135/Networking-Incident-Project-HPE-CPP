import re
from typing import Dict, Any, Optional, List
from schema_conversion.rag_module.pattern_generation.pattern_store import PatternStore


class PatternMatcher:
    def __init__(self, store_path: str = "pattern_registry.json"):
        self.store = PatternStore(store_path)

    def _filter_by_vendor(
        self,
        patterns: List[Dict[str, Any]],
        vendor_hint: Optional[str]
    ) -> List[Dict[str, Any]]:
        if not vendor_hint:
            return patterns

        vendor_hint = vendor_hint.lower().strip()
        return [
            p for p in patterns
            if str(p.get("vendor", "")).lower().strip() == vendor_hint
        ]

    def match(
        self,
        raw_message: str,
        vendor_hint: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        patterns = self.store.get_all()
        patterns = self._filter_by_vendor(patterns, vendor_hint)

        for pattern in patterns:
            regex = pattern.get("regex")
            if not regex:
                continue

            try:
                compiled = re.compile(regex)
            except re.error:
                # Skip invalid regex patterns
                continue

            match_obj = compiled.match(raw_message)
            if match_obj:
                extracted = {
                    k: v.strip() if isinstance(v, str) else v
                    for k, v in match_obj.groupdict().items()
                }

                self.store.increment_usage(pattern["pattern_id"])

                return {
                    "matched": True,
                    "pattern_id": pattern.get("pattern_id"),
                    "vendor": pattern.get("vendor"),
                    "event_id": pattern.get("event_id"),
                    "message_template": pattern.get("message_template"),
                    "regex": regex,
                    "extracted": extracted,
                    "placeholder_map": pattern.get("placeholder_map", {}),
                    "schema_defaults": pattern.get("schema_defaults", {}),
                    "trust_score": pattern.get("trust_score", 1.0),
                    "created_from": pattern.get("created_from", "rag"),
                    "usage_count": pattern.get("usage_count", 0),
                }

        return None


if __name__ == "__main__":
    matcher = PatternMatcher("pattern_registry.json")

    raw_message = "Port 1/1/10-re-auth timeout 30 too short."
    result = matcher.match(raw_message, vendor_hint="aruba")

    print("MATCH RESULT:")
    print(result)