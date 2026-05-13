from schema_conversion.rag_module.pattern_generation.pattern_matcher import PatternMatcher
from regex_match_to_schema import regex_match_to_schema


def main():
    matcher = PatternMatcher("pattern_registry.json")

    raw_log = {
        "event_time": "2026-04-03T10:20:11Z",
        "hostname": "sw1",
        "ip": None,
        "message": "Port 1/1/10-re-auth timeout 30 too short."
    }

    match = matcher.match(raw_log["message"], vendor_hint="aruba")
    print("PATTERN MATCH:")
    print(match)

    if match:
        schema = regex_match_to_schema(raw_log, match)
        print("\nFINAL SCHEMA:")
        print(schema)


if __name__ == "__main__":
    main()