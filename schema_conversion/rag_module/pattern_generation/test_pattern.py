import re
from schema_conversion.rag_module.pattern_generation.pattern_generator import template_to_regex


def test_match(template: str, raw_log: str):
    regex = template_to_regex(template)
    match = re.match(regex, raw_log)

    print("\nTemplate :", template)
    print("Raw Log  :", raw_log)
    print("Regex    :", regex)

    if match:
        print("Matched  : YES")
        print("Groups   :", match.groupdict())
    else:
        print("Matched  : NO")


if __name__ == "__main__":
    test_match(
        "Port <PORT_NAME>-re-auth timeout <TIME> too short.",
        "Port 1/1/10-re-auth timeout 30 too short."
    )

    test_match(
        "Unable to resolve the Activate <SERVER_ADDRESS> <URL ADDRESS>.",
        "Unable to resolve the Activate activate.example.com https://activate.example.com."
    )

    test_match(
        "Error connecting to the Activate server: <ERROR REASON STR>",
        "Error connecting to the Activate server: timeout"
    )