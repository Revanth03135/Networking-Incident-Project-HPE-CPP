import re
from typing import Dict, Optional


def template_to_regex(template: str) -> str:
    """
    Convert template with <PLACEHOLDER> into regex with named capture groups.
    """
    pattern = ""
    i = 0
    while i < len(template):
        if template[i] == "<":
            j = template.find(">", i)
            if j == -1:
                pattern += re.escape(template[i])
                i += 1
                continue

            placeholder = template[i + 1:j].strip()
            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", placeholder)
            pattern += rf"(?P<{safe_name}>.+?)"
            i = j + 1
        else:
            pattern += re.escape(template[i])
            i += 1

    return "^" + pattern + "$"


def extract_template_values(template: str, raw_message: str) -> Dict[str, str]:
    regex = template_to_regex(template)
    match = re.match(regex, raw_message)
    if not match:
        return {}
    return {k: v.strip() for k, v in match.groupdict().items()}