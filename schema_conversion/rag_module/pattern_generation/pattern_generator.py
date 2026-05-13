import re
from typing import Dict, List


def safe_group_name(name: str) -> str:
    """
    Convert placeholder names into valid Python regex group names.
    Example:
      'PORT NAME' -> 'PORT_NAME'
      'NMS-URL NMS-IP' -> 'NMS_URL_NMS_IP'
    """
    name = name.strip()
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    name = re.sub(r"_+", "_", name)
    if re.match(r"^\d", name):
        name = f"FIELD_{name}"
    return name


def extract_placeholders(template: str) -> List[str]:
    return re.findall(r"<([^>]+)>", template)


def template_to_regex(template: str) -> str:
    """
    Convert a template with <PLACEHOLDER> fields into a regex with named groups.
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
            group_name = safe_group_name(placeholder)

            # non-greedy capture
            pattern += rf"(?P<{group_name}>.+?)"
            i = j + 1
        else:
            pattern += re.escape(template[i])
            i += 1

    return "^" + pattern + "$"


if __name__ == "__main__":
    template = "Port <PORT_NAME>-re-auth timeout <TIME> too short."
    regex = template_to_regex(template)

    print("Template:", template)
    print("Regex   :", regex)