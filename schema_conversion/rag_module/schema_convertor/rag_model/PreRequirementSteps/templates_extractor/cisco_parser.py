import re
import json
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any

import pdfplumber


@dataclass
class CiscoEventRecord:
    record_id: str
    vendor: str
    product_family: str
    event_id: str
    category: Optional[str]
    severity: Optional[str]
    message_template: Optional[str]
    description: Optional[str]
    recommended_action: Optional[str]
    placeholders: List[str]
    raw_source_text: str


class CiscoSyslogGuideParserV2:
    ID_LINE_RE = re.compile(r"^\d{6}(?:\s*,\s*\d{6})*$")
    ERROR_RE = re.compile(r"^Error Message\s+(.*)$", re.IGNORECASE)
    EXPLANATION_RE = re.compile(r"^Explanation\s*(.*)$", re.IGNORECASE)
    ACTION_RE = re.compile(r"^Recommended Action\s*(.*)$", re.IGNORECASE)

    PAGE_ARTIFACT_RE = re.compile(
    r"^(Cisco Security Appliance System Log Messages Guide|"
    r"OL-\d+-\d+|"
    r"Chapter \d+.*|"
    r"Chapter\d+.*|"
    r"Messages \d+ to \d+.*|"
    r"Table \d+-\d+.*|"
    r"\d+-\d+$)$",
    re.IGNORECASE
)

    TABLE_NOISE_RE = re.compile(
        r"^(Table \d+-\d+.*|Reason\s*$|Code Description\s*$)$",
        re.IGNORECASE
    )

    BULLET_RE = re.compile(r"^[•\-]\s*")

    CISCO_SEV_RE = re.compile(r"%[A-Z0-9|_-]+-(\d)-\d{6}:?")
    SEVERITY_MAP = {
        "0": "Emergency",
        "1": "Alert",
        "2": "Critical",
        "3": "Error",
        "4": "Warning",
        "5": "Notification",
        "6": "Informational",
        "7": "Debugging",
    }

    PLACEHOLDER_PATTERNS = [
        re.compile(r"\bIP_address\b", re.IGNORECASE),
        re.compile(r"\binside_address\b", re.IGNORECASE),
        re.compile(r"\boutside_address\b", re.IGNORECASE),
        re.compile(r"\bsource_address\b", re.IGNORECASE),
        re.compile(r"\bdest_address\b", re.IGNORECASE),
        re.compile(r"\binterface_name\b", re.IGNORECASE),
        re.compile(r"\binterface_number\b", re.IGNORECASE),
        re.compile(r"\bsource_port\b", re.IGNORECASE),
        re.compile(r"\bdest_port\b", re.IGNORECASE),
        re.compile(r"\buser\b", re.IGNORECASE),
        re.compile(r"\bstring\b", re.IGNORECASE),
        re.compile(r"\bnumber\b", re.IGNORECASE),
        re.compile(r"\bprotocol\b", re.IGNORECASE),
        re.compile(r"\btcp_flags\b", re.IGNORECASE),
        re.compile(r"\bcode\b", re.IGNORECASE),
        re.compile(r"\bver_num\b", re.IGNORECASE),
        re.compile(r"\bcontext_name\b", re.IGNORECASE),
        re.compile(r"\block_owner_name\b", re.IGNORECASE),
        re.compile(r"\bacl_ID\b", re.IGNORECASE),
        re.compile(r"\bsrc_IP\b", re.IGNORECASE),
        re.compile(r"\bdst_IP\b", re.IGNORECASE),
        re.compile(r"\busername\b", re.IGNORECASE),
        re.compile(r"\bapplication-name\b", re.IGNORECASE),
    ]

    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path

    def extract_text(self) -> str:
        parts = []
        with pdfplumber.open(self.pdf_path) as pdf:
            for page in pdf.pages:
                txt = page.extract_text() or ""
                if txt:
                    parts.append(txt)
        return "\n".join(parts)

    @staticmethod
    def clean_text(text: str) -> str:
        text = text.replace("\u00ad", "")
        text = text.replace("(cid:129)", "")
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{2,}", "\n", text)
        return text.strip()

    def preprocess_lines(self, text: str) -> List[str]:
        text = self.clean_text(text)
        lines = [line.strip() for line in text.split("\n")]

        cleaned = []
        for line in lines:
            if not line:
                continue
            if self.PAGE_ARTIFACT_RE.search(line):
                continue
            cleaned.append(line)
        return cleaned

    @staticmethod
    def join_lines(lines: List[str]) -> Optional[str]:
        if not lines:
            return None
        s = " ".join(x.strip() for x in lines if x.strip())
        s = re.sub(r"\s+", " ", s).strip()
        return s or None

    def extract_severity(self, message_template: Optional[str]) -> Optional[str]:
        if not message_template:
            return None
        m = self.CISCO_SEV_RE.search(message_template)
        if not m:
            return None
        return self.SEVERITY_MAP.get(m.group(1), m.group(1))

    def infer_category(self, message_template: Optional[str], description: Optional[str]) -> Optional[str]:
        text = f"{message_template or ''} {description or ''}".lower()
        if "failover" in text:
            return "High Availability"
        if "rip" in text:
            return "RIP"
        if "ospf" in text:
            return "OSPF"
        if "auth" in text or "authorization" in text or "aaa" in text:
            return "AAA"
        if "smtp" in text or "esmtp" in text:
            return "SMTP"
        if "access-list" in text or "acl" in text:
            return "ACL"
        if "vpn" in text:
            return "VPN"
        if "interface" in text:
            return "Interface"
        return None

    def extract_placeholders(self, message_template: Optional[str]) -> List[str]:
        if not message_template:
            return []
        found = []
        for pat in self.PLACEHOLDER_PATTERNS:
            for m in pat.finditer(message_template):
                found.append(m.group(0))
        seen = set()
        out = []
        for item in found:
            k = item.lower()
            if k not in seen:
                seen.add(k)
                out.append(item)
        return out

    def parse_block(self, block_lines: List[str]) -> List[CiscoEventRecord]:
        if not block_lines:
            return []
    
        id_line = block_lines[0]
        event_ids = [x.strip() for x in id_line.split(",")]

        error_messages: List[str] = []
        explanation_lines: List[str] = []
        action_lines: List[str] = []

        mode: Optional[str] = None

        i = 1
        while i < len(block_lines):
            line = block_lines[i]

            m = self.ERROR_RE.match(line)
            if m:
                error_messages.append(m.group(1).strip())
                mode = "error"
                i += 1
                continue

            m = self.EXPLANATION_RE.match(line)
            if m:
                mode = "explanation"
                first = m.group(1).strip()
                if first:
                    explanation_lines.append(first)
                i += 1
                continue

            m = self.ACTION_RE.match(line)
            if m:
                mode = "action"
                first = m.group(1).strip()
                if first:
                    action_lines.append(first)
                i += 1
                continue

            if mode == "error":
                error_messages[-1] += " " + line
            elif mode == "explanation":
                cleaned = self.BULLET_RE.sub("", line).strip()
                if cleaned:
                    explanation_lines.append(cleaned)
            elif mode == "action":
                cleaned = self.BULLET_RE.sub("", line).strip()
                if cleaned:
                    action_lines.append(cleaned)

            i += 1

        description = self.join_lines(explanation_lines)
        recommended_action = self.join_lines(action_lines)

        # map message lines to IDs
        if len(error_messages) == len(event_ids):
            pairs = list(zip(event_ids, error_messages))
        elif len(error_messages) == 1:
            pairs = [(eid, error_messages[0]) for eid in event_ids]
        else:
            # safer fallback: only keep the first N pairable messages
            pairs = []
            for idx, eid in enumerate(event_ids):
                msg = error_messages[idx] if idx < len(error_messages) else None
                if msg:
                    pairs.append((eid, msg))

        records = []
        for eid, msg in pairs:
            msg = re.sub(r"\s+", " ", msg).strip()
            severity = self.extract_severity(msg)
            category = self.infer_category(msg, description)

            records.append(
                CiscoEventRecord(
                    record_id=f"cisco_{eid}",
                    vendor="cisco",
                    product_family="Cisco Security Appliance",
                    event_id=eid,
                    category=category,
                    severity=severity,
                    message_template=msg,
                    description=description,
                    recommended_action=recommended_action,
                    placeholders=self.extract_placeholders(msg),
                    raw_source_text="\n".join(block_lines),
                )
            )

        return records

    def parse(self) -> List[CiscoEventRecord]:
        text = self.extract_text()
        lines = self.preprocess_lines(text)

        blocks: List[List[str]] = []
        current_block: List[str] = []

        for line in lines:
            if self.ID_LINE_RE.match(line):
                if current_block:
                    blocks.append(current_block)
                current_block = [line]
            else:
                if current_block:
                    current_block.append(line)

        if current_block:
            blocks.append(current_block)

        all_records: List[CiscoEventRecord] = []
        for block in blocks:
            all_records.extend(self.parse_block(block))

        return all_records

    def parse_to_dicts(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self.parse()]


if __name__ == "__main__":
    parser = CiscoSyslogGuideParserV2(r"D:\NetworkIncident-HPE\schema_convertor\template\ciscologmsgs.pdf")
    records = parser.parse_to_dicts()

    with open("cisco_event_records_v2.json", "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    print(f"Extracted {len(records)} Cisco records")