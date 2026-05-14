import re
import json
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any

import pdfplumber


@dataclass
class ArubaEventRecord:
    record_id: str
    vendor: str
    product_family: str
    event_id: str
    category: Optional[str]
    severity: Optional[str]
    message_template: Optional[str]
    description: Optional[str]
    platforms: List[str]
    placeholders: List[str]
    raw_source_text: str


class ArubaEventGuideParser:
    """
    Parser for Aruba Event Log Message Reference Guide for ArubaOS-Switch 16.09.

    The PDF is structured as repeated event blocks with fields such as:
    - Event ID
    - Message
    - Platforms
    - Category
    - Severity
    - Description

    This parser extracts those blocks into structured records.
    When a Description is not present in the PDF, one is auto-generated
    from the event_type (derived from the message template), category,
    and message_template fields.
    """

    EVENT_START_RE = re.compile(
        r"^Event ID:\s*(\d+)(?:\s*\(Severity:\s*([^)]+)\))?\s*$",
        re.IGNORECASE
    )

    SIMPLE_FIELD_RE = re.compile(
        r"^(Platforms|Category|Severity|Description)\s*(.*)$",
        re.IGNORECASE
    )

    PLACEHOLDER_RE = re.compile(r"<([^>]+)>")

    SKIP_LINE_RE = re.compile(
        r"^(Chapter \d+|Contents|Table Continued|Aruba Event Log Message Reference Guide|"
        r"\d+\s+Aruba Event Log Message Reference Guide|Page \d+|^\d+$)",
        re.IGNORECASE
    )

    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path

    # ─────────────────────────────────────────────────────────────────────────
    # Description generation
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_description(
        category: Optional[str],
        message_template: Optional[str],
        placeholders: List[str],
    ) -> str:
        """
        Build a human-readable description when the PDF provides none.

        Strategy:
          1. Start with the category context.
          2. Describe what the message reports using the template text
             (placeholder tokens replaced with readable labels).
          3. If placeholders exist, list the dynamic fields involved.

        Example output:
          "[802.1x] Event related to auth timeout.
           Message pattern: \"<NUMBER_OF> auth-timeouts for the last <TIME> sec.\"
           Dynamic fields: NUMBER_OF, TIME."
        """
        parts: List[str] = []

        # Part 1: category prefix
        if category:
            parts.append(f"[{category}]")

        # Part 2: derive a human label from the template
        if message_template:
            # Strip placeholders to get static words, then form a label
            static_text = re.sub(r"<[^>]+>", "", message_template)
            static_text = re.sub(r"[^a-zA-Z0-9\s]", " ", static_text)
            static_text = re.sub(r"\s+", " ", static_text).strip().lower()

            if static_text:
                label = static_text.rstrip(".").strip()
                parts.append(f"Event indicating: {label}.")
            else:
                parts.append("Event with dynamic content only.")

            # Part 3: include the raw pattern for reference
            parts.append(f'Message pattern: "{message_template}".')
        else:
            parts.append("No message template available.")

        # Part 4: enumerate dynamic fields if any
        if placeholders:
            fields = ", ".join(placeholders)
            parts.append(f"Dynamic fields: {fields}.")

        return " ".join(parts)

    # ─────────────────────────────────────────────────────────────────────────
    # PDF extraction & preprocessing
    # ─────────────────────────────────────────────────────────────────────────

    def extract_text(self) -> str:
        parts: List[str] = []
        with pdfplumber.open(self.pdf_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text() or ""
                if text:
                    parts.append(text)
        return "\n".join(parts)

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        text = text.replace("\u00ad", "")   # soft hyphen
        text = text.replace("\uf0b7", " ")  # bullet oddities
        text = text.replace("\ufffe", " ")
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{2,}", "\n", text)
        return text.strip()

    @staticmethod
    def clean_multiline_value(lines: List[str]) -> str:
        joined = " ".join(line.strip() for line in lines if line.strip())
        joined = re.sub(r"\s+", " ", joined).strip()
        return joined

    @staticmethod
    def parse_platforms(value: str) -> List[str]:
        if not value:
            return []
        return [p.strip() for p in value.split(",") if p.strip()]

    @classmethod
    def extract_placeholders(cls, message_template: Optional[str]) -> List[str]:
        if not message_template:
            return []
        return cls.PLACEHOLDER_RE.findall(message_template)

    def preprocess_lines(self, raw_text: str) -> List[str]:
        raw_text = self.normalize_whitespace(raw_text)
        lines = [line.strip() for line in raw_text.split("\n")]

        cleaned: List[str] = []
        for line in lines:
            if not line:
                continue
            if self.SKIP_LINE_RE.search(line):
                continue
            if re.match(r"^Chapter \d+ .* Events$", line, re.IGNORECASE):
                continue
            if re.match(r"^\d+$", line):
                continue
            cleaned.append(line)

        return cleaned

    # ─────────────────────────────────────────────────────────────────────────
    # Parsing
    # ─────────────────────────────────────────────────────────────────────────

    def parse(self) -> List[ArubaEventRecord]:
        raw_text = self.extract_text()
        lines = self.preprocess_lines(raw_text)

        records: List[ArubaEventRecord] = []

        current_event_id: Optional[str] = None
        current_inline_severity: Optional[str] = None
        current_message_lines: List[str] = []
        current_description_lines: List[str] = []
        current_platforms: List[str] = []
        current_category: Optional[str] = None
        current_severity: Optional[str] = None
        current_raw_lines: List[str] = []

        mode: Optional[str] = None  # "message" | "description"

        def flush_current():
            nonlocal current_event_id, current_inline_severity
            nonlocal current_message_lines, current_description_lines
            nonlocal current_platforms, current_category, current_severity
            nonlocal current_raw_lines, mode

            if current_event_id is None:
                return

            message_template = (
                self.clean_multiline_value(current_message_lines)
                if current_message_lines else None
            )

            # Use PDF-extracted description if available;
            # otherwise auto-generate from category + template.
            if current_description_lines:
                description = self.clean_multiline_value(current_description_lines)
            else:
                placeholders = self.extract_placeholders(message_template)
                description = self.generate_description(
                    category=current_category,
                    message_template=message_template,
                    placeholders=placeholders,
                )

            final_severity = current_severity or current_inline_severity

            record = ArubaEventRecord(
                record_id=f"aruba_{current_event_id}",
                vendor="aruba",
                product_family="ArubaOS-Switch",
                event_id=current_event_id,
                category=current_category,
                severity=final_severity,
                message_template=message_template,
                description=description,
                platforms=current_platforms,
                placeholders=self.extract_placeholders(message_template),
                raw_source_text="\n".join(current_raw_lines).strip(),
            )
            records.append(record)

            current_event_id = None
            current_inline_severity = None
            current_message_lines = []
            current_description_lines = []
            current_platforms = []
            current_category = None
            current_severity = None
            current_raw_lines = []
            mode = None

        i = 0
        while i < len(lines):
            line = lines[i]

            # Event block start
            m_event = self.EVENT_START_RE.match(line)
            if m_event:
                flush_current()
                current_event_id = m_event.group(1)
                current_inline_severity = (
                    m_event.group(2).strip() if m_event.group(2) else None
                )
                current_raw_lines.append(line)
                i += 1
                continue

            # Ignore content before the first event
            if current_event_id is None:
                i += 1
                continue

            current_raw_lines.append(line)

            # Field label "Message"
            if line.lower() == "message":
                mode = "message"
                i += 1
                continue

            # Standard inline fields
            m_field = self.SIMPLE_FIELD_RE.match(line)
            if m_field:
                field_name = m_field.group(1).lower()
                field_value = m_field.group(2).strip()

                if field_name == "platforms":
                    current_platforms = self.parse_platforms(field_value)
                    mode = None

                elif field_name == "category":
                    current_category = field_value if field_value else None
                    mode = None

                elif field_name == "severity":
                    current_severity = field_value if field_value else None
                    mode = None

                elif field_name == "description":
                    mode = "description"
                    if field_value:
                        current_description_lines.append(field_value)

                i += 1
                continue

            # Detect next event without consuming it
            if self.EVENT_START_RE.match(line):
                flush_current()
                continue

            # Accumulate message / description multi-line values
            if mode == "message":
                if self.SIMPLE_FIELD_RE.match(line):
                    mode = None
                    continue
                current_message_lines.append(line)

            elif mode == "description":
                if self.EVENT_START_RE.match(line):
                    flush_current()
                    continue
                if re.match(
                    r"^The following are the events related to ", line, re.IGNORECASE
                ):
                    mode = None
                    i += 1
                    continue
                current_description_lines.append(line)

            i += 1

        flush_current()
        return records

    def parse_to_dicts(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self.parse()]


if __name__ == "__main__":
    TEMPLATE_DIR = Path(__file__).parent.parent.parent / "template"
    PDF_FILES = list(TEMPLATE_DIR.glob("*.pdf"))
    
    if not PDF_FILES:
        raise FileNotFoundError(f"No PDF files found in {TEMPLATE_DIR}")
    
    PDF_PATH = PDF_FILES[0]  # Use first PDF found

    parser = ArubaEventGuideParser(str(PDF_PATH))
    records = parser.parse_to_dicts()

    with open("aruba_event_records.json", "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    print(f"Extracted {len(records)} Aruba event records")

    if records:
        # Show one record with a PDF description and one without (auto-generated)
        pdf_desc  = next((r for r in records if r["description"] and "Message pattern" not in r["description"]), None)
        auto_desc = next((r for r in records if r["description"] and "Message pattern" in r["description"]), None)

        print("\n--- Record with PDF-extracted description ---")
        if pdf_desc:
            print(json.dumps(pdf_desc, indent=2, ensure_ascii=False))

        print("\n--- Record with auto-generated description ---")
        if auto_desc:
            print(json.dumps(auto_desc, indent=2, ensure_ascii=False))