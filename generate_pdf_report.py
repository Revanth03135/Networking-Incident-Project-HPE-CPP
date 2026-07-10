import json
import re
from datetime import datetime, timezone
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to calculate the total page count dynamically 
    and render consistent page headers/footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0F172A"))
        
        # Header (Skip on Page 1 cover section if desired, but we show on all pages for consistency)
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(36, 756, 576, 756)
        self.drawString(36, 762, "CONFIDENTIAL - ENTERPRISE NETWORK INCIDENT INVESTIGATION REPORT")
        
        # Footer
        self.line(36, 54, 576, 54)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.drawString(36, 42, f"Generated: {gen_time}")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 42, page_text)
        self.restoreState()


def parse_markdown_to_html(md_text: str) -> str:
    """
    Convert basic markdown styling to ReportLab-compatible HTML tags,
    escaping XML special characters first.
    """
    # 1. Escape XML characters
    escaped = md_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    # 2. Convert Bold (**text** -> <b>text</b>)
    escaped = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', escaped)
    
    # 3. Convert Italic (*text* -> <i>text</i>)
    escaped = re.sub(r'\*(.*?)\*', r'<i>\1</i>', escaped)
    
    return escaped


def create_pdf_report(timeline_path: Path, causal_path: Path, md_report_path: Path, pdf_output_path: Path):
    """
    Generates a beautifully structured PDF network incident report.
    Directly incorporates structured summary tables from JSON outputs
    and renders the detailed markdown report.
    """
    # Load JSON data
    with open(timeline_path, "r", encoding="utf-8") as f:
        timeline_data = json.load(f)
    
    with open(causal_path, "r", encoding="utf-8") as f:
        causal_data = json.load(f)

    # Reconstruct stats
    incidents = timeline_data if isinstance(timeline_data, list) else timeline_data.get("incidents", [])
    total_incidents = len(incidents)
    total_events = sum(len(inc.get("events", [])) for inc in incidents)

    # Color scheme
    primary_color = colors.HexColor("#1E3A8A")  # Deep blue
    accent_color = colors.HexColor("#0D9488")   # Teal
    text_color = colors.HexColor("#1F2937")     # Charcoal
    bg_light = colors.HexColor("#F8FAFC")       # Soft gray
    
    # Setup document template
    doc = SimpleDocTemplate(
        str(pdf_output_path),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Define custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=primary_color,
        spaceAfter=6
    )
    
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=primary_color,
        spaceBefore=18,
        spaceAfter=10,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=accent_color,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    h3_style = ParagraphStyle(
        'SectionH3',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0F4C81"),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    h4_style = ParagraphStyle(
        'SectionH4',
        parent=styles['Normal'],
        fontName='Helvetica-BoldOblique',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#374151"),
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=text_color,
        spaceAfter=8
    )

    note_style = ParagraphStyle(
        'NoteStyle',
        parent=body_style,
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#374151"),
        backColor=colors.HexColor("#EFF6FF"),
        borderColor=colors.HexColor("#BFDBFE"),
        borderWidth=0.5,
        borderPadding=5,
        leftIndent=10,
        spaceBefore=4,
        spaceAfter=4,
    )

    bullet_style = ParagraphStyle(
        'BulletDark',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9"),
        borderColor=colors.HexColor("#E2E8F0"),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=6,
        spaceAfter=6
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=text_color,
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=table_cell_style,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#1E3A8A"),
    )

    story = []

    def _flush_table(table_rows, story, table_cell_style, table_header_style):
        """Render collected markdown table rows as a styled PDF Table."""
        if not table_rows:
            return
        rl_rows = []
        for r_idx, row in enumerate(table_rows):
            cell_style = table_header_style if r_idx == 0 else table_cell_style
            rl_row = []
            for cell in row:
                cell_html = parse_markdown_to_html(cell.strip())
                rl_row.append(Paragraph(cell_html, cell_style))
            rl_rows.append(rl_row)
        if not rl_rows:
            return
        n_cols = max(len(r) for r in rl_rows)
        for r in rl_rows:
            while len(r) < n_cols:
                r.append(Paragraph("", table_cell_style))
        col_w = 540 / n_cols
        col_widths = [col_w] * n_cols
        tbl = Table(rl_rows, colWidths=col_widths, repeatRows=1)
        row_bg_a = colors.HexColor("#F0F4FF")
        row_bg_b = colors.HexColor("#FFFFFF")
        style_cmds = [
            ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor("#C7D7F0")),
            ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0, 0), (-1, 0),  8),
            ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.HexColor("#1E3A8A")),
            ('BOX',           (0, 0), (-1, -1), 0.8, colors.HexColor("#94A3B8")),
            ('INNERGRID',     (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING',   (0, 0), (-1, -1), 5),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('WORDWRAP',      (0, 0), (-1, -1), True),
        ]
        for i in range(1, len(rl_rows)):
            bg = row_bg_a if i % 2 == 1 else row_bg_b
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), bg))
        tbl.setStyle(TableStyle(style_cmds))
        story.append(tbl)
        story.append(Spacer(1, 6))

    if md_report_path.exists():
        story.append(Paragraph("Network Incident Investigation Report", title_style))
        story.append(Spacer(1, 10))

        with open(md_report_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_code_block = False
        code_lines    = []
        table_rows    = []   # accumulated markdown table rows
        in_table      = False

        def _is_table_row(s):
            return s.startswith("|") and s.endswith("|")

        def _is_separator_row(s):
            # e.g. |---|---|
            inner = s.strip("|").strip()
            return bool(re.match(r'^[\-\s\|:]+$', inner))

        def _parse_table_row(s):
            # Split on | and strip surrounding whitespace
            parts = s.strip().strip("|").split("|")
            return [p.strip() for p in parts]

        for line in lines:
            stripped = line.strip()

            # ── Code block ────────────────────────────────────────────
            if stripped.startswith("```"):
                if in_table:
                    _flush_table(table_rows, story, table_cell_style, table_header_style)
                    table_rows = []; in_table = False
                if in_code_block:
                    code_text = "\n".join(code_lines)
                    safe = code_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    story.append(Paragraph(safe.replace("\n", "<br/>"), code_style))
                    code_lines = []; in_code_block = False
                else:
                    in_code_block = True
                continue

            if in_code_block:
                safe = line.rstrip().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                code_lines.append(safe)
                continue

            # ── Markdown table row ────────────────────────────────────
            if _is_table_row(stripped):
                in_table = True
                if not _is_separator_row(stripped):
                    table_rows.append(_parse_table_row(stripped))
                continue
            else:
                # Flush any accumulated table
                if in_table:
                    _flush_table(table_rows, story, table_cell_style, table_header_style)
                    table_rows = []; in_table = False

            # ── Horizontal rule ───────────────────────────────────────
            if stripped in ("---", "***", "___"):
                story.append(Spacer(1, 4))
                continue

            # ── Headings ──────────────────────────────────────────────
            if stripped.startswith("#### "):
                story.append(Paragraph(parse_markdown_to_html(stripped[5:]), h4_style))
            elif stripped.startswith("### "):
                story.append(Paragraph(parse_markdown_to_html(stripped[4:]), h3_style))
            elif stripped.startswith("## "):
                story.append(Paragraph(parse_markdown_to_html(stripped[3:]), h2_style))
            elif stripped.startswith("# "):
                heading_text = parse_markdown_to_html(stripped[2:])
                if "Network Incident Investigation Report" not in heading_text:
                    story.append(Paragraph(heading_text, h1_style))

            # ── Blockquote ────────────────────────────────────────────
            elif stripped.startswith("> "):
                note_text = parse_markdown_to_html(stripped[2:])
                story.append(Paragraph(note_text, note_style))

            # ── Bullet points ─────────────────────────────────────────
            elif stripped.startswith("- ") or stripped.startswith("* "):
                bullet_content = parse_markdown_to_html(stripped[2:])
                story.append(Paragraph(f"&bull; {bullet_content}", bullet_style))

            # ── Numbered list ─────────────────────────────────────────
            elif re.match(r'^\d+\.\s', stripped):
                match = re.match(r'^(\d+\.\s)(.*)', stripped)
                num_content = parse_markdown_to_html(match.group(2))
                story.append(Paragraph(f"{match.group(1)}{num_content}", bullet_style))

            # ── Normal paragraph ──────────────────────────────────────
            elif stripped:
                story.append(Paragraph(parse_markdown_to_html(stripped), body_style))

            # ── Blank line ────────────────────────────────────────────
            else:
                story.append(Spacer(1, 4))

        # Flush any trailing table
        if in_table:
            _flush_table(table_rows, story, table_cell_style, table_header_style)

    # Save document
    doc.build(story, canvasmaker=NumberedCanvas)

