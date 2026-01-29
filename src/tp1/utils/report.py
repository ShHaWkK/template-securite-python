from typing import List, Tuple
from xml.sax.saxutils import escape
from .config import logger
try:
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    _HAS_RL = True
except Exception:
    _HAS_RL = False
    from fpdf import FPDF


def _protocol_table(protocols: List[Tuple[str, int]]):
    rows = [["Protocole", "Paquets"]] + [[p, str(n)] for p, n in protocols]
    if _HAS_RL:
        t = Table(rows, hAlign="LEFT")
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return t
    return rows


def _verdict_table(verdicts):
    rows = [["Protocole", "Paquets", "Légitimité", "Notes"]]
    for v in verdicts:
        rows.append([v.protocol, str(v.packets), v.status, v.notes])
    if _HAS_RL:
        t = Table(rows, colWidths=[80, 60, 90, 270], hAlign="LEFT")
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return t
    return rows


def _pie_data(protocols: List[Tuple[str, int]], top: int = 6):
    items = protocols[:top]
    labels = [p for p, _ in items]
    values = [n for _, n in items]

    other = sum(n for _, n in protocols[top:])
    if other > 0:
        labels.append("Other")
        values.append(other)

    return labels, values


def _build_pie(protocols: List[Tuple[str, int]]):
    labels, values = _pie_data(protocols)
    if _HAS_RL:
        drawing = Drawing(450, 220)
        pie = Pie()
        pie.x = 120
        pie.y = 20
        pie.width = 180
        pie.height = 180
        pie.data = values if values else [1]
        pie.labels = labels if labels else ["None"]
        drawing.add(pie)
        return drawing
    return list(zip(labels, values))


def _alerts_block(alerts):
    if _HAS_RL:
        styles = getSampleStyleSheet()
        if not alerts:
            return [Paragraph("Tout va bien : aucune tentative détectée.", styles["BodyText"])]
        items = []
        for a in alerts[:30]:
            line = f"[{a.ts}] {a.protocol} - {a.src_ip} / {a.src_mac} - {a.reason}"
            items.append(Paragraph(escape(line), styles["BodyText"]))
        if len(alerts) > 30:
            items.append(Paragraph(escape(f"... ({len(alerts) - 30} alertes supplémentaires)"), styles["BodyText"]))
        return items
    if not alerts:
        return ["Tout va bien : aucune tentative détectée."]
    out = []
    for a in alerts[:30]:
        out.append(f"[{a.ts}] {a.protocol} - {a.src_ip} / {a.src_mac} - {a.reason}")
    if len(alerts) > 30:
        out.append(f"... ({len(alerts) - 30} alertes supplémentaires)")
    return out


class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "TP 1 : Un IDS/IPS maison"
        self.subtitle = "ESGI 4A - Programmation et sécurité python avancée 50 / 101"
        self.summary = summary
        self.array = None
        self.graph = None

    def generate(self, param: str) -> None:
        protocols = self.capture.sort_network_protocols()
        if param == "graph":
            self.graph = _build_pie(protocols)
        elif param == "array":
            self.array = _protocol_table(protocols)

    def save(self, filename: str) -> None:
        logger.info(f"Saving PDF report to {filename}")
        verdicts = self.capture.get_verdicts()
        alerts = self.capture.get_alerts()
        if _HAS_RL:
            doc = SimpleDocTemplate(filename, pagesize=A4)
            styles = getSampleStyleSheet()
            summary_html = escape(self.summary).replace("\n", "<br/>")
            story = [
                Paragraph(self.title, styles["Title"]),
                Paragraph(self.subtitle, styles["Italic"]),
                Spacer(1, 12),
                Paragraph("Résumé", styles["Heading2"]),
                Paragraph(summary_html, styles["BodyText"]),
                Spacer(1, 12),
            ]
            if self.array is not None:
                story += [Paragraph("Statistiques des protocoles", styles["Heading2"]), self.array, Spacer(1, 12)]
            if self.graph is not None:
                story += [Paragraph("Graphique (répartition simple)", styles["Heading2"]), self.graph, Spacer(1, 12)]
            story += [
                Paragraph("Analyse de légitimité par protocole", styles["Heading2"]),
                _verdict_table(verdicts),
                Spacer(1, 12),
                Paragraph("Détails des tentatives / alertes", styles["Heading2"]),
                Spacer(1, 6),
            ]
            story += _alerts_block(alerts)
            doc.build(story)
            return
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=14)
        pdf.cell(0, 10, self.title, ln=1)
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 8, self.subtitle, ln=1)
        pdf.ln(4)
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 8, "Résumé", ln=1)
        for line in (self.summary or "").splitlines():
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 6, line)
        pdf.ln(4)
        if isinstance(self.array, list):
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 8, "Statistiques des protocoles", ln=1)
            pdf.set_font("Arial", size=10)
            for row in self.array:
                pdf.cell(0, 6, " | ".join(row), ln=1)
            pdf.ln(4)
        if isinstance(self.graph, list):
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 8, "Graphique (répartition simple)", ln=1)
            pdf.set_font("Arial", size=10)
            total = sum(v for _, v in self.graph) or 1
            for label, value in self.graph:
                w = int(100 * value / total)
                pdf.cell(0, 6, f"{label}: {'#' * max(1, w // 5)} ({value})", ln=1)
            pdf.ln(4)
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 8, "Analyse de légitimité par protocole", ln=1)
        pdf.set_font("Arial", size=10)
        vt = _verdict_table(verdicts)
        if isinstance(vt, list):
            for row in vt:
                pdf.cell(0, 6, " | ".join(row), ln=1)
        pdf.ln(4)
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 8, "Détails des tentatives / alertes", ln=1)
        pdf.set_font("Arial", size=10)
        ab = _alerts_block(alerts)
        if isinstance(ab, list):
            for line in ab:
                pdf.multi_cell(0, 6, line)
        pdf.output(filename)
