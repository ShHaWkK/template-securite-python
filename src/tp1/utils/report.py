"""
Module de génération de rapport PDF.
"""

from datetime import datetime

from .config import logger

# Import ReportLab (préféré) ou FPDF (fallback)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.legends import Legend

    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    try:
        from fpdf import FPDF
    except ImportError:
        pass


# Couleurs pour le graphique
COLORS = (
    [
        colors.steelblue,
        colors.coral,
        colors.lightgreen,
        colors.gold,
        colors.plum,
        colors.lightskyblue,
        colors.salmon,
        colors.khaki,
    ]
    if HAS_REPORTLAB
    else []
)


class Report:
    """Génère un rapport PDF avec graphique et tableau."""

    def __init__(self, capture, filename="report.pdf"):
        """
        Initialise le rapport.

        Args:
            capture: Instance de Capture avec les données
            filename: Nom du fichier PDF
        """
        self.capture = capture
        self.filename = filename
        self.protocols = capture.get_sorted_protocols()
        self.summary = capture.get_summary()

    def save(self):
        """Génère et sauvegarde le rapport PDF."""
        logger.info(f"Génération du rapport PDF: {self.filename}")

        if HAS_REPORTLAB:
            self._save_reportlab()
        else:
            self._save_fpdf()

        logger.info(f"Rapport sauvegardé: {self.filename}")

    def _save_reportlab(self):
        """Génère le PDF avec ReportLab."""
        doc = SimpleDocTemplate(self.filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Titre
        story.append(Paragraph("TP1 - Analyse du Trafic Réseau", styles["Title"]))
        story.append(
            Paragraph(
                f"ESGI 4A - Sécurité Python | {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Italic"]
            )
        )
        story.append(Spacer(1, 20))

        # Résumé
        story.append(Paragraph("Résumé de la capture", styles["Heading2"]))
        for line in self.summary.split("\n"):
            if line.strip():
                story.append(Paragraph(line, styles["BodyText"]))
        story.append(Spacer(1, 20))

        # Graphique
        if self.protocols:
            story.append(Paragraph("Répartition des protocoles", styles["Heading2"]))
            story.append(self._create_pie_chart())
            story.append(Spacer(1, 20))

        # Tableau
        story.append(Paragraph("Statistiques détaillées", styles["Heading2"]))
        story.append(self._create_table())

        doc.build(story)

    def _create_pie_chart(self) -> Drawing:
        """Crée un graphique en camembert."""
        # Limiter à 8 protocoles max
        top_protocols = self.protocols[:7]
        other = sum(n for _, n in self.protocols[7:])

        labels = [p for p, _ in top_protocols]
        values = [n for _, n in top_protocols]

        if other > 0:
            labels.append("Autres")
            values.append(other)

        # Créer le dessin
        drawing = Drawing(500, 250)

        # Créer le pie
        pie = Pie()
        pie.x = 100
        pie.y = 25
        pie.width = 180
        pie.height = 180
        pie.data = values if values else [1]
        pie.labels = [f"{label}\n({val})" for label, val in zip(labels, values)] if values else ["Aucun"]

        # Couleurs
        for i in range(len(values)):
            pie.slices[i].fillColor = COLORS[i % len(COLORS)]

        drawing.add(pie)

        # Légende
        legend = Legend()
        legend.x = 320
        legend.y = 150
        legend.columnMaximum = 8
        legend.colorNamePairs = [(COLORS[i % len(COLORS)], labels[i]) for i in range(len(labels))]
        drawing.add(legend)

        return drawing

    def _create_table(self) -> Table:
        """Crée le tableau des protocoles."""
        total = sum(n for _, n in self.protocols)

        # En-tête
        data = [["Protocole", "Paquets", "Pourcentage"]]

        # Données
        for proto, count in self.protocols:
            pct = f"{100 * count / total:.1f}%" if total > 0 else "0%"
            data.append([proto, str(count), pct])

        # Total
        data.append(["TOTAL", str(total), "100%"])

        # Style
        table = Table(data, colWidths=[200, 100, 100])
        table.setStyle(
            TableStyle(
                [
                    # En-tête
                    ("BACKGROUND", (0, 0), (-1, 0), colors.steelblue),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                    # Corps
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                    # Dernière ligne (total)
                    ("BACKGROUND", (0, -1), (-1, -1), colors.lightgrey),
                    ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                    # Grille
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("PADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )

        return table

    def _save_fpdf(self):
        """Génère le PDF avec FPDF (fallback)."""
        pdf = FPDF()
        pdf.add_page()

        # Titre
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "TP1 - Analyse du Trafic Reseau", ln=True, align="C")
        pdf.set_font("Arial", "I", 10)
        pdf.cell(
            0,
            8,
            f"ESGI 4A - Securite Python | {datetime.now().strftime('%d/%m/%Y %H:%M')}",
            ln=True,
            align="C",
        )
        pdf.ln(10)

        # Résumé
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Resume de la capture", ln=True)
        pdf.set_font("Arial", "", 10)
        for line in self.summary.split("\n"):
            if line.strip():
                pdf.multi_cell(0, 6, line)
        pdf.ln(10)

        # Graphique (texte)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Repartition des protocoles", ln=True)
        pdf.set_font("Arial", "", 10)

        total = sum(n for _, n in self.protocols)
        for proto, count in self.protocols[:10]:
            pct = int(100 * count / total) if total > 0 else 0
            bar = "#" * (pct // 5)
            pdf.cell(0, 6, f"{proto}: {bar} ({count} - {pct}%)", ln=True)
        pdf.ln(10)

        # Tableau
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Statistiques detaillees", ln=True)
        pdf.set_font("Arial", "B", 10)
        pdf.cell(80, 8, "Protocole", 1)
        pdf.cell(40, 8, "Paquets", 1)
        pdf.cell(40, 8, "Pourcentage", 1)
        pdf.ln()

        pdf.set_font("Arial", "", 10)
        for proto, count in self.protocols:
            pct = f"{100 * count / total:.1f}%" if total > 0 else "0%"
            pdf.cell(80, 6, proto, 1)
            pdf.cell(40, 6, str(count), 1)
            pdf.cell(40, 6, pct, 1)
            pdf.ln()

        # Total
        pdf.set_font("Arial", "B", 10)
        pdf.cell(80, 8, "TOTAL", 1)
        pdf.cell(40, 8, str(total), 1)
        pdf.cell(40, 8, "100%", 1)

        pdf.output(self.filename)
