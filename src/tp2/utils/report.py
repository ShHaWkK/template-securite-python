# src/tp2/utils/report.py
"""
Générateur de rapport PDF pour l'analyse de shellcode.
Utilise fpdf2 pour créer un rapport professionnel avec l'analyse LLM.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from fpdf import FPDF


class ShellcodeReportPDF(FPDF):
    """PDF personnalisé pour les rapports d'analyse de shellcode."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
    
    @staticmethod
    def _sanitize_text(text: str) -> str:
        """Remplace les caractères Unicode non supportés par des équivalents ASCII."""
        replacements = {
            "•": "-",
            "→": "->",
            "←": "<-",
            "✓": "[OK]",
            "✗": "[X]",
            "⚠️": "[!]",
            "⚠": "[!]",
            "\u2022": "-",
            "—": "--",
            "–": "-",
            "'": "'",
            "'": "'",
            """: '"',
            """: '"',
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "Rapport d'Analyse de Shellcode", border=0, align="C")
        self.ln(5)
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}", border=0, align="C")
        self.set_text_color(0, 0, 0)
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def add_section_title(self, title: str, color: tuple = (41, 128, 185)):
        """Ajoute un titre de section avec style."""
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.cell(0, 8, f"  {title}", fill=True, align="L")
        self.ln(10)
        self.set_text_color(0, 0, 0)

    def add_subsection(self, title: str):
        """Ajoute un sous-titre."""
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(52, 73, 94)
        self.cell(0, 6, title, align="L")
        self.ln(6)
        self.set_text_color(0, 0, 0)

    def add_text(self, text: str, font_size: int = 10):
        """Ajoute du texte normal."""
        self.set_font("Helvetica", "", font_size)
        self.multi_cell(0, 5, self._sanitize_text(text))
        self.ln(3)

    def add_code_block(self, code: str, max_lines: int = 50):
        """Ajoute un bloc de code avec fond gris."""
        self.set_font("Courier", "", 8)
        self.set_fill_color(245, 245, 245)
        
        lines = code.split("\n")
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            lines.append(f"... ({len(code.split(chr(10))) - max_lines} lignes supplementaires)")
        
        for line in lines:
            line = self._sanitize_text(line)
            # Tronquer les lignes trop longues
            if len(line) > 100:
                line = line[:97] + "..."
            self.cell(0, 4, line, fill=True, align="L")
            self.ln(4)
        self.ln(5)

    def add_key_value(self, key: str, value: str):
        """Ajoute une paire clé-valeur."""
        self.set_font("Helvetica", "B", 10)
        self.cell(50, 6, f"{key}:", align="L")
        self.set_font("Helvetica", "", 10)
        self.cell(0, 6, value, align="L")
        self.ln(6)

    def add_separator(self):
        """Ajoute une ligne de séparation."""
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)


def generate_shellcode_report(
    shellcode: bytes,
    shellcode_index: int,
    strings: list[str],
    pylibemu_out: str,
    capstone_out: str,
    llm_analysis: str,
    output_path: Optional[str] = None,
    llm_provider: str = "N/A",
) -> str:
    """
    Génère un rapport PDF complet de l'analyse de shellcode.
    
    Args:
        shellcode: Le shellcode analysé (bytes)
        shellcode_index: Index du shellcode dans le fichier
        strings: Liste des chaînes détectées
        pylibemu_out: Sortie de l'analyse pylibemu
        capstone_out: Sortie du désassemblage capstone
        llm_analysis: Analyse générée par le LLM
        output_path: Chemin de sortie (optionnel, généré automatiquement sinon)
        llm_provider: Nom du provider LLM utilisé
    
    Returns:
        Le chemin du fichier PDF généré
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"shellcode_report_{shellcode_index}_{timestamp}.pdf"

    pdf = ShellcodeReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Section: Informations générales
    pdf.add_section_title("Informations Generales", color=(52, 73, 94))
    pdf.add_key_value("Shellcode #", str(shellcode_index))
    pdf.add_key_value("Taille", f"{len(shellcode)} octets")
    pdf.add_key_value("Provider LLM", llm_provider.upper())
    pdf.add_key_value("Hash MD5", _compute_md5(shellcode))
    pdf.add_key_value("Hash SHA256", _compute_sha256(shellcode)[:32] + "...")
    pdf.ln(5)

    # Section: Chaînes détectées
    pdf.add_section_title("Chaines Detectees", color=(39, 174, 96))
    if strings:
        for s in strings[:20]:  # Limiter à 20 chaînes
            pdf.add_text(f"- {s}", font_size=9)
    else:
        pdf.add_text("Aucune chaine detectee dans le shellcode.", font_size=9)
    pdf.ln(3)

    # Section: Analyse Pylibemu
    pdf.add_section_title("Analyse Pylibemu (Emulation)", color=(142, 68, 173))
    pdf.add_text(pylibemu_out)
    pdf.ln(3)

    # Section: Désassemblage Capstone
    pdf.add_section_title("Desassemblage (Capstone)", color=(230, 126, 34))
    pdf.add_code_block(capstone_out, max_lines=60)

    # Section: Analyse LLM
    pdf.add_page()
    pdf.add_section_title("Analyse par Intelligence Artificielle", color=(192, 57, 43))
    pdf.add_subsection(f"Provider: {llm_provider.upper()}")
    pdf.ln(3)
    
    # Diviser l'analyse LLM en sections si possible
    llm_lines = llm_analysis.strip().split("\n")
    current_section = []
    
    for line in llm_lines:
        # Détection des titres de section (commencent par un chiffre ou sont en majuscules)
        if line.strip() and (
            line.strip()[0].isdigit() and ")" in line[:5]
            or line.strip().startswith("Résumé")
            or line.strip().startswith("Comportement")
            or line.strip().startswith("IOC")
            or line.strip().startswith("Niveau")
        ):
            if current_section:
                pdf.add_text("\n".join(current_section))
                pdf.ln(2)
            pdf.add_subsection(line.strip())
            current_section = []
        else:
            current_section.append(line)
    
    if current_section:
        pdf.add_text("\n".join(current_section))

    # Section: Hexdump du shellcode
    pdf.add_page()
    pdf.add_section_title("Hexdump du Shellcode", color=(44, 62, 80))
    hexdump = _generate_hexdump(shellcode, max_bytes=256)
    pdf.add_code_block(hexdump)

    # Sauvegarder le PDF
    pdf.output(output_path)
    return output_path


def _compute_md5(data: bytes) -> str:
    """Calcule le hash MD5."""
    import hashlib
    return hashlib.md5(data).hexdigest()


def _compute_sha256(data: bytes) -> str:
    """Calcule le hash SHA256."""
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _generate_hexdump(data: bytes, max_bytes: int = 256) -> str:
    """Génère un hexdump formaté."""
    lines = []
    data_to_dump = data[:max_bytes]
    
    for i in range(0, len(data_to_dump), 16):
        chunk = data_to_dump[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
    
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} octets supplémentaires)")
    
    return "\n".join(lines)
