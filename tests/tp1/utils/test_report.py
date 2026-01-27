import os
import tempfile

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from src.tp1.utils.capture import Capture
from src.tp1.utils.report import Report


def test_pdf_generation():
    cap = Capture()
    cap.interface = "lo"
    cap.packets = [Ether() / IP(src="1.1.1.1") / TCP()] * 3
    cap.protocol_counts = cap._count_protocols(cap.packets)
    cap.analyse("all")

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        pdf_path = f.name

    try:
        report = Report(cap, pdf_path, cap.get_summary())
        report.generate("array")
        report.generate("graph")
        report.save(pdf_path)
        assert os.path.exists(pdf_path)
        assert os.path.getsize(pdf_path) > 800
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
