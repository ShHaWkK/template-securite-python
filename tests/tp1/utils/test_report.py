import os
import tempfile
from unittest.mock import patch

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from src.tp1.utils.capture import Capture
from src.tp1.utils.report import Report


def test_report_pdf_generation():
    with patch("src.tp1.utils.capture.choose_interface", return_value="lo"):
        cap = Capture()

    cap.packets = [Ether() / IP(src="1.1.1.1") / TCP()] * 3
    cap.protocol_counts = cap._count_protocols(cap.packets)
    cap.analyse("all")
    cap.summary = cap.gen_summary()

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name

    try:
        report = Report(cap, path, cap.get_summary())
        report.generate("array")
        report.generate("graph")
        report.save(path)

        assert os.path.exists(path)
        assert os.path.getsize(path) > 800
    finally:
        if os.path.exists(path):
            os.remove(path)
