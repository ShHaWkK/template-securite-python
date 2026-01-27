from unittest.mock import patch

from src.tp1.utils.capture import Capture


def test_capture_init():
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        capture = Capture()
    assert capture.interface == ""
    assert capture.summary == ""


def test_capture_trafic_no_interface_no_crash():
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        capture = Capture()
    capture.capture_traffic()
    assert capture.packets == []
    assert capture.get_all_protocols() == {}


def test_sort_network_protocols_empty():
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        capture = Capture()
    assert capture.sort_network_protocols() == []


def test_get_all_protocols_empty():
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        capture = Capture()
    assert capture.get_all_protocols() == {}


def test_analyse_calls_expected_methods():
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        capture = Capture()

    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        capture = Capture()
    capture.summary = "Test summary"
    assert capture.get_summary() == "Test summary"


def test_gen_summary_default_format():
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        capture = Capture()
    capture.alerts = []
    capture.protocol_counts = {}
    s = capture.gen_summary()
    assert "Paquets capturés" in s
    assert "Alertes" in s
