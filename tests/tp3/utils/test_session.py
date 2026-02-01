"""
Tests pour le module session.
"""
from unittest.mock import MagicMock, patch
from src.tp3.utils.session import Session


def test_session_init():
    # Given
    url = "http://example.com/captcha1/"

    # When
    session = Session(url)

    # Then
    assert session.url == url
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""


def test_submit_request_sans_captcha():
    # Given
    session = Session("http://example.com/captcha1/")
    session.captcha_value = ""

    # When
    session.submit_request()

    # Then
    assert session.response is None


def test_submit_request_avec_captcha():
    # Given
    session = Session("http://example.com/captcha1/")
    session.html = '<input name="captcha">'
    session.captcha_value = "ABC123"
    session.session = MagicMock()

    # When
    session.submit_request()

    # Then
    session.session.post.assert_called_once()


def test_process_response_avec_flag():
    # Given
    session = Session("http://example.com/captcha1/")
    mock_response = MagicMock()
    mock_response.text = '<html>Bravo! flag{test_flag_123}</html>'
    session.response = mock_response

    # When
    result = session.process_response()

    # Then
    assert result is True
    assert "flag{test_flag_123}" in session.valid_flag


def test_process_response_echec():
    # Given
    session = Session("http://example.com/captcha1/")
    mock_response = MagicMock()
    mock_response.text = '<html>Wrong answer</html>'
    session.response = mock_response

    # When
    result = session.process_response()

    # Then
    assert result is False


def test_get_flag():
    # Given
    session = Session("http://example.com/captcha1/")
    session.valid_flag = "FLAG{abc123}"

    # When
    result = session.get_flag()

    # Then
    assert result == "FLAG{abc123}"
