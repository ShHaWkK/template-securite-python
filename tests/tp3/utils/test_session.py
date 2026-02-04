"""
Tests pour le module session.
"""

from unittest.mock import MagicMock
from src.tp3.utils.session import ChallengeSession


def test_challenge_session_init():
    """Test l'initialisation d'une session de challenge."""
    # Given
    challenge_num = 1

    # When
    session = ChallengeSession(challenge_num)

    # Then
    assert session.challenge_num == 1
    assert session.url.endswith("/captcha1/")
    assert session.flag_min == 1000
    assert session.flag_max == 2000
    assert session.needs_captcha is False
    assert session.found_flag is None
    assert session.flag_string is None


def test_challenge_session_init_ch5():
    """Test l'initialisation pour le challenge 5."""
    # Given
    challenge_num = 5

    # When
    session = ChallengeSession(challenge_num)

    # Then
    assert session.challenge_num == 5
    assert session.url.endswith("/captcha5/")
    assert session.flag_min == 8000
    assert session.flag_max == 9000
    assert session.needs_captcha is True
    assert "Magic-Word" in session.headers


def test_create_session():
    """Test la creation d'une session HTTP."""
    # Given
    challenge = ChallengeSession(1)

    # When
    session = challenge._create_session()

    # Then
    assert session is not None
    assert "User-Agent" in session.headers


def test_get_post_headers():
    """Test la generation des headers POST."""
    # Given
    challenge = ChallengeSession(1)

    # When
    headers = challenge._get_post_headers()

    # Then
    assert "Content-Type" in headers
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert "Referer" in headers


def test_extract_flag_format_standard():
    """Test l'extraction d'un flag format standard."""
    # Given
    challenge = ChallengeSession(1)
    html = "<html>Bravo! FLAG-1{test_flag}</html>"

    # When
    result = challenge._extract_flag(html)

    # Then
    assert result == "FLAG-1{test_flag}"


def test_extract_flag_avec_espaces():
    """Test l'extraction d'un flag avec espaces (challenge 5)."""
    # Given
    challenge = ChallengeSession(5)
    html = "<html>F L A G - 5 {Th3_l4st_0n3}</html>"

    # When
    result = challenge._extract_flag(html)

    # Then
    assert result is not None
    assert "Th3_l4st_0n3" in result


def test_extract_flag_absent():
    """Test l'extraction quand pas de flag."""
    # Given
    challenge = ChallengeSession(1)
    html = "<html>Incorrect flag</html>"

    # When
    result = challenge._extract_flag(html)

    # Then
    assert result is None


def test_is_success_avec_correct():
    """Test la detection de succes avec 'Correct'."""
    # Given
    challenge = ChallengeSession(1)
    response = MagicMock()
    response.text = "<html>Correct! You found it!</html>"
    response.headers = {}

    # When
    result = challenge._is_success(response)

    # Then
    assert result is True


def test_is_success_avec_incorrect():
    """Test la detection d'echec avec 'Incorrect'."""
    # Given
    challenge = ChallengeSession(1)
    response = MagicMock()
    response.text = "<html>Incorrect flag</html>"
    response.headers = {}

    # When
    result = challenge._is_success(response)

    # Then
    assert result is False


def test_is_success_content_length():
    """Test la detection de succes par Content-Length."""
    # Given
    challenge = ChallengeSession(1)
    response = MagicMock()
    response.text = "<html>Some content</html>"
    response.headers = {"Content-Length": "588"}

    # When
    result = challenge._is_success(response, expected_cl="588")

    # Then
    assert result is True


def test_get_result():
    """Test la recuperation des resultats."""
    # Given
    challenge = ChallengeSession(1)
    challenge.found_flag = 1337
    challenge.flag_string = "FLAG-1{test}"

    # When
    result = challenge.get_result()

    # Then
    assert result["challenge"] == 1
    assert result["flag_value"] == 1337
    assert result["flag_string"] == "FLAG-1{test}"
    assert "url" in result
