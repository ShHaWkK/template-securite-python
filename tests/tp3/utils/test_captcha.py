"""
Tests pour le module captcha.
"""

from unittest.mock import MagicMock
from src.tp3.utils.captcha import Captcha, solve_captcha


def test_captcha_init():
    """Test l'initialisation du captcha."""
    # Given
    session = MagicMock()

    # When
    captcha = Captcha(session)

    # Then
    assert captcha.session == session
    assert captcha.image is None
    assert captcha.value == ""


def test_captcha_init_sans_session():
    """Test l'initialisation sans session."""
    # When
    captcha = Captcha()

    # Then
    assert captcha.session is None
    assert captcha.image is None


def test_solve_sans_image():
    """Test la resolution sans image chargee."""
    # Given
    captcha = Captcha()
    captcha.image = None

    # When
    result = captcha.solve()

    # Then
    assert result is False
    assert captcha.value == ""


def test_capture_sans_session():
    """Test la capture sans session."""
    # Given
    captcha = Captcha(session=None)

    # When
    result = captcha.capture()

    # Then
    assert result is False
    assert captcha.image is None


def test_capture_erreur_http():
    """Test la capture avec erreur HTTP."""
    # Given
    session = MagicMock()
    session.get.return_value.status_code = 404
    captcha = Captcha(session)

    # When
    result = captcha.capture("http://example.com/captcha.php")

    # Then
    assert result is False
    assert captcha.image is None


def test_capture_exception():
    """Test la capture avec exception."""
    # Given
    session = MagicMock()
    session.get.side_effect = Exception("Erreur reseau")
    captcha = Captcha(session)

    # When
    result = captcha.capture()

    # Then
    assert result is False
    assert captcha.image is None


def test_get_value():
    """Test la recuperation de la valeur."""
    # Given
    captcha = Captcha()
    captcha.value = "123456"

    # When
    result = captcha.get_value()

    # Then
    assert result == "123456"


def test_is_valid_true():
    """Test la validation avec valeur correcte."""
    # Given
    captcha = Captcha()
    captcha.value = "123456"  # 6 chiffres

    # When
    result = captcha.is_valid()

    # Then
    assert result is True


def test_is_valid_false_trop_court():
    """Test la validation avec valeur trop courte."""
    # Given
    captcha = Captcha()
    captcha.value = "12345"  # 5 chiffres

    # When
    result = captcha.is_valid()

    # Then
    assert result is False


def test_is_valid_false_vide():
    """Test la validation avec valeur vide."""
    # Given
    captcha = Captcha()
    captcha.value = ""

    # When
    result = captcha.is_valid()

    # Then
    assert result is False


def test_str_representation():
    """Test la representation string."""
    # Given
    captcha = Captcha()
    captcha.value = "123456"

    # When
    result = str(captcha)

    # Then
    assert "123456" in result
    assert "valid=True" in result


def test_solve_captcha_function():
    """Test la fonction utilitaire solve_captcha."""
    # Given
    session = MagicMock()
    session.get.side_effect = Exception("Erreur")

    # When
    result = solve_captcha(session)

    # Then
    assert result == ""
