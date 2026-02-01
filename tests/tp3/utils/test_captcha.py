"""
Tests pour le module captcha.
"""
from unittest.mock import MagicMock, patch
from src.tp3.utils.captcha import Captcha


def test_captcha_init():
    # Given
    url = "http://example.com/captcha1/"

    # When
    captcha = Captcha(url)

    # Then
    assert captcha.url == url
    assert captcha.image is None
    assert captcha.value == ""


def test_solve_sans_image():
    # Given
    captcha = Captcha("http://example.com/captcha1/")
    captcha.image = None

    # When
    captcha.solve()

    # Then
    assert captcha.value == ""


def test_capture_sans_connexion():
    # Given
    captcha = Captcha("http://example.com/captcha1/")
    captcha.session = MagicMock()
    captcha.session.get.side_effect = Exception("Pas de connexion")

    # When
    captcha.capture()

    # Then
    assert captcha.image is None


def test_get_value():
    # Given
    captcha = Captcha("http://example.com/captcha1/")
    captcha.value = "ABC123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "ABC123"
