"""
Tests pour le module decoder du TP4.
"""

from src.tp4.utils.decoder import (
    decode_base64,
    decode_hex,
    decode_binary,
    decode_rot13,
    decode_ascii,
    decode_url,
    detect_and_decode,
    decode_chain,
)


class TestDecodeBase64:
    """Tests pour decode_base64."""

    def test_decode_simple(self):
        # Given
        encoded = "SGVsbG8gV29ybGQh"

        # When
        result = decode_base64(encoded)

        # Then
        assert result == "Hello World!"

    def test_decode_with_padding(self):
        # Given
        encoded = "SGVsbG8="

        # When
        result = decode_base64(encoded)

        # Then
        assert result == "Hello"

    def test_decode_without_padding(self):
        # Given - base64 sans padding
        encoded = "SGVsbG8"

        # When
        result = decode_base64(encoded)

        # Then
        assert result == "Hello"

    def test_decode_invalid(self):
        # Given
        encoded = "not valid base64!!!"

        # When
        result = decode_base64(encoded)

        # Then
        assert result is None or result == ""


class TestDecodeHex:
    """Tests pour decode_hex."""

    def test_decode_simple(self):
        # Given
        encoded = "48656c6c6f"

        # When
        result = decode_hex(encoded)

        # Then
        assert result == "Hello"

    def test_decode_with_spaces(self):
        # Given
        encoded = "48 65 6c 6c 6f"

        # When
        result = decode_hex(encoded)

        # Then
        assert result == "Hello"

    def test_decode_uppercase(self):
        # Given
        encoded = "48656C6C6F"

        # When
        result = decode_hex(encoded)

        # Then
        assert result == "Hello"


class TestDecodeBinary:
    """Tests pour decode_binary."""

    def test_decode_simple(self):
        # Given - "Hello" en binaire
        encoded = "0100100001100101011011000110110001101111"

        # When
        result = decode_binary(encoded)

        # Then
        assert result == "Hello"

    def test_decode_with_spaces(self):
        # Given
        encoded = "01001000 01100101 01101100 01101100 01101111"

        # When
        result = decode_binary(encoded)

        # Then
        assert result == "Hello"


class TestDecodeRot13:
    """Tests pour decode_rot13."""

    def test_decode_simple(self):
        # Given
        encoded = "Uryyb"

        # When
        result = decode_rot13(encoded)

        # Then
        assert result == "Hello"

    def test_decode_full_alphabet(self):
        # Given
        encoded = "Gur dhvpx oebja sbk"

        # When
        result = decode_rot13(encoded)

        # Then
        assert result == "The quick brown fox"


class TestDecodeAscii:
    """Tests pour decode_ascii."""

    def test_decode_with_spaces(self):
        # Given - "Hello" en codes ASCII
        encoded = "72 101 108 108 111"

        # When
        result = decode_ascii(encoded)

        # Then
        assert result == "Hello"

    def test_decode_with_commas(self):
        # Given
        encoded = "72,101,108,108,111"

        # When
        result = decode_ascii(encoded)

        # Then
        assert result == "Hello"


class TestDecodeUrl:
    """Tests pour decode_url."""

    def test_decode_spaces(self):
        # Given
        encoded = "Hello%20World"

        # When
        result = decode_url(encoded)

        # Then
        assert result == "Hello World"

    def test_decode_special_chars(self):
        # Given
        encoded = "Hello%21%3F"

        # When
        result = decode_url(encoded)

        # Then
        assert result == "Hello!?"


class TestDetectAndDecode:
    """Tests pour detect_and_decode."""

    def test_detect_base64(self):
        # Given
        encoded = "SGVsbG8gV29ybGQh"

        # When
        result, encoding = detect_and_decode(encoded)

        # Then
        assert result == "Hello World!"
        assert encoding == "base64"

    def test_detect_hex(self):
        # Given
        encoded = "48656c6c6f"

        # When
        result, encoding = detect_and_decode(encoded)

        # Then
        assert result == "Hello"
        assert encoding == "hex"

    def test_detect_binary(self):
        # Given
        encoded = "01001000 01100101 01101100 01101100 01101111"

        # When
        result, encoding = detect_and_decode(encoded)

        # Then
        assert result == "Hello"
        assert encoding == "binary"

    def test_detect_empty(self):
        # Given
        encoded = ""

        # When
        result, encoding = detect_and_decode(encoded)

        # Then
        assert result is None
        assert encoding == "empty"


class TestDecodeChain:
    """Tests pour decode_chain (multi-couches)."""

    def test_single_layer(self):
        # Given
        encoded = "SGVsbG8="

        # When
        result = decode_chain(encoded)

        # Then
        assert result == "Hello"

    def test_double_layer_base64(self):
        # Given - hex("Hello")
        encoded = "48656c6c6f"

        # When
        result = decode_chain(encoded)

        # Then
        assert result == "Hello"
