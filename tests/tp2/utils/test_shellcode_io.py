"""
Tests unitaires pour le module shellcode_io.
"""

import os
import tempfile

from src.tp2.utils.shellcode_io import read_shellcodes_from_file


def test_when_file_not_exists_then_return_empty_list():
    # Given
    fake_path = "/nonexistent/path/shellcode.txt"

    # When
    result = read_shellcodes_from_file(fake_path)

    # Then
    assert result == []


def test_when_file_is_empty_then_return_empty_list():
    # Given
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("")
        temp_path = f.name

    try:
        # When
        result = read_shellcodes_from_file(temp_path)

        # Then
        assert result == []
    finally:
        os.unlink(temp_path)


def test_when_file_contains_c_style_shellcode_then_parse_correctly():
    # Given
    shellcode_text = r"\x90\x90\xeb\xfe"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(shellcode_text)
        temp_path = f.name

    try:
        # When
        result = read_shellcodes_from_file(temp_path)

        # Then
        assert len(result) == 1
        assert result[0] == b"\x90\x90\xeb\xfe"
    finally:
        os.unlink(temp_path)


def test_when_file_contains_hex_stream_then_parse_correctly():
    # Given
    hex_stream = "9090ebfe"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(hex_stream)
        temp_path = f.name

    try:
        # When
        result = read_shellcodes_from_file(temp_path)

        # Then
        assert len(result) == 1
        assert result[0] == b"\x90\x90\xeb\xfe"
    finally:
        os.unlink(temp_path)


def test_when_file_contains_spaced_hex_then_parse_correctly():
    # Given
    hex_stream = "90 90 eb fe"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(hex_stream)
        temp_path = f.name

    try:
        # When
        result = read_shellcodes_from_file(temp_path)

        # Then
        assert len(result) == 1
        assert result[0] == b"\x90\x90\xeb\xfe"
    finally:
        os.unlink(temp_path)


def test_when_path_is_empty_then_return_empty_list():
    # Given
    empty_path = ""

    # When
    result = read_shellcodes_from_file(empty_path)

    # Then
    assert result == []


def test_when_path_is_none_then_return_empty_list():
    # Given
    none_path = None

    # When
    result = read_shellcodes_from_file(none_path)

    # Then
    assert result == []


def test_when_file_contains_binary_data_then_return_raw_bytes():
    # Given
    binary_data = b"\x90\x90\xeb\xfe"
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
        f.write(binary_data)
        temp_path = f.name

    try:
        # When
        result = read_shellcodes_from_file(temp_path)

        # Then
        assert len(result) == 1
        assert result[0] == binary_data
    finally:
        os.unlink(temp_path)
