"""
Tests unitaires pour le module Analysis.
"""

from src.tp2.analysis.Analysis import (
    get_shellcode_strings,
    get_capstone_analysis,
    get_pylibemu_analysis,
    _extract_analysis_hints,
)


class TestGetShellcodeStrings:
    """Tests pour get_shellcode_strings."""

    def test_when_shellcode_has_no_strings_then_return_empty_list(self):
        # Given
        shellcode = b"\x90\x90\xeb\xfe"

        # When
        result = get_shellcode_strings(shellcode)

        # Then
        assert result == []

    def test_when_shellcode_has_ascii_string_then_extract_it(self):
        # Given
        shellcode = b"\x90\x90/bin/sh\x00\xeb\xfe"

        # When
        result = get_shellcode_strings(shellcode)

        # Then
        assert "/bin/sh" in result

    def test_when_shellcode_has_short_string_then_ignore_it(self):
        # Given
        shellcode = b"\x90\x90abc\x00\xeb\xfe"  # "abc" est trop court (< 4 chars)

        # When
        result = get_shellcode_strings(shellcode, min_len=4)

        # Then
        assert "abc" not in result

    def test_when_min_len_is_3_then_extract_short_strings(self):
        # Given
        shellcode = b"\x90\x90cmd\x00\xeb\xfe"

        # When
        result = get_shellcode_strings(shellcode, min_len=3)

        # Then
        assert "cmd" in result

    def test_when_shellcode_has_multiple_strings_then_extract_all(self):
        # Given
        shellcode = b"AAAA/bin/sh\x00BBBBcmd.exe\x00CCCC"

        # When
        result = get_shellcode_strings(shellcode)

        # Then
        # La fonction extrait les chaînes ASCII contiguës, donc "AAAA/bin/sh" est une chaîne
        assert any("/bin/sh" in s for s in result)
        assert any("cmd.exe" in s for s in result)

    def test_when_shellcode_has_duplicate_strings_then_deduplicate(self):
        # Given
        shellcode = b"test_string\x00AAAA\x00test_string\x00"

        # When
        result = get_shellcode_strings(shellcode)

        # Then
        assert result.count("test_string") == 1

    def test_when_shellcode_is_empty_then_return_empty_list(self):
        # Given
        shellcode = b""

        # When
        result = get_shellcode_strings(shellcode)

        # Then
        assert result == []


class TestGetCapstoneAnalysis:
    """Tests pour get_capstone_analysis."""

    def test_when_shellcode_is_nop_sled_then_disassemble_correctly(self):
        # Given
        shellcode = b"\x90\x90\x90\x90"  # NOP NOP NOP NOP

        # When
        result = get_capstone_analysis(shellcode, bits=32)

        # Then
        assert "nop" in result.lower()

    def test_when_shellcode_is_jmp_short_then_disassemble_correctly(self):
        # Given
        shellcode = b"\xeb\xfe"  # jmp short -2 (infinite loop)

        # When
        result = get_capstone_analysis(shellcode, bits=32)

        # Then
        assert "jmp" in result.lower()

    def test_when_shellcode_is_empty_then_return_no_disassembly(self):
        # Given
        shellcode = b""

        # When
        result = get_capstone_analysis(shellcode, bits=32)

        # Then
        assert "aucun" in result.lower() or result == ""

    def test_when_base_addr_is_custom_then_use_it(self):
        # Given
        shellcode = b"\x90"
        base_addr = 0x401000

        # When
        result = get_capstone_analysis(shellcode, bits=32, base_addr=base_addr)

        # Then
        assert "0x00401000" in result

    def test_when_bits_is_64_then_use_64bit_mode(self):
        # Given
        shellcode = b"\x48\x31\xc0"  # xor rax, rax (64-bit)

        # When
        result = get_capstone_analysis(shellcode, bits=64)

        # Then
        assert "xor" in result.lower()
        assert "rax" in result.lower()


class TestGetPylibemuAnalysis:
    """Tests pour get_pylibemu_analysis."""

    def test_when_shellcode_is_simple_then_return_analysis(self):
        # Given
        shellcode = b"\x90\x90\xeb\xfe"

        # When
        result = get_pylibemu_analysis(shellcode)

        # Then
        # Doit retourner quelque chose (même si pylibemu n'est pas installé)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_when_shellcode_is_empty_then_handle_gracefully(self):
        # Given
        shellcode = b""

        # When
        result = get_pylibemu_analysis(shellcode)

        # Then
        assert isinstance(result, str)


class TestExtractAnalysisHints:
    """Tests pour _extract_analysis_hints."""

    def test_when_shellcode_has_nop_then_detect_it(self):
        # Given
        shellcode = b"\x90\x90\x90\x90"
        asm_lines = ["0x1000: nop", "0x1001: nop", "0x1002: nop", "0x1003: nop"]
        strings = []

        # When
        resume, comportement, iocs, level = _extract_analysis_hints(shellcode, asm_lines, strings)

        # Then
        assert any("NOP" in r for r in resume)

    def test_when_shellcode_has_xor_then_detect_encoding(self):
        # Given
        shellcode = b"\x31\xc0"  # xor eax, eax
        asm_lines = ["0x1000: xor eax, eax"]
        strings = []

        # When
        resume, comportement, iocs, level = _extract_analysis_hints(shellcode, asm_lines, strings)

        # Then
        assert any("XOR" in r or "encodage" in r for r in resume)

    def test_when_shellcode_has_syscall_then_detect_linux(self):
        # Given
        shellcode = b"\xcd\x80"  # int 0x80
        asm_lines = ["0x1000: int 0x80"]
        strings = []

        # When
        resume, comportement, iocs, level = _extract_analysis_hints(shellcode, asm_lines, strings)

        # Then
        assert any("Linux" in c or "syscall" in c.lower() for c in comportement) or any(
            "Linux" in r or "système" in r for r in resume
        )

    def test_when_shellcode_has_windows_api_strings_then_detect_them(self):
        # Given
        shellcode = b"LoadLibraryA\x00GetProcAddress\x00"
        asm_lines = []
        strings = ["LoadLibraryA", "GetProcAddress"]

        # When
        resume, comportement, iocs, level = _extract_analysis_hints(shellcode, asm_lines, strings)

        # Then
        assert any("Windows" in c or "API" in c for c in comportement)

    def test_when_shellcode_has_network_indicators_then_detect_them(self):
        # Given
        shellcode = b"http://evil.com\x00"
        asm_lines = []
        strings = ["http://evil.com"]

        # When
        resume, comportement, iocs, level = _extract_analysis_hints(shellcode, asm_lines, strings)

        # Then
        # le code utilise "reseau" sans accent
        assert any("reseau" in c.lower() or "network" in c.lower() for c in comportement)

    def test_when_shellcode_is_small_then_level_is_facile(self):
        # Given
        shellcode = b"\x90" * 10
        asm_lines = ["0x1000: nop"] * 10
        strings = []

        # When
        resume, comportement, iocs, level = _extract_analysis_hints(shellcode, asm_lines, strings)

        # Then
        assert level == "facile"

    def test_when_shellcode_is_complex_then_level_is_difficile(self):
        # Given
        shellcode = b"\x90" * 600  # Grande taille
        asm_lines = ["0x1000: xor eax, eax", "0x1002: call 0x1010", "0x1007: loop 0x1000"]
        strings = ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"]

        # When
        resume, comportement, iocs, level = _extract_analysis_hints(shellcode, asm_lines, strings)

        # Then
        assert level == "difficile"

    def test_when_strings_contain_ip_then_extract_as_ioc(self):
        # Given
        shellcode = b"192.168.1.100\x00"
        asm_lines = []
        strings = ["192.168.1.100"]

        # When
        resume, comportement, iocs, level = _extract_analysis_hints(shellcode, asm_lines, strings)

        # Then
        assert any("IP:" in ioc or "192.168.1.100" in ioc for ioc in iocs)
