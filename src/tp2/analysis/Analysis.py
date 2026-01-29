from __future__ import annotations

from typing import Literal, Optional
from .capstone_impl import capstone_disasm
from .pylibemu_impl import pylibemu_analyze
from .llm import explain_with_llm

Bits = Literal[32, 64]


def get_shellcode_strings(shellcode: bytes, min_len: int = 4) -> list[str]:
    def is_printable(b: int) -> bool:
        return 32 <= b <= 126

    out: list[str] = []

    # ASCII
    cur = bytearray()
    for b in shellcode:
        if is_printable(b):
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))

    # UTF-16LE (heuristique: printable + 0x00)
    i = 0
    while i + 1 < len(shellcode):
        start = i
        chars = []
        while i + 1 < len(shellcode):
            c = shellcode[i]
            z = shellcode[i + 1]
            if z == 0x00 and is_printable(c):
                chars.append(c)
                i += 2
            else:
                break
        if len(chars) >= min_len:
            out.append(bytes(chars).decode("ascii", errors="ignore"))
        i = (i + 2) if i == start else (i + 2)

    # dédup stable
    seen = set()
    uniq = []
    for s in out:
        s2 = s.strip()
        if s2 and s2 not in seen:
            uniq.append(s2)
            seen.add(s2)
    return uniq


def get_pylibemu_analysis(shellcode: bytes) -> str:
    return pylibemu_analyze(shellcode)


def get_capstone_analysis(shellcode: bytes, bits: Bits = 32, base_addr: int = 0x1000) -> str:
    return capstone_disasm(shellcode, bits=bits, base_addr=base_addr)


def get_llm_analysis(
    shellcode: bytes,
    bits: Bits = 32,
    base_addr: int = 0x1000,
    *,
    strings: Optional[list[str]] = None,
    pylibemu_out: Optional[str] = None,
    capstone_out: Optional[str] = None,
    llm_provider: Optional[str] = None,
) -> str:
    strings = strings if strings is not None else get_shellcode_strings(shellcode)
    pylibemu_out = pylibemu_out if pylibemu_out is not None else get_pylibemu_analysis(shellcode)
    capstone_out = capstone_out if capstone_out is not None else get_capstone_analysis(shellcode, bits=bits, base_addr=base_addr)

    # Prompt compact (optimisé coût/tokens)
    asm_lines = capstone_out.splitlines()
    asm_preview = "\n".join(asm_lines[:120])  # assez pour “comprendre” sans exploser les tokens

    prompt = f"""
Analyse un shellcode.

Chaînes détectées:
{strings if strings else "(aucune)"}

Analyse pylibemu:
{pylibemu_out}

Désassemblage (extrait):
{asm_preview}

Rends:
1) Résumé (5 lignes max)
2) Comportement probable (API, DLL, process, commandes, réseau, fichiers)
3) IOC (IP/port, chemins, strings, commandes)
4) Niveau (facile/moyen/difficile) + justification
""".strip()

    return explain_with_llm(prompt, provider=llm_provider)
