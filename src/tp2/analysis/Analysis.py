from __future__ import annotations

from typing import Literal, Optional
from .capstone_impl import capstone_disasm
from .pylibemu_impl import pylibemu_analyze
from .llm import explain_with_llm
import os

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

    provider = (llm_provider or "").strip().lower()
    if not provider:
        env_choice = os.getenv("TP2_LLM_PROVIDER", "").strip().lower()
        if env_choice:
            provider = env_choice
        else:
            has_openai = bool(os.getenv("OPENAI_API_KEY", "").strip())
            has_gemini = bool(os.getenv("GEMINI_API_KEY", "").strip())
            if has_openai:
                provider = "openai"
            elif has_gemini:
                provider = "gemini"
            else:
                provider = "local"
    if provider == "local":
        size = len(shellcode)
        has_jmp = any("jmp" in l.lower() for l in asm_lines)
        has_nop = any("nop" in l.lower() for l in asm_lines)
        level = "facile" if size <= 256 else "moyen"
        resume = []
        resume.append(f"Shellcode de taille {size} octets.")
        if has_nop:
            resume.append("Présence de instructions NOP.")
        if has_jmp:
            resume.append("Présence de branchement/loop (JMP).")
        comportement = []
        if has_jmp:
            comportement.append("Boucle ou redirection de flux.")
        if has_nop:
            comportement.append("Alignement ou no-op.")
        iocs = []
        for s in (strings or [])[:10]:
            iocs.append(f"String: {s}")
        return (
            "Résumé:\n- " + "\n- ".join(resume or ["Pas d'éléments notables"]) + "\n\n"
            "Comportement probable:\n- " + "\n- ".join(comportement or ["Insuffisant pour conclure"]) + "\n\n"
            "IOC:\n- " + ("\n- ".join(iocs) if iocs else "(aucun)") + "\n\n"
            f"Niveau: {level} (taille {size}B)"
        )
    out = explain_with_llm(prompt, provider=provider)
    if out.strip().startswith("(LLM/") or out.strip().startswith("(LLM"):
        provider = "local"
        size = len(shellcode)
        has_jmp = any("jmp" in l.lower() for l in asm_lines)
        has_nop = any("nop" in l.lower() for l in asm_lines)
        level = "facile" if size <= 256 else "moyen"
        resume = []
        resume.append(f"Shellcode de taille {size} octets.")
        if has_nop:
            resume.append("Présence de instructions NOP.")
        if has_jmp:
            resume.append("Présence de branchement/loop (JMP).")
        comportement = []
        if has_jmp:
            comportement.append("Boucle ou redirection de flux.")
        if has_nop:
            comportement.append("Alignement ou no-op.")
        iocs = []
        for s in (strings or [])[:10]:
            iocs.append(f"String: {s}")
        return (
            "Résumé:\n- " + "\n- ".join(resume or ["Pas d'éléments notables"]) + "\n\n"
            "Comportement probable:\n- " + "\n- ".join(comportement or ["Insuffisant pour conclure"]) + "\n\n"
            "IOC:\n- " + ("\n- ".join(iocs) if iocs else "(aucun)") + "\n\n"
            f"Niveau: {level} (taille {size}B)"
        )
    return out
