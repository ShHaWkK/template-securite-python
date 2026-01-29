from __future__ import annotations

import os
from typing import Literal, Optional

from tp2.analysis.capstone_impl import capstone_disasm
from tp2.analysis.pylibemu_impl import pylibemu_analyze
from tp2.analysis.llm import explain_with_llm

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
        return _local_analysis(shellcode, asm_lines, strings)
    out = explain_with_llm(prompt, provider=provider)
    if out.strip().startswith("(LLM/") or out.strip().startswith("(LLM"):
        # Afficher l'erreur LLM puis faire l'analyse locale
        error_msg = out.strip()
        local_analysis = _local_analysis(shellcode, asm_lines, strings)
        return f"⚠️  {error_msg}\n\n--- Analyse locale (heuristique) ---\n\n{local_analysis}"
    return out


def _local_analysis(shellcode: bytes, asm_lines: list[str], strings: Optional[list[str]]) -> str:
    """Analyse heuristique locale détaillée (sans LLM)."""
    size = len(shellcode)
    asm_lower = [l.lower() for l in asm_lines]
    asm_text = "\n".join(asm_lower)
    
    # Détection des patterns
    has_nop = any("nop" in l for l in asm_lower)
    has_jmp = any("jmp" in l for l in asm_lower)
    has_call = any("call" in l for l in asm_lower)
    has_push = any("push" in l for l in asm_lower)
    has_pop = any("pop" in l for l in asm_lower)
    has_xor = any("xor" in l for l in asm_lower)
    has_int80 = "int 0x80" in asm_text or "int80" in asm_text
    has_syscall = "syscall" in asm_text
    has_sysenter = "sysenter" in asm_text
    has_mov = any("mov" in l for l in asm_lower)
    has_loop = any(x in asm_text for x in ["loop", "rep", "jne", "jnz", "je", "jz"])
    has_stack_ops = has_push or has_pop or "esp" in asm_text or "rsp" in asm_text
    
    # Détection API Windows (par patterns dans strings)
    windows_apis = []
    linux_syscalls = []
    suspicious_strings = []
    network_indicators = []
    file_indicators = []
    
    for s in (strings or []):
        sl = s.lower()
        # APIs Windows
        if any(api in sl for api in ["loadlibrary", "getprocaddress", "virtualalloc", "createprocess",
                                       "winexec", "shellexecute", "urldownload", "wsastartup", "socket",
                                       "connect", "recv", "send", "createfile", "writefile", "readfile"]):
            windows_apis.append(s)
        # Indicateurs réseau
        if any(x in sl for x in ["http", "https", "ftp", "://", "www.", ".com", ".net", ".ru", ".cn"]):
            network_indicators.append(s)
        # Indicateurs fichiers
        if any(x in sl for x in [".exe", ".dll", ".bat", ".ps1", ".vbs", "c:\\", "system32", "temp"]):
            file_indicators.append(s)
        # Strings suspectes
        if any(x in sl for x in ["cmd", "powershell", "wget", "curl", "/bin/sh", "/bin/bash"]):
            suspicious_strings.append(s)
    
    # Résumé
    resume = [f"Shellcode de {size} octets ({len(asm_lines)} instructions désassemblées)."]
    
    if has_nop:
        nop_count = sum(1 for l in asm_lower if "nop" in l)
        resume.append(f"NOP sled détecté ({nop_count} NOP) - technique d'alignement/évasion.")
    
    if has_xor:
        xor_count = sum(1 for l in asm_lower if "xor" in l)
        resume.append(f"XOR détecté ({xor_count}x) - possible décodage/chiffrement.")
    
    if has_int80 or has_syscall or has_sysenter:
        resume.append("Appels système Linux détectés (int 0x80/syscall/sysenter).")
    
    if has_call and has_push:
        resume.append("Pattern PUSH/CALL détecté - probable passage de paramètres.")
    
    # Comportement
    comportement = []
    
    if has_int80 or has_syscall:
        comportement.append("Exécution de syscalls Linux (shellcode Linux probable).")
    
    if windows_apis:
        comportement.append(f"APIs Windows référencées: {', '.join(windows_apis[:5])}")
    
    if has_loop:
        comportement.append("Boucle/itération détectée (possible décodage ou brute-force).")
    
    if has_stack_ops and has_call:
        comportement.append("Manipulation de pile avec appels - structure de fonction.")
    
    if network_indicators:
        comportement.append(f"Indicateurs réseau: {', '.join(network_indicators[:3])}")
    
    if file_indicators:
        comportement.append(f"Indicateurs fichiers: {', '.join(file_indicators[:3])}")
    
    if suspicious_strings:
        comportement.append(f"Commandes suspectes: {', '.join(suspicious_strings[:3])}")
    
    if not comportement:
        if size < 50:
            comportement.append("Shellcode court - possible stub ou shellcode simple.")
        else:
            comportement.append("Analyse heuristique insuffisante - examen manuel recommandé.")
    
    # IOC
    iocs = []
    for s in (strings or [])[:15]:
        iocs.append(f"String: \"{s}\"")
    
    # Détecter IPs potentielles dans le shellcode
    import re
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for s in (strings or []):
        ips = ip_pattern.findall(s)
        for ip in ips:
            iocs.append(f"IP: {ip}")
    
    # Niveau de difficulté
    complexity_score = 0
    if has_xor: complexity_score += 2
    if has_loop: complexity_score += 1
    if has_call: complexity_score += 1
    if size > 200: complexity_score += 1
    if size > 500: complexity_score += 2
    if windows_apis: complexity_score += 2
    
    if complexity_score <= 2:
        level = "facile"
        level_reason = "shellcode simple, peu d'obfuscation"
    elif complexity_score <= 5:
        level = "moyen"
        level_reason = "techniques d'encodage ou taille modérée"
    else:
        level = "difficile"
        level_reason = "multiple techniques, APIs complexes ou grande taille"
    
    # Formater le résultat
    result = []
    result.append("1) RÉSUMÉ")
    for r in resume:
        result.append(f"   • {r}")
    
    result.append("\n2) COMPORTEMENT PROBABLE")
    for c in comportement:
        result.append(f"   • {c}")
    
    result.append("\n3) IOC (Indicateurs de Compromission)")
    if iocs:
        for ioc in iocs[:10]:
            result.append(f"   • {ioc}")
    else:
        result.append("   • (aucun détecté)")
    
    result.append(f"\n4) NIVEAU: {level.upper()}")
    result.append(f"   Justification: {level_reason}")
    
    return "\n".join(result)
