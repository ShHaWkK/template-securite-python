import os
import re

from .capstone_impl import capstone_disasm
from .pylibemu_impl import pylibemu_analyze
from .llm import explain_with_llm


# APIs Windows connues
WINDOWS_APIS = [
    "loadlibrary",
    "getprocaddress",
    "virtualalloc",
    "createprocess",
    "winexec",
    "shellexecute",
    "urldownload",
    "wsastartup",
    "socket",
    "connect",
    "recv",
    "send",
    "createfile",
    "writefile",
    "readfile",
]


def get_shellcode_strings(shellcode, min_len=4):
    """Extrait les chaines ASCII du shellcode."""
    results = []
    current = ""

    for byte in shellcode:
        if 32 <= byte <= 126:
            current += chr(byte)
        else:
            if len(current) >= min_len:
                results.append(current)
            current = ""

    if len(current) >= min_len:
        results.append(current)

    # enlever doublons
    seen = set()
    final = []
    for s in results:
        s = s.strip()
        if s and s not in seen:
            final.append(s)
            seen.add(s)

    return final


def get_pylibemu_analysis(shellcode):
    """Lance l'analyse pylibemu."""
    return pylibemu_analyze(shellcode)


def get_capstone_analysis(shellcode, bits=32, base_addr=0x1000):
    """Desassemble le shellcode avec capstone."""
    return capstone_disasm(shellcode, bits=bits, base_addr=base_addr)


# =============================================================================
# FONCTIONS DE BASE - appelees par les autres
# =============================================================================


def analyser_instructions(asm_lines):
    """Cherche des patterns dans le code asm."""
    asm_text = "\n".join(asm_lines).lower()

    return {
        "nop": "nop" in asm_text,
        "xor": "xor" in asm_text,
        "call": "call" in asm_text,
        "push": "push" in asm_text,
        "pop": "pop" in asm_text,
        "int80": "int 0x80" in asm_text,
        "syscall": "syscall" in asm_text,
        "loop": any(x in asm_text for x in ["loop", "jne", "jnz", "je", "jz"]),
    }


def detecter_indicateurs(strings):
    """Detecte des indicateurs suspects dans les strings."""
    apis = []
    reseau = []
    fichiers = []
    commandes = []

    for s in strings or []:
        sl = s.lower()

        for api in WINDOWS_APIS:
            if api in sl:
                apis.append(s)
                break

        if "http" in sl or "://" in sl or "www." in sl:
            reseau.append(s)

        if ".exe" in sl or ".dll" in sl or "system32" in sl:
            fichiers.append(s)

        if "cmd" in sl or "powershell" in sl or "/bin/sh" in sl:
            commandes.append(s)

    return apis, reseau, fichiers, commandes


def calculer_niveau(patterns, size, apis):
    """Calcule le niveau de difficulte."""
    score = 0

    if patterns.get("xor"):
        score += 2
    if patterns.get("loop"):
        score += 1
    if patterns.get("call"):
        score += 1
    if size > 200:
        score += 1
    if size > 500:
        score += 2
    if apis:
        score += 2

    if score <= 2:
        return "facile"
    elif score <= 5:
        return "moyen"
    return "difficile"


def extraire_iocs(strings):
    """Extrait les IOCs des strings."""
    iocs = []
    ip_regex = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    for s in (strings or [])[:10]:
        iocs.append(f'String: "{s}"')
        for ip in ip_regex.findall(s):
            iocs.append(f"IP: {ip}")

    return iocs


# =============================================================================
# FONCTIONS QUI APPELLENT LES AUTRES
# =============================================================================


def generer_resume(patterns, size, nb_instructions):
    """Genere le resume a partir des patterns detectes."""
    resume = [f"Shellcode de {size} octets ({nb_instructions} instructions)"]

    if patterns["nop"]:
        resume.append("NOP sled detecte")
    if patterns["xor"]:
        resume.append("XOR detecte (encodage probable)")
    if patterns["int80"] or patterns["syscall"]:
        resume.append("Syscalls Linux")
    if patterns["call"] and patterns["push"]:
        resume.append("Pattern PUSH/CALL")

    return resume


def generer_comportement(patterns, apis, reseau, fichiers, commandes):
    """Genere la liste des comportements detectes."""
    comportement = []

    if patterns["int80"] or patterns["syscall"]:
        comportement.append("Shellcode Linux (syscalls)")
    if apis:
        comportement.append(f"APIs Windows: {', '.join(apis[:3])}")
    if reseau:
        comportement.append(f"Indicateurs reseau: {', '.join(reseau[:2])}")
    if fichiers:
        comportement.append(f"Fichiers: {', '.join(fichiers[:2])}")
    if commandes:
        comportement.append(f"Commandes: {', '.join(commandes[:2])}")
    if patterns["loop"]:
        comportement.append("Boucle detectee")
    if patterns["call"] and patterns["push"]:
        comportement.append("Pattern PUSH/CALL")

    return comportement


def analyser_shellcode(shellcode, asm_lines, strings):
    """
    Fonction centrale qui analyse le shellcode.
    Appelee par toutes les autres fonctions d'analyse.
    """
    size = len(shellcode)

    # appel des fonctions de base
    patterns = analyser_instructions(asm_lines)
    apis, reseau, fichiers, commandes = detecter_indicateurs(strings)
    niveau = calculer_niveau(patterns, size, apis)
    iocs = extraire_iocs(strings)

    # generation du resume et comportement
    resume = generer_resume(patterns, size, len(asm_lines))
    comportement = generer_comportement(patterns, apis, reseau, fichiers, commandes)

    return {
        "size": size,
        "patterns": patterns,
        "apis": apis,
        "reseau": reseau,
        "fichiers": fichiers,
        "commandes": commandes,
        "niveau": niveau,
        "iocs": iocs,
        "resume": resume,
        "comportement": comportement,
    }


# =============================================================================
# FONCTIONS PRINCIPALES - utilisent analyser_shellcode()
# =============================================================================


def construire_prompt(shellcode, strings, pylibemu_out, capstone_out):
    """Construit le prompt pour le LLM."""
    asm_lines = capstone_out.splitlines()

    # utilise la fonction centrale
    analyse = analyser_shellcode(shellcode, asm_lines, strings)

    # extrait du desassemblage (100 lignes max)
    asm_extrait = "\n".join(asm_lines[:100])

    prompt = f"""Analyse ce shellcode de {analyse["size"]} octets.

Strings: {strings if strings else "aucune"}

Pylibemu:
{pylibemu_out}

Desassemblage:
{asm_extrait}

Resume: {", ".join(analyse["resume"])}
Comportement: {", ".join(analyse["comportement"]) if analyse["comportement"] else "a determiner"}
IOC: {", ".join(analyse["iocs"]) if analyse["iocs"] else "aucun"}
Niveau estime: {analyse["niveau"]}

Donne moi:
1) Resume en 5 lignes max
2) Comportement (API, DLL, reseau, fichiers, commandes)
3) IOC detectes
4) Niveau de difficulte avec justification"""

    return prompt, analyse


def analyse_locale(shellcode, asm_lines, strings):
    """Analyse sans LLM - utilise analyser_shellcode()."""

    # utilise la fonction centrale
    analyse = analyser_shellcode(shellcode, asm_lines, strings)

    output = []

    # resume
    output.append("1) RESUME")
    for r in analyse["resume"]:
        output.append(f"   {r}")

    # comportement
    output.append("\n2) COMPORTEMENT")
    if analyse["comportement"]:
        for c in analyse["comportement"]:
            output.append(f"   {c}")
    else:
        if analyse["size"] < 50:
            output.append("   Shellcode court - stub ou payload simple")
        else:
            output.append("   Analyse manuelle recommandee")

    # IOC
    output.append("\n3) IOC")
    if analyse["iocs"]:
        for ioc in analyse["iocs"][:10]:
            output.append(f"   {ioc}")
    else:
        output.append("   Aucun IOC detecte")

    # niveau
    output.append(f"\n4) NIVEAU: {analyse['niveau'].upper()}")
    if analyse["niveau"] == "facile":
        output.append("   Shellcode simple, peu d'obfuscation")
    elif analyse["niveau"] == "moyen":
        output.append("   Techniques d'encodage ou taille moyenne")
    else:
        output.append("   Techniques multiples, APIs complexes")

    return "\n".join(output)


def get_llm_analysis(
    shellcode,
    bits=32,
    base_addr=0x1000,
    strings=None,
    pylibemu_out=None,
    capstone_out=None,
    llm_provider=None,
):
    """Analyse le shellcode avec un LLM ou en local."""

    # recuperer les donnees si pas fournies
    if strings is None:
        strings = get_shellcode_strings(shellcode)
    if pylibemu_out is None:
        pylibemu_out = get_pylibemu_analysis(shellcode)
    if capstone_out is None:
        capstone_out = get_capstone_analysis(shellcode, bits=bits, base_addr=base_addr)

    asm_lines = capstone_out.splitlines()

    # determiner le provider
    provider = (llm_provider or "").strip().lower()
    if not provider:
        provider = os.getenv("TP2_LLM_PROVIDER", "").strip().lower()
    if not provider:
        if os.getenv("OPENAI_API_KEY", "").strip():
            provider = "openai"
        elif os.getenv("GEMINI_API_KEY", "").strip():
            provider = "gemini"
        else:
            provider = "local"

    # si local, analyse sans LLM
    if provider == "local":
        return analyse_locale(shellcode, asm_lines, strings)

    # construire le prompt et appeler le LLM
    prompt, _ = construire_prompt(shellcode, strings, pylibemu_out, capstone_out)

    result = explain_with_llm(prompt, provider=provider)

    # si erreur LLM, fallback sur analyse locale
    if result.startswith("(LLM"):
        local = analyse_locale(shellcode, asm_lines, strings)
        return f"Erreur LLM: {result}\n\n--- Analyse locale ---\n\n{local}"

    return result


# =============================================================================
# FONCTION POUR LES TESTS
# =============================================================================


def _extract_analysis_hints(shellcode, asm_lines, strings):
    """Pour les tests - utilise analyser_shellcode()."""
    analyse = analyser_shellcode(shellcode, asm_lines, strings)

    return (analyse["resume"], analyse["comportement"], analyse["iocs"], analyse["niveau"])
