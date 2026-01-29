"""
TP2 - Analyse de shellcodes avec pylibemu, capstone et LLM.

Fonctions principales:
    - get_shellcode_strings: retourne les chaînes de caractères présentes dans le shellcode
    - get_pylibemu_analysis: retourne l'analyse Pylibemu du shellcode
    - get_capstone_analysis: retourne l'analyse Capstone du shellcode
    - get_llm_analysis: retourne l'analyse LLM du shellcode
"""
from __future__ import annotations

import argparse
import os

from tp2.utils.config import logger
from tp2.utils.shellcode_io import read_shellcodes_from_file
from tp2.utils.report import generate_shellcode_report

from tp2.analysis.Analysis import (
    get_shellcode_strings,
    get_pylibemu_analysis,
    get_capstone_analysis,
    get_llm_analysis,
)


def _get_provider_name(args_provider: str | None) -> str:
    """Détermine le provider LLM à utiliser selon la configuration."""
    if args_provider:
        return args_provider
    env_choice = os.getenv("TP2_LLM_PROVIDER", "").strip().lower()
    if env_choice:
        return env_choice
    if os.getenv("OPENAI_API_KEY", "").strip():
        return "openai"
    if os.getenv("GEMINI_API_KEY", "").strip():
        return "gemini"
    return "local"


def main() -> int:
    """Point d'entrée principal du TP2."""
    parser = argparse.ArgumentParser(
        prog="tp2",
        description="TP2 - Analyse de shellcodes avec pylibemu, capstone et LLM",
    )
    parser.add_argument("-f", "--file", required=True, help="Fichier contenant le(s) shellcode(s)")
    parser.add_argument("--provider", choices=["openai", "gemini", "local"], help="Provider LLM à utiliser")
    parser.add_argument("--no-llm", action="store_true", help="Désactive l'analyse LLM")
    parser.add_argument("--pdf", action="store_true", help="Génère un rapport PDF")
    parser.add_argument("-o", "--output-dir", default=".", help="Répertoire de sortie pour les PDF")
    args = parser.parse_args()

    # Lecture des shellcodes depuis le fichier
    shellcodes = read_shellcodes_from_file(args.file)
    if not shellcodes:
        logger.error("Aucun shellcode trouvé dans le fichier.")
        return 2

    provider_name = _get_provider_name(args.provider)
    generated_pdfs: list[str] = []

    for idx, shellcode in enumerate(shellcodes, start=1):
        # Log 
        logger.info(f"Testing shellcode #{idx} of size {len(shellcode)}B")

        # Extraction des chaînes
        strings = get_shellcode_strings(shellcode)

        # Analyse Pylibemu (émulation)
        pylibemu_out = get_pylibemu_analysis(shellcode)

        # Analyse Capstone (désassemblage)
        capstone_out = get_capstone_analysis(shellcode, bits=32, base_addr=0x1000)

        logger.info("Shellcode analysed !")

        # Affichage de l'analyse Pylibemu (format prof)
        if pylibemu_out and "API" in pylibemu_out:
            for line in pylibemu_out.split("\n"):
                if line.strip():
                    logger.info(line.strip())

        # Affichage des instructions désassemblées
        print("\n<Shellcode instructions>")
        for line in capstone_out.split("\n"):
            print(line)

        # 4. Analyse LLM
        llm_analysis = ""
        if not args.no_llm:
            llm_analysis = get_llm_analysis(
                shellcode,
                bits=32,
                base_addr=0x1000,
                strings=strings,
                pylibemu_out=pylibemu_out,
                capstone_out=capstone_out,
                llm_provider=args.provider,
            )
            print("\n<Explication LLM>")
            logger.info(f"Explication LLM: {llm_analysis[:200]}..." if len(llm_analysis) > 200 else f"Explication LLM: {llm_analysis}")
            print(llm_analysis)

        # Génération du rapport PDF si demandé
        if args.pdf:
            os.makedirs(args.output_dir, exist_ok=True)
            pdf_path = generate_shellcode_report(
                shellcode=shellcode,
                shellcode_index=idx,
                strings=strings,
                pylibemu_out=pylibemu_out,
                capstone_out=capstone_out,
                llm_analysis=llm_analysis if llm_analysis else "(Analyse LLM désactivée)",
                output_path=os.path.join(args.output_dir, f"shellcode_report_{idx}.pdf"),
                llm_provider=provider_name,
            )
            generated_pdfs.append(pdf_path)
            logger.info(f"Rapport PDF généré: {pdf_path}")

        print("\n" + "=" * 60 + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
