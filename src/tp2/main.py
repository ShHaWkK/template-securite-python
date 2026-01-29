from __future__ import annotations

import argparse
import os

from src.tp2.utils.config import logger
from src.tp2.utils.shellcode_io import read_shellcodes_from_file
from src.tp2.utils.report import generate_shellcode_report

from src.tp2.analysis.Analysis import (
    get_shellcode_strings,
    get_pylibemu_analysis,
    get_capstone_analysis,
    get_llm_analysis,
)


def _get_provider_name(args_provider: str | None) -> str:
    """Détermine le nom du provider LLM utilisé."""
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
    parser = argparse.ArgumentParser(
        prog="tp2",
        description="TP2 - Analyse de shellcodes avec LLM et génération de rapport PDF",
    )
    parser.add_argument("-f", "--file", required=True, help="Fichier contenant le(s) shellcode(s).")
    parser.add_argument("--provider", choices=["openai", "gemini", "local"], help="Force le modèle IA.")
    parser.add_argument("--no-llm", action="store_true", help="Désactive l'explication IA.")
    parser.add_argument("--pdf", action="store_true", help="Génère un rapport PDF de l'analyse.")
    parser.add_argument("--output-dir", "-o", default=".", help="Répertoire de sortie pour les rapports PDF.")
    args = parser.parse_args()

    shellcodes = read_shellcodes_from_file(args.file)
    if not shellcodes:
        logger.error("Aucun shellcode trouvé dans le fichier.")
        return 2

    provider_name = _get_provider_name(args.provider)
    generated_pdfs: list[str] = []

    for idx, sc in enumerate(shellcodes, start=1):
        logger.info(f"Analyse du shellcode #{idx} ({len(sc)} octets)")

        strings = get_shellcode_strings(sc)
        pylibemu_out = get_pylibemu_analysis(sc)
        capstone_out = get_capstone_analysis(sc, bits=32, base_addr=0x1000)

        llm_analysis = ""
        if not args.no_llm:
            logger.info(f"Génération de l'analyse LLM (provider: {provider_name})...")
            llm_analysis = get_llm_analysis(
                sc,
                bits=32,
                base_addr=0x1000,
                strings=strings,
                pylibemu_out=pylibemu_out,
                capstone_out=capstone_out,
                llm_provider=args.provider,
            )

        logger.info("Shellcode analysé !")

        # Affichage console
        print("\n" + "=" * 80)
        print(f"  SHELLCODE #{idx} - {len(sc)} octets")
        print("=" * 80)

        print("\n[Chaînes détectées]")
        print("\n".join(f"  • {s}" for s in strings) if strings else "  (aucune)")

        print("\n[Analyse Pylibemu]")
        print(f"  {pylibemu_out}")

        print("\n[Désassemblage Capstone]")
        for line in capstone_out.split("\n")[:30]:  # Limiter l'affichage console
            print(f"  {line}")
        if capstone_out.count("\n") > 30:
            print(f"  ... ({capstone_out.count(chr(10)) - 30} lignes supplémentaires)")

        if llm_analysis:
            print("\n[Analyse LLM]")
            for line in llm_analysis.split("\n"):
                print(f"  {line}")

        # Génération PDF si demandée
        if args.pdf:
            os.makedirs(args.output_dir, exist_ok=True)
            pdf_path = generate_shellcode_report(
                shellcode=sc,
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

        print("\n")

    # Résumé final
    if generated_pdfs:
        print("=" * 80)
        print("  RAPPORTS PDF GÉNÉRÉS")
        print("=" * 80)
        for pdf in generated_pdfs:
            print(f"  ✓ {pdf}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
