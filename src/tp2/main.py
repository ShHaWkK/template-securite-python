from __future__ import annotations

import argparse

from src.tp2.utils.config import logger
from src.tp2.utils.shellcode_io import read_shellcodes_from_file

from src.tp2.analysis.Analysis import (
    get_shellcode_strings,
    get_pylibemu_analysis,
    get_capstone_analysis,
    get_llm_analysis,
)

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tp2",
        description="TP2 - Analyse de shellcodes",
    )
    parser.add_argument("-f", "--file", required=True, help="Fichier contenant le(s) shellcode(s).")
    parser.add_argument("--provider", choices=["openai", "gemini", "local"], help="Force le modèle IA ")
    parser.add_argument("--no-llm", action="store_true", help="Désactive l'explication IA.")
    args = parser.parse_args()

    shellcodes = read_shellcodes_from_file(args.file)
    if not shellcodes:
        logger.error("Aucun shellcode trouvé dans le fichier.")
        return 2

    for idx, sc in enumerate(shellcodes, start=1):
        logger.info(f"Testing shellcode #{idx} of size {len(sc)}B")

        strings = get_shellcode_strings(sc)
        pylibemu_out = get_pylibemu_analysis(sc)
        capstone_out = get_capstone_analysis(sc, bits=32, base_addr=0x1000)  

        logger.info("Shellcode analysed !")

        print("\n<Strings>")
        print("\n".join(f"- {s}" for s in strings) if strings else "(aucune)")

        print("\n<Pylibemu>")
        print(pylibemu_out)

        print("\n<Shellcode instructions>")
        print(capstone_out)

        if not args.no_llm:
            print("\n<LLM>")
            print(get_llm_analysis(
                sc,
                bits=32,
                base_addr=0x1000,
                strings=strings,
                pylibemu_out=pylibemu_out,
                capstone_out=capstone_out,
                llm_provider=args.provider, 
            ))

        print("\n" + ("=" * 80) + "\n")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
