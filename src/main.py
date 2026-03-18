"""
Lanceur principal - Sécurité Python ESGI 4A
============================================

Usage:
    poetry run main --all                     # Lance tous les TPs
    poetry run main --all -f shellcode.txt    # Tous les TPs avec shellcode
    poetry run main tp1                       # TP1 seulement
    poetry run main tp2 -f shellcode.txt      # TP2 seulement
    poetry run main tp3                       # TP3 seulement
    poetry run main tp4                       # TP4 seulement
"""

import argparse
import os

from tp1.main import main as run_tp1
from tp2.main import main as run_tp2
from tp3.main import main as run_tp3
from tp4.main import main as run_tp4


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="main",
        description="Sécurité Python ESGI 4A - Lanceur de TPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
exemples:
  poetry run main --all -f shellcode.txt    Lance tous les TPs
  poetry run main tp1                       Lance le TP1
  poetry run main tp2 -f shellcode.txt      Lance le TP2
  poetry run main tp3 --challenge 1         Lance le challenge 1 du TP3
  poetry run main tp4 --ip 1.2.3.4          Lance le TP4 sur une IP donnée
        """,
    )
    parser.add_argument("--all", action="store_true", help="Lance tous les TPs séquentiellement")
    parser.add_argument("-f", "--file", help="Fichier shellcode pour TP2 (avec --all)")
    parser.add_argument("-o", "--output-dir", default=".", help="Répertoire de sortie PDF TP2")

    sub = parser.add_subparsers(dest="tp")

    # TP1
    sub.add_parser("tp1", help="TP1 - IDS/IPS Maison (capture réseau)")

    # TP2
    p2 = sub.add_parser("tp2", help="TP2 - Analyse de shellcodes")
    p2.add_argument("-f", "--file", required=True, help="Fichier contenant les shellcodes")
    p2.add_argument("-o", "--output-dir", default=".", help="Répertoire de sortie PDF")
    p2.add_argument("--provider", choices=["openai", "gemini", "local"], help="Provider LLM")
    p2.add_argument("--no-llm", action="store_true", help="Désactive l'analyse LLM")
    p2.add_argument("--pdf", action="store_true", help="Génère un rapport PDF")

    # TP3
    p3 = sub.add_parser("tp3", help="TP3 - CAPTCHA Solver")
    p3.add_argument("--challenge", "-c", type=int, choices=[1, 2, 3, 4, 5], help="Challenge spécifique")

    # TP4
    p4 = sub.add_parser("tp4", help="TP4 - Crazy Decoder")
    p4.add_argument("--ip", help="IP du serveur")
    p4.add_argument("--port", "-p", type=int, help="Port du serveur")
    p4.add_argument("--rounds", "-r", type=int, help="Nombre max de rounds")

    args = parser.parse_args()

    #  Mode --all 
    if args.all:
        run_tp1()

        file = args.file or (
            os.path.join(os.getcwd(), "shellcode.txt")
            if os.path.exists(os.path.join(os.getcwd(), "shellcode.txt"))
            else None
        )
        if file:
            argv = ["-f", file, "-o", args.output_dir]
            run_tp2(argv)
        else:
            print("TP2 ignoré : aucun fichier shellcode (utilisez -f)")

        run_tp3()
        run_tp4()
        return 0

    # Sous-commandes 
    if args.tp == "tp1":
        return run_tp1() or 0

    if args.tp == "tp2":
        argv = ["-f", args.file, "-o", args.output_dir]
        if args.provider:
            argv += ["--provider", args.provider]
        if args.no_llm:
            argv += ["--no-llm"]
        if args.pdf:
            argv += ["--pdf"]
        return run_tp2(argv) or 0

    if args.tp == "tp3":
        argv = ["--challenge", str(args.challenge)] if args.challenge else None
        return run_tp3(argv) or 0

    if args.tp == "tp4":
        argv = []
        if args.ip:
            argv += ["--ip", args.ip]
        if args.port:
            argv += ["--port", str(args.port)]
        if args.rounds:
            argv += ["--rounds", str(args.rounds)]
        return run_tp4(argv or None) or 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
