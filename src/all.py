import argparse
import os
import sys
import subprocess


def run_cmd(cmd):
    print("\n" + "=" * 60)
    print(" ".join(cmd))
    print("=" * 60 + "\n")
    try:
        r = subprocess.run(cmd, check=False)
        return r.returncode
    except Exception as e:
        print(f"Erreur: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Lance TP1, TP2, TP3, TP4")
    parser.add_argument("--tp2-file", "-f")
    parser.add_argument("--tp2-provider", choices=["openai", "gemini", "local"])
    parser.add_argument("--tp2-no-llm", action="store_true")
    parser.add_argument("--tp2-pdf", action="store_true")
    parser.add_argument("--tp2-output-dir", "-o", default=".")
    parser.add_argument("--tp3-challenge", "-c", type=int, choices=[1, 2, 3, 4, 5])
    parser.add_argument("--tp4-ip")
    parser.add_argument("--tp4-port", "-p", type=int)
    parser.add_argument("--tp4-rounds", "-r", type=int)
    parser.add_argument("--skip-tp1", action="store_true")
    parser.add_argument("--skip-tp2", action="store_true")
    parser.add_argument("--skip-tp3", action="store_true")
    parser.add_argument("--skip-tp4", action="store_true")
    args = parser.parse_args()

    python = sys.executable

    if not args.skip_tp1:
        run_cmd([python, "-m", "src.tp1.main"])

    if not args.skip_tp2:
        file = args.tp2_file
        if not file:
            default = os.path.join(os.getcwd(), "shellcode.txt")
            if os.path.exists(default):
                file = default
        if file:
            cmd = [python, "-m", "src.tp2.main", "-f", file]
            if args.tp2_provider:
                cmd += ["--provider", args.tp2_provider]
            if args.tp2_no_llm:
                cmd += ["--no-llm"]
            if args.tp2_pdf:
                cmd += ["--pdf"]
            if args.tp2_output_dir:
                cmd += ["-o", args.tp2_output_dir]
            run_cmd(cmd)
        else:
            print("TP2 ignoré: aucun fichier shellcode")

    if not args.skip_tp3:
        if args.tp3_challenge:
            run_cmd([python, "-m", "src.tp3.main", "--challenge", str(args.tp3_challenge)])
        else:
            run_cmd([python, "-m", "src.tp3.main"])

    if not args.skip_tp4:
        cmd = [python, "-m", "src.tp4.main"]
        if args.tp4_ip:
            cmd += ["--ip", args.tp4_ip]
        if args.tp4_port:
            cmd += ["--port", str(args.tp4_port)]
        if args.tp4_rounds:
            cmd += ["--rounds", str(args.tp4_rounds)]
        run_cmd(cmd)


if __name__ == "__main__":
    main()
