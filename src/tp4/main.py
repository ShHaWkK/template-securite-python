"""
TP4 - Crazy Decoder
===================

Challenge de décodage automatique.
Le serveur envoie des données encodées, il faut les décoder rapidement.

Usage:
    poetry run python -m src.tp4.main
    poetry run python -m src.tp4.main --ip 31.220.95.27 --port 13337

FLAG: ESGI{G00d_Pr0gr4mmer}
"""
import argparse

from .utils.config import logger, SERVER_IP, SERVER_PORT
from .utils.decoder import decode
from .utils.client import run_challenge


def main():
    parser = argparse.ArgumentParser(description="TP4 - Crazy Decoder")
    parser.add_argument("--ip", default=SERVER_IP, help="IP du serveur")
    parser.add_argument("--port", "-p", type=int, default=SERVER_PORT, help="Port")
    parser.add_argument("--rounds", "-r", type=int, default=200, help="Max rounds")
    args = parser.parse_args()
    
    success = run_challenge(args.ip, args.port, decode, args.rounds)
    
    if success:
        print("\nChallenge réussi!")
    else:
        print("\nChallenge échoué")


if __name__ == "__main__":
    main()
