"""
TP3 - Captcha Solver
====================

Resout 5 challenges de contournement de CAPTCHA avec differentes techniques:

- Challenge 1: Bypass sans captcha (bruteforce simple)
- Challenge 2: OCR + detection par Content-Length
- Challenge 3: OCR + detection par Content-Length
- Challenge 4: Magic-Word: Trackflaw + captcha en 2 etapes
- Challenge 5: Magic-Word + User-Agent (WAF) + flag cache avec espaces

Utilisation:
    poetry run python -m src.tp3.main
    poetry run python -m src.tp3.main --challenge 5
    poetry run python -m src.tp3.main --all

FLAGS TROUVES:
- Challenge 1: FLAG-1{1z1_one} (flag=1337)
- Challenge 2: FLAG-2{4_l1ttl3_h4rder} (flag=2756)
- Challenge 3: FLAG-3{N0_t1m3_to_Sl33p} (flag=3889)
- Challenge 4: FLAG-4{B4d_Pr0tection} (flag=7629)
- Challenge 5: FLAG-5{Th3_l4st_0n3} (flag=8632)
"""
import argparse
import sys
from typing import Optional

from .utils.config import logger, BASE_URL, CHALLENGES
from .utils.session import ChallengeSession


def solve_challenge(challenge_num: int) -> Optional[str]:
    """
    Resout un challenge specifique.

    Args:
        challenge_num: Numero du challenge (1-5)

    Returns:
        Le flag trouve ou None
    """
    if challenge_num not in CHALLENGES:
        logger.error(f"Challenge {challenge_num} inconnu (1-5 disponibles)")
        return None

    session = ChallengeSession(challenge_num)
    return session.solve()


def solve_all_challenges() -> dict:
    """
    Resout tous les challenges.

    Returns:
        Dictionnaire {challenge_num: flag_string}
    """
    logger.info("=" * 60)
    logger.info("TP3 - CAPTCHA SOLVER")
    logger.info(f"Serveur: {BASE_URL}")
    logger.info("=" * 60)

    results = {}

    for challenge_num in range(1, 6):
        logger.info("")
        flag = solve_challenge(challenge_num)
        results[challenge_num] = flag

        if flag:
            logger.info(f"*** FLAG {challenge_num}: {flag} ***")
        else:
            logger.warning(f"Challenge {challenge_num}: Non trouve")

    # Resume final
    print_summary(results)

    return results


def print_summary(results: dict) -> None:
    """Affiche le resume des flags trouves."""
    logger.info("")
    logger.info("=" * 60)
    logger.info("RESUME DES FLAGS")
    logger.info("=" * 60)

    for i in range(1, 6):
        status = results.get(i) or "Non trouve"
        logger.info(f"  Challenge {i}: {status}")

    # Compter les succes
    found = sum(1 for v in results.values() if v and not v.startswith("flag="))
    logger.info("")
    logger.info(f"Total: {found}/5 flags trouves")


def parse_args():
    """Parse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(
        description="TP3 - Captcha Solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python -m src.tp3.main              # Resout tous les challenges
  python -m src.tp3.main --challenge 1  # Resout uniquement le challenge 1
  python -m src.tp3.main -c 5         # Resout uniquement le challenge 5
        """,
    )

    parser.add_argument(
        "-c",
        "--challenge",
        type=int,
        choices=[1, 2, 3, 4, 5],
        help="Numero du challenge a resoudre (1-5)",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Resout tous les challenges (par defaut)",
    )

    return parser.parse_args()


def main():
    """Point d'entree principal."""
    args = parse_args()

    if args.challenge:
        # Resoudre un seul challenge
        logger.info("=" * 60)
        logger.info(f"TP3 - Challenge {args.challenge}")
        logger.info("=" * 60)

        flag = solve_challenge(args.challenge)

        if flag:
            logger.info("")
            logger.info(f"*** FLAG {args.challenge}: {flag} ***")
            return {args.challenge: flag}
        else:
            logger.warning(f"Challenge {args.challenge}: Non trouve")
            return {args.challenge: None}
    else:
        # Resoudre tous les challenges
        return solve_all_challenges()


if __name__ == "__main__":
    main()
