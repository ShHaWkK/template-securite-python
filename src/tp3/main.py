"""
TP3 - Captcha Solver
====================

5 challenges de contournement de CAPTCHA.

Usage:
    poetry run python -m src.tp3.main
    poetry run python -m src.tp3.main --challenge 1

FLAGS:
- Challenge 1: FLAG-1{1z1_one}
- Challenge 2: FLAG-2{4_l1ttl3_h4rder}
- Challenge 3: FLAG-3{N0_t1m3_to_Sl33p}
- Challenge 4: FLAG-4{B4d_Pr0tection}
- Challenge 5: FLAG-5{Th3_l4st_0n3}
"""

import argparse

from .utils.config import logger, BASE_URL
from .utils.session import (
    solve_challenge_1,
    solve_with_content_length,
    solve_challenge_4,
    solve_challenge_5,
)


def solve_challenge(num):
    """Résout un challenge spécifique."""
    if num == 1:
        return solve_challenge_1()
    elif num in [2, 3]:
        return solve_with_content_length(num)
    elif num == 4:
        return solve_challenge_4()
    elif num == 5:
        return solve_challenge_5()
    else:
        logger.error(f"Challenge {num} inconnu")
        return None


def solve_all():
    """Résout tous les challenges."""
    print("=" * 50)
    print("TP3 - CAPTCHA SOLVER")
    print(f"Serveur: {BASE_URL}")
    print("=" * 50)

    results = {}

    for num in range(1, 6):
        print()
        results[num] = solve_challenge(num)

    # Résumé
    print("\n" + "=" * 50)
    print("RESUME")
    print("=" * 50)
    for num in range(1, 6):
        status = results.get(num) or "Non trouvé"
        print(f"  Challenge {num}: {status}")

    found = sum(1 for v in results.values() if v and "FLAG" in str(v))
    print(f"\nTotal: {found}/5 flags")

    return results


def main():
    parser = argparse.ArgumentParser(description="TP3 - Captcha Solver")
    parser.add_argument("-c", "--challenge", type=int, choices=[1, 2, 3, 4, 5])
    args = parser.parse_args()

    if args.challenge:
        result = solve_challenge(args.challenge)
        print(f"\nRésultat: {result or 'Non trouvé'}")
    else:
        solve_all()


if __name__ == "__main__":
    main()
