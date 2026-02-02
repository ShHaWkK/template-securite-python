"""
Configuration du TP3 - Captcha Solver.
Centralise les constantes et la configuration.
"""
import os
from src.config import logging

# Logger
logger = logging.getLogger("TP3")

# URL de base du serveur de challenges
BASE_URL = "http://31.220.95.27:9002"

# Configuration Tesseract pour Windows
TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Headers par defaut pour contourner le WAF
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
}

# Configuration des challenges
CHALLENGES = {
    1: {
        "url": "/captcha1/",
        "flag_range": (1000, 2000),
        "needs_captcha": False,
        "headers": {},
    },
    2: {
        "url": "/captcha2/",
        "flag_range": (2000, 3000),
        "needs_captcha": True,
        "headers": {},
    },
    3: {
        "url": "/captcha3/",
        "flag_range": (3000, 4000),
        "needs_captcha": True,
        "headers": {},
    },
    4: {
        "url": "/captcha4/",
        "flag_range": (7000, 8000),
        "needs_captcha": True,
        "headers": {"Magic-Word": "Trackflaw"},
    },
    5: {
        "url": "/captcha5/",
        "flag_range": (8000, 9000),
        "needs_captcha": True,
        "headers": {"Magic-Word": "anything"},
        "success_content_length": "588",  # CL different pour succes
    },
}


def get_challenge_url(challenge_num: int) -> str:
    """Retourne l'URL complete d'un challenge."""
    return BASE_URL + CHALLENGES[challenge_num]["url"]


def get_challenge_headers(challenge_num: int) -> dict:
    """Retourne les headers requis pour un challenge."""
    headers = DEFAULT_HEADERS.copy()
    headers.update(CHALLENGES[challenge_num].get("headers", {}))
    return headers


def get_challenge_flag_range(challenge_num: int) -> tuple:
    """Retourne la plage de flags a tester."""
    return CHALLENGES[challenge_num]["flag_range"]


def challenge_needs_captcha(challenge_num: int) -> bool:
    """Indique si le challenge necessite un captcha."""
    return CHALLENGES[challenge_num].get("needs_captcha", False)
