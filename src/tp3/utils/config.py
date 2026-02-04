"""
Configuration du TP3 - Captcha Solver.
"""

import logging

# Logger
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("TP3")

# Serveur
BASE_URL = "http://31.220.95.27:9002"

# Tesseract (Windows)
TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Headers pour passer le WAF
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

# Configuration des challenges
CHALLENGES = {
    1: {"url": "/captcha1/", "range": (1000, 2000), "captcha": False},
    2: {"url": "/captcha2/", "range": (2000, 3000), "captcha": True},
    3: {"url": "/captcha3/", "range": (3000, 4000), "captcha": True},
    4: {"url": "/captcha4/", "range": (7000, 8000), "captcha": True, "magic": "Trackflaw"},
    5: {"url": "/captcha5/", "range": (8000, 9000), "captcha": True, "magic": "anything"},
}
