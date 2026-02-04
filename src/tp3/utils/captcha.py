"""
Module OCR pour résoudre les captchas.
"""

import os
from io import BytesIO

from .config import logger, BASE_URL, TESSERACT_PATH

# Import OCR
try:
    from PIL import Image, ImageOps
    import pytesseract

    if os.name == "nt" and os.path.exists(TESSERACT_PATH):
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

    OCR_OK = True
except ImportError:
    OCR_OK = False
    logger.warning("pytesseract/PIL non installé")


def solve_captcha(session):
    """
    Résout le captcha par OCR.

    Args:
        session: Session requests avec cookies

    Returns:
        str: 6 chiffres ou chaîne vide si échec
    """
    if not OCR_OK:
        return ""

    try:
        # Télécharger l'image
        r = session.get(f"{BASE_URL}/captcha.php")
        if r.status_code != 200 or len(r.content) < 100:
            return ""

        # Prétraitement
        img = Image.open(BytesIO(r.content))
        img = img.convert("L")
        img = img.resize((img.width * 3, img.height * 3), Image.LANCZOS)
        img = ImageOps.autocontrast(img)

        # OCR
        text = pytesseract.image_to_string(img, config="--psm 7 -c tessedit_char_whitelist=0123456789")

        # Garder que les chiffres
        digits = "".join(c for c in text if c.isdigit())
        return digits if len(digits) == 6 else ""

    except Exception as e:
        logger.debug(f"Erreur OCR: {e}")
        return ""
