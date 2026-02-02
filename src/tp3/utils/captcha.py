"""
Module pour la resolution de CAPTCHAs par OCR.
Utilise Tesseract via pytesseract pour extraire le texte des images.
"""
import os
from io import BytesIO

from .config import logger, BASE_URL, TESSERACT_PATH

# Configuration OCR
try:
    from PIL import Image, ImageOps, ImageFilter
    import pytesseract

    # Configuration Tesseract pour Windows
    if os.name == "nt" and os.path.exists(TESSERACT_PATH):
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

    OCR_DISPONIBLE = True
except ImportError:
    OCR_DISPONIBLE = False
    logger.warning("pytesseract ou PIL non disponible - OCR desactive")


class Captcha:
    """
    Classe pour capturer et resoudre les CAPTCHAs par OCR.

    Attributes:
        session: Session HTTP pour recuperer l'image
        image: Image PIL du captcha
        value: Valeur extraite par OCR
    """

    # Configuration OCR Tesseract
    OCR_CONFIG = "--psm 7 -c tessedit_char_whitelist=0123456789"
    CAPTCHA_LENGTH = 6

    def __init__(self, session=None):
        """
        Initialise le captcha.

        Args:
            session: Session requests (optionnel)
        """
        self.session = session
        self.image = None
        self.value = ""
        self._raw_text = ""

    def capture(self, captcha_url: str = None) -> bool:
        """
        Capture l'image du captcha depuis le serveur.

        Args:
            captcha_url: URL du captcha (defaut: BASE_URL/captcha.php)

        Returns:
            True si la capture a reussi, False sinon
        """
        if not OCR_DISPONIBLE:
            logger.warning("OCR non disponible")
            return False

        if self.session is None:
            logger.warning("Session non fournie")
            return False

        url = captcha_url or f"{BASE_URL}/captcha.php"

        try:
            response = self.session.get(url)
            if response.status_code != 200:
                logger.warning(f"Erreur HTTP {response.status_code} lors de la capture")
                return False

            if len(response.content) < 100:
                logger.warning("Image captcha trop petite")
                return False

            self.image = Image.open(BytesIO(response.content))
            return True

        except Exception as e:
            logger.warning(f"Erreur capture captcha: {e}")
            return False

    def solve(self) -> bool:
        """
        Resout le captcha par OCR.

        Returns:
            True si la resolution a reussi et le captcha est valide, False sinon
        """
        if not OCR_DISPONIBLE or self.image is None:
            self.value = ""
            return False

        try:
            # Preprocessing de l'image pour ameliorer l'OCR
            img = self._preprocess_image(self.image)

            # Extraction du texte
            self._raw_text = pytesseract.image_to_string(img, config=self.OCR_CONFIG)
            self._raw_text = self._raw_text.strip()

            # Nettoyage: garder uniquement les chiffres
            self.value = "".join(c for c in self._raw_text if c.isdigit())

            return self.is_valid()

        except Exception as e:
            logger.warning(f"Erreur OCR: {e}")
            self.value = ""
            return False

    def _preprocess_image(self, image: Image.Image) -> Image.Image:
        """
        Pretraitement de l'image pour ameliorer la reconnaissance OCR.

        Args:
            image: Image PIL originale

        Returns:
            Image preprocessee
        """
        # Conversion en niveaux de gris
        img = image.convert("L")

        # Agrandissement (x3) pour ameliorer la precision
        img = img.resize((img.width * 3, img.height * 3), Image.LANCZOS)

        # Ajustement automatique du contraste
        img = ImageOps.autocontrast(img)

        return img

    def get_value(self) -> str:
        """Retourne la valeur du captcha."""
        return self.value

    def is_valid(self) -> bool:
        """Verifie si le captcha est valide (6 chiffres)."""
        return len(self.value) == self.CAPTCHA_LENGTH

    def capture_and_solve(self, captcha_url: str = None) -> str:
        """
        Capture et resout le captcha en une seule operation.

        Args:
            captcha_url: URL du captcha (optionnel)

        Returns:
            Valeur du captcha ou chaine vide si echec
        """
        if self.capture(captcha_url) and self.solve():
            return self.value
        return ""

    def __str__(self) -> str:
        return f"Captcha(value='{self.value}', valid={self.is_valid()})"

    def __repr__(self) -> str:
        return self.__str__()


def solve_captcha(session, captcha_url: str = None) -> str:
    """
    Fonction utilitaire pour resoudre un captcha rapidement.

    Args:
        session: Session requests
        captcha_url: URL du captcha (optionnel)

    Returns:
        Valeur du captcha ou chaine vide si echec
    """
    captcha = Captcha(session)
    return captcha.capture_and_solve(captcha_url)
