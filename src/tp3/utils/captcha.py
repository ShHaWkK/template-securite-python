"""
Module pour resoudre les CAPTCHAs.
"""
import requests
import re
from io import BytesIO


def get_pil():
    """Import PIL de maniere lazy."""
    try:
        from PIL import Image, ImageFilter, ImageOps
        return Image, ImageFilter, ImageOps
    except ImportError:
        return None, None, None


def get_tesseract():
    """Import pytesseract de maniere lazy."""
    try:
        import pytesseract
        # Chemin Tesseract sur Windows
        import os
        if os.name == 'nt':
            tesseract_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
            if os.path.exists(tesseract_path):
                pytesseract.pytesseract.tesseract_cmd = tesseract_path
        return pytesseract
    except ImportError:
        return None


class Captcha:
    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.image = None
        self.value = ""

    def capture(self):
        """Recupere l'image du captcha."""
        Image, _, _ = get_pil()
        if Image is None:
            return
        
        base_url = self.url.rsplit("/", 2)[0]
        captcha_url = base_url + "/captcha.php"
        
        try:
            r = self.session.get(captcha_url)
            if r.status_code == 200 and len(r.content) > 100:
                self.image = Image.open(BytesIO(r.content))
        except Exception as e:
            print(f"Erreur capture: {e}")

    def solve(self):
        """Resout le captcha par OCR."""
        if self.image is None:
            self.value = ""
            return
        
        pytesseract = get_tesseract()
        if pytesseract is None:
            self.value = ""
            return
        
        Image, _, ImageOps = get_pil()
        
        try:
            img = self.image.convert("L")
            img = ImageOps.autocontrast(img)
            img = img.point(lambda x: 255 if x > 128 else 0, "1")
            
            config = "--psm 7 -c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            text = pytesseract.image_to_string(img, config=config)
            self.value = text.strip()
        except Exception as e:
            print(f"Erreur OCR: {e}")
            self.value = ""

    def get_value(self):
        return self.value
