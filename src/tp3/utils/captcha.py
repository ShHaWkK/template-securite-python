"""
Module pour resoudre les CAPTCHAs.
"""
import os
import requests
from io import BytesIO

try:
    from PIL import Image, ImageOps
    import pytesseract
    
    if os.name == 'nt':
        tesseract_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        if os.path.exists(tesseract_path):
            pytesseract.pytesseract.tesseract_cmd = tesseract_path
    
    OCR_DISPONIBLE = True
except ImportError:
    OCR_DISPONIBLE = False


class Captcha:
    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.image = None
        self.value = ""

    def capture(self):
        if not OCR_DISPONIBLE:
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
        if not OCR_DISPONIBLE or self.image is None:
            self.value = ""
            return
        try:
            img = self.image.convert("L")
            img = img.resize((img.width * 3, img.height * 3), Image.LANCZOS)
            img = ImageOps.autocontrast(img)
            config = "--psm 7 -c tessedit_char_whitelist=0123456789"
            text = pytesseract.image_to_string(img, config=config).strip()
            self.value = "".join(c for c in text if c.isdigit())
        except Exception as e:
            print(f"Erreur OCR: {e}")
            self.value = ""

    def get_value(self):
        return self.value
    
    def is_valid(self):
        return len(self.value) == 6
