"""
Module pour gerer les sessions et resoudre les challenges.
"""
import requests
import re

from .config import logger
from .captcha import Captcha


class Session:
    """Gere une session pour un challenge captcha."""

    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.captcha = None
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.response = None
        self.html = ""

    def prepare_request(self):
        """Prepare la requete en capturant le captcha."""
        # Charger la page
        try:
            r = self.session.get(self.url)
            self.html = r.text
        except:
            self.html = ""
        
        # Capturer et resoudre le captcha
        self.captcha = Captcha(self.url, session=self.session)
        self.captcha.capture()
        self.captcha.solve()
        self.captcha_value = self.captcha.get_value()
        
        logger.info(f"Captcha: {self.captcha_value}")

    def submit_request(self):
        """Envoie la requete."""
        if not self.captcha_value:
            return
        
        # Trouver le champ captcha
        champ = "captcha"
        match = re.search(r'name=["\']([^"\']*captcha[^"\']*)["\']', self.html, re.IGNORECASE)
        if match:
            champ = match.group(1)
        
        data = {champ: self.captcha_value}
        
        # Ajouter le flag si present
        if self.flag_value:
            data["flag"] = self.flag_value
        
        logger.info(f"Envoi: {data}")
        
        try:
            self.response = self.session.post(self.url, data=data)
        except:
            self.response = None

    def process_response(self):
        """Traite la reponse."""
        if self.response is None:
            return False
        
        html = self.response.text
        
        # Chercher le flag
        match = re.search(r'[A-Za-z]+\{[^}]+\}', html)
        if match:
            self.valid_flag = match.group(0)
            logger.info(f"Flag: {self.valid_flag}")
            return True
        
        # Verifier echec
        if "wrong" in html.lower() or "incorrect" in html.lower():
            return False
        
        if "congratulation" in html.lower() or "success" in html.lower():
            return True
        
        return False

    def get_flag(self):
        return self.valid_flag
