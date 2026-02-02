"""
TP3 - Captcha Solver
====================

Module pour resoudre les challenges CAPTCHA par differentes techniques:
- Bruteforce sans captcha
- OCR avec Tesseract
- Detection par Content-Length
- Contournement de WAF (User-Agent, Magic-Word)
"""
from .main import main, solve_challenge, solve_all_challenges

__all__ = ["main", "solve_challenge", "solve_all_challenges"]
