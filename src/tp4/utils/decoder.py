"""
Module de décodage pour le TP4.
Supporte: base64, hex, morse.
"""
import base64

from .config import logger

# Table Morse
MORSE = {
    '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
    '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
    '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
    '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
    '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
    '--..': 'z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
    '-----': '0',
}


def decode_base64(data):
    """Décode du base64."""
    try:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return None


def decode_hex(data):
    """Décode de l'hexadécimal."""
    try:
        data = data.replace(" ", "")
        return bytes.fromhex(data).decode("utf-8", errors="ignore")
    except:
        return None


def decode_morse(data):
    """Décode du code Morse."""
    try:
        result = ""
        for letter in data.split():
            if letter in MORSE:
                result += MORSE[letter]
        return result if result else None
    except:
        return None


def decode(data):
    """
    Détecte et décode automatiquement.
    
    Args:
        data: Données encodées
        
    Returns:
        Texte décodé
    """
    data = data.strip()
    if not data:
        return data
    
    # Morse (. et - avec espaces)
    if all(c in ".- " for c in data):
        result = decode_morse(data)
        if result:
            return result
    
    # Hex (uniquement hex)
    if all(c in "0123456789abcdefABCDEF" for c in data):
        result = decode_hex(data)
        if result and result.isprintable():
            return result
    
    # Base64
    if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in data):
        result = decode_base64(data)
        if result and result.isprintable():
            return result
    
    return data
