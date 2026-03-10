"""
Module pour appeler les LLMs (OpenAI ou Gemini).
"""

import os
import requests


SYSTEM_PROMPT = """Tu es un expert en analyse de malware et shellcode x86/x64 Windows/Linux.

Réponds toujours en français, avec des phrases complètes et un style narratif clair — comme un rapport d'incident rédigé par un analyste SOC.

Ton objectif : expliquer concrètement ce que fait ce shellcode sur la machine victime.
- Décris l'enchaînement logique des actions (pas juste une liste de noms d'API).
- Explique pourquoi chaque étape est là (ex: pourquoi ce XOR, pourquoi ce JMP, pourquoi ces chaînes sur la pile).
- Traduis les strings et les valeurs numériques en comportement réel.
- Conclus avec l'effet final sur la machine (accès, persistance, exfiltration, exécution...).
"""


def call_openai(prompt, system):
    """Appelle l'API OpenAI."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return "(LLM/OpenAI) OPENAI_API_KEY manquante dans .env"

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com").rstrip("/")

    url = f"{base_url}/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 10000,
        "temperature": 0.2,
    }

    try:
        r = requests.post(url, json=data, headers=headers, timeout=60)

        if r.status_code == 429:
            return "(LLM/OpenAI) QUOTA DEPASSE - verifie ton compte OpenAI"
        if r.status_code == 401:
            return "(LLM/OpenAI) CLE API INVALIDE"
        if r.status_code >= 400:
            return f"(LLM/OpenAI) Erreur HTTP {r.status_code}"

        resp = r.json()
        text = _extract_openai_text(resp)
        return text if text else "(LLM/OpenAI) reponse vide"

    except Exception as e:
        return f"(LLM/OpenAI) erreur: {e}"


def call_gemini(prompt, system):
    """Appelle l'API Gemini."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return "(LLM/Gemini) GEMINI_API_KEY manquante dans .env"

    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
    }

    data = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 10000,
        },
    }

    try:
        r = requests.post(url, json=data, headers=headers, timeout=60)

        if r.status_code == 429:
            return "(LLM/Gemini) QUOTA DEPASSE"
        if r.status_code in [401, 403]:
            return "(LLM/Gemini) CLE API INVALIDE"
        if r.status_code >= 400:
            return f"(LLM/Gemini) Erreur HTTP {r.status_code}"

        resp = r.json()
        text = _extract_gemini_text(resp)
        return text if text else "(LLM/Gemini) reponse vide"

    except Exception as e:
        return f"(LLM/Gemini) erreur: {e}"


def _extract_openai_text(data):
    """Extrait le texte de la reponse OpenAI."""
    try:
        choices = data.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            content = msg.get("content", "")
            return content.strip()
    except Exception:
        pass
    return ""


def _extract_gemini_text(data):
    """Extrait le texte de la reponse Gemini."""
    try:
        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            if parts:
                return parts[0].get("text", "").strip()
    except Exception:
        pass
    return ""


def _safe_get(obj, path, default=None):
    """Navigue dans un dict/list de maniere safe."""
    current = obj
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
            current = current[key]
        else:
            return default
    return current


def explain_with_llm(prompt, provider=None):
    """Fonction principale pour appeler un LLM."""

    # determiner le provider
    if provider:
        chosen = provider.strip().lower()
    else:
        env_provider = os.getenv("TP2_LLM_PROVIDER", "").strip().lower()
        if env_provider:
            chosen = env_provider
        elif os.getenv("OPENAI_API_KEY", "").strip():
            chosen = "openai"
        elif os.getenv("GEMINI_API_KEY", "").strip():
            chosen = "gemini"
        else:
            chosen = "local"

    if chosen == "openai":
        return call_openai(prompt, SYSTEM_PROMPT)
    elif chosen == "gemini":
        return call_gemini(prompt, SYSTEM_PROMPT)
    else:
        return "(LLM/local) pas de LLM configure, analyse locale uniquement"
