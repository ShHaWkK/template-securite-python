# src/tp2/analysis/llm.py
from __future__ import annotations

import os
from typing import Any, Optional

import requests


# -----------------------------
# Helpers
# -----------------------------

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default


def _safe_get(obj: Any, path: list[Any], default: Any = None) -> Any:
    cur = obj
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        elif isinstance(cur, list) and isinstance(key, int) and 0 <= key < len(cur):
            cur = cur[key]
        else:
            return default
    return cur


# -----------------------------
# OpenAI (Responses API)
# -----------------------------

DEFAULT_OPENAI_BASE_URL = "https://api.openai.com"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"      
ALT_OPENAI_MODEL = "gpt-4-turbo"   


def _extract_openai_text(data: dict) -> str:
    # Certaines réponses exposent directement output_text
    out_text = data.get("output_text")
    if isinstance(out_text, str) and out_text.strip():
        return out_text.strip()

    # Fallback: parcours "output" -> message -> content -> text
    chunks: list[str] = []
    for item in data.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "message":
            continue
        for c in item.get("content", []) or []:
            if not isinstance(c, dict):
                continue
            if c.get("type") in ("output_text", "text") and isinstance(c.get("text"), str):
                chunks.append(c["text"])

    return "\n".join(x for x in chunks if x.strip()).strip()


def call_openai(prompt: str, system: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return "(LLM/OpenAI) OPENAI_API_KEY manquante dans .env"

    base_url = os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL).rstrip("/")
    model = os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL

    timeout = _env_int("OPENAI_TIMEOUT", 60)
    max_out = _env_int("OPENAI_MAX_OUTPUT_TOKENS", 700)
    temperature = _env_float("OPENAI_TEMPERATURE", 0.2)

    url = f"{base_url}/v1/responses"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "instructions": system,
        "input": prompt,
        "max_output_tokens": max_out,
        "temperature": temperature,
    }

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=timeout)
        if r.status_code >= 400:
            # Retour court mais utile (évite d'imprimer des pages entières)
            return f"(LLM/OpenAI) HTTP {r.status_code}: {r.text[:400]}"
        data = r.json()
        text = _extract_openai_text(data)
        return text if text else "(LLM/OpenAI) réponse vide"
    except Exception as e:
        return f"(LLM/OpenAI) indisponible: {e}"


# -----------------------------
# Gemini (Google AI Studio REST)
# -----------------------------

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


def _extract_gemini_text(data: dict) -> str:
    # Format courant: candidates[0].content.parts[0].text
    t = _safe_get(data, ["candidates", 0, "content", "parts", 0, "text"])
    if isinstance(t, str) and t.strip():
        return t.strip()

    # Fallback: concat tous les parts.text
    chunks: list[str] = []
    candidates = data.get("candidates") or []
    if isinstance(candidates, list):
        for cand in candidates:
            parts = _safe_get(cand, ["content", "parts"], default=[])
            if isinstance(parts, list):
                for p in parts:
                    if isinstance(p, dict) and isinstance(p.get("text"), str):
                        chunks.append(p["text"])
    return "\n".join(x for x in chunks if x.strip()).strip()


def call_gemini(prompt: str, system: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return "(LLM/Gemini) GEMINI_API_KEY manquante dans .env"

    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip() or DEFAULT_GEMINI_MODEL
    timeout = _env_int("GEMINI_TIMEOUT", 60)
    max_out = _env_int("GEMINI_MAX_OUTPUT_TOKENS", 700)
    temperature = _env_float("GEMINI_TEMPERATURE", 0.2)

    # Google AI Studio Gemini API (Generative Language API)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "systemInstruction": {
            "parts": [{"text": system}],
        },
        "contents": [
            {"role": "user", "parts": [{"text": prompt}]},
        ],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_out,
        },
    }

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=timeout)
        if r.status_code >= 400:
            return f"(LLM/Gemini) HTTP {r.status_code}: {r.text[:400]}"
        data = r.json()
        text = _extract_gemini_text(data)
        return text if text else "(LLM/Gemini) réponse vide"
    except Exception as e:
        return f"(LLM/Gemini) indisponible: {e}"


# -----------------------------
# Public API (used by Analysis.py)
# -----------------------------

def explain_with_llm(prompt: str, *, provider: Optional[str] = None) -> str:
    env_choice = os.getenv("TP2_LLM_PROVIDER", "").strip().lower()
    if provider:
        chosen = provider.strip().lower()
    elif env_choice:
        chosen = env_choice
    else:
        has_openai = bool(os.getenv("OPENAI_API_KEY", "").strip())
        has_gemini = bool(os.getenv("GEMINI_API_KEY", "").strip())
        if has_openai:
            chosen = "openai"
        elif has_gemini:
            chosen = "gemini"
        else:
            chosen = "local"

    system = (
        "Tu es analyste shellcode/malware. Réponds en français, structuré et factuel.\n"
        "Objectif: expliquer le comportement (API/DLL, processus, réseau, fichiers, commandes) et les IOC.\n"
        "Interdit: donner des instructions d'exploitation, des payloads, ou des étapes opératoires pour attaquer.\n"
        "Reste côté analyse/défense."
    )

    if chosen == "openai":
        return call_openai(prompt, system)
    if chosen == "gemini":
        return call_gemini(prompt, system)

    return "(LLM/local) explication non connectée indisponible ici"
