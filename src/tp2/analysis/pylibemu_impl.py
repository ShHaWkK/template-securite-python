from __future__ import annotations


def pylibemu_analyze(shellcode: bytes) -> str:
    try:
        import pylibemu
    except Exception:
        return "(Pylibemu) non disponible: installez la dépendance 'pylibemu'."

    try:
        e = pylibemu.Emulator()
        e.prepare(shellcode, len(shellcode))
        return "(Pylibemu) analyse basique effectuée."
    except Exception as e:
        return f"(Pylibemu) erreur: {e}"
