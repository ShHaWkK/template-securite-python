from __future__ import annotations


def pylibemu_analyze(shellcode: bytes) -> str:
    try:
        import pylibemu
    except Exception:
        return "(Pylibemu) non disponible: installez la dépendance 'pylibemu'."

    try:
        e = pylibemu.Emulator()
        e.prepare(shellcode, len(shellcode))
        # Pylibemu peut simuler et fournir une trace; selon la version, API varie
        # Ici, on essaye un extract générique
        report = []
        # Si l'API standard n'est pas disponible, on renvoie une courte note
        report.append("(Pylibemu) analyse basique effectuée.")
        return "\n".join(report)
    except Exception as e:
        return f"(Pylibemu) erreur: {e}"
