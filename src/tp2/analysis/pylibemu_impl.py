from __future__ import annotations

from typing import Optional


def pylibemu_analyze(shellcode: bytes, max_steps: int = 10000000) -> str:
    """
    Analyse un shellcode avec pylibemu (émulateur x86).
    
    Args:
        shellcode: Le shellcode à analyser
        max_steps: Nombre maximum d'instructions à émuler
    
    Returns:
        Une chaîne décrivant le résultat de l'émulation
    """
    try:
        import pylibemu
    except ImportError:
        return "(Pylibemu) non disponible: installez la dépendance 'pylibemu'."

    try:
        emulator = pylibemu.Emulator()
        
        # Préparer et exécuter l'émulation
        offset = emulator.shellcode_getpc_test(shellcode)
        emulator.prepare(shellcode, offset)
        
        # Exécuter l'émulation
        emulator.test(max_steps)
        
        # Récupérer le profil d'exécution (appels API Windows détectés)
        profile = emulator.emu_profile_output
        
        results = []
        results.append(f"Offset de départ: {offset}")
        results.append(f"Taille du shellcode: {len(shellcode)} octets")
        
        if profile:
            results.append("\nAppels API détectés:")
            # Parser et formater le profil
            for line in profile.strip().split("\n"):
                if line.strip():
                    results.append(f"  {line.strip()}")
        else:
            results.append("\nAucun appel API Windows détecté.")
            results.append("(Le shellcode peut être incomplet ou utiliser des techniques d'évasion)")
        
        return "\n".join(results)
        
    except AttributeError as e:
        # Certaines versions de pylibemu ont une API différente
        return _pylibemu_fallback(shellcode)
    except Exception as e:
        return f"(Pylibemu) erreur lors de l'émulation: {e}"


def _pylibemu_fallback(shellcode: bytes) -> str:
    """Fallback pour les versions plus anciennes de pylibemu."""
    try:
        import pylibemu
        
        emulator = pylibemu.Emulator()
        emulator.prepare(shellcode, len(shellcode))
        
        return (
            f"Shellcode préparé pour émulation ({len(shellcode)} octets).\n"
            "Note: Version de pylibemu limitée, profil d'exécution non disponible."
        )
    except Exception as e:
        return f"(Pylibemu) erreur: {e}"
