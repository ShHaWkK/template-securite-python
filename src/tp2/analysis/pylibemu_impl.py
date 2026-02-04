"""
Module d'analyse de shellcode avec pylibemu.

Pylibemu est un wrapper Python pour libemu, une bibliothèque
d'émulation x86 permettant de détecter et analyser les shellcodes.
"""

from __future__ import annotations


def pylibemu_analyze(shellcode: bytes, max_steps: int = 10000000) -> str:
    """
    Analyse un shellcode avec pylibemu (émulateur x86).

    Args:
        shellcode: Le shellcode à analyser (bytes)
        max_steps: Nombre maximum d'instructions à émuler

    Returns:
        Le profil d'exécution contenant les appels API Windows détectés
    """
    try:
        import pylibemu
    except ImportError:
        return "(Pylibemu non disponible - exécutez: poetry install)"

    try:
        # Instanciation de l'émulateur
        emulator = pylibemu.Emulator()

        # Détection du point d'entrée (GetPC heuristics)
        offset = emulator.shellcode_getpc_test(shellcode)

        # Préparation et exécution de l'émulation
        emulator.prepare(shellcode, offset)
        emulator.test(max_steps)

        # Récupération du profil d'exécution (appels API Windows)
        profile = emulator.emu_profile_output

        if profile and profile.strip():
            # Le profil contient les appels API détectés
            # Format: HMODULE LoadLibraryA(...), SOCKET WSASocket(...), etc.
            return profile.strip()
        else:
            return (
                f"Émulation terminée (offset={offset}, taille={len(shellcode)}B)\n"
                "Aucun appel API Windows détecté.\n"
                "Note: shellcode Linux ou techniques d'évasion possibles."
            )

    except AttributeError:
        # API différente selon les versions de pylibemu
        return _pylibemu_simple(shellcode)
    except Exception as e:
        return f"Erreur pylibemu: {e}"


def _pylibemu_simple(shellcode: bytes) -> str:
    """Analyse simplifiée pour anciennes versions de pylibemu."""
    try:
        import pylibemu

        emulator = pylibemu.Emulator()
        emulator.prepare(shellcode, len(shellcode))

        return f"Shellcode chargé ({len(shellcode)} octets) - profil non disponible"
    except Exception as e:
        return f"Erreur pylibemu: {e}"
