"""
Fonctions utilitaires pour le TP1.
"""

import os
import sys

from scapy.all import get_if_list, conf

from .config import logger


def get_default_interface():
    """Retourne l'interface par défaut de Scapy."""
    try:
        return conf.iface
    except Exception:
        return None


def list_interfaces():
    """Liste toutes les interfaces réseau disponibles."""
    return get_if_list()


def choose_interface(interface=None):
    """
    Sélectionne une interface réseau.

    Args:
        interface: Nom de l'interface (optionnel)

    Returns:
        Nom de l'interface sélectionnée
    """
    interfaces = list_interfaces()

    # 1. Interface spécifiée en argument
    if interface and interface in interfaces:
        return interface

    # 2. Variable d'environnement
    env_iface = os.getenv("TP1_INTERFACE", "").strip()
    if env_iface and env_iface in interfaces:
        return env_iface

    # 3. Interface par défaut de Scapy
    default = get_default_interface()
    if default and default in interfaces:
        return default

    # 4. Mode interactif
    if sys.stdin.isatty():
        print("\nInterfaces réseau disponibles:")
        for i, iface in enumerate(interfaces, 1):
            marker = " (défaut)" if iface == default else ""
            print(f"  {i}. {iface}{marker}")

        try:
            choice = input("\nChoisir une interface (numéro ou nom): ").strip()

            # Choix par numéro
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]

            # Choix par nom
            if choice in interfaces:
                return choice

        except (EOFError, KeyboardInterrupt):
            pass

    # 5. Première interface disponible
    if interfaces:
        logger.warning(f"Utilisation de l'interface par défaut: {interfaces[0]}")
        return interfaces[0]

    return None
