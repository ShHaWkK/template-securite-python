"""
TP1 - IDS/IPS Maison
====================

Analyse du trafic réseau avec Scapy.

Fonctionnalités:
- Capture du trafic sur une interface réseau
- Identification des protocoles (TCP, UDP, DNS, HTTP, etc.)
- Génération d'un rapport PDF avec graphique et tableau

Usage:
    poetry run python -m src.tp1.main
    poetry run python -m src.tp1.main -i eth0 -t 30 -c 500
    poetry run python -m src.tp1.main --interface "Wi-Fi" --time 10 --count 100

Note: Nécessite les droits administrateur pour la capture réseau.
"""

import argparse

from .utils.config import logger, DEFAULT_CAPTURE_SECONDS, DEFAULT_PACKET_COUNT
from .utils.capture import Capture
from .utils.report import Report


def main():
    parser = argparse.ArgumentParser(description="TP1 - Analyse du trafic réseau avec Scapy")
    parser.add_argument("-i", "--interface", help="Interface réseau à utiliser")
    parser.add_argument(
        "-t",
        "--time",
        type=int,
        default=DEFAULT_CAPTURE_SECONDS,
        help=f"Durée de capture en secondes (défaut: {DEFAULT_CAPTURE_SECONDS})",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=DEFAULT_PACKET_COUNT,
        help=f"Nombre max de paquets (défaut: {DEFAULT_PACKET_COUNT})",
    )
    parser.add_argument(
        "-o", "--output", default="report.pdf", help="Fichier PDF de sortie (défaut: report.pdf)"
    )
    parser.add_argument("--list", action="store_true", help="Liste les interfaces disponibles")
    args = parser.parse_args()

    # Lister les interfaces
    if args.list:
        from .utils.lib import list_interfaces, get_default_interface

        interfaces = list_interfaces()
        default = get_default_interface()
        print("\nInterfaces réseau disponibles:")
        for iface in interfaces:
            marker = " (défaut)" if iface == default else ""
            print(f"  - {iface}{marker}")
        return

    print("=" * 50)
    print("TP1 - ANALYSE DU TRAFIC RÉSEAU")
    print("=" * 50)

    # Capture
    logger.info("Démarrage de la capture...")
    capture = Capture(args.interface)

    if not capture.interface:
        logger.error("Aucune interface disponible")
        return

    capture.capture_traffic(seconds=args.time, count=args.count)

    # Afficher le résumé
    capture.print_summary()

    # Générer le rapport
    if capture.packets:
        report = Report(capture, args.output)
        report.save()
        print(f"\nRapport généré: {args.output}")
    else:
        logger.warning("Aucun paquet capturé - rapport non généré")


if __name__ == "__main__":
    main()
