"""
Module de capture réseau avec Scapy.
"""

from collections import Counter
from typing import Dict, List, Tuple

from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet

from .config import logger, DEFAULT_CAPTURE_SECONDS, DEFAULT_PACKET_COUNT
from .lib import choose_interface


def get_protocol(pkt: Packet) -> str:
    """Identifie le protocole d'un paquet."""
    # Layer 2
    if pkt.haslayer(ARP):
        return "ARP"

    # IPv6
    if pkt.haslayer(IPv6):
        if pkt.haslayer(TCP):
            return "TCP/IPv6"
        if pkt.haslayer(UDP):
            return "UDP/IPv6"
        return "IPv6"

    # IPv4
    if pkt.haslayer(IP):
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(HTTP):
            return "HTTP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            # Ports connus
            if tcp.dport == 443 or tcp.sport == 443:
                return "HTTPS"
            if tcp.dport == 80 or tcp.sport == 80:
                return "HTTP"
            if tcp.dport == 22 or tcp.sport == 22:
                return "SSH"
            return "TCP"
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.dport == 53 or udp.sport == 53:
                return "DNS"
            return "UDP"
        return "IP"

    # Autre
    return pkt.lastlayer().name if pkt.lastlayer() else "Unknown"


class Capture:
    """Classe pour capturer et analyser le trafic réseau."""

    def __init__(self, interface=None):
        """
        Initialise la capture.
        Args:
            interface: Interface réseau à utiliser
        """
        self.interface = choose_interface(interface)
        self.packets: List[Packet] = []
        self.protocol_counts: Counter = Counter()

    def capture_traffic(self, seconds=None, count=None):
        """
        Capture le trafic réseau.

        Args:
            seconds: Durée de capture en secondes
            count: Nombre de paquets à capturer
        """
        if not self.interface:
            logger.error("Aucune interface réseau disponible")
            return

        seconds = seconds or DEFAULT_CAPTURE_SECONDS
        count = count or DEFAULT_PACKET_COUNT

        logger.info(f"Capture sur {self.interface} pendant {seconds}s (max {count} paquets)")

        try:
            self.packets = list(sniff(iface=self.interface, timeout=seconds, count=count))
            logger.info(f"Capturé {len(self.packets)} paquets")
        except PermissionError:
            logger.error("Permission refusée")
            self.packets = []
        except Exception as e:
            logger.error(f"Erreur de capture: {e}")
            self.packets = []

        # Compter les protocoles
        self.protocol_counts = Counter(get_protocol(pkt) for pkt in self.packets)

    def get_protocols(self) -> Dict[str, int]:
        """Retourne le dictionnaire des protocoles"""
        return dict(self.protocol_counts)

    def get_sorted_protocols(self) -> List[Tuple[str, int]]:
        """Retourne les protocoles triés par nombre de paquets"""
        return sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)

    def get_summary(self) -> str:
        """Génère un résumé textuel."""
        total = sum(self.protocol_counts.values())
        lines = [
            f"Interface: {self.interface}",
            f"Paquets capturés: {total}",
            f"Protocoles distincts: {len(self.protocol_counts)}",
            "",
            "Répartition:",
        ]

        for proto, count in self.get_sorted_protocols():
            pct = 100 * count / total if total > 0 else 0
            lines.append(f"  - {proto}: {count} ({pct:.1f}%)")

        return "\n".join(lines)

    def print_summary(self):
        """Affiche le résumé dans la console"""
        print("\n" + "=" * 50)
        print("RÉSUMÉ DE LA CAPTURE")
        print("=" * 50)
        print(self.get_summary())
        print("=" * 50 + "\n")
