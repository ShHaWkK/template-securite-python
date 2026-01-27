import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from scapy.all import sniff
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest
from src.tp1.utils.config import logger
from src.tp1.utils.lib import choose_interface


"""

"""
@dataclass
class Alert:
    ts: str
    protocol: str
    src_ip: str
    src_mac: str
    reason: str


def _packet_src(pkt: Packet) -> Tuple[str, str]:
    src_ip = ""
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src

    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
    return src_ip, src_mac


def _packet_protocol(pkt: Packet) -> str:
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IPv6):
        if pkt.haslayer(TCP):
            return "TCPv6"
        if pkt.haslayer(UDP):
            return "UDPv6"
        return "IPv6"
    if pkt.haslayer(IP):
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        return "IP"
    return pkt.lastlayer().name or "UNKNOWN"


def _raw_payload_bytes(pkt: Packet) -> bytes:
    raw = bytes(pkt) if pkt is not None else b""
    return raw


def _looks_like_sqli(payload: bytes) -> Optional[str]:
    if not payload:
        return None

    p = payload.lower()
    needles = [
        b"union select",
        b"' or 1=1",
        b"or 1=1",
        b"drop table",
        b"information_schema",
        b"sleep(",
    ]
    for n in needles:
        if n in p:
            return f"SQLi pattern: {n.decode(errors='ignore')}"
    return None


def _detect_arp_spoof(pkt: Packet, arp_map: Dict[str, str]) -> Optional[str]:
    if not pkt.haslayer(ARP):
        return None
    arp = pkt[ARP]
    if arp.op != 2:  # ARP reply
        return None

    ip = arp.psrc
    mac = arp.hwsrc
    old = arp_map.get(ip)
    if old and old.lower() != mac.lower():
        return f"ARP spoof suspected: {ip} was {old}, now {mac}"
    arp_map[ip] = mac
    return None


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets: List[Packet] = []
        self.protocol_counts: Counter = Counter()
        self.alerts: List[Alert] = []
        self.summary = ""

    def capture_traffic(self) -> None:
        seconds = int(os.getenv("TP1_CAPTURE_SECONDS", "10"))
        count = int(os.getenv("TP1_PACKET_COUNT", "0"))  # 0 => illimité pendant timeout

        if not self.interface:
            raise RuntimeError("No network interface found.")

        logger.info(f"Capturing on {self.interface} for {seconds}s (count={count})")
        self.packets = self._sniff_packets(seconds, count)
        self.protocol_counts = self._count_protocols(self.packets)

    def _sniff_packets(self, seconds: int, count: int) -> List[Packet]:
        try:
            pkts = sniff(iface=self.interface, timeout=seconds, count=count or 0)
            return list(pkts)
        except PermissionError:
            raise PermissionError("Sniff requires root. Try: sudo python3 main.py")

    def _count_protocols(self, packets: List[Packet]) -> Counter:
        c = Counter()
        for pkt in packets:
            c[_packet_protocol(pkt)] += 1
        return c

    def sort_network_protocols(self) -> List[Tuple[str, int]]:
        return sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)

    def get_all_protocols(self) -> Dict[str, int]:
        return dict(self.protocol_counts)

    def analyse(self, protocols: str) -> None:
        """
        Analyse basique :
        - ARP spoofing (changement IP->MAC sur ARP reply)
        - SQLi heuristique dans payload brut (approche simple)
        """
        arp_map: Dict[str, str] = {}
        wanted = (protocols or "").lower().strip()
        self.alerts = self._run_detectors(self.packets, arp_map, wanted)
        self.summary = self.gen_summary()

        logger.debug(f"All protocols: {self.get_all_protocols()}")
        logger.debug(f"Sorted protocols: {self.sort_network_protocols()}")

    def _run_detectors(
        self,
        packets: List[Packet],
        arp_map: Dict[str, str],
        wanted: str,
    ) -> List[Alert]:
        alerts: List[Alert] = []
        for pkt in packets:
            proto = _packet_protocol(pkt).lower()
            if wanted and wanted not in proto:
                continue

            arp_reason = _detect_arp_spoof(pkt, arp_map)
            if arp_reason:
                alerts.append(self._make_alert(pkt, "ARP", arp_reason))

            sqli_reason = _looks_like_sqli(_raw_payload_bytes(pkt))
            if sqli_reason:
                alerts.append(self._make_alert(pkt, _packet_protocol(pkt), sqli_reason))
        return alerts

    def _make_alert(self, pkt: Packet, protocol: str, reason: str) -> Alert:
        src_ip, src_mac = _packet_src(pkt)
        return Alert(
            ts=datetime.utcnow().isoformat(timespec="seconds") + "Z",
            protocol=protocol,
            src_ip=src_ip,
            src_mac=src_mac,
            reason=reason,
        )

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        total = sum(self.protocol_counts.values())
        lines = [
            "Résumé de capture",
            f"- Interface: {self.interface}",
            f"- Paquets capturés: {total}",
            f"- Protocoles distincts: {len(self.protocol_counts)}",
            f"- Alertes: {len(self.alerts)}",
        ]

        if self.alerts:
            lines.append("\nAlertes détectées:")
            for a in self.alerts[:10]:
                lines.append(f"  * [{a.ts}] {a.protocol} {a.src_ip} {a.src_mac} -> {a.reason}")
        return "\n".join(lines) + "\n"
