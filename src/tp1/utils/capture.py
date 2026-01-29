import os
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from .config import logger
from .lib import choose_interface


@dataclass
class Alert:
    ts: str
    protocol: str
    src_ip: str
    src_mac: str
    reason: str


@dataclass
class ProtocolVerdict:
    protocol: str
    packets: int
    # "OK" | "ILLEGITIME"
    status: str
    notes: str


def _utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


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


def _packet_src(pkt: Packet) -> Tuple[str, str]:
    ip = ""
    if pkt.haslayer(IP):
        ip = pkt[IP].src
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6].src

    mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
    return ip, mac


def _packet_bytes(pkt: Packet) -> bytes:
    try:
        return bytes(pkt)
    except Exception:
        return b""


def _looks_like_sqli(payload: bytes) -> Optional[str]:
    if not payload:
        return None

    p = payload.lower()
    patterns = [
        b"union select",
        b"' or 1=1",
        b" or 1=1",
        b"information_schema",
        b"drop table",
        b"sleep(",
    ]
    for pat in patterns:
        if pat in p:
            return f"SQLi suspect: {pat.decode(errors='ignore')}"
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
        self.verdicts: List[ProtocolVerdict] = []
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture trafic via Scapy. Ne plante pas si l'interface est vide
        (utile pour les tests unitaires).
        """
        if not self.interface:
            logger.warning("No interface selected. Skipping sniff.")
            self.packets = []
            self.protocol_counts = Counter()
            return

        seconds = int(os.getenv("TP1_CAPTURE_SECONDS", "10"))
        count = int(os.getenv("TP1_PACKET_COUNT", "0"))

        logger.info(f"Capturing on {self.interface} for {seconds}s (count={count})")
        self.packets = self._sniff_packets(seconds, count)
        self.protocol_counts = self._count_protocols(self.packets)

    def _sniff_packets(self, seconds: int, count: int) -> List[Packet]:
        try:
            pkts = sniff(iface=self.interface, timeout=seconds, count=count or 0)
            return list(pkts)
        except PermissionError:
            logger.error("Sniff requires sudo/root.")
            return []

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
        Exigence TP: analyse par protocole + légitimité.
        - on conserve 'protocols' pour compatibilité main.py
        """
        _ = self.get_all_protocols()
        _ = self.sort_network_protocols()

        self.alerts = self._run_detectors(self.packets)
        self.verdicts = self._build_verdicts()
        self.summary = self.gen_summary()

    def _run_detectors(self, packets: List[Packet]) -> List[Alert]:
        arp_map: Dict[str, str] = {}
        alerts: List[Alert] = []

        for pkt in packets:
            arp_reason = _detect_arp_spoof(pkt, arp_map)
            if arp_reason:
                alerts.append(self._make_alert(pkt, "ARP", arp_reason))
                continue

            sqli_reason = _looks_like_sqli(_packet_bytes(pkt))
            if sqli_reason:
                alerts.append(self._make_alert(pkt, _packet_protocol(pkt), sqli_reason))

        return alerts

    def _make_alert(self, pkt: Packet, proto: str, reason: str) -> Alert:
        ip, mac = _packet_src(pkt)
        return Alert(ts=_utc_now(), protocol=proto, src_ip=ip, src_mac=mac, reason=reason)

    def _build_verdicts(self) -> List[ProtocolVerdict]:
        alerts_by_proto = defaultdict(int)
        for a in self.alerts:
            alerts_by_proto[a.protocol] += 1

        verdicts: List[ProtocolVerdict] = []
        for proto, count in self.sort_network_protocols():
            if alerts_by_proto.get(proto, 0) > 0:
                verdicts.append(ProtocolVerdict(proto, count, "ILLEGITIME", "Alertes détectées"))
            else:
                verdicts.append(ProtocolVerdict(proto, count, "OK", "Trafic légitime"))
        return verdicts

    def gen_summary(self) -> str:
        total = sum(self.protocol_counts.values())
        lines = [
            f"- Interface: {self.interface}",
            f"- Paquets capturés: {total}",
            f"- Protocoles distincts: {len(self.protocol_counts)}",
            f"- Alertes: {len(self.alerts)}",
        ]
        return "\n".join(lines) + "\n"

    def get_summary(self) -> str:
        return self.summary

    def get_alerts(self):
        return self.alerts

    def get_verdicts(self):
        return self.verdicts

    def block_attacker(self, ip: str) -> bool:
        """
        FACULTATIF IPS : active seulement si TP1_ENABLE_BLOCK=1
        """
        if not ip or os.getenv("TP1_ENABLE_BLOCK", "0") != "1":
            return False

        try:
            import platform
            if platform.system().lower().startswith("win"):
                cmds = [
                    ["netsh", "advfirewall", "firewall", "add", "rule", "name", f"TP1_Block_In_{ip}", "dir", "in", "action", "block", "remoteip", ip],
                    ["netsh", "advfirewall", "firewall", "add", "rule", "name", f"TP1_Block_Out_{ip}", "dir", "out", "action", "block", "remoteip", ip],
                ]
                for cmd in cmds:
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                logger.warning(f"Blocked attacker IP via Windows Firewall: {ip}")
                return True
            else:
                cmd = ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"]
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                logger.warning(f"Blocked attacker IP via nftables: {ip}")
                return True
        except Exception as e:
            logger.error(f"Failed to block {ip}: {e}")
            return False
