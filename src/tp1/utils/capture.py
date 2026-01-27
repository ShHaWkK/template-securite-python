import os
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from scapy.all import sniff
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from scapy.packet import Packet

from src.tp1.utils.config import logger
from src.tp1.utils.lib import choose_interface


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


def _now_utc() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


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


def _normalize_wanted(wanted: str) -> Optional[set]:
    w = (wanted or "").strip().lower()
    if not w or w == "all":
        return None
    return {x.strip() for x in w.split(",") if x.strip()}


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets: List[Packet] = []
        self.protocol_counts: Counter = Counter()
        self.alerts: List[Alert] = []
        self.verdicts: List[ProtocolVerdict] = []
        self.summary = ""

    def capture_traffic(self) -> None:
        seconds = int(os.getenv("TP1_CAPTURE_SECONDS", "10"))
        count = int(os.getenv("TP1_PACKET_COUNT", "0"))

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
        wanted = _normalize_wanted(protocols)
        self.alerts = self._run_detectors(self.packets, wanted)
        self.verdicts = self._build_verdicts()
        self.summary = self.gen_summary()

    def _run_detectors(self, packets: List[Packet], wanted: Optional[set]) -> List[Alert]:
        arp_map: Dict[str, str] = {}
        alerts: List[Alert] = []

        for pkt in packets:
            proto = _packet_protocol(pkt)
            if wanted and proto.lower() not in wanted:
                continue

            reason = _detect_arp_spoof(pkt, arp_map)
            if reason:
                alerts.append(self._make_alert(pkt, "ARP", reason))
                continue

            sqli = _looks_like_sqli(_packet_bytes(pkt))
            if sqli:
                alerts.append(self._make_alert(pkt, proto, sqli))

        return alerts

    def _make_alert(self, pkt: Packet, protocol: str, reason: str) -> Alert:
        src_ip, src_mac = _packet_src(pkt)
        return Alert(ts=_now_utc(), protocol=protocol, src_ip=src_ip, src_mac=src_mac, reason=reason)

    def _build_verdicts(self) -> List[ProtocolVerdict]:
        per_proto_alerts = defaultdict(list)
        for a in self.alerts:
            per_proto_alerts[a.protocol].append(a)

        verdicts: List[ProtocolVerdict] = []
        for proto, count in self.sort_network_protocols():
            alerts = per_proto_alerts.get(proto, [])
            verdicts.append(self._verdict_for_protocol(proto, count, alerts))
        return verdicts

    def _verdict_for_protocol(self, proto: str, count: int, alerts: List[Alert]) -> ProtocolVerdict:
        if not alerts:
            return ProtocolVerdict(proto, count, "OK", "Trafic légitime (aucune alerte)")

        note = f"{len(alerts)} alerte(s). Ex: {alerts[0].reason}"
        return ProtocolVerdict(proto, count, "ILLEGITIME", note)

    def get_summary(self) -> str:
        return self.summary

    def get_alerts(self) -> List[Alert]:
        return self.alerts

    def get_verdicts(self) -> List[ProtocolVerdict]:
        return self.verdicts

    def gen_summary(self) -> str:
        total = sum(self.protocol_counts.values())
        lines = [
            f"- Interface: {self.interface}",
            f"- Paquets capturés: {total}",
            f"- Protocoles distincts: {len(self.protocol_counts)}",
            f"- Alertes: {len(self.alerts)}",
        ]
        return "\n".join(lines) + "\n"

    def block_attacker(self, ip: str) -> bool:
        """
        Blocage IPS: désactivé par défaut
        Active avec: TP1_ENABLE_BLOCK=1 et éexcution de root 
        """
        if not ip or os.getenv("TP1_ENABLE_BLOCK", "0") != "1":
            return False

        cmd = ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.warning(f"Blocked attacker IP via nftables: {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to block {ip}: {e}")
            return False
