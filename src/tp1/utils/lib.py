import os
from scapy.all import conf, get_if_list


def hello_world() -> str:
    return "hello world"


def choose_interface() -> str:
    interfaces = get_if_list()
    env_iface = os.getenv("TP1_INTERFACE", "").strip()

    if env_iface and env_iface in interfaces:
        return env_iface
    return ""
