import os
from scapy.all import conf, get_if_list


def hello_world() -> str:
    return "hello world"


def _default_interface() -> str:
    route = conf.route.route("0.0.0.0")
    return route[0] if route and route[0] else ""


def choose_interface() -> str:
    interfaces = get_if_list()
    env_iface = os.getenv("TP1_INTERFACE", "").strip()

    if env_iface and env_iface in interfaces:
        return env_iface

    default = _default_interface()
    if default and default in interfaces:
        return default

    return interfaces[0] if interfaces else ""