"""
Configuration du TP4 - Crazy Decoder.
"""

import logging

# Logger
_root = logging.getLogger()
if not _root.handlers:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("TP4")

# Serveur
SERVER_IP = "31.220.95.27"
SERVER_PORT = 13337

# Timeout
TIMEOUT = 10
