"""
Configuration du TP1 - IDS/IPS maison.
"""

import logging

# Logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("TP1")

# Configuration par défaut
DEFAULT_CAPTURE_SECONDS = 10
DEFAULT_PACKET_COUNT = 100
