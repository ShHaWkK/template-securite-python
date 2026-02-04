from __future__ import annotations

import os
import logging
from pathlib import Path

# Charger le .env depuis le dossier src/
try:
    from dotenv import load_dotenv

    # Chercher le .env dans plusieurs emplacements possibles
    env_paths = [
        Path(__file__).parent.parent.parent / ".env",  # src/.env
        Path.cwd() / "src" / ".env",
        Path.cwd() / ".env",
    ]
    for env_path in env_paths:
        if env_path.exists():
            load_dotenv(env_path)
            break
except Exception:
    pass

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Configure logging une seule fois (évite les doublons si import multiple)
_root = logging.getLogger()
if not _root.handlers:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="<Logger> - %(message)s",
    )

# Logger global TP2 (celui que tu importes partout)
logger = logging.getLogger("TP2")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
