from __future__ import annotations

import os
import logging
try:
    from dotenv import load_dotenv
    load_dotenv()
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
