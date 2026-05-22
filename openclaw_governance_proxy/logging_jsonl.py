from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from threading import Lock

from .config import LOG_DIR
from .redaction import redact_text
from .utils import utciso

_lock = Lock()


def setup_logging() -> None:
    LOG_DIR.mkdir(exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")

    if not any(isinstance(handler, logging.FileHandler) and getattr(handler, "baseFilename", "") == str(LOG_DIR / "app.log") for handler in root.handlers):
        file_handler = logging.FileHandler(LOG_DIR / "app.log")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    if not any(getattr(handler, "_openclaw_console", False) for handler in root.handlers):
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        console_handler._openclaw_console = True
        root.addHandler(console_handler)


def write_jsonl(name: str, event: dict) -> None:
    LOG_DIR.mkdir(exist_ok=True)
    safe_event = {k: redact_text(str(v)) if isinstance(v, str) else v for k, v in event.items()}
    safe_event.setdefault("timestamp", utciso())
    path = LOG_DIR / name
    with _lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(safe_event, sort_keys=True, ensure_ascii=True, default=str) + "\n")
