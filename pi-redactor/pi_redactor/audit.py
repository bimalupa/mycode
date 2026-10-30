"""Audit trail via Python logging. Raw PI is never written: values are HMAC fingerprints."""
import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone

from .config import settings

_KEY = (settings.audit_key or os.urandom(32).hex()).encode()


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "level": record.levelname,
            "event": record.getMessage(),
            **getattr(record, "fields", {}),
        }
        return json.dumps(payload, default=str)


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("pi_redactor.audit")
    if logger.handlers:
        return logger
    settings.audit_log.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(settings.audit_log, encoding="utf-8")
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


_logger = _build_logger()
log = logging.getLogger("pi_redactor")
if not log.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def fingerprint(value: str) -> str:
    return hmac.new(_KEY, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def audit(event: str, **fields) -> None:
    if "text" in fields:
        raise ValueError("Raw text must not be written to the audit log")
    _logger.info(event, extra={"fields": fields})


def read_audit(limit: int = 500) -> list[dict]:
    if not settings.audit_log.exists():
        return []
    lines = settings.audit_log.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(line) for line in lines if line.strip()]
