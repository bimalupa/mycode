"""Connectivity check for the GenAI Lab endpoint: python scripts/check_llm.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pi_redactor.config import settings  # noqa: E402
from pi_redactor.llm import get_chat_llm, get_embeddings  # noqa: E402

print(f"Base URL   : {settings.llm_base_url or '(not set)'}")
print(f"API key    : {'set' if settings.llm_api_key else '(not set)'}")
print(f"Verify SSL : {settings.verify_ssl}")
if not settings.llm_enabled:
    sys.exit("Set GENAI_BASE_URL and GENAI_API_KEY in .env")

for name, call in [("chat", lambda: get_chat_llm().invoke("Reply with the single word OK").content),
                   ("embeddings", lambda: f"{len(get_embeddings().embed_query('hello'))} dimensions")]:
    try:
        print(f"{name:10} : OK -> {call()}")
    except Exception as exc:
        root = exc
        while root.__cause__ is not None:
            root = root.__cause__
        print(f"{name:10} : FAILED -> {type(exc).__name__}: {exc}")
        print(f"{'':10}   root cause -> {type(root).__name__}: {root}")
        if "CERTIFICATE" in str(root).upper():
            print(f"{'':10}   fix: set GENAI_VERIFY_SSL=false in .env (or pip install pip-system-certs)")
