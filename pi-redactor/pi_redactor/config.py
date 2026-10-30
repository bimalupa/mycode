import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _bool(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Settings:
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai_compatible")  # or "azure"
    llm_base_url: str = os.getenv("GENAI_BASE_URL", "")
    llm_api_key: str = os.getenv("GENAI_API_KEY", "")
    llm_model: str = os.getenv("GENAI_CHAT_MODEL", "azure/genailab-maas-gpt-4o-mini")
    embed_model: str = os.getenv("GENAI_EMBED_MODEL", "azure/genailab-maas-text-embedding-3-large")
    azure_api_version: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
    verify_ssl: bool = _bool("GENAI_VERIFY_SSL", "true")

    spacy_model: str = os.getenv("SPACY_MODEL", "en_core_web_lg")
    cross_encoder_model: str = os.getenv("CROSS_ENCODER_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")
    use_cross_encoder: bool = _bool("USE_CROSS_ENCODER", "true")
    chroma_dir: str = os.getenv("CHROMA_DIR", "")  # empty => in-memory only

    policy_dir: Path = ROOT / "data" / "policies"
    guardrails_dir: Path = ROOT / "guardrails_config"
    audit_log: Path = ROOT / os.getenv("AUDIT_LOG", "logs/audit.jsonl")
    audit_key: str = os.getenv("AUDIT_HMAC_KEY", "")

    llm_max_chars_per_call: int = int(os.getenv("LLM_MAX_CHARS_PER_CALL", "12000"))
    llm_max_calls_per_doc: int = int(os.getenv("LLM_MAX_CALLS_PER_DOC", "8"))

    m365_tenant_id: str = os.getenv("M365_TENANT_ID", "")
    m365_client_id: str = os.getenv("M365_CLIENT_ID", "")
    m365_client_secret: str = os.getenv("M365_CLIENT_SECRET", "")

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key and self.llm_base_url)

    @property
    def m365_enabled(self) -> bool:
        return bool(self.m365_tenant_id and self.m365_client_id and self.m365_client_secret)


settings = Settings()
