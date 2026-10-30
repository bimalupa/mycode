"""Safety layer: NeMo Guardrails (input/output self-checks + Presidio output masking),
prompt-injection screening for document text, and a pure-Python fallback when NeMo is unavailable."""
import logging
import re

from .audit import audit, log
from .config import settings

logging.getLogger("nemoguardrails").setLevel(logging.WARNING)

INJECTION_PATTERNS = [
    r"ignore (all|any|the)? ?(previous|prior|above) (instructions|prompts?)",
    r"disregard (all|any|the)? ?(previous|prior|above)",
    r"you are now",
    r"system prompt",
    r"mark (everything|all) as (not|non)[- ]?(pi|pii|sensitive)",
    r"do not redact",
    r"reveal (the )?(original|hidden|redacted)",
]
_INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)

REFUSAL = ("I can't help with that request. I can answer questions about PI categories, "
           "redaction rules and privacy regulations.")


def scan_injection(text: str) -> list[str]:
    return sorted({m.group(0) for m in _INJECTION_RE.finditer(text)})


class Guard:
    def __init__(self, llm, detector):
        self.llm = llm
        self.detector = detector
        self.rails = None
        if llm is None:
            return
        try:
            from nemoguardrails import LLMRails, RailsConfig
            self.rails = LLMRails(RailsConfig.from_path(str(settings.guardrails_dir)), llm=llm)
            self.rails.register_action(self._mask_pii_action, name="mask_pii")
            log.info("NeMo Guardrails enabled")
        except Exception as exc:
            log.warning("NeMo Guardrails unavailable, using built-in guard: %s", exc)

    @property
    def engine(self) -> str:
        return "NeMo Guardrails" if self.rails else "built-in guard"

    def mask_pii(self, text: str) -> str:
        from .detection import DEFAULT_ENTITIES
        from .models import Segment
        dets = self.detector.detect_segment(Segment("x", text), DEFAULT_ENTITIES, [], 0.5)
        for d in sorted(dets, key=lambda d: -d.start):
            text = text[: d.start] + f"<{d.entity_type}>" + text[d.end:]
        return text

    async def _mask_pii_action(self, text: str = "") -> str:
        return self.mask_pii(text or "")

    def ask(self, prompt: str, question: str) -> str:
        """Run a grounded prompt through the rails. `question` is the raw user input (for screening)."""
        if self.llm is None:
            raise RuntimeError("LLM not configured")
        if scan_injection(question):
            audit("guardrail_block", stage="input", engine="heuristic")
            return REFUSAL
        if self.rails is not None:
            result = self.rails.generate(messages=[{"role": "user", "content": prompt}])
            content = result["content"] if isinstance(result, dict) else str(result)
            if content.strip().lower().startswith("i'm sorry, i can't respond"):
                audit("guardrail_block", stage="rails", engine="nemo")
                return REFUSAL
            return content
        answer = self.llm.invoke(prompt).content
        return self.mask_pii(answer)
