from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Segment:
    """A unit of text inside a document, addressable for in-place redaction."""
    id: str
    text: str
    label: str = ""  # human-friendly location, e.g. "Page 2", "Sheet1!B4"


@dataclass
class Detection:
    id: str
    segment_id: str
    start: int
    end: int
    text: str
    entity_type: str
    score: float
    source: str  # presidio | custom | llm | manual
    rationale: str = ""
    approved: bool = True
    llm_verdict: Optional[bool] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RedactionOptions:
    entities: list[str] = field(default_factory=list)
    min_score: float = 0.35
    auto_approve_score: float = 0.6
    custom_keywords: list[str] = field(default_factory=list)
    style: str = "label"  # label | block | redacted
    use_llm: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "RedactionOptions":
        return cls(**d)
