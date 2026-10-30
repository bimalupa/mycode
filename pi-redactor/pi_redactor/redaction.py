from collections import defaultdict

from .detection import resolve_overlaps
from .formats import Span
from .models import Detection

STYLES = {
    "label": "Readable labels, consistent per value: [PERSON_1], [EMAIL_ADDRESS_2]",
    "block": "Black-out characters, length preserved: ██████",
    "redacted": "Generic marker: [REDACTED]",
}


def build_plan(detections: list[Detection], style: str) -> dict[str, list[Span]]:
    approved = resolve_overlaps([d for d in detections if d.approved])
    labels: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = defaultdict(int)
    plan: dict[str, list[Span]] = defaultdict(list)
    for d in sorted(approved, key=lambda d: (d.segment_id, d.start)):
        if style == "block":
            rep = "█" * len(d.text)
        elif style == "redacted":
            rep = "[REDACTED]"
        else:
            key = (d.entity_type, d.text.strip().lower())
            if key not in labels:
                counters[d.entity_type] += 1
                labels[key] = f"[{d.entity_type}_{counters[d.entity_type]}]"
            rep = labels[key]
        plan[d.segment_id].append(Span(d.start, d.end, rep, d.text, d.entity_type))
    return dict(plan)
