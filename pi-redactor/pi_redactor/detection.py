"""PI detection with Microsoft Presidio + custom recognizers for Indian / enterprise identifiers."""
import logging
import re
import uuid

import spacy.util
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .audit import log
from .config import settings
from .models import Detection, Segment

ENTITY_CATALOG = {
    "PERSON": "Person name",
    "EMAIL_ADDRESS": "Email address",
    "PHONE_NUMBER": "Phone number",
    "LOCATION": "Address / location",
    "IN_AADHAAR": "Aadhaar number (India)",
    "IN_PAN": "PAN (India)",
    "IN_PASSPORT": "Passport number (India)",
    "US_SSN": "US Social Security Number",
    "US_PASSPORT": "US passport",
    "UK_NHS": "UK NHS number",
    "CREDIT_CARD": "Credit card number",
    "IBAN_CODE": "IBAN",
    "IP_ADDRESS": "IP address",
    "EMPLOYEE_ID": "Employee ID",
    "DATE_TIME": "Dates (e.g. date of birth) - noisy",
    "URL": "URL - noisy",
    "CUSTOM_KEYWORD": "User-defined sensitive keyword",
}
logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

DEFAULT_ENTITIES = [e for e in ENTITY_CATALOG if e not in {"DATE_TIME", "URL"}]
NER_ENTITIES = {"PERSON", "LOCATION", "NRP", "DATE_TIME"}


def _custom_recognizers() -> list[PatternRecognizer]:
    return [
        PatternRecognizer(
            supported_entity="IN_AADHAAR",
            name="AadhaarRecognizer",
            patterns=[Pattern("aadhaar", r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", 0.5)],
            context=["aadhaar", "aadhar", "uid", "uidai"],
        ),
        PatternRecognizer(
            supported_entity="IN_PAN",
            name="PanRecognizer",
            patterns=[Pattern("pan", r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b", 0.7)],
            context=["pan", "permanent account", "income tax"],
        ),
        PatternRecognizer(
            supported_entity="IN_PASSPORT",
            name="InPassportRecognizer",
            patterns=[Pattern("in_passport", r"\b[A-PR-WY][1-9]\d{6}\b", 0.3)],
            context=["passport"],
        ),
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            name="PhonePatternRecognizer",
            patterns=[
                Pattern("in_mobile", r"(?<![\w+])(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\w)", 0.6),
                Pattern("intl", r"(?<![\w+])\+\d{1,3}[\s-]?\(?\d{1,4}\)?(?:[\s-]?\d{2,5}){2,3}(?!\w)", 0.55),
            ],
            context=["phone", "mobile", "call", "contact", "tel", "whatsapp", "reach"],
        ),
        PatternRecognizer(
            supported_entity="LOCATION",
            name="StreetAddressRecognizer",
            patterns=[Pattern("street", r"\b\d{1,5}[A-Za-z]?,?\s+(?:[A-Z][a-z]+\s+){1,4}(?:Street|St|Road|Rd|"
                                        r"Avenue|Ave|Lane|Ln|Crescent|Drive|Dr|Nagar|Marg|Colony|Boulevard|"
                                        r"Blvd|Way|Court|Ct|Place|Pl|Square|Sq|Terrace|Path)\b\.?", 0.6)],
            context=["address", "moved", "live", "residing", "located"],
        ),
        PatternRecognizer(
            supported_entity="EMPLOYEE_ID",
            name="EmployeeIdRecognizer",
            patterns=[Pattern("emp_id", r"\bEMP[-_]?\d{4,8}\b", 0.65)],
            context=["employee", "emp", "staff"],
        ),
    ]


def _resolve_spacy_model(preferred: str) -> str:
    for name in (preferred, "en_core_web_lg", "en_core_web_md", "en_core_web_sm"):
        if spacy.util.is_package(name):
            if name != preferred:
                log.warning("spaCy model %s not installed; falling back to %s", preferred, name)
            return name
    raise RuntimeError("No spaCy English model installed. Run: python -m spacy download en_core_web_lg")


class PIDetector:
    def __init__(self, spacy_model: str | None = None):
        model = _resolve_spacy_model(spacy_model or settings.spacy_model)
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        })
        self.analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        for rec in _custom_recognizers():
            self.analyzer.registry.add_recognizer(rec)
        self.spacy_model = model

    def detect_segment(self, segment: Segment, entities: list[str], keywords: list[str],
                       min_score: float) -> list[Detection]:
        if not segment.text.strip():
            return []
        ad_hoc = []
        wanted = [e for e in entities if e != "CUSTOM_KEYWORD"]
        if keywords and "CUSTOM_KEYWORD" in entities:
            ad_hoc.append(PatternRecognizer(supported_entity="CUSTOM_KEYWORD", deny_list=keywords,
                                            name="CustomKeywordRecognizer"))
            wanted.append("CUSTOM_KEYWORD")
        if not wanted:
            return []
        results = self.analyzer.analyze(text=segment.text, language="en", entities=wanted,
                                        ad_hoc_recognizers=ad_hoc or None, score_threshold=min_score)
        dets = []
        for r in results:
            start, end = _trim(segment.text, r.start, r.end)
            if end - start < 2:
                continue
            dets.append(Detection(
                id=uuid.uuid4().hex[:10],
                segment_id=segment.id,
                start=start,
                end=end,
                text=segment.text[start:end],
                entity_type=r.entity_type,
                score=round(float(r.score), 2),
                source="custom" if r.entity_type in {"CUSTOM_KEYWORD", "EMPLOYEE_ID"} else "presidio",
                rationale=_explain(r),
            ))
        return resolve_overlaps(dets)

    def detect(self, segments: list[Segment], entities: list[str], keywords: list[str],
               min_score: float, auto_approve: float) -> list[Detection]:
        out: list[Detection] = []
        for seg in segments:
            out.extend(self.detect_segment(seg, entities, keywords, min_score))
        out = apply_column_headers(segments, out, entities)
        out = resolve_overlaps(out + propagate(segments, out))
        for d in out:
            d.approved = d.score >= auto_approve or d.entity_type == "CUSTOM_KEYWORD"
        return out


HEADER_HINTS = [
    (r"e-?mail", "EMAIL_ADDRESS"),
    (r"phone|mobile|contact\s*(no|num)|\btel\b", "PHONE_NUMBER"),
    (r"aadha?ar", "IN_AADHAAR"),
    (r"\bpan\b", "IN_PAN"),
    (r"passport", "IN_PASSPORT"),
    (r"emp(loyee)?\s*(id|no|code)", "EMPLOYEE_ID"),
    (r"address|city|town|location|pin\s*code|zip", "LOCATION"),
    (r"name|customer|client|employee|contact person|owner", "PERSON"),
]
_CELL_RE = re.compile(r"^(?P<sheet>.*)!(?P<col>[A-Z]+)(?P<row>\d+)$")


def apply_column_headers(segments: list[Segment], dets: list[Detection], entities: list[str]) -> list[Detection]:
    """Spreadsheets: a header such as 'City' or 'Mobile' classifies every value below it."""
    cells = {}
    for s in segments:
        m = _CELL_RE.match(s.id)
        if m:
            cells[s.id] = (m["sheet"], m["col"], int(m["row"]), s)
    if not cells:
        return dets
    header_row = {}
    for sheet, _, row, _ in cells.values():
        header_row[sheet] = min(row, header_row.get(sheet, row))
    column_type, header_ids = {}, set()
    for sid, (sheet, col, row, seg) in cells.items():
        if row != header_row[sheet] or len(seg.text) > 40:
            continue
        for pattern, etype in HEADER_HINTS:
            if re.search(pattern, seg.text, re.IGNORECASE):
                header_ids.add(sid)
                if etype in entities:
                    column_type[(sheet, col)] = (etype, seg.text.strip())
                break
    out = [d for d in dets if d.segment_id not in header_ids]
    for sid, (sheet, col, row, seg) in cells.items():
        hint = column_type.get((sheet, col))
        if hint and row > header_row[sheet] and seg.text.strip():
            start = len(seg.text) - len(seg.text.lstrip())
            out.append(Detection(id=uuid.uuid4().hex[:10], segment_id=sid, start=start,
                                 end=start + len(seg.text.strip()), text=seg.text.strip(),
                                 entity_type=hint[0], score=0.9, source="column",
                                 rationale=f"Column header '{hint[1]}'"))
    return out


_NAME_STOPWORDS = {"the", "and", "mr", "mrs", "ms", "dr", "team", "dear", "hi", "hello", "regards"}


def propagate(segments: list[Segment], dets: list[Detection], min_score: float = 0.6) -> list[Detection]:
    """A value confirmed in one place is PI everywhere in the document (incl. first/last name on its own)."""
    out, seen = [], set()
    for d in dets:
        if d.score < min_score:
            continue
        values = [(d.text, d.score, "Same value detected elsewhere in document")]
        if d.entity_type == "PERSON":
            values += [(tok, 0.6, f"Part of detected name ({d.entity_type})")
                       for tok in d.text.split()
                       if len(tok) >= 3 and tok[0].isupper() and tok.lower() not in _NAME_STOPWORDS]
        for value, score, why in values:
            key = (value, d.entity_type)
            if key in seen:
                continue
            seen.add(key)
            out += find_occurrences(segments, value, d.entity_type, "propagated", why, score)
    return out


_EDGE_CHARS = " \t\r\n<>()[]{},;:\"'|"


def _trim(text: str, start: int, end: int) -> tuple[int, int]:
    """NER spans sometimes swallow surrounding punctuation, e.g. 'Jane Doe <'."""
    while start < end and text[start] in _EDGE_CHARS:
        start += 1
    while end > start and text[end - 1] in _EDGE_CHARS:
        end -= 1
    return start, end


def _explain(result) -> str:
    exp = getattr(result, "analysis_explanation", None)
    if exp is None:
        return ""
    name = getattr(exp, "recognizer", "") or ""
    ctx = " (context boost)" if getattr(exp, "score_context_improvement", 0) else ""
    return f"{name}{ctx}"


def resolve_overlaps(dets: list[Detection]) -> list[Detection]:
    """Keep the strongest, then longest, non-overlapping detections per segment.

    Pattern/checksum recognizers get priority over statistical NER guesses for the same text.
    """
    def strength(d: Detection) -> float:
        return d.score + (0.2 if d.entity_type not in NER_ENTITIES else 0.0)

    kept: list[Detection] = []
    for d in sorted(dets, key=lambda d: (-strength(d), -(d.end - d.start))):
        if all(d.segment_id != k.segment_id or d.end <= k.start or d.start >= k.end for k in kept):
            kept.append(d)
    return sorted(kept, key=lambda d: (d.segment_id, d.start))


def find_occurrences(segments: list[Segment], needle: str, entity_type: str, source: str,
                     rationale: str = "", score: float = 1.0,
                     segment_id: str | None = None) -> list[Detection]:
    """Locate every whole-word, verbatim occurrence of `needle` (manual, LLM-suggested, propagated PI)."""
    out = []
    if not needle or len(needle.strip()) < 2:
        return out
    pattern = re.compile(r"(?<!\w)" + re.escape(needle) + r"(?!\w)")
    for seg in segments:
        if segment_id and seg.id != segment_id:
            continue
        for m in pattern.finditer(seg.text):
            out.append(Detection(id=uuid.uuid4().hex[:10], segment_id=seg.id, start=m.start(),
                                 end=m.end(), text=needle, entity_type=entity_type,
                                 score=score, source=source, rationale=rationale))
    return out
