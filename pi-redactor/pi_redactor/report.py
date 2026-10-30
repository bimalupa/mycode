"""Summary reports. They describe what was redacted without containing any raw PI."""
import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone

from .audit import fingerprint


def document_report(state: dict, residual: list[str]) -> dict:
    dets = state["detections"]
    seg_labels = {s.id: s.label for s in state["segments"]}
    approved = [d for d in dets if d.approved]
    return {
        "doc_id": state["doc_id"],
        "file_name": state["file_name"],
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "redaction_style": state["options"].get("style"),
        "llm_review": bool(state["options"].get("use_llm")),
        "segments_scanned": len(state["segments"]),
        "detections_total": len(dets),
        "redacted": len(approved),
        "rejected_by_reviewer": len(dets) - len(approved),
        "by_entity_type": dict(Counter(d.entity_type for d in approved)),
        "by_source": dict(Counter(d.source for d in approved)),
        "llm_disagreements": sum(1 for d in dets if d.llm_verdict is False),
        "residual_pi_after_redaction": len(residual),
        "notes": state.get("notes", []),
        "timings": state.get("timings", {}),
        "items": [
            {"location": seg_labels.get(d.segment_id, d.segment_id), "entity_type": d.entity_type,
             "fingerprint": fingerprint(d.text), "length": len(d.text), "score": d.score,
             "source": d.source, "decision": "redacted" if d.approved else "kept"}
            for d in dets
        ],
    }


def batch_summary(reports: list[dict]) -> dict:
    by_type: Counter = Counter()
    for r in reports:
        by_type.update(r["by_entity_type"])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "documents": len(reports),
        "detections_total": sum(r["detections_total"] for r in reports),
        "redacted_total": sum(r["redacted"] for r in reports),
        "rejected_total": sum(r["rejected_by_reviewer"] for r in reports),
        "residual_total": sum(r["residual_pi_after_redaction"] for r in reports),
        "by_entity_type": dict(by_type.most_common()),
    }


def to_markdown(reports: list[dict]) -> str:
    s = batch_summary(reports)
    lines = [
        "# PI Redaction Summary Report",
        f"Generated: {s['generated_at']}",
        "",
        f"- Documents processed: **{s['documents']}**",
        f"- PI items detected: **{s['detections_total']}**",
        f"- Redacted: **{s['redacted_total']}**  |  Kept after review: **{s['rejected_total']}**",
        f"- Residual PI found by post-redaction verification: **{s['residual_total']}**",
        "",
        "## Redactions by category",
        "| Entity type | Count |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in s["by_entity_type"].items()],
        "",
        "## Documents",
        "| File | Detected | Redacted | Kept | LLM disagreements | Residual |",
        "|---|---|---|---|---|---|",
        *[f"| {r['file_name']} | {r['detections_total']} | {r['redacted']} | {r['rejected_by_reviewer']} | "
          f"{r['llm_disagreements']} | {r['residual_pi_after_redaction']} |" for r in reports],
        "",
        "_Values are represented by keyed fingerprints only; this report contains no raw personal information._",
    ]
    for r in reports:
        if r["notes"]:
            lines += ["", f"### Notes - {r['file_name']}", *[f"- {n}" for n in r["notes"]]]
    return "\n".join(lines)


def to_csv(reports: list[dict]) -> str:
    buf = io.StringIO()
    fields = ["file_name", "location", "entity_type", "fingerprint", "length", "score", "source", "decision"]
    w = csv.DictWriter(buf, fieldnames=fields)
    w.writeheader()
    for r in reports:
        for item in r["items"]:
            w.writerow({"file_name": r["file_name"], **item})
    return buf.getvalue()


def to_json(reports: list[dict]) -> str:
    return json.dumps({"summary": batch_summary(reports), "documents": reports}, indent=2)
