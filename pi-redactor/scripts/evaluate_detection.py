"""Measure detection/redaction quality against synthetic ground truth.

Recall    = ground-truth PI values no longer present in the redacted output.
Precision = redacted items that correspond to a ground-truth value.

Usage: python scripts/evaluate_detection.py [--samples samples] [--truth data/ground_truth.json] [--llm]
"""
import argparse
import json
import sys
import uuid
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pi_redactor import formats  # noqa: E402
from pi_redactor.detection import DEFAULT_ENTITIES, PIDetector  # noqa: E402
from pi_redactor.graph import RedactionPipeline  # noqa: E402
from pi_redactor.models import RedactionOptions  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", default="samples")
    ap.add_argument("--truth", default="data/ground_truth.json")
    ap.add_argument("--llm", action="store_true", help="enable the LLM review agent")
    args = ap.parse_args()

    truth = json.loads(Path(args.truth).read_text())
    reviewer = None
    if args.llm:
        from pi_redactor.agents import ReviewAgent
        from pi_redactor.llm import get_chat_llm
        from pi_redactor.retrieval import get_retriever
        reviewer = ReviewAgent(get_chat_llm(), get_retriever())
    pipe = RedactionPipeline(PIDetector(), reviewer)
    opts = RedactionOptions(entities=DEFAULT_ENTITIES, custom_keywords=truth["custom_keywords"], use_llm=args.llm)

    per_type = defaultdict(lambda: [0, 0])  # caught, total
    tp_items = fp_items = 0
    print(f"{'file':28} {'recall':>7} {'precision':>9}  missed")
    for name, items in truth["files"].items():
        doc_id = uuid.uuid4().hex[:8]
        state = pipe.start(doc_id, name, (Path(args.samples) / name).read_bytes(), opts)
        state = pipe.approve(doc_id, {}, [], "evaluator")  # accept the AI recommendation as-is
        after = " ".join(s.text for s in formats.extract(name, state["redacted_bytes"]))
        missed = [i for i in items if i["text"] in after]
        for i in items:
            per_type[i["entity_type"]][1] += 1
            per_type[i["entity_type"]][0] += i not in missed
        gt_texts = [i["text"] for i in items]
        redacted = [d for d in state["detections"] if d.approved]
        tp = sum(1 for d in redacted if any(d.text in g or g in d.text for g in gt_texts))
        tp_items, fp_items = tp_items + tp, fp_items + len(redacted) - tp
        rec = 1 - len(missed) / max(len(items), 1)
        prec = tp / max(len(redacted), 1)
        print(f"{name:28} {rec:7.1%} {prec:9.1%}  {[(m['entity_type'], m['text']) for m in missed]}")
        pipe.purge(doc_id)

    caught = sum(v[0] for v in per_type.values())
    total = sum(v[1] for v in per_type.values())
    print("\nRecall by entity type")
    for t, (c, n) in sorted(per_type.items()):
        print(f"  {t:16} {c:3}/{n:<3} {c / n:6.1%}")
    precision = tp_items / max(tp_items + fp_items, 1)
    recall = caught / max(total, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    print(f"\nOVERALL  recall={recall:.1%}  precision={precision:.1%}  F1={f1:.1%}")


if __name__ == "__main__":
    main()
