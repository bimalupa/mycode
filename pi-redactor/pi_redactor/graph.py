"""LangGraph stateful pipeline with a human-in-the-loop approval interrupt.

extract -> detect (Presidio) -> [llm_review] -> human_review (interrupt) -> redact -> report
State lives only in an in-memory checkpointer and is purged after download.
"""
import hashlib
import time
from typing import Optional, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from . import formats
from .agents import ReviewAgent
from .audit import audit, fingerprint
from .detection import PIDetector, find_occurrences
from .models import Detection, RedactionOptions, Segment
from .redaction import build_plan


class PipelineState(TypedDict, total=False):
    doc_id: str
    file_name: str
    file_bytes: bytes
    options: dict
    segments: list[Segment]
    detections: list[Detection]
    notes: list[str]
    redacted_bytes: bytes
    report: dict
    error: str
    timings: dict


class RedactionPipeline:
    def __init__(self, detector: PIDetector, reviewer: Optional[ReviewAgent] = None):
        self.detector = detector
        self.reviewer = reviewer
        self.checkpointer = InMemorySaver(serde=JsonPlusSerializer(allowed_msgpack_modules=[
            ("pi_redactor.models", "Segment"), ("pi_redactor.models", "Detection")]))
        self.graph = self._build()

    # ----- nodes -----
    def _extract(self, state: PipelineState) -> dict:
        t = time.perf_counter()
        segments = formats.extract(state["file_name"], state["file_bytes"])
        audit("document_ingested", doc_id=state["doc_id"], file_type=formats.ext_of(state["file_name"]),
              size_bytes=len(state["file_bytes"]), segments=len(segments),
              sha256=hashlib.sha256(state["file_bytes"]).hexdigest()[:16])
        return {"segments": segments, "notes": [], "timings": {"extract_s": round(time.perf_counter() - t, 2)}}

    def _detect(self, state: PipelineState) -> dict:
        t = time.perf_counter()
        opts = RedactionOptions.from_dict(state["options"])
        dets = self.detector.detect(state["segments"], opts.entities, opts.custom_keywords,
                                    opts.min_score, opts.auto_approve_score)
        audit("pi_detected", doc_id=state["doc_id"], count=len(dets),
              types=sorted({d.entity_type for d in dets}))
        return {"detections": dets, "timings": {**state["timings"], "detect_s": round(time.perf_counter() - t, 2)}}

    def _route_after_detect(self, state: PipelineState) -> str:
        use_llm = state["options"].get("use_llm") and self.reviewer is not None
        return "llm_review" if use_llm else "human_review"

    def _llm_review(self, state: PipelineState) -> dict:
        t = time.perf_counter()
        opts = RedactionOptions.from_dict(state["options"])
        dets, notes = self.reviewer.review(state["segments"], state["detections"], opts.entities,
                                           opts.custom_keywords)
        return {"detections": dets, "notes": state["notes"] + notes,
                "timings": {**state["timings"], "llm_review_s": round(time.perf_counter() - t, 2)}}

    def _human_review(self, state: PipelineState) -> dict:
        decision = interrupt({"doc_id": state["doc_id"], "detections": len(state["detections"])})
        approvals: dict[str, bool] = decision.get("approvals", {})
        dets = state["detections"]
        for d in dets:
            if d.id in approvals:
                d.approved = bool(approvals[d.id])
        for item in decision.get("manual", []):
            dets.extend(find_occurrences(state["segments"], item["text"], item.get("entity_type", "MANUAL"),
                                         "manual", "Added by reviewer"))
        audit("review_decision", doc_id=state["doc_id"], reviewer=decision.get("reviewer", "unknown"),
              reviewer_role=decision.get("role", ""), prepared_by=decision.get("prepared_by", ""),
              approved=sum(d.approved for d in dets), rejected=sum(not d.approved for d in dets),
              manual_terms=len(decision.get("manual", [])),
              approved_fingerprints=[fingerprint(d.text) for d in dets if d.approved][:200])
        return {"detections": dets}

    def _redact(self, state: PipelineState) -> dict:
        t = time.perf_counter()
        plan = build_plan(state["detections"], state["options"].get("style", "label"))
        out = formats.redact(state["file_name"], state["file_bytes"], plan)
        audit("document_redacted", doc_id=state["doc_id"], spans=sum(len(v) for v in plan.values()),
              style=state["options"].get("style"))
        return {"redacted_bytes": out, "timings": {**state["timings"], "redact_s": round(time.perf_counter() - t, 2)}}

    def _verify_and_report(self, state: PipelineState) -> dict:
        """Re-scan the redacted output: any approved value still present is flagged as residual."""
        from .report import document_report
        residual = []
        try:
            approved = {d.text for d in state["detections"] if d.approved}
            after = " ".join(s.text for s in formats.extract(state["file_name"], state["redacted_bytes"]))
            residual = [fingerprint(v) for v in approved if v in after]
        except Exception as exc:
            state["notes"].append(f"Post-redaction verification skipped: {exc}")
        report = document_report(state, residual)
        audit("document_reported", doc_id=state["doc_id"], residual=len(residual))
        return {"report": report}

    def _build(self):
        g = StateGraph(PipelineState)
        g.add_node("extract", self._extract)
        g.add_node("detect", self._detect)
        g.add_node("llm_review", self._llm_review)
        g.add_node("human_review", self._human_review)
        g.add_node("redact", self._redact)
        g.add_node("verify_and_report", self._verify_and_report)
        g.add_edge(START, "extract")
        g.add_edge("extract", "detect")
        g.add_conditional_edges("detect", self._route_after_detect, ["llm_review", "human_review"])
        g.add_edge("llm_review", "human_review")
        g.add_edge("human_review", "redact")
        g.add_edge("redact", "verify_and_report")
        g.add_edge("verify_and_report", END)
        return g.compile(checkpointer=self.checkpointer)

    # ----- public API -----
    @staticmethod
    def _cfg(doc_id: str) -> dict:
        return {"configurable": {"thread_id": doc_id}}

    def start(self, doc_id: str, file_name: str, data: bytes, options: RedactionOptions) -> PipelineState:
        try:
            self.graph.invoke({"doc_id": doc_id, "file_name": file_name, "file_bytes": data,
                               "options": options.to_dict()}, self._cfg(doc_id))
        except Exception as exc:
            audit("pipeline_error", doc_id=doc_id, stage="detect", error=type(exc).__name__)
            raise
        return self.state(doc_id)

    def approve(self, doc_id: str, approvals: dict[str, bool], manual: list[dict],
                reviewer: str = "unknown", role: str = "", prepared_by: str = "") -> PipelineState:
        self.graph.invoke(Command(resume={"approvals": approvals, "manual": manual, "reviewer": reviewer,
                                          "role": role, "prepared_by": prepared_by}),
                          self._cfg(doc_id))
        return self.state(doc_id)

    def state(self, doc_id: str) -> PipelineState:
        return self.graph.get_state(self._cfg(doc_id)).values

    def purge(self, doc_id: str) -> None:
        self.checkpointer.delete_thread(doc_id)
        audit("document_purged", doc_id=doc_id)
