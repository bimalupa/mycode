"""Streamlit UI - AI-Powered Sensitive Personal Information Detection and Redaction Utility."""
import html
import io
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pandas as pd
import streamlit as st

from pi_redactor import formats
from pi_redactor.agents import PolicyAssistant, ReviewAgent
from pi_redactor.audit import audit, read_audit
from pi_redactor.config import settings
from pi_redactor.detection import DEFAULT_ENTITIES, ENTITY_CATALOG, PIDetector
from pi_redactor.graph import RedactionPipeline
from pi_redactor.guardrails import Guard
from pi_redactor.llm import get_chat_llm
from pi_redactor.models import RedactionOptions
from pi_redactor.redaction import STYLES
from pi_redactor.report import batch_summary, to_csv, to_json, to_markdown
from pi_redactor.retrieval import get_retriever

st.set_page_config(page_title="PI Redaction Utility", page_icon="🛡️", layout="wide")

COLORS = {
    "PERSON": "#ffd166", "EMAIL_ADDRESS": "#8ecae6", "PHONE_NUMBER": "#b5e48c", "LOCATION": "#f4a261",
    "IN_AADHAAR": "#ff8fab", "IN_PAN": "#ffafcc", "IN_PASSPORT": "#cdb4db", "CREDIT_CARD": "#ff6b6b",
    "EMPLOYEE_ID": "#a0c4ff", "CUSTOM_KEYWORD": "#c77dff", "MANUAL": "#e9c46a",
}


@st.cache_resource(show_spinner="Loading detection models, policy index and guardrails...")
def load_engine():
    detector = PIDetector()
    llm = get_chat_llm()
    retriever = get_retriever()
    pipeline = RedactionPipeline(detector, ReviewAgent(llm, retriever) if llm else None)
    guard = Guard(llm, detector)
    return detector, pipeline, PolicyAssistant(retriever, guard), guard, retriever


detector, pipeline, assistant, guard, retriever = load_engine()
ss = st.session_state
ss.setdefault("docs", {})
ss.setdefault("approvals", {})
ss.setdefault("editor_ver", {})
ss.setdefault("chat", [])
ss.setdefault("m365_files", [])


def purge(doc_ids):
    for doc_id in list(doc_ids):
        pipeline.purge(doc_id)
        ss.docs.pop(doc_id, None)
        ss.approvals.pop(doc_id, None)


def redacted_name(name: str) -> str:
    p = Path(name)
    return f"{p.stem}_redacted{p.suffix}"


def highlight(text: str, dets, approvals: dict) -> str:
    parts, pos = [], 0
    for d in sorted(dets, key=lambda d: d.start):
        if d.start < pos:
            continue
        parts.append(html.escape(text[pos:d.start]))
        on = approvals.get(d.id, d.approved)
        style = (f"background:{COLORS.get(d.entity_type, '#dddddd')};color:#111;" if on
                 else "background:#e5e5e5;color:#777;text-decoration:line-through;")
        parts.append(f"<mark style='{style}border-radius:4px;padding:0 3px' "
                     f"title='{html.escape(d.entity_type)} | score {d.score} | {html.escape(d.source)}'>"
                     f"{html.escape(d.text)}<sup style='font-size:0.6em;margin-left:2px'>"
                     f"{html.escape(d.entity_type)}</sup></mark>")
        pos = d.end
    parts.append(html.escape(text[pos:]))
    return "".join(parts).replace("\n", "<br>")


# ---------------- sidebar ----------------
with st.sidebar:
    st.title("🛡️ PI Redaction Utility")
    reviewer = st.text_input("Reviewer", value="compliance.officer")
    entities = st.multiselect("PI categories", list(ENTITY_CATALOG), default=DEFAULT_ENTITIES,
                              format_func=lambda e: f"{e} - {ENTITY_CATALOG[e]}")
    keywords = [k.strip() for k in st.text_area("Custom sensitive keywords (one per line)",
                                                "Project Falcon").splitlines() if k.strip()]
    min_score = st.slider("Detection sensitivity (min confidence)", 0.1, 0.9, 0.35, 0.05)
    auto_score = st.slider("Pre-approve when confidence ≥", 0.3, 1.0, 0.6, 0.05)
    style = st.radio("Redaction style", list(STYLES), format_func=STYLES.get)
    use_llm = st.toggle("LLM contextual review (GPT-4o-mini)", value=settings.llm_enabled,
                        disabled=not settings.llm_enabled,
                        help="Validates low-confidence detections and finds contextual PI. "
                             "High-confidence values are masked before text is sent.")
    st.divider()
    st.caption(f"NLP model: `{detector.spacy_model}`")
    st.caption(f"LLM: {'🟢 ' + settings.llm_model if settings.llm_enabled else '⚪ not configured (.env)'}")
    st.caption(f"Safety layer: {guard.engine}")
    st.caption("Retrieval: BM25" + (" + semantic (ChromaDB)" if retriever.collection else "")
               + (" + cross-encoder" if retriever.reranker else ""))
    if st.button("🧹 Purge all session data", use_container_width=True):
        purge(ss.docs.keys())
        ss.chat = []
        st.success("All in-memory documents and state purged.")

options = RedactionOptions(entities=entities, min_score=min_score, auto_approve_score=auto_score,
                           custom_keywords=keywords, style=style, use_llm=use_llm)

tab_scan, tab_review, tab_results, tab_chat, tab_audit = st.tabs(
    ["1 · Select & scan", "2 · Review & approve", "3 · Results & report", "4 · Policy assistant", "5 · Audit trail"])

# ---------------- 1. select & scan ----------------
with tab_scan:
    st.subheader("Select documents")
    source = st.radio("Source", ["Upload files", "Local folder", "Microsoft 365 (OneDrive / SharePoint)"],
                      horizontal=True)
    loaders = []  # (name, callable -> bytes, meta)
    exts = sorted(e.lstrip(".") for e in formats.SUPPORTED)
    if source == "Upload files":
        for f in st.file_uploader("Word, Excel, PowerPoint, PDF, text and email files", type=exts,
                                  accept_multiple_files=True) or []:
            loaders.append((f.name, f.getvalue, {"source": "upload"}))
    elif source == "Local folder":
        folder = st.text_input("Folder path", value=str(Path("samples").resolve()))
        recursive = st.checkbox("Include sub-folders")
        path = Path(folder)
        if path.is_dir():
            found = sorted(p for p in (path.rglob("*") if recursive else path.glob("*"))
                           if p.is_file() and formats.is_supported(p.name))
            chosen = st.multiselect("Files", found, default=found, format_func=lambda p: str(p.relative_to(path)))
            loaders += [(p.name, p.read_bytes, {"source": "local"}) for p in chosen]
        else:
            st.warning("Folder not found.")
    else:
        if not settings.m365_enabled:
            st.info("Configure M365_TENANT_ID, M365_CLIENT_ID and M365_CLIENT_SECRET in `.env` "
                    "(app registration with Files.ReadWrite.All).")
        else:
            from pi_redactor.m365 import GraphClient
            c1, c2 = st.columns(2)
            drive_id = c1.text_input("Drive ID")
            m_folder = c2.text_input("Folder path", value="/")
            if st.button("Connect & list files") and drive_id:
                try:
                    ss.m365_files = [f for f in GraphClient().list_files(drive_id, m_folder)
                                     if formats.is_supported(f["name"])]
                except Exception as exc:
                    st.error(f"Microsoft Graph error: {exc}")
            chosen = st.multiselect("Files", ss.m365_files, default=ss.m365_files, format_func=lambda f: f["name"])
            for f in chosen:
                loaders.append((f["name"], lambda f=f: GraphClient().download(drive_id, f["id"]),
                                {"source": "m365", "drive_id": drive_id, "folder": m_folder}))

    if st.button(f"🔍 Scan {len(loaders)} file(s) for PI", type="primary", disabled=not loaders or not entities):
        progress = st.progress(0.0, text="Scanning...")
        jobs = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            for name, load, meta in loaders:
                doc_id = uuid.uuid4().hex[:12]
                ss.docs[doc_id] = {"name": name, "status": "scanning", **meta}
                jobs[pool.submit(lambda n=name, l=load, d=doc_id: pipeline.start(d, n, l(), options))] = doc_id
            for i, fut in enumerate(as_completed(jobs), start=1):
                doc_id = jobs[fut]
                try:
                    fut.result()
                    ss.docs[doc_id]["status"] = "review"
                except Exception as exc:
                    ss.docs[doc_id].update(status="error", error=f"{type(exc).__name__}: {exc}")
                progress.progress(i / len(jobs), text=f"Scanned {i}/{len(jobs)}")
        st.success("Scan complete - continue in **2 · Review & approve**.")

    if ss.docs:
        rows = []
        for doc_id, d in ss.docs.items():
            n = len(pipeline.state(doc_id).get("detections", [])) if d["status"] != "error" else 0
            rows.append({"File": d["name"], "Status": d["status"], "PI found": n, "Error": d.get("error", "")})
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    with st.expander("How it works (LangGraph pipeline)"):
        st.markdown("Every file runs through a stateful LangGraph pipeline held **only in memory**. "
                    "It pauses at `human_review` until a reviewer approves - nothing is redacted permanently "
                    "without approval.")
        st.code(pipeline.graph.get_graph().draw_mermaid(), language="text")

# ---------------- 2. review ----------------
with tab_review:
    pending = [i for i, d in ss.docs.items() if d["status"] == "review"]
    if not pending:
        st.info("No documents waiting for review. Scan files in step 1.")
    else:
        doc_id = st.selectbox("Document", pending, format_func=lambda i: ss.docs[i]["name"])
        state = pipeline.state(doc_id)
        dets, segments = state["detections"], state["segments"]
        approvals = ss.approvals.setdefault(doc_id, {d.id: d.approved for d in dets})
        ver = ss.editor_ver.setdefault(doc_id, 0)

        for note in state.get("notes", []):
            st.warning(note, icon="⚠️")
        m = st.columns(4)
        m[0].metric("PI detected", len(dets))
        m[1].metric("Selected for redaction", sum(approvals.get(d.id, d.approved) for d in dets))
        m[2].metric("LLM: not PI", sum(1 for d in dets if d.llm_verdict is False))
        m[3].metric("Found by LLM", sum(1 for d in dets if d.source == "llm"))

        b = st.columns(4)

        def bulk(fn):
            ss.approvals[doc_id] = {d.id: fn(d) for d in dets}
            ss.editor_ver[doc_id] = ver + 1
            st.rerun()

        if b[0].button("Select all"):
            bulk(lambda d: True)
        if b[1].button("Clear all"):
            bulk(lambda d: False)
        if b[2].button("Reset to AI recommendation"):
            bulk(lambda d: d.approved)
        if b[3].button(f"Only confidence ≥ {auto_score}"):
            bulk(lambda d: d.score >= auto_score)

        left, right = st.columns([1.1, 1])
        with right:
            st.markdown("**Detections** - untick anything that should stay visible")
            labels = {s.id: s.label for s in segments}
            df = pd.DataFrame([{
                "id": d.id, "Redact": approvals.get(d.id, d.approved), "Type": d.entity_type, "Text": d.text,
                "Confidence": d.score, "Source": d.source, "Location": labels.get(d.segment_id, d.segment_id),
                "Why": d.rationale,
            } for d in dets])
            if df.empty:
                st.caption("No PI detected with current settings.")
            else:
                edited = st.data_editor(
                    df, key=f"editor_{doc_id}_{ver}", hide_index=True, use_container_width=True, height=460,
                    column_config={"id": None, "Redact": st.column_config.CheckboxColumn(width="small"),
                                   "Confidence": st.column_config.ProgressColumn(min_value=0, max_value=1,
                                                                                 format="%.2f")},
                    disabled=[c for c in df.columns if c != "Redact"])
                ss.approvals[doc_id] = approvals = {str(k): bool(v) for k, v in zip(edited["id"], edited["Redact"])}
        with left:
            show_all = st.toggle("Show full document text", value=False)
            by_seg = {}
            for d in dets:
                by_seg.setdefault(d.segment_id, []).append(d)
            shown = [s for s in segments if show_all or s.id in by_seg][:300]
            body = "".join(f"<div style='margin-bottom:10px'><span style='font-size:0.75em;opacity:0.6'>"
                           f"{html.escape(s.label)}</span><br>{highlight(s.text, by_seg.get(s.id, []), approvals)}"
                           f"</div>" for s in shown)
            with st.container(height=520, border=True):
                st.markdown(body or "_Nothing to show_", unsafe_allow_html=True)

        manual_text = st.text_area("Missed something? Add exact text to redact (one per line)", key=f"manual_{doc_id}")
        manual = [{"text": t.strip(), "entity_type": "MANUAL"} for t in manual_text.splitlines() if t.strip()]

        c1, c2 = st.columns(2)
        if c1.button("✅ Approve & redact this document", type="primary", use_container_width=True):
            with st.spinner("Redacting and verifying..."):
                pipeline.approve(doc_id, ss.approvals[doc_id], manual, reviewer)
            ss.docs[doc_id]["status"] = "done"
            st.rerun()
        if len(pending) > 1 and c2.button(f"⚡ Approve & redact all {len(pending)} pending documents",
                                          use_container_width=True,
                                          help="Uses your selections where you reviewed a document, "
                                               "otherwise the AI recommendation."):
            with st.spinner("Bulk redaction..."):
                for pid in pending:
                    pipeline.approve(pid, ss.approvals.get(pid, {}), manual if pid == doc_id else [], reviewer)
                    ss.docs[pid]["status"] = "done"
            audit("bulk_approval", reviewer=reviewer, documents=len(pending))
            st.rerun()

# ---------------- 3. results ----------------
with tab_results:
    done = [i for i, d in ss.docs.items() if d["status"] == "done"]
    if not done:
        st.info("Redacted documents will appear here after approval.")
    else:
        states = {i: pipeline.state(i) for i in done}
        reports = [s["report"] for s in states.values()]
        summary = batch_summary(reports)
        m = st.columns(5)
        m[0].metric("Documents", summary["documents"])
        m[1].metric("PI detected", summary["detections_total"])
        m[2].metric("Redacted", summary["redacted_total"])
        m[3].metric("Kept after review", summary["rejected_total"])
        m[4].metric("Residual PI (verification)", summary["residual_total"])

        c1, c2 = st.columns([1, 1.4])
        with c1:
            st.markdown("**Redactions by category**")
            if summary["by_entity_type"]:
                st.bar_chart(pd.Series(summary["by_entity_type"], name="count"), horizontal=True)
        with c2:
            st.markdown("**Documents**")
            st.dataframe(pd.DataFrame([{
                "File": r["file_name"], "Redacted": r["redacted"], "Kept": r["rejected_by_reviewer"],
                "Residual": r["residual_pi_after_redaction"],
                "Time (s)": round(sum(r["timings"].values()), 2)} for r in reports]),
                hide_index=True, use_container_width=True)

        st.markdown("#### Downloads")
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
            for i, s in states.items():
                z.writestr(redacted_name(s["file_name"]), s["redacted_bytes"])
            z.writestr("redaction_report.md", to_markdown(reports))
        d = st.columns(4)
        d[0].download_button("📦 All redacted files (.zip)", zbuf.getvalue(), "redacted_documents.zip",
                             use_container_width=True)
        d[1].download_button("📝 Summary report (.md)", to_markdown(reports), "redaction_report.md",
                             use_container_width=True)
        d[2].download_button("🧾 Detailed report (.csv)", to_csv(reports), "redaction_items.csv",
                             use_container_width=True)
        d[3].download_button("{ } Report (.json)", to_json(reports), "redaction_report.json",
                             use_container_width=True)
        cols = st.columns(min(len(done), 4))
        for n, (i, s) in enumerate(states.items()):
            cols[n % len(cols)].download_button(f"⬇️ {redacted_name(s['file_name'])}", s["redacted_bytes"],
                                                redacted_name(s["file_name"]), key=f"dl_{i}")

        m365_done = [i for i in done if ss.docs[i].get("source") == "m365"]
        if m365_done and st.button(f"☁️ Upload {len(m365_done)} redacted file(s) back to Microsoft 365 (/Redacted)"):
            from pi_redactor.m365 import GraphClient
            client = GraphClient()
            for i in m365_done:
                meta = ss.docs[i]
                url = client.upload(meta["drive_id"], f"{meta['folder'].rstrip('/')}/Redacted",
                                    redacted_name(meta["name"]), states[i]["redacted_bytes"])
                audit("m365_upload", doc_id=i)
                st.success(f"Uploaded {redacted_name(meta['name'])} {url}")

        st.markdown("#### Before / after")
        pick = st.selectbox("Compare", done, format_func=lambda i: ss.docs[i]["name"])
        s = states[pick]
        after = {seg.id: seg.text for seg in formats.extract(s["file_name"], s["redacted_bytes"])}
        by_seg = {}
        for d in s["detections"]:
            by_seg.setdefault(d.segment_id, []).append(d)
        rows = [seg for seg in s["segments"] if seg.id in by_seg][:60]
        a, b = st.columns(2)
        a.markdown("**Original (highlighted)**")
        b.markdown("**Redacted output**")
        for seg in rows:
            a, b = st.columns(2)
            a.markdown(f"<div style='font-size:0.9em'>{highlight(seg.text, by_seg[seg.id], {})}</div>",
                       unsafe_allow_html=True)
            b.markdown(f"<div style='font-size:0.9em'>{html.escape(after.get(seg.id, '')).replace(chr(10), '<br>')}"
                       f"</div>", unsafe_allow_html=True)
        for note in s["report"]["notes"]:
            st.caption(f"Note: {note}")

        if st.button("🧹 Purge processed documents from memory"):
            purge(done)
            st.rerun()

# ---------------- 4. policy assistant ----------------
with tab_chat:
    st.subheader("Privacy policy assistant")
    st.caption(f"Hybrid RAG over the organisation's privacy policies, protected by {guard.engine}. "
               "Answers are grounded in policy excerpts and PI in answers is masked.")
    examples = ["Can I keep an employee's work email when sharing internally?",
                "How must PDFs be redacted?",
                "What does the DPDP Act say about Aadhaar numbers?"]
    ex_cols = st.columns(len(examples))
    pressed = [c.button(q, use_container_width=True) for c, q in zip(ex_cols, examples)]
    clicked = next((q for q, p in zip(examples, pressed) if p), None)
    for msg in ss.chat:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
    question = st.chat_input("Ask about PI categories, redaction rules or regulations") or clicked
    if question:
        ss.chat.append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)
        with st.chat_message("assistant"):
            with st.spinner("Retrieving policy and answering..."):
                res = assistant.answer(question)
            st.markdown(res["answer"])
            with st.expander("Sources"):
                for c in res["sources"]:
                    st.markdown(f"**{c.source} > {c.heading}** (score {c.score:.3f})")
                    st.caption(c.text[:600])
        ss.chat.append({"role": "assistant", "content": res["answer"]})

# ---------------- 5. audit ----------------
with tab_audit:
    st.subheader("Audit trail")
    st.caption(f"JSON-lines log at `{settings.audit_log}`. Values are HMAC fingerprints - no raw PI is logged.")
    entries = read_audit()
    if entries:
        st.dataframe(pd.DataFrame(entries[::-1]), hide_index=True, use_container_width=True, height=500)
        st.download_button("Download audit log", settings.audit_log.read_bytes(), "audit.jsonl")
    else:
        st.info("No audit events yet.")
