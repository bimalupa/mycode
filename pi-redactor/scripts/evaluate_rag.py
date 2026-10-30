"""RAGAS evaluation of the policy-assistant RAG pipeline (hybrid retrieval + guarded GPT-4o-mini).

Usage: python scripts/evaluate_rag.py   (requires GENAI_* settings in .env)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pi_redactor.agents import PolicyAssistant  # noqa: E402
from pi_redactor.detection import PIDetector  # noqa: E402
from pi_redactor.guardrails import Guard  # noqa: E402
from pi_redactor.llm import get_chat_llm, get_embeddings  # noqa: E402
from pi_redactor.retrieval import get_retriever  # noqa: E402

TESTSET = [
    {"question": "Which identifiers must always be redacted, even for authorised recipients?",
     "reference": "Tier 1 identifiers: Aadhaar, PAN, passport, SSN, national insurance/NHS, driving licence, "
                  "credit/debit card, bank account numbers and IBANs must always be redacted."},
    {"question": "Is it enough to draw a black box over text in a PDF?",
     "reference": "No. PDF redaction must remove the underlying text, the output must be re-scanned and "
                  "metadata cleared."},
    {"question": "When may a reviewer keep a work email address?",
     "reference": "Only when the recipient is inside the same legal entity with a business need, and the reason "
                  "is recorded in the review step."},
    {"question": "Which redaction method should be used for documents sent to a regulator?",
     "reference": "Black-out is required for documents released outside the organisation or to regulators."},
    {"question": "What is the maximum GDPR fine for serious infringements?",
     "reference": "Up to 20 million euros or 4% of worldwide annual turnover, whichever is higher."},
    {"question": "Can LLM-suggested PI be accepted if the text is not in the document?",
     "reference": "No. LLM suggestions are accepted only if the suggested text exists verbatim in the document."},
]


def main():
    llm, emb = get_chat_llm(), get_embeddings()
    if llm is None:
        sys.exit("Configure GENAI_BASE_URL / GENAI_API_KEY in .env first.")
    from ragas import EvaluationDataset, evaluate
    from ragas.embeddings import LangchainEmbeddingsWrapper
    from ragas.llms import LangchainLLMWrapper
    from ragas.metrics import Faithfulness, LLMContextPrecisionWithReference, LLMContextRecall
    try:
        from ragas.metrics import ResponseRelevancy as Relevancy
    except ImportError:
        from ragas.metrics import AnswerRelevancy as Relevancy

    assistant = PolicyAssistant(get_retriever(), Guard(llm, PIDetector()))
    rows = []
    for item in TESTSET:
        res = assistant.answer(item["question"])
        rows.append({"user_input": item["question"], "retrieved_contexts": res["contexts"],
                     "response": res["answer"], "reference": item["reference"]})
        print(f"Q: {item['question']}\nA: {res['answer'][:200]}\n")

    result = evaluate(
        dataset=EvaluationDataset.from_list(rows),
        metrics=[Faithfulness(), Relevancy(), LLMContextPrecisionWithReference(), LLMContextRecall()],
        llm=LangchainLLMWrapper(llm),
        embeddings=LangchainEmbeddingsWrapper(emb),
    )
    print(result)
    out = Path("logs/ragas_results.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result.to_pandas().drop(columns=["retrieved_contexts"], errors="ignore")
                              .to_dict(orient="records"), indent=2, default=str))
    print(f"Per-question scores written to {out}")


if __name__ == "__main__":
    main()
