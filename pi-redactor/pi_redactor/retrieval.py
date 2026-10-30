"""Hybrid retrieval over the privacy-policy knowledge base: BM25 + ChromaDB semantic + cross-encoder rerank."""
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from rank_bm25 import BM25Okapi

from .audit import log
from .config import settings
from .llm import get_embeddings


@dataclass
class Chunk:
    id: str
    source: str
    heading: str
    text: str
    score: float = 0.0


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def load_policy_chunks(policy_dir: Path, max_chars: int = 1200) -> list[Chunk]:
    chunks = []
    for path in sorted(policy_dir.glob("*.md")):
        title = path.stem
        for i, section in enumerate(re.split(r"\n(?=## )", path.read_text(encoding="utf-8"))):
            section = section.strip()
            if not section:
                continue
            heading = section.splitlines()[0].lstrip("# ").strip()
            for j in range(0, len(section), max_chars):
                chunks.append(Chunk(f"{title}-{i}-{j}", path.name, heading, section[j:j + max_chars]))
    return chunks


class HybridRetriever:
    def __init__(self, chunks: list[Chunk]):
        self.chunks = chunks
        self.by_id = {c.id: c for c in chunks}
        self.bm25 = BM25Okapi([_tokenize(f"{c.heading} {c.text}") for c in chunks])
        self.embeddings = get_embeddings()
        self.collection = self._build_vector_store() if self.embeddings else None
        self.reranker = self._load_reranker()

    def _build_vector_store(self):
        try:
            import chromadb
            client = (chromadb.PersistentClient(path=settings.chroma_dir) if settings.chroma_dir
                      else chromadb.EphemeralClient())
            col = client.get_or_create_collection("privacy_policies", metadata={"hnsw:space": "cosine"},
                                                  embedding_function=None)
            existing = set(col.get(ids=[c.id for c in self.chunks])["ids"])
            new = [c for c in self.chunks if c.id not in existing]
            if new:
                vectors = self.embeddings.embed_documents([c.text for c in new])
                col.add(ids=[c.id for c in new], embeddings=vectors, documents=[c.text for c in new],
                        metadatas=[{"source": c.source, "heading": c.heading} for c in new])
            return col
        except Exception as exc:
            log.warning("Semantic index unavailable, using BM25 only: %s", exc)
            return None

    def _load_reranker(self):
        if not settings.use_cross_encoder:
            return None
        try:
            from sentence_transformers import CrossEncoder
            return CrossEncoder(settings.cross_encoder_model)
        except Exception as exc:
            log.warning("Cross-encoder unavailable, skipping rerank: %s", exc)
            return None

    def search(self, query: str, k: int = 4, candidates: int = 10) -> list[Chunk]:
        rankings: list[list[str]] = []
        scores = self.bm25.get_scores(_tokenize(query))
        rankings.append([self.chunks[i].id for i in sorted(range(len(scores)), key=lambda i: -scores[i])[:candidates]])
        if self.collection is not None:
            try:
                qv = self.embeddings.embed_query(query)
                res = self.collection.query(query_embeddings=[qv], n_results=min(candidates, len(self.chunks)))
                rankings.append(res["ids"][0])
            except Exception as exc:
                log.warning("Semantic search failed: %s", exc)
        fused: dict[str, float] = {}
        for ranking in rankings:  # reciprocal rank fusion
            for rank, cid in enumerate(ranking):
                fused[cid] = fused.get(cid, 0.0) + 1.0 / (60 + rank)
        ids = sorted(fused, key=lambda c: -fused[c])[:candidates]
        hits = [Chunk(**{**self.by_id[c].__dict__, "score": fused[c]}) for c in ids]
        if self.reranker is not None and hits:
            ce = self.reranker.predict([(query, h.text) for h in hits])
            for h, s in zip(hits, ce):
                h.score = float(s)
            hits.sort(key=lambda h: -h.score)
        return hits[:k]


@lru_cache(maxsize=1)
def get_retriever() -> HybridRetriever:
    return HybridRetriever(load_policy_chunks(settings.policy_dir))


def format_context(chunks: list[Chunk]) -> str:
    return "\n\n".join(f"[{c.source} > {c.heading}]\n{c.text}" for c in chunks)
