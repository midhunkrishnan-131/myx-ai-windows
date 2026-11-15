"""
MYX AI (Windows Edition) — Advanced Hybrid Retrieval with Reciprocal Rank Fusion (RRF).
Merges ranked candidates from semantic vector search and exact BM25 keyword search,
deduplicating chunks, preserving document metadata, and computing composite relevance.
"""
from typing import List, Dict, Any, Optional
import numpy as np
from app.services.bm25_search_service import BM25SearchEngine


def compute_rrf_score(rank: int, k: int = 60) -> float:
    """
    Computes reciprocal rank score: 1 / (k + rank), where rank is 1-indexed.
    Default constant k = 60 is standard in information retrieval literature.
    """
    return 1.0 / (k + rank)


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Computes cosine similarity between two numerical embedding vectors."""
    a = np.array(v1, dtype=np.float32)
    b = np.array(v2, dtype=np.float32)
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


class HybridRetrievalService:
    """
    Orchestrates dense vector search and sparse BM25 retrieval, combining results via RRF.
    """
    def __init__(self, rrf_k: int = 60, vector_weight: float = 0.5, bm25_weight: float = 0.5):
        self.rrf_k = rrf_k
        self.vector_weight = vector_weight
        self.bm25_weight = bm25_weight
        self.bm25_engine = BM25SearchEngine()

    def index_corpus(self, documents: List[Dict[str, Any]]):
        """Indexes knowledge base documents into the BM25 search engine."""
        self.bm25_engine.index_documents(documents, text_field="content_text")

    def perform_hybrid_search(
        self,
        query: str,
        query_embedding: Optional[List[float]],
        vector_candidates: List[Dict[str, Any]],
        top_n: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Executes hybrid retrieval:
        1. BM25 keyword search over indexed documents
        2. Vector cosine similarity ranking over vector candidates
        3. Reciprocal Rank Fusion (RRF) merge with deduplication and metadata preservation
        """
        # 1. Run BM25 search
        bm25_results = self.bm25_engine.search(query, top_k=top_n * 2)

        # 2. Rank vector candidates if embeddings are available
        vector_ranked: List[Dict[str, Any]] = []
        if query_embedding and vector_candidates:
            scored_vector = []
            for item in vector_candidates:
                emb = item.get("embedding")
                if emb and isinstance(emb, list):
                    sim = cosine_similarity(query_embedding, emb)
                    scored_vector.append((item, sim))
            scored_vector.sort(key=lambda x: x[1], reverse=True)
            vector_ranked = [item for item, _ in scored_vector[:top_n * 2]]
        elif vector_candidates:
            vector_ranked = vector_candidates[:top_n * 2]

        # 3. Reciprocal Rank Fusion
        # Map: chunk_id -> { "doc": doc, "rrf_score": float, "sources": List[str], "vector_rank": Optional[int], "bm25_rank": Optional[int] }
        fused_scores: Dict[str, Dict[str, Any]] = {}

        # Process Vector candidates (1-indexed ranks)
        for rank_idx, doc in enumerate(vector_ranked):
            cid = str(doc.get("chunk_id") or doc.get("id") or f"doc-vec-{rank_idx}")
            rrf_contrib = self.vector_weight * compute_rrf_score(rank=rank_idx + 1, k=self.rrf_k)
            if cid not in fused_scores:
                fused_scores[cid] = {
                    "doc": doc,
                    "rrf_score": 0.0,
                    "sources": ["vector_semantic"],
                    "vector_rank": rank_idx + 1,
                    "bm25_rank": None
                }
            fused_scores[cid]["rrf_score"] += rrf_contrib

        # Process BM25 candidates (1-indexed ranks)
        for rank_idx, (doc, bm_score) in enumerate(bm25_results):
            cid = str(doc.get("chunk_id") or doc.get("id") or f"doc-bm25-{rank_idx}")
            rrf_contrib = self.bm25_weight * compute_rrf_score(rank=rank_idx + 1, k=self.rrf_k)
            if cid not in fused_scores:
                fused_scores[cid] = {
                    "doc": doc,
                    "rrf_score": 0.0,
                    "sources": ["bm25_keyword"],
                    "vector_rank": None,
                    "bm25_rank": rank_idx + 1
                }
            else:
                fused_scores[cid]["sources"].append("bm25_keyword")
                fused_scores[cid]["bm25_rank"] = rank_idx + 1

            fused_scores[cid]["rrf_score"] += rrf_contrib
            fused_scores[cid]["bm25_raw_score"] = bm_score

        # 4. Sort fused candidates by combined RRF score
        sorted_fused = sorted(fused_scores.values(), key=lambda x: x["rrf_score"], reverse=True)

        # 5. Build final result payload preserving document metadata and audit references
        final_results = []
        for entry in sorted_fused[:top_n]:
            doc_data = dict(entry["doc"])
            doc_data["rrf_score"] = round(entry["rrf_score"], 6)
            doc_data["retrieval_sources"] = entry["sources"]
            doc_data["vector_rank"] = entry["vector_rank"]
            doc_data["bm25_rank"] = entry["bm25_rank"]
            final_results.append(doc_data)

        return final_results
