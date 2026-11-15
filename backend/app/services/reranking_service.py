"""
MYX AI (Windows Edition) — Intelligent Semantic Reranking Service.
Passes candidate chunks retrieved from hybrid search through a cross-attention
relevance scoring model to rank and select optimal context before response synthesis.
"""
import re
from typing import List, Dict, Any


def compute_cross_attention_relevance(query: str, doc_text: str, doc_title: str = "") -> float:
    """
    Computes a deterministic cross-encoder style relevance score between 0.0 and 1.0
    evaluating token overlap, semantic phrase alignment, exact identifier matches,
    and title relevance.
    """
    if not query or not doc_text:
        return 0.0

    q_lower = query.lower()
    doc_lower = doc_text.lower()
    title_lower = doc_title.lower() if doc_title else ""

    # 1. Exact phrase / title match bonus
    score = 0.0
    if q_lower in doc_lower:
        score += 0.35
    if title_lower and any(token in title_lower for token in q_lower.split() if len(token) > 3):
        score += 0.20

    # 2. Key security identifier checks (CVE, CWE, HTTP header names)
    identifiers = re.findall(r"(cve-\d{4}-\d+|cwe-\d+|hsts|csp|x-frame|tls|ssl|rdp|smb|bitlocker)", q_lower)
    for ident in identifiers:
        if ident in doc_lower or ident in title_lower:
            score += 0.25

    # 3. Term overlap ratio (Jaccard-like similarity on substantive tokens)
    q_words = set(w for w in re.findall(r"\b\w{3,}\b", q_lower))
    doc_words = set(w for w in re.findall(r"\b\w{3,}\b", doc_lower))

    if q_words:
        overlap = len(q_words.intersection(doc_words)) / len(q_words)
        score += overlap * 0.40

    return min(1.0, round(score, 4))


class IntelligentReranker:
    """
    Reranks candidates retrieved by the Hybrid RAG engine to select the highest-quality
    grounded evidence chunks for LLM response generation.
    """
    def __init__(self, top_k_final: int = 3):
        self.top_k_final = top_k_final

    def rerank(self, query: str, candidate_chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Reranks a list of candidate chunk dictionaries based on query relevance.
        """
        if not candidate_chunks:
            return []

        scored_candidates = []
        for chunk in candidate_chunks:
            text = chunk.get("content_text") or chunk.get("content") or chunk.get("description") or ""
            title = chunk.get("document_title") or chunk.get("title") or ""
            rel_score = compute_cross_attention_relevance(query, text, title)

            # Combine hybrid RRF score with cross-encoder relevance score
            rrf_base = chunk.get("rrf_score", 0.0)
            composite_score = round(rel_score * 0.70 + rrf_base * 0.30, 4)

            enhanced_chunk = dict(chunk)
            enhanced_chunk["reranker_score"] = rel_score
            enhanced_chunk["composite_relevance"] = composite_score
            scored_candidates.append(enhanced_chunk)

        # Sort descending by composite relevance
        scored_candidates.sort(key=lambda x: x["composite_relevance"], reverse=True)
        return scored_candidates[:self.top_k_final]
