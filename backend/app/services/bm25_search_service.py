"""
MYX AI (Windows Edition) — In-Memory BM25 Keyword Search Engine.
Implements Okapi BM25 ranking for exact keyword matching, technical terminology,
CVE identifiers (e.g., CVE-2024-38077), CWE numbers, and security configuration keys.
"""
import math
import re
from typing import List, Dict, Any, Tuple


def tokenize_technical_text(text: str) -> List[str]:
    """
    Tokenizes text while preserving technical tokens like CVE-2026-0041, CWE-284,
    dot-separated domains, and hyphenated terms, stripping trailing punctuation.
    """
    if not text:
        return []
    # Match alphanumeric sequences with hyphens and underscores
    raw_tokens = re.findall(r"[a-zA-Z0-9_\-\.:/]+", text.lower())
    stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "is", "are", "was", "were"}
    
    cleaned = []
    for t in raw_tokens:
        clean_t = t.strip(".,;:?!'\"()[]{}")
        if len(clean_t) > 1 and clean_t not in stop_words:
            cleaned.append(clean_t)
            # If token contains hyphens, also index its sub-parts (e.g. 'cve', '2024', '38077' for 'cve-2024-38077')
            if "-" in clean_t:
                for sub in clean_t.split("-"):
                    if len(sub) > 1 and sub not in stop_words:
                        cleaned.append(sub)
    return cleaned


class BM25SearchEngine:
    """
    In-memory Okapi BM25 implementation.
    Parameters:
        k1: Controls term frequency saturation (default: 1.5)
        b: Controls degree of document length normalization (default: 0.75)
    """
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.corpus: List[Dict[str, Any]] = []
        self.doc_lengths: List[int] = []
        self.avg_doc_len: float = 0.0
        self.doc_freqs: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.tokenized_corpus: List[List[str]] = []

    def index_documents(self, documents: List[Dict[str, Any]], text_field: str = "content"):
        """
        Indexes a list of document dicts. Each dict must contain an identifier and a text field.
        """
        self.corpus = documents
        self.tokenized_corpus = []
        self.doc_lengths = []
        self.doc_freqs = {}

        total_tokens = 0
        for doc in documents:
            text = str(doc.get(text_field, "") or "")
            # Also append title or header if available to boost matches
            title = str(doc.get("title", "") or doc.get("document_title", "") or "")
            combined = f"{title} {text}"
            tokens = tokenize_technical_text(combined)
            self.tokenized_corpus.append(tokens)
            doc_len = len(tokens)
            self.doc_lengths.append(doc_len)
            total_tokens += doc_len

            # Track unique terms in this document for document frequency
            unique_terms = set(tokens)
            for term in unique_terms:
                self.doc_freqs[term] = self.doc_freqs.get(term, 0) + 1

        num_docs = len(documents)
        self.avg_doc_len = (total_tokens / num_docs) if num_docs > 0 else 1.0

        # Compute IDF for all indexed terms
        self.idf = {}
        for term, df in self.doc_freqs.items():
            # Standard Lucene/BM25 IDF formula with smoothing
            self.idf[term] = math.log(1.0 + (num_docs - df + 0.5) / (df + 0.5))

    def search(self, query: str, top_k: int = 5) -> List[Tuple[Dict[str, Any], float]]:
        """
        Performs BM25 search for the given query string.
        Returns a sorted list of (document, bm25_score) tuples.
        """
        if not self.corpus:
            return []

        query_tokens = tokenize_technical_text(query)
        if not query_tokens:
            return []

        scores: List[float] = [0.0] * len(self.corpus)

        for token in query_tokens:
            if token not in self.idf:
                continue
            idf_val = self.idf[token]

            for doc_idx, doc_tokens in enumerate(self.tokenized_corpus):
                # Count term frequency in document
                tf = doc_tokens.count(token)
                if tf == 0:
                    continue

                doc_len = self.doc_lengths[doc_idx]
                numerator = tf * (self.k1 + 1.0)
                denominator = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / self.avg_doc_len))
                scores[doc_idx] += idf_val * (numerator / denominator)

        # Pair scores with documents
        ranked = []
        for idx, score in enumerate(scores):
            if score > 0.0:
                ranked.append((self.corpus[idx], float(score)))

        # Sort descending by score
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked[:top_k]
