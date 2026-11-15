"""
MYX AI (Windows Edition) — Agentic Hybrid RAG & Report Explanation Test Suite.
Validates:
1. Intent classification bypasses retrieval for greetings and small talk.
2. BM25 keyword search accurately retrieves exact technical identifiers (CVEs, headers).
3. Hybrid RAG merges dense and sparse results via Reciprocal Rank Fusion (RRF).
4. Cross-encoder reranker improves relevance ordering.
5. Conversation memory correctly rewrites follow-up questions.
6. 6-part structured finding explanations work in Beginner-Friendly and Technical modes.
7. Executive summary reflects strictly genuine assessment counts.
"""
import pytest
from app.services.intent_classification_service import classify_user_intent, get_direct_conversational_response
from app.services.bm25_search_service import BM25SearchEngine, tokenize_technical_text
from app.services.hybrid_retrieval_service import HybridRetrievalService, compute_rrf_score
from app.services.reranking_service import IntelligentReranker, compute_cross_attention_relevance
from app.services.conversation_memory_service import ConversationMemoryManager
from app.services.report_explanation_service import (
    explain_finding_structured,
    generate_executive_posture_summary,
    generate_contextual_followups,
)
from app.services.agent_orchestration_service import AgenticRagOrchestrator


def test_intent_classification_bypasses_retrieval_for_greetings():
    """Rule: Greetings and small talk must not trigger unnecessary vector searches."""
    assert classify_user_intent("Hi")[0] == "GREETING"
    assert classify_user_intent("Hello!")[0] == "GREETING"
    assert classify_user_intent("Hey copilot")[0] == "GREETING"
    assert classify_user_intent("Good morning")[0] == "GREETING"
    assert classify_user_intent("How are you today?")[0] == "SMALL_TALK"
    assert classify_user_intent("Thank you so much")[0] == "SMALL_TALK"

    # Conversational replies must be immediate and friendly
    reply = get_direct_conversational_response("GREETING")
    assert "Welcome to MYX-AI" in reply

    # Direct query test via orchestrator
    orchestrator = AgenticRagOrchestrator()
    res = orchestrator.process_query("Hi", session_id="test-sess-01")
    assert res["intent"] == "GREETING"
    assert res["retrieval_executed"] is False
    assert "Hey!" in res["reply"] or "Welcome" in res["reply"]


def test_bm25_exact_cve_and_keyword_search():
    """Rule: BM25 must index and accurately retrieve exact technical terms and CVE codes."""
    bm25 = BM25SearchEngine()
    docs = [
        {"id": "doc-1", "title": "Windows 11 Baseline", "content": "Enforce NLA on RDP port 3389 and patch CVE-2024-38077."},
        {"id": "doc-2", "title": "OWASP Headers", "content": "Configure Strict-Transport-Security HSTS with max-age=31536000."},
        {"id": "doc-3", "title": "SQL Injection Guide", "content": "Use prepared statements to prevent CWE-89 SQL injection attacks."},
    ]
    bm25.index_documents(docs, text_field="content")

    # Search for exact CVE
    results_cve = bm25.search("CVE-2024-38077", top_k=2)
    assert len(results_cve) > 0
    assert results_cve[0][0]["id"] == "doc-1"

    # Search for HSTS
    results_hsts = bm25.search("Strict-Transport-Security HSTS", top_k=2)
    assert len(results_hsts) > 0
    assert results_hsts[0][0]["id"] == "doc-2"


def test_rrf_hybrid_merging_and_deduplication():
    """Rule: Hybrid RAG fuses vector and BM25 results with Reciprocal Rank Fusion."""
    hybrid = HybridRetrievalService(rrf_k=60)
    corpus = [
        {"id": "c1", "content_text": "Configure Content-Security-Policy to prevent XSS."},
        {"id": "c2", "content_text": "Enable BitLocker volume encryption on Windows 11."},
        {"id": "c3", "content_text": "Deploy TLS 1.3 and disable SSLv3 and TLS 1.0."},
    ]
    hybrid.index_corpus(corpus)

    # Provide vector candidates with a precomputed embedding
    fused = hybrid.perform_hybrid_search(
        query="Content-Security-Policy",
        query_embedding=[0.1, 0.2, 0.3],
        vector_candidates=[
            {"id": "c1", "content_text": "Configure Content-Security-Policy to prevent XSS.", "embedding": [0.1, 0.2, 0.3]},
            {"id": "c3", "content_text": "Deploy TLS 1.3 and disable SSLv3 and TLS 1.0.", "embedding": [0.0, 0.0, 0.5]},
        ],
        top_n=3
    )

    assert len(fused) > 0
    # Top chunk should be c1 since it matches both BM25 and Vector
    assert fused[0]["id"] == "c1"
    assert "vector_semantic" in fused[0]["retrieval_sources"]
    assert "bm25_keyword" in fused[0]["retrieval_sources"]
    assert fused[0]["rrf_score"] > 0


def test_reranker_relevance_ordering():
    """Rule: Reranker scores candidates and selects highest-quality context."""
    reranker = IntelligentReranker(top_k_final=2)
    candidates = [
        {"id": "gen-1", "title": "General Security", "content": "Security is important for software."},
        {"id": "spec-2", "title": "HSTS Directives", "content": "Strict-Transport-Security must includeSubDomains and preload."},
    ]
    reranked = reranker.rerank("How do I configure HSTS max-age?", candidates)
    assert len(reranked) == 2
    assert reranked[0]["id"] == "spec-2"
    assert reranked[0]["composite_relevance"] > reranked[1]["composite_relevance"]


def test_conversation_memory_followup_rewriting():
    """Rule: Conversational memory understands pronouns and follow-up requests."""
    mem = ConversationMemoryManager()
    mem.append_message("org-1", "sess-1", "user", "What is SQL injection?")
    mem.append_message("org-1", "sess-1", "assistant", "SQL injection is CWE-89...")

    rewritten = mem.rewrite_query_with_context("org-1", "sess-1", "Explain it simply")
    assert "regarding: What is SQL injection?" in rewritten


def test_beginner_and_technical_report_explanations():
    """Rule: 6-part finding explanation must support both Beginner and Technical modes."""
    finding = {
        "finding_code": "MYX-FND-2026-TEST",
        "title": "Strict-Transport-Security (HSTS) Missing",
        "severity": "High",
        "affected_asset": "portal.myx-security.io",
        "affected_endpoint": "/",
        "cwe_id": "CWE-319",
        "confidence": "Confirmed",
        "raw_evidence": "HTTP/1.1 200 OK\r\nServer: nginx\r\n(No Strict-Transport-Security header detected)",
        "remediation_guidance": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;",
    }

    # 1. Beginner Mode
    beg_expl = explain_finding_structured(finding, mode="BEGINNER")
    assert beg_expl["mode"] == "BEGINNER"
    assert "Overview" in str(beg_expl) or "overview" in beg_expl
    assert "What Does This Mean" in str(beg_expl) or "what_does_this_mean" in beg_expl
    assert "Real-World Impact" in str(beg_expl) or "real_world_impact" in beg_expl
    assert "Technical Evidence" in str(beg_expl) or "technical_evidence" in beg_expl
    assert "Recommended Solution" in str(beg_expl) or "recommended_solution" in beg_expl
    assert "Priority" in str(beg_expl) or "priority" in beg_expl
    # Beginner explanation uses clear, everyday analogy
    assert "deadbolt" in beg_expl["what_does_this_mean"] or "front door" in beg_expl["what_does_this_mean"]

    # 2. Technical Mode
    tech_expl = explain_finding_structured(finding, mode="TECHNICAL")
    assert tech_expl["mode"] == "TECHNICAL"
    assert "OWASP" in tech_expl["what_does_this_mean"] or "CWE-319" in str(tech_expl)


def test_executive_posture_summary_grounded_in_actual_data():
    """Rule: Executive summary counts and narrative must come strictly from actual assessment data."""
    run = {
        "target_url": "https://portal.myx-security.io",
        "overall_score": 68,
        "controls_passed": 3,
        "controls_failed": 2,
        "controls_warning": 1,
    }
    findings = [
        {"severity": "Critical", "title": "Missing SSL"},
        {"severity": "High", "title": "Missing HSTS"},
        {"severity": "Medium", "title": "Missing CSP"},
    ]
    summary = generate_executive_posture_summary(run, findings)
    assert summary["score"] == 68
    assert summary["total_findings"] == 3
    assert summary["critical_count"] == 1
    assert summary["high_count"] == 1
    assert summary["medium_count"] == 1
    assert summary["posture_band"] == "ELEVATED RISK POSTURE"
    assert len(summary["immediate_actions"]) > 0

    followups = generate_contextual_followups(findings, score=68, target="https://portal.myx-security.io")
    assert len(followups) >= 4
    assert any("critical" in f.lower() for f in followups)
