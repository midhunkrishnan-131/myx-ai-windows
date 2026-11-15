"""
MYX AI (Windows Edition) — Intent Classification Service.
Classifies user incoming prompts to distinguish conversational greetings and small talk
from substantive security queries and technical document inquiries, preventing unnecessary
vector and database retrieval for casual conversation.
"""
import re
from typing import Dict, Any, Tuple

# Fast pattern definitions for casual greetings and acknowledgments
GREETING_PATTERNS = [
    r"^(hi|hello|hey|greetings|howdy|yo|sup|good morning|good afternoon|good evening|welcome)\b",
    r"^(who are you|what can you do|introduce yourself|what is your name|help)\b",
]

SMALL_TALK_PATTERNS = [
    r"^(how are you|how's it going|what's up|doing good|nice to meet you|thank you|thanks|thx|cool|ok|okay|bye|goodbye)\b",
    r"^(who made you|who created you|are you ai|are you a human)\b",
]

REPORT_KEYWORDS = [
    "report", "finding", "vulnerability", "cve-", "cwe-", "hsts", "csp", "clickjacking",
    "ssl", "tls", "dns", "audit", "assessment", "score", "remediation", "prioritize",
    "critical", "high", "medium", "fix first", "what does this mean", "explain this report"
]


def classify_user_intent(query: str, has_attached_findings: bool = False) -> Tuple[str, float]:
    """
    Classifies a user query into one of:
    - GREETING: Quick conversational greeting
    - SMALL_TALK: Polite banter or pleasantries
    - REPORT_ANALYSIS: Query explicitly asking about an assessment finding or report
    - DOCUMENT_RAG: Technical query requiring knowledge base / pgvector retrieval
    - GENERAL_SECURITY: General cybersecurity question answerable via core security knowledge
    """
    clean_query = query.strip().lower()
    if not clean_query:
        return "GREETING", 1.0

    # Check for direct greeting
    for pat in GREETING_PATTERNS:
        if re.search(pat, clean_query):
            # If the user says "Hello, what is SQL injection?", that's a security question despite the greeting
            if len(clean_query.split()) > 4 and any(kw in clean_query for kw in ["sql", "cve", "hsts", "port", "vulnerability", "fix", "attack", "how", "why"]):
                break
            return "GREETING", 0.98

    # Check for small talk
    for pat in SMALL_TALK_PATTERNS:
        if re.search(pat, clean_query):
            if len(clean_query.split()) <= 6:
                return "SMALL_TALK", 0.95

    # Check for report or finding inspection
    if any(kw in clean_query for kw in REPORT_KEYWORDS) or has_attached_findings:
        if any(trigger in clean_query for trigger in ["report", "finding", "assessment", "score", "fix first", "prioritize", "mean", "impact"]):
            return "REPORT_ANALYSIS", 0.92

    # Check for technical doc retrieval signals
    if any(kw in clean_query for kw in ["in my document", "in the pdf", "uploaded policy", "baseline", "standard", "guide"]):
        return "DOCUMENT_RAG", 0.90

    return "GENERAL_SECURITY", 0.85


def get_direct_conversational_response(intent: str, user_name: str = "Analyst") -> str:
    """
    Generates an immediate, grounded conversational reply without invoking retrieval engines.
    """
    if intent == "GREETING":
        return (
            "Hey! Welcome to MYX-AI Security Analyst Copilot. "
            "How can I help you with your security posture, finding analysis, or defensive hardening today?"
        )
    if intent == "SMALL_TALK":
        return (
            "I'm operating at peak readiness! All defensive analyzers, RAG pipelines, "
            "and Windows 10/11 telemetry monitors are active. What security topic would you like to explore?"
        )
    return "I am ready to assist. Please specify a security question or target assessment to analyze."
