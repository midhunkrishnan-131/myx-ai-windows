"""
MYX AI (Windows Edition) — Advanced AI Copilot Router.
Exposes endpoints for Agentic Hybrid RAG, conversational memory,
beginner/technical report explanations, and executive posture summaries.
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.services.agent_orchestration_service import AgenticRagOrchestrator
from app.services.report_explanation_service import (
    explain_finding_structured,
    generate_executive_posture_summary,
    generate_contextual_followups,
)

router = APIRouter(prefix="/api/v1/ai/copilot", tags=["AI Copilot & Agentic RAG"])
orchestrator = AgenticRagOrchestrator()


class ChatQueryRequest(BaseModel):
    query: str = Field(..., description="User query or instruction")
    sessionId: Optional[str] = Field("conv-general-01", description="Session identifier")
    session_id: Optional[str] = Field(None, description="Alternative session identifier")
    orgId: Optional[str] = Field("org-default", description="Tenant organization ID")
    org_id: Optional[str] = Field(None, description="Alternative org identifier")
    mode: Optional[str] = Field("BEGINNER", description="Explanation mode: BEGINNER or TECHNICAL")
    attachedFindings: Optional[List[Dict[str, Any]]] = Field(None, description="Active assessment findings")
    assessmentRun: Optional[Dict[str, Any]] = Field(None, description="Active assessment summary")
    vectorCandidates: Optional[List[Dict[str, Any]]] = Field(None, description="Knowledge base chunks")
    queryEmbedding: Optional[List[float]] = Field(None, description="Precomputed query embedding")


class ExplainFindingRequest(BaseModel):
    finding: Dict[str, Any] = Field(..., description="Finding payload")
    mode: Optional[str] = Field("BEGINNER", description="BEGINNER or TECHNICAL")


class ExecutiveSummaryRequest(BaseModel):
    assessmentRun: Dict[str, Any] = Field(..., description="Assessment run record")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Associated findings")


@router.post("/chat", summary="Process query through Agentic Hybrid RAG Engine")
def copilot_chat(req: ChatQueryRequest):
    sess_id = req.sessionId or req.session_id or "conv-general-01"
    organization = req.orgId or req.org_id or "org-default"

    res = orchestrator.process_query(
        query=req.query,
        session_id=sess_id,
        org_id=organization,
        mode=req.mode or "BEGINNER",
        attached_findings=req.attachedFindings,
        assessment_run=req.assessmentRun,
        vector_candidates=req.vectorCandidates,
        query_embedding=req.queryEmbedding,
    )
    return res


@router.post("/explain-finding", summary="Generate structured 6-part finding explanation")
def explain_finding_endpoint(req: ExplainFindingRequest):
    explanation = explain_finding_structured(req.finding, mode=req.mode or "BEGINNER")
    return {"explanation": explanation}


@router.post("/executive-summary", summary="Generate executive summary strictly from real assessment data")
def executive_summary_endpoint(req: ExecutiveSummaryRequest):
    summary = generate_executive_posture_summary(req.assessmentRun, req.findings)
    followups = generate_contextual_followups(
        req.findings,
        score=summary["score"],
        target=summary["target"]
    )
    return {
        "summary": summary,
        "followups": followups,
    }
