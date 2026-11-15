"""
MYX AI (Windows Edition) — Conversational Memory & Context Rewriting Service.
Manages session-based conversation history, tenant isolation, follow-up query
resolution, and token-aware context summarization.
"""
from typing import List, Dict, Any, Optional
import datetime


class ConversationMemoryManager:
    """
    In-memory session manager with tenant-scoped isolation.
    """
    def __init__(self, max_history_turns: int = 10):
        self.max_history_turns = max_history_turns
        # Key: (org_id, session_id) -> List[Dict[str, Any]]
        self._sessions: Dict[str, List[Dict[str, Any]]] = {}

    def _session_key(self, org_id: str, session_id: str) -> str:
        return f"{org_id.strip()}::{session_id.strip()}"

    def get_history(self, org_id: str, session_id: str) -> List[Dict[str, Any]]:
        """Retrieves session history, strictly partitioned by organization ID."""
        key = self._session_key(org_id, session_id)
        return self._sessions.get(key, [])

    def append_message(
        self,
        org_id: str,
        session_id: str,
        role: str,
        content: str,
        model_name: str = "gemini-3-flash-preview",
        structured_response: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Appends a user or assistant message to the session history."""
        key = self._session_key(org_id, session_id)
        if key not in self._sessions:
            self._sessions[key] = []

        msg = {
            "id": f"msg-{int(datetime.datetime.now().timestamp() * 1000)}",
            "role": role,
            "content": content,
            "model_name": model_name,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "structured_response": structured_response,
        }
        self._sessions[key].append(msg)

        # Enforce history turn limit
        if len(self._sessions[key]) > self.max_history_turns * 2:
            # Keep the first welcome message and the most recent turns
            self._sessions[key] = [self._sessions[key][0]] + self._sessions[key][-(self.max_history_turns * 2 - 1):]

        return msg

    def clear_session(self, org_id: str, session_id: str):
        """Clears messages for a specific session."""
        key = self._session_key(org_id, session_id)
        if key in self._sessions:
            self._sessions[key] = []

    def rewrite_query_with_context(self, org_id: str, session_id: str, current_query: str) -> str:
        """
        Resolves pronouns and follow-up references ('Explain it simply', 'How do I fix that?')
        using the previous conversation turns.
        """
        clean_q = current_query.strip()
        history = self.get_history(org_id, session_id)
        if not history:
            return clean_q

        # Identify follow-up patterns
        follow_up_triggers = [
            "explain it", "explain that", "how do i fix it", "how do i fix that",
            "more detail", "elaborate", "what about the other one", "show steps",
            "in simple terms", "simply", "why does that happen"
        ]

        is_follow_up = any(trig in clean_q.lower() for trig in follow_up_triggers) or len(clean_q.split()) <= 4

        if is_follow_up:
            # Find the most recent assistant or user topic
            last_user_query = ""
            for msg in reversed(history):
                if msg.get("role") == "user":
                    last_user_query = msg.get("content", "")
                    break

            if last_user_query and last_user_query.lower() != clean_q.lower():
                # Rewritten combined query preserving core subject
                return f"{clean_q} regarding: {last_user_query}"

        return clean_q
