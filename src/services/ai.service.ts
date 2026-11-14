import { apiClient } from './apiClient';
import { AiConversationSession, RagDocumentRecord } from '../types/ai.types';
import { INITIAL_AI_CONVERSATIONS, INITIAL_RAG_DOCUMENTS } from '../data/seedPreviewData';

export const aiService = {
  async listSessions() {
    return apiClient.request<AiConversationSession[]>(
      '/ai/chat/sessions',
      { method: 'GET' },
      () => INITIAL_AI_CONVERSATIONS
    );
  },

  async listRagDocuments() {
    return apiClient.request<RagDocumentRecord[]>(
      '/rag/documents',
      { method: 'GET' },
      () => INITIAL_RAG_DOCUMENTS
    );
  },
};
