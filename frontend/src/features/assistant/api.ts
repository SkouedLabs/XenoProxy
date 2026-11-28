/** Assistant API: status, conversations, one turn. */

import { api, ApiError } from '@/lib/api-client';
import type { AssistantStatus, ChatMessage, Conversation } from '@/lib/types';

export const assistantApi = {
  status: () => api.get<AssistantStatus>('/assistant'),
  conversations: () => api.get<Conversation[]>('/assistant/conversations'),
  open: (jobId?: string) =>
    api.post<Conversation>('/assistant/conversations', jobId ? { job_id: jobId } : {}),
  read: (id: string) => api.get<Conversation>(`/assistant/conversations/${id}`),
  remove: (id: string) => api.delete<{ message: string }>(`/assistant/conversations/${id}`),
  ask: (id: string, message: string) =>
    api.post<ChatMessage & { error?: string }>(`/assistant/conversations/${id}/ask`, { message }),
};

export interface StartedStep {
  index: number;
  tool: string;
  arguments: Record<string, unknown>;
}

export interface FinishedStep {
  index: number;
  tool: string;
  ok: boolean;
  result: unknown;
}

export interface TurnHandlers {
  onToken(text: string): void;
  onStep(step: StartedStep): void;
  onStepResult(step: FinishedStep): void;
}

/**
 * Send one question and follow the turn as it happens.
 *
 * `fetch` is used directly rather than the shared client: the client parses a
 * JSON body, and this response is an event stream read as it is produced. The
 * CSRF header and the credentials are the same ones the client sends.
 */
export async function streamAnswer(
  conversationId: string,
  message: string,
  handlers: TurnHandlers,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`/api/v1/assistant/conversations/${conversationId}/stream`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    body: JSON.stringify({ message }),
    signal,
  });
  if (!response.ok || !response.body) {
    throw new ApiError(response.status, null, `The assistant answered HTTP ${response.status}.`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let failure: string | null = null;

  const dispatch = (event: string, payload: Record<string, unknown>) => {
    if (event === 'token') handlers.onToken(String(payload.text ?? ''));
    else if (event === 'step') handlers.onStep(payload as unknown as StartedStep);
    else if (event === 'step_result') handlers.onStepResult(payload as unknown as FinishedStep);
    else if (event === 'error') failure = String(payload.message ?? 'the assistant failed');
  };

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // Server-sent events are separated by a blank line.
    const blocks = buffer.split('\n\n');
    buffer = blocks.pop() ?? '';
    for (const block of blocks) {
      const event = /^event:\s*(.+)$/m.exec(block)?.[1]?.trim();
      const data = /^data:\s*(.+)$/m.exec(block)?.[1];
      if (!event || !data) continue;
      try {
        dispatch(event, JSON.parse(data) as Record<string, unknown>);
      } catch {
        // A frame that is not JSON is dropped rather than shown as content.
      }
    }
  }

  if (failure) throw new Error(failure);
}
