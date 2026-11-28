/**
 * Public submission page: no sidebar, one box to submit, the caller's remaining
 * allowance, and the result of the submission they just made (and only that one).
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { LogIn } from 'lucide-react';
import { useState, type FormEvent } from 'react';

import { useAuth } from '@/app/auth-context';
import { Badge, Button, Card, ErrorBanner, Input, Skeleton } from '@/components/ui';
import { LogoMark } from '@/components/ui/Logo';
import { ApiError, api } from '@/lib/api-client';

interface PublicQuota {
  limit: number;
  remaining: number;
  window_seconds: number;
  reset_seconds: number;
}

interface PublicSource {
  name: string;
  status: string;
  verdict: string;
}

interface PublicSubmission {
  id: string;
  value: string;
  type: string;
  status: string;
  verdict: string;
  created_at: string | null;
  finished_at: string | null;
  sources: PublicSource[];
}

const STORAGE_KEY = 'xenoproxy.public.submission';
const ACTIVE = new Set(['pending', 'queued', 'running']);

type Tone = 'neutral' | 'success' | 'warning' | 'danger';

function verdictTone(verdict: string): Tone {
  if (verdict === 'malicious') return 'danger';
  if (verdict === 'suspicious') return 'warning';
  if (verdict === 'clean') return 'success';
  return 'neutral';
}

function readStoredId(): string | null {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function storeId(id: string | null): void {
  try {
    if (id) window.sessionStorage.setItem(STORAGE_KEY, id);
    else window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Without storage the result simply is not remembered across a reload.
  }
}

function formatReset(seconds: number): string {
  const minutes = Math.max(1, Math.ceil(seconds / 60));
  return minutes >= 60 ? `${Math.ceil(minutes / 60)} h` : `${minutes} min`;
}

function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404) return 'Public submission is not available on this instance.';
    if (error.status === 403) return 'Public submission is not open to your address.';
    if (error.status === 429) return 'You have used your allowance for now. Try again later.';
    return error.message;
  }
  return 'Something went wrong. Try again.';
}

export function PublicPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [value, setValue] = useState('');
  const [submissionId, setSubmissionId] = useState<string | null>(readStoredId);

  const quota = useQuery({
    queryKey: ['public', 'quota'],
    queryFn: () => api.get<PublicQuota>('/public/quota'),
    retry: false,
    staleTime: 0,
  });

  const result = useQuery({
    queryKey: ['public', 'submission', submissionId],
    queryFn: () => api.get<PublicSubmission>(`/public/submissions/${submissionId}`),
    enabled: submissionId !== null,
    retry: false,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data && !ACTIVE.has(data.status) ? false : 3000;
    },
  });

  const submit = useMutation({
    mutationFn: (observable: string) =>
      api.post<PublicSubmission>('/public/submissions', { value: observable }),
    onSuccess: (created) => {
      storeId(created.id);
      setSubmissionId(created.id);
      queryClient.setQueryData(['public', 'submission', created.id], created);
      setValue('');
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ['public', 'quota'] });
    },
  });

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = value.trim();
    if (trimmed) submit.mutate(trimmed);
  };

  const exhausted = quota.data?.remaining === 0;
  const unavailable = quota.error instanceof ApiError ? quota.error : null;
  const blocked = unavailable !== null && [403, 404].includes(unavailable.status);

  // A stored id that no longer resolves is dropped rather than shown as an error.
  if (result.error instanceof ApiError && result.error.status === 404 && submissionId) {
    storeId(null);
    setSubmissionId(null);
  }

  const data = result.data;

  return (
    <div className="flex min-h-full flex-col bg-canvas text-text">
      <header className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2.5">
          <LogoMark size={28} />
          <span className="text-sm font-semibold">XenoProxy</span>
        </div>
        {user ? (
          <a href="/scan" className="text-sm text-muted hover:text-text">
            {user.display_name ?? user.username} · open the workspace
          </a>
        ) : (
          <a
            href="/scan"
            className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm hover:bg-surface-raised"
          >
            <LogIn size={14} aria-hidden="true" /> Sign in
          </a>
        )}
      </header>

      <main className="mx-auto w-full max-w-2xl flex-1 space-y-5 px-4 py-10">
        <div>
          <h1 className="text-xl font-semibold">Check an observable</h1>
          <p className="mt-1 text-sm text-muted">
            An IP address, a domain, a URL or a file hash. It is sent to the reputation sources this
            instance has chosen for public use.
          </p>
        </div>

        {blocked ? <ErrorBanner message={describe(unavailable)} /> : null}

        {!blocked ? (
          <Card>
            <form onSubmit={onSubmit} className="flex flex-col gap-3 sm:flex-row">
              <Input
                value={value}
                onChange={(event) => setValue(event.target.value)}
                placeholder="example.com, 203.0.113.7, https://…, sha256"
                aria-label="Observable to check"
                maxLength={2048}
                disabled={exhausted}
                className="flex-1"
              />
              <Button type="submit" disabled={!value.trim() || exhausted || submit.isPending}>
                {submit.isPending ? 'Sending…' : 'Check'}
              </Button>
            </form>
            <div className="mt-3 text-xs text-muted" aria-live="polite">
              {quota.isLoading ? (
                <Skeleton className="h-4 w-48" />
              ) : quota.data ? (
                <p>
                  {quota.data.remaining} of {quota.data.limit} checks left this hour
                  {quota.data.remaining < quota.data.limit && quota.data.reset_seconds > 0
                    ? `, renewed in ${formatReset(quota.data.reset_seconds)}`
                    : ''}
                  .
                </p>
              ) : null}
            </div>
          </Card>
        ) : null}

        {submit.error ? <ErrorBanner message={describe(submit.error)} /> : null}

        {data ? (
          <Card
            title={<span className="break-all">{data.value}</span>}
            description={`${data.type} · ${data.status}`}
            actions={<Badge tone={verdictTone(data.verdict)}>{data.verdict}</Badge>}
          >
            {data.sources.length === 0 ? (
              <p className="text-sm text-muted">
                {ACTIVE.has(data.status) ? 'Waiting for the sources…' : 'No source answered.'}
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {data.sources.map((source) => (
                  <li key={source.name} className="flex items-center justify-between py-2 text-sm">
                    <span>{source.name}</span>
                    <span className="flex items-center gap-2">
                      <span className="text-xs text-muted">{source.status}</span>
                      <Badge tone={verdictTone(source.verdict)}>{source.verdict}</Badge>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        ) : null}
      </main>
    </div>
  );
}
