/**
 * Public submission page.
 *
 * Same look as the analyst's "New scan" page, without the workspace: no sidebar,
 * one field to check an observable, the caller's remaining allowance, and only the
 * result of the submission made in this tab.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CircleAlert, LogIn, Send } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';

import { useAuth } from '@/app/auth-context';
import { Badge, Button, Card, ErrorBanner, Input, Skeleton } from '@/components/ui';
import { LogoMark } from '@/components/ui/Logo';
import { ObservableTypeBadge, VerdictBadge } from '@/components/ui/verdict';
import { ApiError, api } from '@/lib/api-client';
import type { Verdict } from '@/lib/types';

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
    // Without storage the result is simply not kept across a reload.
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
    if (error.status === 429) return 'You have used your allowance for this hour.';
    return error.message;
  }
  return 'Something went wrong. Try again.';
}

const KNOWN_VERDICTS = new Set<string>(['clean', 'suspicious', 'malicious']);

function asVerdict(value: string): Verdict {
  return KNOWN_VERDICTS.has(value) ? (value as Verdict) : 'unknown';
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

  const unavailable = quota.error instanceof ApiError ? quota.error : null;
  const blocked = unavailable !== null && [403, 404].includes(unavailable.status);
  const exhausted = quota.data?.remaining === 0;

  // A stored id that no longer resolves is dropped rather than shown as an error.
  if (result.error instanceof ApiError && result.error.status === 404 && submissionId) {
    storeId(null);
    setSubmissionId(null);
  }

  const data = result.data;
  const used = quota.data ? quota.data.limit - quota.data.remaining : 0;

  return (
    <div className="min-h-full bg-canvas text-text">
      <header className="glass sticky top-0 z-30 flex items-center justify-between border-b border-border px-4 py-3">
        <Link to="/public" className="flex items-center gap-2.5">
          <LogoMark size={28} />
          <span className="text-sm font-semibold">XenoProxy</span>
        </Link>
        {user ? (
          <Link to="/scan" className="text-sm text-muted hover:text-text">
            {user.display_name ?? user.username} · workspace
          </Link>
        ) : (
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm hover:bg-surface-raised"
          >
            <LogIn size={14} aria-hidden="true" /> Sign in
          </Link>
        )}
      </header>

      <main className="mx-auto max-w-3xl px-4 pb-24 pt-14">
        <section className="mb-7 text-center">
          <LogoMark size={44} className="mx-auto" />
          <h1 className="mt-3.5 text-3xl font-semibold">
            Is it <span className="text-gradient">safe</span>?
          </h1>
          <p className="mx-auto mt-2 max-w-xl text-sm text-muted">
            Paste an address, a domain, a URL or a file hash. XenoProxy checks it against the
            sources this instance makes available to the public.
          </p>

          {blocked ? (
            <div className="mx-auto mt-8 max-w-2xl text-left">
              <ErrorBanner message={describe(unavailable)} />
            </div>
          ) : (
            <form onSubmit={onSubmit} className="relative mx-auto mt-7 max-w-2xl">
              <Input
                value={value}
                onChange={(event) => setValue(event.target.value)}
                placeholder="8.8.8.8 · example.com · https://example.com/path · a file hash"
                aria-label="Observable to check"
                maxLength={2048}
                spellCheck={false}
                disabled={exhausted}
                className="h-14 pr-32 text-base"
              />
              <Button
                type="submit"
                className="absolute right-2 top-2 h-10"
                disabled={!value.trim() || exhausted || submit.isPending}
              >
                <Send className="h-4 w-4" aria-hidden />
                {submit.isPending ? 'Sending…' : 'Check'}
              </Button>
            </form>
          )}

          {!blocked ? (
            <div className="mx-auto mt-4 flex max-w-2xl flex-col items-center gap-2 text-xs text-muted sm:flex-row sm:justify-between" aria-live="polite">
              {quota.isLoading ? (
                <Skeleton className="h-4 w-48" />
              ) : quota.data ? (
                <>
                  <div className="flex items-center gap-2">
                    <span className="flex gap-1" aria-hidden>
                      {Array.from({ length: quota.data.limit }, (_, index) => (
                        <span
                          key={index}
                          className={`h-1.5 w-4 rounded-pill ${index < used ? 'bg-primary' : 'bg-surface-sunken'}`}
                        />
                      ))}
                    </span>
                    <span>
                      {quota.data.remaining} of {quota.data.limit} checks left this hour
                    </span>
                  </div>
                  {quota.data.remaining < quota.data.limit && quota.data.reset_seconds > 0 ? (
                    <span>renews in {formatReset(quota.data.reset_seconds)}</span>
                  ) : null}
                </>
              ) : null}
            </div>
          ) : null}
        </section>

        {exhausted && !blocked ? (
          <div className="mx-auto mb-6 flex max-w-2xl items-center gap-2 text-sm text-warning">
            <CircleAlert className="h-4 w-4" aria-hidden /> You have used this hour's checks. Come
            back shortly.
          </div>
        ) : null}

        {submit.error ? (
          <div className="mx-auto mb-6 max-w-2xl">
            <ErrorBanner message={describe(submit.error)} />
          </div>
        ) : null}

        {data ? (
          <Card
            className="mx-auto max-w-2xl"
            title={<span className="break-all font-mono text-base">{data.value}</span>}
            description={<ObservableTypeBadge type={data.type} />}
            actions={<VerdictBadge verdict={asVerdict(data.verdict)} />}
          >
            <p className="mb-3 text-xs text-muted">
              {ACTIVE.has(data.status) ? 'Analysis in progress…' : 'Analysis complete.'}
            </p>
            {data.sources.length === 0 ? (
              <p className="text-sm text-muted">
                {ACTIVE.has(data.status) ? 'Waiting for the sources…' : 'No source answered.'}
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {data.sources.map((source) => (
                  <li key={source.name} className="flex items-center justify-between py-2.5 text-sm">
                    <span className="font-medium">{source.name}</span>
                    <span className="flex items-center gap-2">
                      <Badge tone="neutral">{source.status}</Badge>
                      <VerdictBadge verdict={asVerdict(source.verdict)} />
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
