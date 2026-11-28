/** Admin page for the local YARA rulesets: pull a public one, switch it off, see what to mount.
 *
 * A pull runs in the worker (the API has no outbound route), so the page polls
 * while one is queued or running.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, FileCode2, Trash2 } from 'lucide-react';

import { PageHeader } from '@/app/AppShell';
import { Badge, Button, Card, ErrorBanner, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError, api } from '@/lib/api-client';
import type { YaraOverview } from '@/lib/types';

const KEY = ['admin', 'yara'];

export function YaraRulesPage() {
  const queryClient = useQueryClient();
  const toast = useToast();

  const query = useQuery({
    queryKey: KEY,
    queryFn: () => api.get<YaraOverview>('/admin/yara'),
    refetchInterval: (current) => {
      const state = current.state.data?.status.state;
      return state === 'queued' || state === 'running' ? 2000 : false;
    },
  });

  function onError(title: string) {
    return (error: unknown) =>
      toast.error(title, error instanceof ApiError ? error.message : 'Unexpected failure.');
  }
  function onSuccess(data: YaraOverview) {
    queryClient.setQueryData(KEY, data);
  }

  const pull = useMutation({
    mutationFn: (id: string) => api.post<YaraOverview>(`/admin/yara/sources/${id}/pull`),
    onSuccess,
    onError: onError('The pull could not be started'),
  });
  const toggle = useMutation({
    mutationFn: (input: { id: string; enabled: boolean }) =>
      api.put<YaraOverview>(`/admin/yara/sources/${input.id}/enabled?enabled=${input.enabled}`),
    onSuccess,
    onError: onError('The ruleset could not be changed'),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.delete<YaraOverview>(`/admin/yara/sources/${id}`),
    onSuccess,
    onError: onError('The ruleset could not be removed'),
  });

  const data = query.data;
  const busy = data?.status.state === 'queued' || data?.status.state === 'running';

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        breadcrumb={['Home', 'Admin', 'YARA rules']}
        title="YARA rules"
        description="Rulesets for the local YARA analyzer (alpha). Scanning happens on this instance: the file is never sent anywhere."
      />

      {query.isLoading ? (
        <Skeleton className="h-40" />
      ) : query.error || !data ? (
        <ErrorBanner
          message={
            query.error instanceof ApiError
              ? query.error.message
              : 'The rulesets could not be loaded.'
          }
          onRetry={() => void query.refetch()}
        />
      ) : (
        <>
          <Card
            title="Your own rules"
            description="Put .yar or .yara files in the custom folder; they are picked up on the next scan."
            className="mb-4"
          >
            <p className="text-sm">
              <FileCode2 className="mr-1 inline h-4 w-4 text-primary" aria-hidden />
              <code>{data.custom_directory}</code> · {data.custom_files} file(s)
            </p>
            <p className="mt-2 text-xs text-muted">
              To manage them from the host, replace the <code>yara_rules</code> volume with a bind
              mount, for example <code>./yara-rules:{data.directory}</code>, and keep your files
              in its <code>custom/</code> folder.
            </p>
          </Card>

          {data.status.state === 'failed' ? (
            <div className="mb-4">
              <ErrorBanner
                message={`The last pull (${data.status.source}) failed: ${data.status.error ?? 'unknown error'}`}
              />
            </div>
          ) : null}

          <Card
            title="Public rulesets"
            description={
              data.pull_enabled
                ? 'Downloaded by the worker. The archive digest is recorded with every pull.'
                : 'Pulling is disabled on this instance (BACKEND_YARA_PULL_ENABLED).'
            }
          >
            <ul className="divide-y divide-border">
              {data.sources.map((source) => (
                <li key={source.id} className="py-3">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                        {source.label}
                        {source.pulled ? (
                          source.enabled ? (
                            <Badge tone="success">Enabled</Badge>
                          ) : (
                            <Badge>Disabled</Badge>
                          )
                        ) : (
                          <Badge>Not pulled</Badge>
                        )}
                      </p>
                      <p className="mt-1 text-xs text-muted">{source.description}</p>
                      <p className="mt-1 text-xs text-muted">
                        Licence: {source.licence} ·{' '}
                        <a
                          href={source.homepage}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="underline"
                        >
                          source
                        </a>
                      </p>
                      {source.pulled ? (
                        <p className="mt-1 text-xs text-muted">
                          {source.files} file(s), pulled{' '}
                          {source.pulled_at ? new Date(source.pulled_at).toLocaleString() : ''}
                          {source.rejected.length > 0
                            ? ` · ${source.rejected.length} file(s) left out`
                            : ''}
                          {source.archive_sha256
                            ? ` · sha256 ${source.archive_sha256.slice(0, 12)}…`
                            : ''}
                        </p>
                      ) : null}
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        icon={<Download className="h-4 w-4" aria-hidden />}
                        disabled={!data.pull_enabled || busy}
                        loading={busy && data.status.source === source.id}
                        onClick={() => pull.mutate(source.id)}
                      >
                        {source.pulled ? 'Update' : 'Pull'}
                      </Button>
                      {source.pulled ? (
                        <>
                          <Button
                            onClick={() =>
                              toggle.mutate({ id: source.id, enabled: !source.enabled })
                            }
                          >
                            {source.enabled ? 'Disable' : 'Enable'}
                          </Button>
                          <Button
                            aria-label={`Remove ${source.label}`}
                            icon={<Trash2 className="h-4 w-4" aria-hidden />}
                            onClick={() => remove.mutate(source.id)}
                          />
                        </>
                      ) : null}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
    </div>
  );
}
