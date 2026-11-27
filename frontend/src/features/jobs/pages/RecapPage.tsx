/**
 * Investigation recap: everything the analysis established about one observable.
 *
 * Built by the server from the stored summaries, so opening it costs no quota.
 * The sections follow the questions an analyst asks in order: what is it, where
 * does it sit on the network, what certificates does it present, who registered
 * it, what did each source say, and how do the pieces connect.
 */

import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Globe, KeyRound, MapPin, Network, ScrollText, Server } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import { Badge, Card, EmptyState, ErrorBanner, Skeleton, Stat } from '@/components/ui';
import { JobStatusBadge, ReportStatusBadge, VerdictBadge } from '@/components/ui/verdict';
import { ApiError } from '@/lib/api-client';
import { formatDateTime } from '@/lib/format';
import { jobsApi } from '../api';
import type { Recap } from '../api';
import { RelationGraph } from '../components/RelationGraph';

function ValueList({ values, empty = 'None found.' }: { values: string[]; empty?: string }) {
  if (values.length === 0) {
    return <p className="text-sm text-muted">{empty}</p>;
  }
  return (
    <ul className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <li
          key={value}
          className="break-all rounded-md border border-border bg-surface-sunken px-2 py-0.5 font-mono text-xs"
        >
          {value}
        </li>
      ))}
    </ul>
  );
}

function Labelled({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="mb-1.5 text-xs font-medium text-faint">{label}</h3>
      {children}
    </div>
  );
}

function SubjectSection({ recap }: { recap: Recap }) {
  const { subject } = recap;
  return (
    <Card
      title={subject.observable_value}
      description={`${subject.observable_type.toUpperCase()} · requested by ${subject.requested_by_name} · ${formatDateTime(subject.created_at)}`}
      actions={<VerdictBadge verdict={subject.verdict} />}
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Job status" value={<JobStatusBadge status={subject.status} />} />
        <Stat label="Pivot jobs" value={subject.jobs - 1} hint="Derived from this observable" />
        <Stat label="Reports" value={subject.reports} hint="Across the whole tree" />
        <Stat label="TLP" value={subject.tlp.toUpperCase()} />
      </div>
      {subject.tags.length > 0 ? (
        <div className="mt-4 flex flex-wrap gap-1.5">
          {subject.tags.map((tag) => (
            <Badge key={tag}>{tag}</Badge>
          ))}
        </div>
      ) : null}
    </Card>
  );
}

function NetworkSection({ recap }: { recap: Recap }) {
  const { network } = recap;
  return (
    <Card title="Network" icon={<Network className="h-4 w-4" aria-hidden />}>
      <div className="grid gap-5 md:grid-cols-2">
        <Labelled label="Addresses">
          <ValueList values={network.ips} />
        </Labelled>
        <Labelled label="Domains">
          <ValueList values={network.domains} />
        </Labelled>
        <Labelled label="Autonomous systems">
          <ValueList values={network.asns} />
        </Labelled>
        <Labelled label="Countries">
          <ValueList values={network.countries} />
        </Labelled>
        <Labelled label="Cities">
          <ValueList values={network.cities} />
        </Labelled>
        <Labelled label="Open ports">
          <ValueList values={network.ports} />
        </Labelled>
        <Labelled label="Technologies">
          <ValueList values={network.technologies} />
        </Labelled>
        <Labelled label="Known CVEs">
          <ValueList values={network.cves} />
        </Labelled>
      </div>
    </Card>
  );
}

function CertificateSection({ recap }: { recap: Recap }) {
  const { certificates } = recap;
  return (
    <Card title="Certificates" icon={<KeyRound className="h-4 w-4" aria-hidden />}>
      <div className="grid gap-5 md:grid-cols-2">
        <Labelled label="Names certified">
          <ValueList values={certificates.names} />
        </Labelled>
        <Labelled label="Issuers">
          <ValueList values={certificates.issuers} />
        </Labelled>
      </div>
      {certificates.certificates.length > 0 ? (
        <div className="mt-5 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-faint">
              <tr>
                <th className="py-1 pr-3 font-medium">Subject</th>
                <th className="py-1 pr-3 font-medium">Issuer</th>
                <th className="py-1 pr-3 font-medium">Valid from</th>
                <th className="py-1 font-medium">Valid until</th>
              </tr>
            </thead>
            <tbody>
              {certificates.certificates.map((cert, index) => (
                <tr key={`${String(cert.label)}-${index}`} className="border-t border-border-subtle">
                  <td className="break-all py-1 pr-3 font-mono">{String(cert.label)}</td>
                  <td className="break-all py-1 pr-3">{String(cert.issuer ?? '—')}</td>
                  <td className="py-1 pr-3">{String(cert.not_before ?? cert.validity ?? '—')}</td>
                  <td className="py-1">{String(cert.not_after ?? '—')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </Card>
  );
}

function RegistrationSection({ recap }: { recap: Recap }) {
  const { registration } = recap;
  return (
    <Card title="Registration" icon={<ScrollText className="h-4 w-4" aria-hidden />}>
      <div className="grid gap-5 md:grid-cols-3">
        <Labelled label="Registrar">
          <ValueList values={registration.registrars} />
        </Labelled>
        <Labelled label="Abuse contacts">
          <ValueList values={registration.contacts} />
        </Labelled>
        <Labelled label="Prefixes">
          <ValueList values={registration.prefixes} />
        </Labelled>
      </div>
    </Card>
  );
}

function VerdictsSection({ recap }: { recap: Recap }) {
  if (recap.verdicts.length === 0) {
    return (
      <EmptyState
        icon={<Server className="h-5 w-5" aria-hidden />}
        title="No source has reported"
        description="Nothing in this investigation has finished yet."
      />
    );
  }
  return (
    <Card title="Per-source verdicts" icon={<Globe className="h-4 w-4" aria-hidden />}>
      <ul className="divide-y divide-border-subtle">
        {recap.verdicts.map((line) => (
          <li key={`${line.job_id}-${line.plugin_name}`} className="py-3 first:pt-0 last:pb-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium">{line.plugin_name}</span>
              <Badge>{line.plugin_type}</Badge>
              <ReportStatusBadge status={line.status} />
              <Badge tone={line.verdict === 'malicious' ? 'danger' : 'neutral'}>
                {line.verdict}
              </Badge>
              {line.detection_ratio ? (
                <span className="font-mono text-xs text-muted">{line.detection_ratio}</span>
              ) : null}
            </div>
            {line.headline ? <p className="mt-1 text-sm text-muted">{line.headline}</p> : null}
            <div className="mt-1.5 flex flex-wrap gap-3 text-xs">
              <Link
                to={`/jobs/${line.job_id}`}
                className="text-primary hover:underline"
              >
                {line.observable_value}
              </Link>
              {line.links.map((link) =>
                link.url ? (
                  <a
                    key={link.url}
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    {link.label ?? link.url}
                  </a>
                ) : null,
              )}
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}

export function RecapPage() {
  const { jobId = '' } = useParams();

  const query = useQuery({
    queryKey: ['job', jobId, 'recap'],
    queryFn: () => jobsApi.recap(jobId),
    enabled: jobId.length > 0,
  });

  if (query.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-32" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (query.error || !query.data) {
    return (
      <ErrorBanner
        message={query.error instanceof ApiError ? query.error.message : 'The recap could not be loaded.'}
        requestId={query.error instanceof ApiError ? query.error.requestId : undefined}
        onRetry={() => void query.refetch()}
      />
    );
  }

  const recap = query.data;
  return (
    <div>
      <PageHeader
        breadcrumb={['Home', 'Jobs', recap.subject.observable_value, 'Recap']}
        title={`Recap of ${recap.subject.observable_value}`}
        description="Facts established by every finished source in this investigation."
        actions={
          <Link
            to={`/jobs/${jobId}`}
            className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
          >
            <ArrowLeft className="h-4 w-4" aria-hidden />
            Back to the job
          </Link>
        }
      />

      <div className="space-y-5">
        <SubjectSection recap={recap} />
        <NetworkSection recap={recap} />
        <CertificateSection recap={recap} />
        <RegistrationSection recap={recap} />
        <VerdictsSection recap={recap} />
        <Card title="Relations" icon={<MapPin className="h-4 w-4" aria-hidden />}>
          <RelationGraph graph={recap.graph} />
        </Card>
      </div>
    </div>
  );
}
