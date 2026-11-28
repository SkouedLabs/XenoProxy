/**
 * The record of a submitted file and what a static inspection found in it.
 *
 * The inspection reads the bytes and never runs them. "No indicator" is not
 * "safe": a packed or password-protected file hides its content, and the card
 * says so rather than showing a reassuring green.
 */

import { FileSearch } from 'lucide-react';

import { Badge, Card } from '@/components/ui';
import { formatRelative } from '@/lib/format';
import type {
  InspectionFinding,
  InspectionSeverity,
  SampleRecord,
} from '@/lib/types';

const TONE: Record<InspectionSeverity, 'danger' | 'warning' | 'info' | 'neutral'> = {
  alert: 'danger',
  warning: 'warning',
  notice: 'info',
  info: 'neutral',
};

const ORDER: InspectionSeverity[] = ['alert', 'warning', 'notice', 'info'];

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function Finding({ finding }: { finding: InspectionFinding }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      <Badge tone={TONE[finding.severity]}>{finding.severity}</Badge>
      <span className="min-w-0 break-words">
        {finding.member ? <span className="font-mono text-muted">{finding.member}: </span> : null}
        {finding.message}
      </span>
    </li>
  );
}

function Hash({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs uppercase tracking-wide text-muted">{label}</dt>
      <dd className="break-all font-mono text-xs">{value}</dd>
    </div>
  );
}

export function SampleCard({ sample }: { sample: SampleRecord }) {
  const inspection = sample.details.inspection;
  const findings = [...(inspection?.findings ?? [])].sort(
    (a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity),
  );
  const verdictTone =
    inspection?.verdict === 'suspicious'
      ? 'warning'
      : inspection?.verdict === 'clean'
        ? 'success'
        : 'neutral';

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <FileSearch className="h-4 w-4 text-muted" aria-hidden />
          File inspection
          <Badge tone="warning">alpha</Badge>
        </span>
      }
      description="Read from the file's bytes on this instance. Nothing is run, and nothing leaves."
      className="mb-4"
    >
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
        <Badge tone="primary">{sample.kind}</Badge>
        <span className="text-muted">{sample.mime}</span>
        <span className="text-muted">· {size(sample.size)}</span>
        <span className="text-muted">· entropy {sample.entropy}</span>
        {sample.extension_mismatch ? <Badge tone="warning">name does not match content</Badge> : null}
        {inspection ? (
          <Badge tone={verdictTone}>
            {inspection.verdict === 'clean' ? 'no static indicator' : inspection.verdict}
          </Badge>
        ) : null}
      </div>

      <dl className="mb-3 grid gap-2 md:grid-cols-3">
        <Hash label="MD5" value={sample.md5} />
        <Hash label="SHA-1" value={sample.sha1} />
        <Hash label="SHA-256" value={sample.sha256} />
      </dl>

      <p className="mb-3 text-xs text-muted">
        Submitted {sample.submission_count} time{sample.submission_count === 1 ? '' : 's'}; first{' '}
        {formatRelative(sample.first_submitted_at)} by {sample.first_submitted_by}, last{' '}
        {formatRelative(sample.last_submitted_at)}.
      </p>

      {!inspection ? (
        <p className="text-sm text-muted">
          This file was recorded before inspection existed, so it has not been inspected.
        </p>
      ) : findings.length === 0 ? (
        <p className="text-sm text-muted">
          No static indicator. That is not a statement that the file is safe: packed,
          encrypted or compressed content cannot be read here.
        </p>
      ) : (
        <ul className="space-y-1.5">
          {findings.map((finding, index) => (
            <Finding key={`${finding.code}-${finding.member ?? ''}-${index}`} finding={finding} />
          ))}
        </ul>
      )}

      {inspection && inspection.members.length > 0 ? (
        <div className="mt-4">
          <h4 className="mb-1 text-xs uppercase tracking-wide text-muted">
            Archive contents ({inspection.members.length})
          </h4>
          <ul className="divide-y divide-border rounded-md border border-border text-sm">
            {inspection.members.map((member, index) => (
              <li key={`${member.name}-${index}`} className="flex flex-wrap items-center gap-2 px-3 py-1.5">
                <span className="min-w-0 flex-1 break-all font-mono text-xs">{member.name}</span>
                {member.kind ? <Badge tone="neutral">{member.kind}</Badge> : null}
                {typeof member.size === 'number' ? (
                  <span className="text-xs text-muted">{size(member.size)}</span>
                ) : null}
                {member.skipped ? (
                  <span className="text-xs text-muted">not read: {member.skipped}</span>
                ) : member.verdict ? (
                  <Badge tone={member.verdict === 'suspicious' ? 'warning' : 'neutral'}>
                    {member.verdict}
                  </Badge>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  );
}
