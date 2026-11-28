/** Embedded help: a condensed version of docs/help, kept in step by hand. */

import { PageHeader } from './AppShell';
import { Card } from '@/components/ui';

const SECTIONS: { title: string; body: string[] }[] = [
  {
    title: 'Submitting a scan',
    body: [
      'Paste an observable in New scan. XenoProxy classifies it as an IP address, domain, URL, hash or generic value while you type, and refangs defanged input such as 1.1.1[.]1 or hxxps://example[.]com.',
      'Only sources that support the detected type, are enabled and have their credentials configured are offered. Pick individual analyzers, or a playbook that groups them.',
      'Analyses run in the background and in parallel. The job page updates itself until every source has finished.',
    ],
  },
  {
    title: 'Cache and quotas',
    body: [
      'A successful result is reused for the same observable and source inside that source’s cache window, which spares the external API quota. Reused reports are marked "from cache".',
      'Tick "Force a refresh" to query every source again. Use it when you need fresh data, not by default.',
    ],
  },
  {
    title: 'Reading a job',
    body: [
      'The banner shows the aggregated verdict: the worst verdict any source reported. Open the per-source tabs for the normalised summary and the raw provider payload.',
      'A source that fails, times out or hits its quota is reported as Failed on its own tab. The rest of the job still completes, and the job status becomes Partial.',
      'Export the job as JSON for tooling, or as Markdown for an incident write-up.',
    ],
  },
  {
    title: 'For administrators',
    body: [
      'Admin, Plugins & keys is where API credentials are stored. A credential is sealed in the backend vault; afterwards only its last four characters are ever shown.',
      'A source cannot be enabled until its required credentials are present. Deleting a required credential disables the source.',
      'Timeouts, cache lifetime and per-source options are set on the same page. Every change is written to the audit trail.',
    ],
  },
  {
    title: 'Adding a source (administrators)',
    body: [
      'Admin, Plugins installs an analyzer without rebuilding the image: upload a zip holding a plugin.json manifest, or copy the folder into the plugins volume and press Rescan.',
      'The archive is checked before anything is written, and a plugin cannot take the name of a built-in analyzer. A plugin runs with the backend’s privileges, so read its code and only accept plugins from a source you trust; every installation is audited with the archive digest.',
      'The format and a working example are in docs/plugin-example in the repository.',
    ],
  },
  {
    title: 'Analysing a file',
    body: [
      'On New scan, "Analyse a file instead" takes a sample from your machine. A password-protected archive is opened only to hash what is inside, and the conventional passwords such as infected are tried for you.',
      'Every file is also read on the instance: hashes, real format, entropy and a first-minute triage of what looks suspicious (alpha). Nothing is run and nothing leaves, at any TLP level. It never changes the verdict. "No static indicator" is not "safe".',
      'The file itself is not sent to providers unless an administrator allowed it; only its hashes are.',
    ],
  },
  {
    title: 'Using the API from a script',
    body: [
      '1. Create a token in My access (shown once, expires after a year, acts with your permissions) and send it as Authorization: Bearer <token>. No other header is needed.',
      '2. Submit: POST /api/v1/jobs with {"observable": "1.1.1[.]1", "playbook": "Fast IP triage", "tags": [...], "tlp": "AMBER"}. Only observable is required. Add an Idempotency-Key header so a retry cannot create a second job. For a file: POST /api/v1/jobs/file as multipart with file, and optionally options (JSON) and archive_password.',
      '3. Wait: GET /api/v1/jobs/{id} every few seconds while status is PENDING or RUNNING. It is finished at SUCCESS, PARTIAL_FAILURE, FAILED or KILLED.',
      '4. Read: the job holds verdict (clean, suspicious, malicious, unknown) and a report per source. GET /api/v1/jobs/{id}/reports/{plugin}/raw gives one raw payload, and /export?format=markdown a write-up.',
      '5. In bulk: GET /api/v1/jobs/results filters by verdict, tag, plugin, date, origin or submitter and returns each source’s outcome, 100 jobs per page.',
      'A 429 means the rate limit was reached: wait and retry with the same Idempotency-Key. Full recipes with curl and Python are in docs/help/analyst.md and docs/api.md.',
    ],
  },
  {
    title: 'Public submission (administrators)',
    body: [
      'Public mode lets anyone who can reach the API submit an IP, domain, URL or hash without an account, through POST /api/v1/public/submissions with {"value": "..."}. Read the result back with GET /api/v1/public/submissions/{id}. While it is off both routes answer 404.',
      'It can only be turned on from the environment: set XENOPROXY_PUBLIC_SUBMISSION=true in the .env file beside docker-compose.yml, then run docker compose up -d api. Remove it to turn it off.',
      'Public jobs always use the Public submission playbook at TLP:CLEAR, are limited to 10 per hour per client address, and spend your own source quotas. Trim that playbook in Admin, Playbooks, and set BACKEND_TRUSTED_PROXY_COUNT behind a reverse proxy. Public jobs show in the history with the origin public.',
    ],
  },
];

export function HelpPage() {
  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        breadcrumb={['Home', 'Help']}
        title="Help"
        description="How to use XenoProxy day to day."
      />
      <div className="space-y-3">
        {SECTIONS.map((section) => (
          <Card key={section.title} title={section.title}>
            {section.body.map((paragraph) => (
              <p key={paragraph.slice(0, 32)} className="mb-2 text-sm last:mb-0">
                {paragraph}
              </p>
            ))}
          </Card>
        ))}
      </div>
    </div>
  );
}
