# REST API and MCP

[Documentation](README.md) · [Users, rights and authentication](users-and-rights.md)

Everything the interface does is a REST endpoint. The interface has no privileged path of
its own, so anything an analyst can do by hand, a script can do with their token.

## Authenticating a script

Create a personal token under **My access**. It acts as you, with exactly your
permissions, and it is shown once.

```bash
curl -s https://xenoproxy.example.org/api/v1/jobs \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Requested-With: XMLHttpRequest'
```

Writing calls also take an `Idempotency-Key` header: the same key with the same body
returns the stored response instead of submitting twice, which is what makes a retry safe.

## Endpoints

| Method | Path | Permission | Description |
|---|---|---|---|
| POST | `/api/v1/auth/login` | public | Sign in with a local account |
| GET | `/api/v1/auth/oidc/start` | public | Begin single sign-on |
| POST | `/api/v1/jobs/preview` | `jobs:read` | Classify an observable and list what can run on it |
| POST | `/api/v1/jobs` | `jobs:write` | Submit a scan |
| GET | `/api/v1/jobs` | `jobs:read` | Team history, filtered and paginated |
| GET | `/api/v1/jobs/results` | `jobs:read` | The same filters, each job with its plugins' normalised outcomes (bulk pull) |
| GET | `/api/v1/jobs/{id}` | `jobs:read` | One job with every report |
| GET | `/api/v1/jobs/{id}/events` | `jobs:read` | Live progress (server-sent events) |
| GET | `/api/v1/jobs/{id}/export?format=json\|markdown` | `jobs:export` | Export a report |
| GET | `/api/v1/jobs/{id}/children` | `jobs:read` | Jobs a pivot derived from this one |
| GET | `/api/v1/jobs/{id}/recap` | `jobs:read` | Facts (network, certificates, registration), per-source verdicts and the relation graph of the job and its pivots |
| GET | `/api/v1/jobs/{id}/detection-graph` | `jobs:read` | Alpha. What each analyzer found and the chain of pivots and lookups that led to it: every node has a `layer` (hops from the observable) and a `via` (the edge that reached it, with the source plugin). Built from stored reports, no provider call |
| POST | `/api/v1/jobs/{id}/kill` | `jobs:write` | Stop a running job at its next checkpoint |
| POST | `/api/v1/jobs/{id}/reports/{report_id}/retry` | `jobs:write` | Re-run one failed, killed or skipped plugin |
| POST | `/api/v1/reports/search` | `jobs:read` | Query inside the raw payloads |
| GET | `/api/v1/stats/service?days=N` | `jobs:read` | Service statistics over a window |
| GET | `/api/v1/plugins?plugin_type=analyzer\|connector\|pivot` | `analyzers:read` | Plugin catalogue |
| PUT | `/api/v1/me/plugin-config/{name}/secrets/{secret}` | `analyzers:read` | Store your own credential for a plugin |
| PUT | `/api/v1/admin/plugins/{name}/secrets/{secret}` | `secrets:manage` | Store an instance credential (write-only) |
| PATCH | `/api/v1/admin/plugins/{name}` | `analyzers:manage` | Enable, timeout, cache window, options |
| POST | `/api/v1/admin/plugins/{name}/healthcheck` | `analyzers:manage` | Probe whether the provider answers |
| POST | `/api/v1/admin/plugin-packages` | `plugins:manage` | Install a plugin package from a zip |
| GET | `/api/v1/admin/settings` | `settings:manage` | Every scalar setting and every section |
| PUT | `/api/v1/admin/settings/sections/{name}` | `settings:manage` | Save one section |
| POST | `/api/v1/admin/settings/sections/{name}/test` | `settings:manage` | Probe a section, saved or not |
| GET | `/api/v1/admin/settings/export` | `settings:manage` | Export the configuration, without secrets |
| POST | `/api/v1/assistant/conversations/{id}/ask` | `jobs:read` | One assistant turn, tools included |
| GET | `/api/v1/admin/audit/verify` | `audit:read` | Verify the audit hash chain |

The full specification is at `/api/openapi.json`, served on a development instance only —
`BACKEND_ENVIRONMENT=development`.

## Filtering the job history

`GET /api/v1/jobs` and `GET /api/v1/jobs/results` take the same filters, combined with AND:

| Parameter | Meaning |
|---|---|
| `search` | Part of the observable value |
| `observable_type` | `ip`, `domain`, `url`, `hash`, `file`, `generic` |
| `status`, `verdict`, `tlp`, `origin` | Job status, verdict, TLP, entry point (`ui`, `api`, `assistant`, `mcp`, `pivot`) |
| `requested_by` | Username of the submitter |
| `tag` | A tag on the job |
| `derived` | `true` for pivot-derived jobs only, `false` for the others |
| `created_from`, `created_to` | ISO 8601 bounds, inclusive. A date without a zone is read as UTC |
| `plugin` | Only jobs where this analyzer, connector or pivot ran |
| `plugin_status` | With `plugin`: only jobs where that plugin ended in this status (`SUCCESS`, `FAILED`, …) |
| `order` | `desc` (default, newest first) or `asc` |
| `page`, `page_size` | Pagination, `page_size` up to 100 |

`/api/v1/jobs/results` embeds each job's reports with their normalised `summary_data`, status
and errors, but not the raw provider payloads. When `plugin` is set, only that plugin's reports
are embedded. Fetch a raw payload with `/api/v1/jobs/{id}/reports/{plugin}/raw`.

```bash
curl -s "https://xenoproxy.example.org/api/v1/jobs/results?created_from=2026-11-01T00:00:00Z&plugin=shodan&plugin_status=SUCCESS&requested_by=<username>&page_size=100" \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Requested-With: XMLHttpRequest'
```

A token only sees what its account can see: jobs at CLEAR or GREEN, plus those shared with
its groups, and everything for an administrator.

## Searching inside the payloads

Every report keeps the provider's raw JSON alongside the normalised summary, and
`POST /api/v1/reports/search` queries inside it. That is how you answer a question the
interface does not have a field for — "which jobs saw this certificate fingerprint", "every
host that answered on port 8443" — without re-running a single source.

## Public submission (optional, no account)

When the deployment sets `BACKEND_PUBLIC_SUBMISSION_ENABLED=true`, anyone who can reach
the API may submit an IP, domain, URL or hash without signing in. Otherwise both routes
answer `404`.

- `POST /api/v1/public/submissions` with `{"value": "..."}` returns `201` and the job's
  public view. Each caller is limited to 10 submissions per hour per client address.
- `GET /api/v1/public/submissions/{id}` returns the same view later, as the analysis
  completes. The random job identifier is the only key.

The route always runs the `Public submission` playbook at TLP:CLEAR. A caller cannot
choose sources, connectors or pivots, and private addresses are refused. Each source is
shared the observable, so the instance's quotas are spent on the public's behalf.

The public view holds the observable, the verdict, the status of each source and its
verdict. It does not hold the requester, groups, raw responses or stored paths.
Signed-in users see public jobs in the history with the `public` origin.

## MCP servers

Two Model Context Protocol servers, JSON-RPC 2.0 over Streamable HTTP, both off by default
and enabled under **Settings › MCP**.

| Endpoint | For | Tools |
|---|---|---|
| `/api/v1/mcp/user` | Analysis | Submit scans, read jobs and reports, search payloads |
| `/api/v1/mcp` | Administration | The analysis tools, plus plugins, settings, users, groups and audit |

Both authenticate with an API token and go through the same authorization as the REST API.
**Neither elevates.** The admin server additionally checks an allow-list of usernames and
honours a read-only mode, so you can expose administration to an agent without granting
it write access.

Every tool call is audited: the token, the tool, its arguments with secrets masked, the
status and the duration.
