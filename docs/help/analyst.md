# Using XenoProxy

## Running a scan

1. Open **New scan** and paste the observable. XenoProxy classifies it as you type and
   refangs defanged input, so `1.1.1[.]1` and `hxxps://example[.]com` work as pasted.
2. Pick a **playbook** for a ready-made pipeline, or tick individual analyzers.
   Only sources that support the detected type, are enabled and have their
   credentials configured are offered; the rest are listed under "not available
   yet" with the reason.
3. Optionally open **After the analysis**. Nothing there runs unless you pick it:
   - a **connector** publishes the finished job to another platform, so the
     observable, its verdict and its tags leave XenoProxy;
   - a **pivot** analyses what it derives from this job — the domain behind a
     flagged URL, the addresses a bad domain resolves to — by creating a child
     job for each. It only acts on a suspicious or malicious verdict.

   A playbook may already include either; the card says so.
4. Add tags if the job belongs to an incident. They make it findable later.
5. Tick **Force a refresh** only when you need fresh data: it bypasses the cache
   and spends an API quota on every selected source.
6. Tick **Send every request through a proxy** (off by default, shown only when the
   administrator configured proxy profiles) and pick the profiles. Several profiles are
   spread over the analyzers; one profile carries everything. Page captures are not covered.
7. Run the analysis. The job page updates itself until every plugin finishes.
   **Stop** halts a run you launched by mistake: nothing further starts, and the
   results already in are kept.

## Reading a result

The banner shows the aggregated verdict, which is the worst verdict any
**analyzer** reported, with the open ports, CVEs, geolocation and networks found
across all sources. Exports and pivots do not vote: "published successfully"
says nothing about whether the address is malicious.

The overview groups the reports by phase — Analyzers, then Exports, then Pivots
— in the order they ran. Each plugin also has its own tab with the normalised
summary and the raw provider payload underneath.

A plugin marked **Failed** did not answer: no credential, a timeout, or the
provider's quota. The rest of the job is unaffected and the job shows as
*Partial*. **Retry** re-runs that one plugin without touching the others or
spending their quota again. A source marked **cache** reused an earlier
identical lookup.

A plugin marked **Skipped** declined, and says why: an export whose verdict
floor was not met, or a pivot on a clean result.

### Following an investigation

When a pivot created child jobs, the Pivots tab lists what it derived and links
to each child, and a **Child jobs** card summarises them. A child job carries a
banner back to its parent and the name of the pivot that produced it, so you can
walk the investigation in either direction.

## Exporting

**JSON** contains everything, including raw payloads, and is meant for tooling.
**Markdown** is a readable incident write-up. Both are listed in the audit trail.

## Using the API from a script

Everything the interface does is available over HTTP. The recipes below use `curl`; replace
`$HOST` with your instance's address and `$TOKEN` with your token.

### 1. Get a token

Open **My access**, create a token and copy it: it is shown once. It starts with
`xenoproxy_`, acts as you with your own permissions, expires after a year by default and
can be revoked at any time. Send it on every call:

```bash
export HOST=https://xenoproxy.example.org
export TOKEN=xenoproxy_...
curl -s "$HOST/api/v1/jobs?page_size=5" -H "Authorization: Bearer $TOKEN"
```

No other header is needed with a token.

### 2. Submit an analysis

```bash
curl -s -X POST "$HOST/api/v1/jobs"   -H "Authorization: Bearer $TOKEN"   -H "Idempotency-Key: $(uuidgen)"   -H 'Content-Type: application/json'   -d '{"observable": "1.1.1[.]1", "playbook": "Fast IP triage", "tags": ["incident-42"], "tlp": "AMBER"}'
```

The answer is `201` with the job and its `id`. Only `observable` is required.

| Field | Meaning |
|---|---|
| `observable` | IP, domain, URL, hash or generic value. Defanged input is accepted |
| `playbook` | A playbook name: a ready-made set of sources |
| `analyzers`, `connectors`, `pivots` | Names to run. `plugins` takes names of any kind |
| `tags` | Up to 20 tags |
| `tlp` | `CLEAR`, `GREEN`, `AMBER` or `RED`: caps what may touch the observable |
| `scan_mode` | `force_new` to bypass the cache, like **Force a refresh** |
| `through_proxy` | `true` sends every request of the job through proxy profiles (default `false`) |
| `proxy_profiles` | names of the profiles to use; empty with `through_proxy` means all of them, spread per analyzer. Under TLP:RED only profiles approved for RED are accepted |
| `runtime_configuration` | Option overrides for this job only, keyed by plugin name |

With neither `playbook` nor `analyzers`, every analyzer that supports the type runs.
Connectors and pivots are never implied: naming one is what turns it on.
List what exists with `GET /api/v1/plugins` and `POST /api/v1/jobs/preview`.

The `Idempotency-Key` makes a retry safe: the same key with the same body returns the
first answer instead of creating a second job. Use a fresh key for each new analysis.

### 3. Submit a file

```bash
curl -s -X POST "$HOST/api/v1/jobs/file"   -H "Authorization: Bearer $TOKEN"   -F file=@sample.zip   -F archive_password=infected   -F 'options={"tlp": "RED", "tags": ["incident-42"]}'
```

The form carries `file` (up to 20 MiB by default), `options` (the same JSON as above, optional) and
`archive_password` (optional). The file's SHA-256 becomes the observable, and the job's
`sample` holds the hashes and the static inspection. The file is never sent to a provider
unless an administrator allowed it.

### 4. Wait for the result

A job is finished when `status` is `SUCCESS`, `PARTIAL_FAILURE` (some sources failed),
`FAILED` or `KILLED`. Poll until then:

```bash
while :; do
  S=$(curl -s "$HOST/api/v1/jobs/$ID" -H "Authorization: Bearer $TOKEN" | jq -r .status)
  case "$S" in PENDING|RUNNING) sleep 3;; *) break;; esac
done
echo "$S"
```

A pushed stream is also available at `GET /api/v1/jobs/{id}/events` (server-sent events).

### 5. Read the result

```bash
# Verdict and status at a glance
curl -s "$HOST/api/v1/jobs/$ID" -H "Authorization: Bearer $TOKEN"   | jq '{status, verdict, tlp, sources: [.reports[] | {plugin: .plugin_name, status, verdict: .summary_data.verdict}]}'

# One source's raw provider payload
curl -s "$HOST/api/v1/jobs/$ID/reports/virustotal/raw" -H "Authorization: Bearer $TOKEN"

# A report to attach to a ticket
curl -s "$HOST/api/v1/jobs/$ID/export?format=markdown" -H "Authorization: Bearer $TOKEN"
```

`verdict` is `clean`, `suspicious`, `malicious` or `unknown`: the worst one any analyzer
reported. `GET /api/v1/jobs/{id}/recap` gives the facts and the relation graph, and
`/children` lists the jobs a pivot created.

### 6. Pull results in bulk

`GET /api/v1/jobs/results` returns many jobs with each source's normalised outcome, without
the raw payloads. It takes the same filters as the history and `page_size` up to 100:

```bash
# Everything malicious since 1 November, from Shodan, as a table
curl -s "$HOST/api/v1/jobs/results?verdict=malicious&created_from=2026-11-01T00:00:00Z&plugin=shodan&page_size=100"   -H "Authorization: Bearer $TOKEN"   | jq -r '.items[] | [.observable_value, .verdict, .created_at] | @tsv'
```

Useful filters: `search`, `observable_type`, `status`, `verdict`, `tlp`, `tag`,
`origin`, `requested_by`, `plugin`, `plugin_status`, `created_from`, `created_to`, `order`,
`page`. A token only sees what its account can see.

### A complete script in Python

```python
import os, time, requests

host = os.environ["HOST"]
http = requests.Session()
http.headers["Authorization"] = f"Bearer {os.environ['TOKEN']}"

job = http.post(f"{host}/api/v1/jobs", json={"observable": "example.com"},
                headers={"Idempotency-Key": "example-com-2026-11-28"}).json()

while job["status"] in ("PENDING", "RUNNING"):
    time.sleep(3)
    job = http.get(f"{host}/api/v1/jobs/{job['id']}").json()

print(job["verdict"], [(r["plugin_name"], r["status"]) for r in job["reports"]])
```

### When it goes wrong

| Answer | Meaning |
|---|---|
| `401` | Missing, revoked or expired token |
| `403` | Your role lacks the permission |
| `404` | Unknown job, a job you may not see, or a route that is disabled (public mode) |
| `422` | The body is invalid; the answer names the field |
| `429` | Rate limit reached (60 submissions a minute): wait, then retry with the same `Idempotency-Key` |

### Without an account: public mode

If your administrator enabled it, an IP, domain, URL or hash can be submitted with no token:

```bash
curl -s -X POST "$HOST/api/v1/public/submissions"   -H 'Content-Type: application/json' -d '{"value": "example.com"}'
curl -s "$HOST/api/v1/public/submissions/$ID"
```

It always runs a fixed set of sources at TLP:CLEAR and returns the verdict and each source's
verdict, with a limit of 10 submissions an hour per address. A `404` means public mode is off.
Signed-in users find these jobs in the history with the origin `public`.

## Keyboard

`Ctrl+K` or `/` focuses the search, `Esc` closes a dialog, `Enter` submits a form.


## Analysing a file

On the scan page, **Analyse a file instead** takes a sample from your machine.
Its SHA-256 is computed in your browser and fills the observable field, so the
file is classified, matched against playbooks and offered the same hash sources
as a digest you typed — and you can see at once whether the team has looked at
this sample before.

### A sample in a password-protected archive

A sample normally arrives zipped with a password — `infected` by convention —
so that nothing opens it by accident on the way. Drop the archive in as it is.
XenoProxy opens it **only to hash what is inside**: nothing is extracted, and
the job is about the file inside, which is what you actually want looked up.
The archive is kept as context, with the hashes of everything it held.

The conventional passwords are tried automatically. An unusual one goes in the
password field beside the file, or in **Settings › Scanning** for a password
your team uses regularly.

An archive holding several files keeps its own digest as the observable, and
lists the inner hashes for you to pick from — guessing which one you meant
would be worse than saying so. An archive inside an archive is not opened.

### File inspection (alpha)

Every file is also read on the instance, in a few seconds, and the job page shows
a **File inspection** card: MD5, SHA-1 and SHA-256, the real format (from the bytes,
not the name), size, entropy, how many times the team has submitted it, and what
the reading found. Nothing is run and nothing leaves the instance, so it applies
at every TLP level, RED included.

It looks for what a first-minute triage looks for:

- a name that lies: wrong extension for the content, `invoice.pdf.exe`, or a
  right-to-left override character;
- packed or encrypted content (near-random bytes);
- in a Windows executable: sections that are both writable and executable,
  process-injection and download APIs, a compile date in the future;
- in a PDF: launch actions and JavaScript that runs on open;
- in an Office file: macros that run on open and what they call;
- in a script: encoded commands, run-a-string-as-code and download calls;
- in an archive: names that escape the folder, password-protected members,
  executables, a compression ratio typical of a bomb. The files inside are read in
  memory, one level deep, and listed with their own findings.

Findings come in four levels (info, notice, warning, alert). A warning or an alert
makes the inspection **suspicious**. It never says malicious, and it **does not change
the job's verdict or its Xeno-score**: a static heuristic misfires on legitimate
software, so only a YARA match or a provider decides that.

"No static indicator" is not "safe". A packed file hides its imports, a PDF can
keep its actions in compressed streams, and a password-protected member cannot be
read at all. This is triage, not a sandbox. A file recorded before this feature
existed shows as not inspected.

### Whether the file itself leaves

By default **it does not**. Only the hashes are sent to providers, which
identify the sample without disclosing it. A sandbox that would submit the file
reports that it could not run, rather than quietly returning "nothing found"
from a detonation that never happened.

An administrator can allow it in **Settings › Scanning**. It is off by default
because a file under investigation may be confidential, and sending it to a
third party cannot be taken back.

The bytes are stored with the job so a sandbox can submit the sample where that
is allowed. They are never served back: there is no download, which is what
keeps a stored sample from becoming a way to hand malware to a browser.
