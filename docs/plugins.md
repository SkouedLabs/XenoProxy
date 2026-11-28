# Plugins and playbooks

[Documentation](README.md) · [Functional specification](specification.md) · [Writing a plugin](plugin-example/README.md)

A plugin's type is declared on its class and decides which phase of a job runs it.

| Type | When it runs | What it does |
|---|---|---|
| **Analyzer** | The analysis phase, in parallel | Enriches the observable from one source |
| **Connector** | After the analysis, on the finished job | Publishes the result, or judges it |
| **Pivot** | Last, on a suspicious or malicious verdict | Derives the next observable and creates a child job |

Connectors and pivots are never selected automatically: one sends data to a third party,
the other creates more jobs. Both have to be chosen.

## Analyzers

Twenty-two, of which ten need no credential and are enabled from the start.

### Keyless, and enabled from the start

| Plugin | Observables | What it adds |
|---|---|---|
| `dns` | domain, url, ip | A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR |
| `rdap` | domain, url, ip | Registration, expiry, abuse contact |
| `ipinfo` | ip | Geolocation, ASN, privacy flags (a token raises the quota) |
| `crtsh` | domain, url | Certificate transparency: every name ever certified, and when |
| `ripestat` | ip, ASN | The announcing prefix, its autonomous system, the abuse contact |
| `shodan_internetdb` | ip | Open ports, hostnames and CVEs, from Shodan's free endpoint |
| `dnsbl` | ip | Spamhaus, SpamCop, Barracuda, SORBS — malicious only at two or more listings |
| `tor_exit` | ip | Whether the address is a Tor exit node |
| `urlscan` | url, domain | Submission and retrieval, screenshot, DOM, associated addresses (a key raises the quota) |
| `feodotracker` | ip | The abuse.ch botnet command-and-control blocklist |

### Keyless, but off until you enable it

| Plugin | Observables | What it adds |
|---|---|---|
| `circl_hashlookup` | hash | CIRCL's known-good set: filters out files that ship with an operating system |

### Key required

| Plugin | Observables | Credential |
|---|---|---|
| `shodan` | ip | API key |
| `censys` | ip, domain | API ID and secret |
| `virustotal` | ip, domain, url, hash | API key (v3) |
| `abuseipdb` | ip | API key |
| `onyphe` | ip, domain, url | API key |
| `threatfox` | ip, domain, url, hash | Auth-Key |
| `malwarebazaar` | hash | Auth-Key |
| `urlhaus` | url, domain, ip | Auth-Key |
| `joesandbox_cloud` | hash, url, file | API key — **submissions are published**, so TLP:CLEAR only |
| `joesandbox_enterprise` | hash, url, file | API key and your appliance URL — submissions stay private, up to TLP:RED |

Every plugin states, in the interface, who serves it, the endpoint XenoProxy calls, where
to create the key, what the free tier allows and the rate limit to expect. That is the
answer to "what do I paste here".

### Sources that answer for an address

`shodan`, `shodan_internetdb`, `ipinfo` and `abuseipdb` index *hosts*, not names.
Given a domain or a URL they resolve it first and report on the address, saying
which one in the headline — so scanning a URL tells you where it is hosted and
what is open there, without pivoting by hand. The resolved address goes through
the same check the submitted observable passed, so a name resolving into a
private range cannot be used to reach the internal network.

### Local YARA rules (alpha)

`yara_local` scans a **submitted file** with YARA rules on this instance. Nothing is
sent anywhere, so it runs up to TLP:RED and does not depend on the "send files to
providers" setting. It runs on uploaded files whatever their type. One matching rule is Suspicious, three or more distinct rules are
Malicious (option `malicious_rules`), and no match is Unknown, never Clean.

Rules come from two places, both under the `yara_rules` volume (`/app/yara_rules`):

- `custom/`: your own `.yar` / `.yara` files, any depth, picked up on the next scan.
  To manage them from the host, bind-mount a folder instead of the named volume:
  `./yara-rules:/app/yara_rules`, and keep your files in `./yara-rules/custom/`
  (readable by UID 10001).
- `sources/`: public rulesets pulled from **Admin, YARA rules**. The worker downloads
  them, since it is the only container with an outbound route. A pull is started by
  an administrator, never on a schedule. Set `BACKEND_YARA_PULL_ENABLED=false` to
  refuse all pulls. Available sources:

  | Id | Ruleset | Licence |
  |---|---|---|
  | `signature-base` | Neo23x0 signature-base | Detection Rule License 1.1 |
  | `elastic` | Elastic protections-artifacts | Elastic License 2.0 |
  | `yara-rules` | Yara-Rules community | GPL-2.0 |
  | `reversinglabs` | ReversingLabs YARA rules | MIT |
  | `bartblaze` | Bartblaze YARA rules | MIT |
  | `mcafee-atr` | McAfee Advanced Threat Research | Apache-2.0 |
  | `loldrivers` | LOLDrivers (vulnerable and malicious drivers) | Apache-2.0 |
  | `stratosphere` | Stratosphere IPS malware rules | CC-BY-SA-4.0 (share-alike) |

  The archive digest is recorded with every pull, and the branch is not pinned, so
  an update takes whatever the project published. Check each ruleset's licence before
  commercial use. Sources that were checked and left out: the Huntress repository
  (not reachable at its published address), the Mandiant countermeasures (one
  incident-specific file, no folder to pull), and Intezer, InQuest, JPCERT, dr4k0nia,
  StrangerealIntel and elceef, whose rule layout or licence could not be confirmed.

A rule file that does not compile is left out and reported, so one broken community
rule does not disable the rest. `BACKEND_YARA_PULL_ENABLED=false` disables pulling
(the folder still works), for instances that must not reach GitHub.

Verified against small local rule fixtures only, not against a full community
ruleset on real samples.

### Office macros (alpha)

`doc_info` reads the macros of a **submitted Office document** with oletools, on this
instance. The macros are read and never run. Auto-run macros (`AutoOpen`,
`Document_Open`, ...) and API calls a dropper uses (`Shell`, `CreateObject`,
`URLDownloadToFile`) are the indicators. An auto-run macro with several suspicious calls
is Malicious (option `malicious_keywords`, default 3), one indicator is Suspicious, and a
document with macros but no indicator is Unknown. Office documents with no macros are
Unknown too, and a file that is not an Office document is skipped.

Verified against stubbed parser output and non-macro documents only.

### Strings (alpha)

`strings_info` extracts the readable strings (ASCII and UTF-16) of a **submitted file** on
this instance and reports what matters: process-injection APIs (`VirtualAllocEx`,
`WriteProcessMemory`, `CreateRemoteThread`, ...), download/exec indicators
(`URLDownloadToFile`, `WinExec`, `powershell -enc`), base64 blobs that decode to text, and
URLs, IPs and registry keys (tags only). Two or more injection APIs are Malicious, one
indicator is Suspicious, and no indicator is Unknown. Option `min_length` (default 6).
Floss-style recovery of strings built at runtime is not included.

Verified against synthetic byte fixtures only.

### File metadata (alpha)

`file_info` identifies a **submitted file** from its bytes (never its name), reports its
hashes and entropy, and reads the structure that matters for triage: the PE header and
sections, the active-content keys of a PDF (`/JavaScript`, `/OpenAction`, `/Launch`...), and
whether an image carries EXIF or XMP. A packer section, a writable and executable section,
high-entropy code or a PDF that acts on open is Suspicious; nothing here is Malicious, and
a file with no indicator is Unknown, never Clean. It is a small reader, not exiftool.

Verified against synthetic byte fixtures only.

### Binary capabilities (alpha)

`capa` reads the import table of a **submitted Windows binary** and reports the capabilities
its APIs point to: code injection (`VirtualAllocEx` with `WriteProcessMemory` and
`CreateRemoteThread`), process hollowing, download-and-execute, service and registry
persistence, keylogging and anti-debugging. An import says the code may call an API, not that
it does, so only the high-severity capabilities (injection, hollowing, download-and-execute)
make a file Suspicious; the others are tags. Nothing is Malicious from imports alone, and a
file with no high-severity capability is Unknown.

It is not capa. The real project matches rules over disassembly and needs a large dependency
and a rule bundle; this one is a dependency-free starting set. Packed files hide their imports,
so an empty result on a packed file means nothing.

Verified against synthetic PE fixtures only.

### Sandboxes and code genetics (alpha)

Three analyzers read what a sandbox already knows about a **SHA-256**. None of them submits
a file: a submission can be published, or tip off whoever watches the infrastructure.

- `intezer` (Intezer Analyze): the family a sample's code is closest to, even when its hash
  is new. `malicious` and `suspicious` map to their verdicts, `trusted` to Clean, anything
  else to Unknown. Needs an API key. Uploads are never sent.
- `triage` (Hatching): the score (0 to 10) and signatures of the newest sandbox run.
  Score 7 and up is Malicious, 4 to 6 Suspicious, and lower is Unknown: a quiet run does
  not prove a file clean. Needs an API token.
- `cape` (CAPE, self-hosted): the newest task of your own instance and its malscore. The
  base URL is required in the options and private addresses are allowed by default, since
  an instance is usually on the internal network. The API token is optional.

Verified against mocks only. The endpoints follow each provider's documented API, and none
of them has been run against a live account or instance yet.

### Leaked credentials (alpha)

`dehashed` looks an **email address** up in Dehashed's leaked-record index. A hit is
Suspicious, never Malicious: it is exposure, not evidence that the address is hostile. A
record with a plaintext password is tagged `plaintext-password` and scores higher, but the
verdict does not change. No record is Unknown, not Clean. Passwords and hashes in the
results are read only to know that one was exposed; they are never stored in the report,
the summary, or the raw output. Needs a paid API key; out of credits is reported as a
failure.

Verified against mocks only.

## Connectors

| Plugin | What it does |
|---|---|
| `opencti_export` | Creates or updates the observable in OpenCTI, verdict as confidence score, tags as labels |
| `ai_assessment` | A model you host reads every source's report and gives its own verdict, with its reasoning and any disagreement it finds |

`ai_assessment` records an opinion beside the aggregate. It does **not** override the
job's verdict: a model's judgement is evidence for the analyst, not the answer.

Outbound webhooks carry `X-XenoProxy-Signature` (HMAC-SHA256) and
`X-XenoProxy-Timestamp` when a signing key is configured, so the receiving workflow can
verify them.

## Pivots

| Plugin | Derives |
|---|---|
| `url_to_domain` | The host of the URL |
| `url_to_ip` | The addresses the URL resolves to |
| `domain_to_ip` | The addresses the domain resolves to |

A pivot only acts on a suspicious or malicious verdict, and is bounded three ways: how
many children one pivot may create, how many a job may create in total, and how deep the
chain may go. Each derived observable is validated like any other input, so a pivot cannot
be used to reach an internal address.

## Playbooks

A playbook is a preset pipeline for one or more observable types: the analyzers to run,
and optionally the connectors and pivots. Eight ship with the product, two of them using
pivots and shipped disabled.

| Playbook | For | Runs |
|---|---|---|
| Fast IP triage | ip | Reputation, exposure and geolocation |
| IP deep dive | ip | Everything available, threat feeds included |
| Domain reconnaissance | domain, url | Registration, DNS, certificates, reputation |
| URL triage | url | Reputation and page analysis |
| Hash triage | hash | Known-good filtering first, then malware intelligence |
| Free sources only | all | Every source that needs no paid quota |
| Domain investigation with pivots | domain | Reconnaissance, then down to the hosting addresses |
| URL investigation with pivots | url | Triage, then to the domain and the hosting address |

Administrators can create their own under **Playbooks**.

## The cache

Before calling a paid provider, the orchestrator looks for a valid report for the same
`(observable, plugin)` pair inside that plugin's window. A hit costs no external call and
is marked as served from cache on the report.

The window is per plugin, defaulting to `BACKEND_CACHE_DEFAULT_TTL_SECONDS` (24 hours).
Set it to zero to disable caching for a source whose answers change by the minute.

An analyst can tick **force a refresh** on a scan to bypass it, which spends the quota of
every selected source.

The cache is shared across the team: that is the point. A lookup one analyst made this
morning costs nothing when a colleague repeats it this afternoon.

## MISP export (alpha)

`misp_export` creates one event per analysed observable in your MISP instance: the
observable as an attribute, the verdict as a threat level and a `xenoproxy:verdict=` tag,
and the job TLP as a `tlp:` tag. The event is unpublished and visible to your
organisation only; only a malicious verdict marks the attribute for IDS export. At
TLP:RED it runs only if you enable **Trusted internal MISP** and the instance resolves to
a private address. Verified against mocked responses only, not a live MISP.

## LLM synthesizer (alpha)

`llm_synthesizer` asks your inference server for three plain lines: what the sources say,
the most important finding, and what to check next. It reads the same evidence as the AI
assessment, is subject to the same TLP gate, and never changes the job's verdict. Verified
against a fake model only.

## APK permissions (alpha)

`apk_info` reads an Android package's manifest in memory with Androguard and reports its
permissions and components. It is never installed or run. A single sensitive permission is
a tag; Suspicious needs a combination typical of abuse, such as accessibility control
with an overlay, a sideload install, or SMS interception. Nothing is Malicious from the
manifest alone. The parser is verified only against a stub and non-APK input.

## Phone metadata (alpha)

`phone_info` reads a phone number offline with libphonenumber: country, line type and the
original carrier, taken from the public numbering plans. The number is never sent anywhere,
so it is allowed at TLP:RED. A number is recognised as a phone only when it starts with
`+` (spaces, dots, dashes and brackets are ignored); a national number without a country
code stays a generic observable. Premium-rate and shared-cost lines are Suspicious, the usual
vehicle for toll fraud; everything else is Unknown. The carrier is the allocation, not the
current operator after porting, and there is no live lookup (HLR). Migration 0012 adds the
`PHONE` observable type.

## Blocklist feed (alpha)

`GET /api/v1/blocklist/ip` and `GET /api/v1/blocklist/domain` return a plain-text list, one
entry per line, built from jobs whose verdict is Malicious (Suspicious with
`min_verdict=suspicious`) within `days` (default 30). It uses the same visibility rule as the
job list, and it requires a token with `jobs:export`. Only jobs at TLP CLEAR, GREEN or AMBER
are listed; RED never leaves the database. Private, loopback, multicast and internal-suffix
(.local, .lan, .internal...) addresses are never listed. Lists are capped at 50,000 IPs and
5,000 domains, and the header states how many were omitted.

The format is a text file for pfSense URL aliases and Palo Alto External Dynamic Lists. It is
verified with synthetic candidates only, not loaded into either device. pfSense aliases cannot
send an Authorization header, so put the feed behind an internal reverse proxy that adds it, or
use a device that supports token authentication. CrowdStrike needs its own API and is not
covered.

## Crypto sanctions check (alpha)

A Bitcoin (legacy or bech32) or Ethereum address is a `crypto` observable. `crypto_taint`
checks it against the sanctions designations loaded on the instance, from the directory set
by `BACKEND_CRYPTO_INTEL_DIR` (default `/app/crypto_intel`, a volume read by the worker). Accepted
files: an OFAC SDN XML (its "Digital Currency Address" identifiers), or `.txt`/`.csv` lists with
one address per line and an optional label. A designated address is Malicious; a designated
mixer (for example Tornado Cash) also gets the `mixer` tag. An address off the list is Unknown,
never Clean. Nothing is downloaded and no chain API is called, so it is allowed at TLP:RED.
This is a designation check, not transaction tracing; that needs a chain-analytics provider and
is a separate decision. The list is not refreshed automatically: replace the file to update it,
and the raw output records the file's SHA-256. Verified with synthetic addresses only.

## Password breach check (alpha)

`POST /api/v1/passwords/check` tells whether a password appears in the Have I Been Pwned
corpus, using the k-anonymity range API: the password is hashed with SHA-1 locally and only the
first five characters of the hash leave the instance; the match is made here. The password is
never stored or logged. The endpoint is off by default: set `BACKEND_HIBP_PASSWORDS_ENABLED=true`
to allow the outbound call. Verified against mocked responses only.

## Takedown drafts (alpha)

`GET /api/v1/jobs/{id}/takedown-draft?recipient=hosting|registrar` builds a formatted abuse report for a finished job (token with `jobs:export`), as text for the analyst to
review and send. Nothing is ever sent by XenoProxy. It is produced only for TLP:CLEAR and
TLP:GREEN jobs (AMBER and RED are refused), and only for IP, domain and URL observables; the
registrar variant is for domains only. The abuse contact is a placeholder to fill in, the
evidence is the headline of each successful analyzer with control characters removed, and the
draft starts with "DRAFT - NOT SENT". Verified with synthetic jobs only.

## Configuration layers

Four layers, each overriding the one before:

1. **The class** — what the plugin's author declared: supported types, default timeout,
   default cache window, maximum TLP.
2. **The instance** — what an administrator set under Plugins & keys.
3. **The analyst** — their own options, and their own credential where the plugin allows
   one, so a team can share an instance without sharing a personal quota.
4. **The job** — what was chosen when the scan was submitted.

## Adding a plugin

Drop a folder into the plugins volume, or upload a zip under **Plugin packages**. No image
rebuild. A complete worked example, with its manifest, is in
[Writing a plugin](plugin-example/README.md).
