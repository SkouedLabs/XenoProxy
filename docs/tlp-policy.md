# TLP policy

[Documentation](README.md) · [Plugins](plugins.md) · [Security](security.md)

A job carries a handling level. It decides which tools may touch the observable and where
the data may go. The level is set when the job is submitted and each tool declares the
highest level it tolerates; a tool whose cap is below the job's level is skipped, with the
reason shown in the job.

| Level | What may run | Where data may go |
|---|---|---|
| `CLEAR` | Every source, including those that publish or index the observable (public sandboxes, URL scanners). | Anywhere. |
| `GREEN` | Everything except sources that publish. | Private receipt by third parties. |
| `AMBER` | Reputation and lookup APIs that receive the observable privately; visibility limited to the submitter's groups. | Trusted third parties, privately. |
| `RED` | Local tools only. | Nowhere outside the deployment. |

## What counts as "inside"

Only what runs in this deployment, or on an address that resolves entirely to a private
network. A tool that reaches a third party is capped at `AMBER`, even when it only asks a
public question: asking NVD about a CVE or a resolver about a name still tells someone what
you are looking at. That is why `dns` and `nvd` are `AMBER`, not `RED`.

Tools allowed at `RED` are listed in `backend/tests/test_tlp_policy.py` with the reason for
each. The test fails when a plugin starts claiming `RED` without being added there, so the
list cannot widen by accident.

## The model server

An inference server is a destination. At `RED`, the assistant and the `ai_assessment`
connector use it only if its address resolves entirely to private addresses. A name that does
not resolve, or resolves partly to public addresses, counts as outside. Otherwise a RED job is
withheld from the model: absent from search, refused when opened, and `ai_assessment` is
skipped.

## Samples are never executed

No plugin starts a process or evaluates code. Local analyzers read the bytes: YARA matches,
header parsing, string extraction, entropy. A test checks statically that nothing under
`app/plugins` imports `subprocess`, `pty` or `ctypes`, or calls `eval`, `exec`, `os.system`
or `os.popen`. Beyond that, the containers are read-only with no shell, and the backend
installs a guard that refuses process creation at runtime.

The same holds for the file inspection shown on every uploaded file: it reads the bytes
(and, for an archive, its members in memory, one level deep, never written to disk), runs
at every TLP level because nothing leaves, and only ever says suspicious. The same static
test covers it.

## Trusted internal services

An administrator can mark a workflow they run as trusted with the `trusted_internal` option
on the **MISP** connector (`misp_export`). That lifts its planning cap to `RED`, so it may
receive RED jobs, but only while its address resolves entirely to private addresses. The
check runs again when the plugin fires, so a switched-on option cannot send data to a public
address. An instance that forwards to a public service is therefore refused at RED even with
the switch on.

No other plugin can be lifted. A vendor under contract stays at its class cap; widening a
third party's cap is a code change, reviewed like any other, not a setting.

## Not decided yet

- The OpenCTI receiver still needs the same treatment as MISP (`misp_export` already has the trusted-internal option).
