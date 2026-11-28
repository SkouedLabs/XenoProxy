/**
 * Where the MCP endpoints are and how an agent connects to them.
 *
 * The addresses are built from the origin the page was loaded from, so they are
 * the ones a client on the same network can use.
 */

import { Copy } from 'lucide-react';

import { Button } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';

const ENDPOINTS = [
  {
    id: 'user',
    label: 'User server',
    path: '/api/v1/mcp/user',
    tools: 16,
    note: 'Submit and read scans, payloads, playbooks, exports. Acts with the rights of the token’s account.',
  },
  {
    id: 'admin',
    label: 'Admin server',
    path: '/api/v1/mcp',
    tools: 29,
    note: 'The user tools plus settings, plugin configuration, users, groups and audit. The account must be listed in the administrators below.',
  },
] as const;

export function McpInfo() {
  const toast = useToast();
  const origin = window.location.origin;

  function copy(text: string) {
    void navigator.clipboard
      .writeText(text)
      .then(() => toast.success('Copied'))
      .catch(() => toast.error('Copy failed'));
  }

  return (
    <div className="mb-6 space-y-3 rounded-lg border border-border-subtle bg-surface-sunken p-4 text-sm">
      <h3 className="text-xs font-medium uppercase tracking-wide text-faint">Endpoints</h3>
      <ul className="space-y-3">
        {ENDPOINTS.map((endpoint) => {
          const url = `${origin}${endpoint.path}`;
          return (
            <li key={endpoint.id}>
              <p className="font-medium">
                {endpoint.label} <span className="text-xs text-muted">({endpoint.tools} tools)</span>
              </p>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <code className="break-all rounded bg-surface px-2 py-1 text-xs">{url}</code>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  aria-label={`Copy the ${endpoint.label} address`}
                  onClick={() => copy(url)}
                >
                  <Copy className="h-4 w-4" aria-hidden />
                </Button>
              </div>
              <p className="mt-1 text-xs text-muted">{endpoint.note}</p>
            </li>
          );
        })}
      </ul>
      <ul className="list-disc space-y-1 pl-5 text-xs text-muted">
        <li>Transport: Streamable HTTP, JSON-RPC 2.0, one POST per call, no session.</li>
        <li>
          Authentication: header <code>Authorization: Bearer xenoproxy_…</code> with a personal
          API token (Profile › API tokens).
        </li>
        <li>Use the address exactly as shown: a trailing slash on the admin one redirects.</li>
        <li>
          If the instance uses a private certificate authority, the client machine must trust it.
        </li>
        <li>
          Claude Code: <code>claude mcp add --transport http xenoproxy {origin}/api/v1/mcp/user
          --header &quot;Authorization: Bearer &lt;token&gt;&quot;</code>
        </li>
      </ul>
    </div>
  );
}
