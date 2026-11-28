/**
 * Named outbound proxies: HTTP, HTTPS or SOCKS5 tunnels an analysis can leave through.
 *
 * The profiles are part of the Network section, so this editor is controlled by
 * the section form and saved with its button. A password is never sent back by
 * the API: its field starts empty, an empty field keeps the stored one, and the
 * placeholder says whether one is stored.
 */

import { useQuery } from '@tanstack/react-query';
import { Plus, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';

import { Badge, Button, Field, Input, Select, Toggle } from '@/components/ui';
import type { SectionValues } from '@/lib/types';
import { adminApi } from '../api';

/** The proxy fields this editor owns, so the generic form does not offer them twice. */
export const PROXY_OWNED = [
  'proxy_profiles',
  'proxy_passwords',
  'proxy_default',
  'proxy_assignments',
] as const;

const SCHEMES = [
  { value: 'socks5h', label: 'SOCKS5 (the proxy resolves names, recommended)' },
  { value: 'socks5', label: 'SOCKS5 (names resolved here)' },
  { value: 'http', label: 'HTTP' },
  { value: 'https', label: 'HTTPS' },
] as const;

/** Captures are an analyzer of their own as far as routing goes. */
const SCREENSHOT = 'screenshot';

interface Row {
  name: string;
  isNew: boolean;
  scheme: string;
  host: string;
  port: string;
  username: string;
  red_approved: boolean;
}

interface StoredProfile {
  name: string;
  url: string;
  username?: string;
  red_approved?: boolean;
}

function parse(profile: StoredProfile): Row {
  const match = /^(\w+):\/\/(\[[^\]]+\]|[^:/]+)(?::(\d+))?\/?$/.exec(profile.url);
  return {
    name: profile.name,
    isNew: false,
    scheme: match?.[1] ?? 'socks5h',
    host: match?.[2] ?? profile.url,
    port: match?.[3] ?? '',
    username: profile.username ?? '',
    red_approved: Boolean(profile.red_approved),
  };
}

function toProfile(row: Row): StoredProfile {
  const host = row.host.trim();
  const port = row.port.trim();
  return {
    name: row.name.trim(),
    url: `${row.scheme}://${host}${port ? `:${port}` : ''}`,
    username: row.username.trim(),
    red_approved: row.red_approved,
  };
}

export function ProxyProfiles({
  draft,
  stored,
  set,
}: {
  draft: SectionValues;
  stored: SectionValues;
  set: (key: string, value: unknown) => void;
}) {
  const [rows, setRows] = useState<Row[]>(() =>
    ((draft.proxy_profiles as StoredProfile[] | undefined) ?? []).map(parse),
  );
  const [pickedAnalyzer, setPickedAnalyzer] = useState('');
  const [pickedProfile, setPickedProfile] = useState('');

  const analyzers = useQuery({
    queryKey: ['admin', 'plugins', 'analyzer'],
    queryFn: () => adminApi.plugins('analyzer'),
  });

  const passwords = (draft.proxy_passwords as Record<string, string> | undefined) ?? {};
  const storedPasswords = (stored.proxy_passwords_set as string[] | undefined) ?? [];
  const assignments = (draft.proxy_assignments as Record<string, string> | undefined) ?? {};
  const fallback = String(draft.proxy_default ?? '');
  // The API keeps a stored password only for a name that is sent back, so the
  // form starts from every stored name with an empty value (empty means keep).
  useEffect(() => {
    const seeded: Record<string, string> = {};
    for (const name of (stored.proxy_passwords_set as string[] | undefined) ?? []) seeded[name] = '';
    set('proxy_passwords', { ...seeded, ...passwords });
    // Seeded once, when the section opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const names = rows.map((row) => row.name.trim()).filter(Boolean);

  function commit(next: Row[]) {
    setRows(next);
    set('proxy_profiles', next.filter((row) => row.name.trim()).map(toProfile));
  }

  function update(index: number, patch: Partial<Row>) {
    commit(rows.map((row, position) => (position === index ? { ...row, ...patch } : row)));
  }

  function remove(index: number) {
    const gone = rows[index]?.name.trim() ?? '';
    commit(rows.filter((_, position) => position !== index));
    if (!gone) return;
    if (fallback === gone) set('proxy_default', '');
    set(
      'proxy_assignments',
      Object.fromEntries(Object.entries(assignments).filter(([, profile]) => profile !== gone)),
    );
    set(
      'proxy_passwords',
      Object.fromEntries(Object.entries(passwords).filter(([name]) => name !== gone)),
    );
  }

  function assign(analyzer: string, profile: string) {
    const next = { ...assignments };
    if (profile) next[analyzer] = profile;
    else delete next[analyzer];
    set('proxy_assignments', next);
  }

  const analyzerNames = [
    SCREENSHOT,
    ...(analyzers.data ?? []).map((plugin) => plugin.name).sort(),
  ].filter((name) => !(name in assignments));

  return (
    <div className="space-y-5">
      <div>
        <h3 className="text-sm font-medium">Proxy profiles</h3>
        <p className="mt-1 text-xs text-muted">
          Each profile is a tunnel an analysis can leave through: SOCKS5 (with or without a user
          name and password), HTTP or HTTPS. Choose below which profile is used by default and
          which analyzers use another. SOCKS4 is not supported.
        </p>
      </div>

      {rows.length === 0 ? (
        <p className="rounded-lg border border-dashed border-border-subtle p-4 text-sm text-muted">
          No profile yet. Analyses leave directly, or through the single proxy set above.
        </p>
      ) : null}

      {rows.map((row, index) => {
        const key = row.name.trim();
        const hasPassword = storedPasswords.includes(key);
        return (
          <fieldset
            key={index}
            className="space-y-3 rounded-lg border border-border-subtle bg-surface-sunken p-4"
          >
            <legend className="flex items-center gap-2 px-1 text-xs font-medium uppercase tracking-wide text-faint">
              {key || 'New profile'}
              {row.red_approved ? <Badge tone="warning">RED approved</Badge> : null}
            </legend>
            <div className="grid gap-x-4 gap-y-1 sm:grid-cols-6">
              <Field label="Name" htmlFor={`proxy-name-${index}`} className="sm:col-span-2">
                <Input
                  id={`proxy-name-${index}`}
                  value={row.name}
                  disabled={!row.isNew}
                  placeholder="tor-exit"
                  onChange={(event) => update(index, { name: event.target.value })}
                />
              </Field>
              <Field label="Type" htmlFor={`proxy-scheme-${index}`} className="sm:col-span-4">
                <Select
                  id={`proxy-scheme-${index}`}
                  value={row.scheme}
                  onChange={(event) => update(index, { scheme: event.target.value })}
                >
                  {SCHEMES.map((scheme) => (
                    <option key={scheme.value} value={scheme.value}>
                      {scheme.label}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Host" htmlFor={`proxy-host-${index}`} className="sm:col-span-4">
                <Input
                  id={`proxy-host-${index}`}
                  value={row.host}
                  placeholder="socks.example.org"
                  spellCheck={false}
                  onChange={(event) => update(index, { host: event.target.value })}
                />
              </Field>
              <Field label="Port" htmlFor={`proxy-port-${index}`} className="sm:col-span-2">
                <Input
                  id={`proxy-port-${index}`}
                  type="number"
                  min={1}
                  max={65535}
                  value={row.port}
                  placeholder="1080"
                  onChange={(event) => update(index, { port: event.target.value })}
                />
              </Field>
              <Field label="User name" htmlFor={`proxy-user-${index}`} className="sm:col-span-3">
                <Input
                  id={`proxy-user-${index}`}
                  value={row.username}
                  autoComplete="off"
                  placeholder="Optional"
                  onChange={(event) => update(index, { username: event.target.value })}
                />
              </Field>
              <Field label="Password" htmlFor={`proxy-pass-${index}`} className="sm:col-span-3">
                <Input
                  id={`proxy-pass-${index}`}
                  type="password"
                  autoComplete="new-password"
                  value={passwords[key] ?? ''}
                  placeholder={hasPassword ? 'Stored, enter a new value to replace it' : 'Optional'}
                  onChange={(event) =>
                    set('proxy_passwords', { ...passwords, [key]: event.target.value })
                  }
                />
              </Field>
            </div>
            <Toggle
              id={`proxy-red-${index}`}
              checked={row.red_approved}
              onChange={(next) => update(index, { red_approved: next })}
              label="Approved for TLP:RED"
              description="Only a profile marked like this may carry TLP:RED material. Tick it only for a tunnel you control end to end."
            />
            <div className="flex justify-end">
              <Button type="button" variant="ghost" size="sm" onClick={() => remove(index)}>
                <Trash2 className="h-4 w-4" aria-hidden /> Remove
              </Button>
            </div>
          </fieldset>
        );
      })}

      <Button
        type="button"
        size="sm"
        onClick={() =>
          commit([
            ...rows,
            {
              name: '',
              isNew: true,
              scheme: 'socks5h',
              host: '',
              port: '1080',
              username: '',
              red_approved: false,
            },
          ])
        }
      >
        <Plus className="h-4 w-4" aria-hidden /> Add a proxy profile
      </Button>

      {names.length > 0 ? (
        <div className="space-y-4">
          <Field
            label="Default profile"
            htmlFor="proxy-default"
            hint="Used by every analyzer that has no profile of its own."
          >
            <Select
              id="proxy-default"
              value={fallback}
              onChange={(event) => set('proxy_default', event.target.value)}
            >
              <option value="">None: the proxy set above, or a direct connection</option>
              {names.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </Select>
          </Field>

          <div>
            <h4 className="text-sm font-medium">Per analyzer</h4>
            <p className="mt-1 text-xs text-muted">
              An analyzer listed here always uses its own profile instead of the default.
              &ldquo;screenshot&rdquo; covers page captures.
            </p>
            <ul className="mt-2 space-y-2">
              {Object.entries(assignments).map(([analyzer, profile]) => (
                <li key={analyzer} className="flex flex-wrap items-center gap-2">
                  <code className="min-w-40 text-sm">{analyzer}</code>
                  <Select
                    aria-label={`Profile for ${analyzer}`}
                    value={profile}
                    onChange={(event) => assign(analyzer, event.target.value)}
                  >
                    {names.map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </Select>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    aria-label={`Stop routing ${analyzer}`}
                    onClick={() => assign(analyzer, '')}
                  >
                    <Trash2 className="h-4 w-4" aria-hidden />
                  </Button>
                </li>
              ))}
            </ul>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Select
                aria-label="Analyzer to route"
                value={pickedAnalyzer}
                onChange={(event) => setPickedAnalyzer(event.target.value)}
              >
                <option value="">Choose an analyzer</option>
                {analyzerNames.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </Select>
              <Select
                aria-label="Profile to use"
                value={pickedProfile}
                onChange={(event) => setPickedProfile(event.target.value)}
              >
                <option value="">Choose a profile</option>
                {names.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </Select>
              <Button
                type="button"
                size="sm"
                disabled={!pickedAnalyzer || !pickedProfile}
                onClick={() => {
                  assign(pickedAnalyzer, pickedProfile);
                  setPickedAnalyzer('');
                  setPickedProfile('');
                }}
              >
                Route it
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
