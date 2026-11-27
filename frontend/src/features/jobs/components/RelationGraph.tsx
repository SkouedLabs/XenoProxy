/**
 * Relation graph of an investigation.
 *
 * A radial layout: the subject sits at the centre and every other element is
 * placed on a ring by how many hops separate it from the subject, so what is
 * closest to the question is closest to the middle. The same relations are
 * available as a table underneath, because a drawing is not readable by
 * everyone and not searchable by anyone.
 */

import { useMemo, useState } from 'react';

import { Badge } from '@/components/ui';
import { cn } from '@/lib/cn';
import type { GraphNode, RelationGraphData } from '../api';

const WIDTH = 960;
const HEIGHT = 640;
const RING = 105;

/** One colour per kind, taken from the theme so the graph follows light and dark. */
const KIND_COLOUR: Record<string, string> = {
  ip: 'var(--color-primary)',
  domain: 'var(--color-info)',
  url: 'var(--color-info)',
  hash: 'var(--color-warning)',
  asn: 'var(--color-success)',
  prefix: 'var(--color-success)',
  country: 'var(--color-warning)',
  city: 'var(--color-warning)',
  certificate: 'var(--color-danger)',
  issuer: 'var(--color-danger)',
  cve: 'var(--color-danger)',
  registrar: 'var(--color-content-muted)',
  contact: 'var(--color-content-muted)',
  port: 'var(--color-content-faint)',
  technology: 'var(--color-content-faint)',
};

/** Kinds that would bury the rest when an address exposes dozens of them. */
const HIDDEN_BY_DEFAULT = new Set(['port', 'technology']);

interface Placed {
  node: GraphNode;
  x: number;
  y: number;
  hops: number;
}

function layout(graph: RelationGraphData, visible: Set<string>): Placed[] {
  const nodes = graph.nodes.filter((node) => visible.has(node.kind) || node.id === graph.root);
  const ids = new Set(nodes.map((node) => node.id));
  const adjacency = new Map<string, string[]>();
  for (const edge of graph.edges) {
    if (!ids.has(edge.source) || !ids.has(edge.target)) continue;
    adjacency.set(edge.source, [...(adjacency.get(edge.source) ?? []), edge.target]);
    adjacency.set(edge.target, [...(adjacency.get(edge.target) ?? []), edge.source]);
  }

  const hops = new Map<string, number>();
  const start = graph.root && ids.has(graph.root) ? graph.root : nodes[0]?.id;
  if (start) {
    hops.set(start, 0);
    const queue = [start];
    for (let index = 0; index < queue.length; index += 1) {
      const current = queue[index] as string;
      for (const next of adjacency.get(current) ?? []) {
        if (!hops.has(next)) {
          hops.set(next, (hops.get(current) ?? 0) + 1);
          queue.push(next);
        }
      }
    }
  }
  const outer = Math.max(0, ...hops.values()) + 1;

  const rings = new Map<number, GraphNode[]>();
  for (const node of nodes) {
    const ring = hops.get(node.id) ?? outer;
    rings.set(ring, [...(rings.get(ring) ?? []), node]);
  }

  const placed: Placed[] = [];
  for (const [ring, members] of rings) {
    const radius = Math.min(ring * RING, HEIGHT / 2 - 30);
    members.forEach((node, index) => {
      const angle = (2 * Math.PI * index) / members.length - Math.PI / 2 + ring * 0.4;
      placed.push({
        node,
        hops: ring,
        x: WIDTH / 2 + (ring === 0 ? 0 : radius * 1.45 * Math.cos(angle)),
        y: HEIGHT / 2 + (ring === 0 ? 0 : radius * Math.sin(angle)),
      });
    });
  }
  return placed;
}

function shorten(label: string, max = 26): string {
  return label.length > max ? `${label.slice(0, max - 1)}…` : label;
}

export function RelationGraph({ graph }: { graph: RelationGraphData }) {
  const kinds = useMemo(
    () => [...new Set(graph.nodes.map((node) => node.kind))].sort(),
    [graph.nodes],
  );
  const [visible, setVisible] = useState<Set<string>>(
    () => new Set(kinds.filter((kind) => !HIDDEN_BY_DEFAULT.has(kind))),
  );
  const [selected, setSelected] = useState<string | null>(null);

  const placed = useMemo(() => layout(graph, visible), [graph, visible]);
  const byId = useMemo(() => new Map(placed.map((entry) => [entry.node.id, entry])), [placed]);
  const edges = graph.edges.filter((edge) => byId.has(edge.source) && byId.has(edge.target));
  const focus = selected ? byId.get(selected)?.node : undefined;

  const toggle = (kind: string) =>
    setVisible((current) => {
      const next = new Set(current);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Element kinds shown">
        {kinds.map((kind) => {
          const on = visible.has(kind);
          return (
            <button
              key={kind}
              type="button"
              aria-pressed={on}
              onClick={() => toggle(kind)}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-pill border px-2 py-0.5 text-xs',
                on ? 'border-border-strong bg-surface-raised' : 'border-border text-faint',
              )}
            >
              <span
                aria-hidden
                className="h-2 w-2 rounded-pill"
                style={{ background: KIND_COLOUR[kind] ?? 'var(--color-content-muted)' }}
              />
              {kind}
            </button>
          );
        })}
      </div>

      <div className="overflow-x-auto rounded-lg border border-border bg-surface-sunken">
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="h-auto min-w-[640px] w-full"
          role="img"
          aria-label={`Relation graph with ${placed.length} elements and ${edges.length} relations`}
        >
          {edges.map((edge) => {
            const from = byId.get(edge.source);
            const to = byId.get(edge.target);
            if (!from || !to) return null;
            const active = selected === edge.source || selected === edge.target;
            return (
              <line
                key={`${edge.source}|${edge.target}|${edge.relation}`}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke="var(--color-border-strong)"
                strokeWidth={active ? 2 : 1}
                opacity={selected && !active ? 0.25 : 0.9}
              />
            );
          })}
          {placed.map(({ node, x, y }) => {
            const isRoot = node.id === graph.root;
            const colour = KIND_COLOUR[node.kind] ?? 'var(--color-content-muted)';
            return (
              <g
                key={node.id}
                transform={`translate(${x} ${y})`}
                tabIndex={0}
                role="button"
                aria-label={`${node.kind} ${node.label}`}
                aria-pressed={selected === node.id}
                className="cursor-pointer outline-none focus-visible:opacity-80"
                onClick={() => setSelected(selected === node.id ? null : node.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    setSelected(selected === node.id ? null : node.id);
                  }
                }}
              >
                <circle
                  r={isRoot ? 13 : 8}
                  fill={colour}
                  stroke="var(--color-surface)"
                  strokeWidth={2}
                />
                <text
                  y={isRoot ? 28 : 20}
                  textAnchor="middle"
                  fontSize={11}
                  fill="var(--color-content)"
                  stroke="var(--color-surface-sunken)"
                  strokeWidth={3}
                  paintOrder="stroke"
                >
                  {shorten(node.label)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {graph.truncated ? (
        <p className="text-xs text-warning">
          The graph was capped at its size limit; some elements are not shown.
        </p>
      ) : null}

      {focus ? (
        <div className="rounded-lg border border-border bg-surface p-3 text-sm">
          <div className="flex items-center gap-2">
            <Badge>{focus.kind}</Badge>
            <span className="break-all font-mono text-xs">{focus.label}</span>
          </div>
          {Object.keys(focus.data).length > 0 ? (
            <dl className="mt-2 grid gap-x-4 gap-y-1 text-xs sm:grid-cols-2">
              {Object.entries(focus.data).map(([key, value]) => (
                <div key={key}>
                  <dt className="inline text-faint">{key}: </dt>
                  <dd className="inline break-all">{String(value)}</dd>
                </div>
              ))}
            </dl>
          ) : null}
        </div>
      ) : null}

      <details className="rounded-lg border border-border bg-surface p-3">
        <summary className="cursor-pointer text-sm font-medium">
          Relations as a table ({edges.length})
        </summary>
        <div className="mt-3 max-h-96 overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-faint">
              <tr>
                <th className="py-1 pr-3 font-medium">From</th>
                <th className="py-1 pr-3 font-medium">Relation</th>
                <th className="py-1 pr-3 font-medium">To</th>
                <th className="py-1 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {edges.map((edge) => (
                <tr
                  key={`${edge.source}|${edge.target}|${edge.relation}`}
                  className="border-t border-border-subtle"
                >
                  <td className="break-all py-1 pr-3 font-mono">{byId.get(edge.source)?.node.label}</td>
                  <td className="py-1 pr-3">{edge.relation.replace(/_/g, ' ')}</td>
                  <td className="break-all py-1 pr-3 font-mono">{byId.get(edge.target)?.node.label}</td>
                  <td className="py-1 text-muted">{edge.plugin ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
