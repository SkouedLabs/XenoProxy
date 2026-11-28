/**
 * Detection graph of an analysis: what was found, by which source, and what led where.
 *
 * Read left to right. The observable you submitted is on the left, then the sources
 * that looked at it, then what they found, then what those findings led to (an
 * address a DNS lookup returned, the ports and networks found on that address...).
 * Selecting any element lights up the path from the start and lists it as a chain,
 * so "this address came from the DNS lookup" is something you read, not infer.
 *
 * The relations are also available as a table underneath, because a drawing is
 * neither searchable nor readable by everyone.
 */

import { ArrowDown } from 'lucide-react';
import { useMemo, useState } from 'react';

import { Badge } from '@/components/ui';
import { cn } from '@/lib/cn';
import type { DetectionGraphData, DetectionNode } from '../api';
import { KIND_COLOUR } from './RelationGraph';

const NODE_W = 176;
const NODE_H = 30;
const GAP_X = 64;
const ROW = 40;
const PAD = 16;

/** Kinds that would bury the rest when an address exposes dozens of them. */
const HIDDEN_BY_DEFAULT = new Set(['port', 'technology', 'tag']);

const VERDICT_COLOUR: Record<string, string> = {
  malicious: 'var(--color-danger)',
  suspicious: 'var(--color-warning)',
  clean: 'var(--color-success)',
  unknown: 'var(--color-content-faint)',
};

interface Placed {
  node: DetectionNode;
  x: number;
  y: number;
}

function layout(nodes: DetectionNode[]): {
  placed: Map<string, Placed>;
  width: number;
  height: number;
} {
  const columns = new Map<number, DetectionNode[]>();
  for (const node of nodes) {
    columns.set(node.layer, [...(columns.get(node.layer) ?? []), node]);
  }
  const last = Math.max(0, ...columns.keys());
  const tallest = Math.max(1, ...[...columns.values()].map((members) => members.length));
  const height = tallest * ROW + PAD * 2;

  const placed = new Map<string, Placed>();
  for (let layer = 0; layer <= last; layer += 1) {
    const members = columns.get(layer) ?? [];
    // Keep a node level with the node that led to it, so the edges stay short.
    const anchor = (node: DetectionNode) => placed.get(node.via?.from ?? '')?.y ?? 0;
    members.sort(
      (a, b) =>
        anchor(a) - anchor(b) || a.kind.localeCompare(b.kind) || a.label.localeCompare(b.label),
    );
    const offset = (height - members.length * ROW) / 2;
    members.forEach((node, index) => {
      placed.set(node.id, {
        node,
        x: PAD + layer * (NODE_W + GAP_X),
        y: offset + index * ROW + (ROW - NODE_H) / 2,
      });
    });
  }
  return { placed, width: PAD * 2 + (last + 1) * NODE_W + last * GAP_X, height };
}

function shorten(label: string, max = 24): string {
  return label.length > max ? `${label.slice(0, max - 1)}…` : label;
}

function words(relation: string): string {
  return relation.replace(/_/g, ' ');
}

function edgePath(from: Placed, to: Placed): string {
  const x1 = from.x + NODE_W;
  const y1 = from.y + NODE_H / 2;
  const x2 = to.x;
  const y2 = to.y + NODE_H / 2;
  const bend = Math.max(24, (x2 - x1) / 2);
  return `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`;
}

function strokeOf(node: DetectionNode): string {
  if (node.kind === 'analyzer') {
    const verdict = String(node.data.verdict ?? 'unknown');
    return VERDICT_COLOUR[verdict] ?? VERDICT_COLOUR.unknown!;
  }
  return KIND_COLOUR[node.kind] ?? 'var(--color-content-muted)';
}

/** The chain of elements from the start to `id`, each with the step that reached it. */
function chainTo(id: string, byId: Map<string, DetectionNode>): DetectionNode[] {
  const chain: DetectionNode[] = [];
  const seen = new Set<string>();
  let current = byId.get(id);
  while (current && !seen.has(current.id)) {
    seen.add(current.id);
    chain.unshift(current);
    current = current.via ? byId.get(current.via.from) : undefined;
  }
  return chain;
}

export function DetectionGraph({ graph }: { graph: DetectionGraphData }) {
  const kinds = useMemo(
    () => [...new Set(graph.nodes.map((node) => node.kind))].sort(),
    [graph.nodes],
  );
  const [hidden, setHidden] = useState<Set<string>>(() => new Set(HIDDEN_BY_DEFAULT));
  const [selected, setSelected] = useState<string | null>(null);

  const byId = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const shown = useMemo(
    () => graph.nodes.filter((node) => node.id === graph.root || !hidden.has(node.kind)),
    [graph.nodes, graph.root, hidden],
  );
  const { placed, width, height } = useMemo(() => layout([...shown]), [shown]);
  const edges = graph.edges.filter((edge) => placed.has(edge.source) && placed.has(edge.target));

  const chain = useMemo(
    () => (selected && placed.has(selected) ? chainTo(selected, byId) : []),
    [selected, placed, byId],
  );
  const pathIds = new Set(chain.map((node) => node.id));
  const onPath = (source: string, target: string) =>
    pathIds.has(source) && pathIds.has(target) && byId.get(target)?.via?.from === source;
  const focus = chain.length > 0 ? chain[chain.length - 1] : undefined;

  const toggle = (kind: string) =>
    setHidden((current) => {
      const next = new Set(current);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });

  const select = (id: string) => setSelected((current) => (current === id ? null : id));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Element kinds shown">
        {kinds.map((kind) => {
          const on = !hidden.has(kind);
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

      <div className="max-h-[34rem] overflow-auto rounded-lg border border-border bg-surface-sunken">
        <svg
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={`Detection graph with ${placed.size} elements and ${edges.length} relations`}
        >
          <defs>
            <marker
              id="detection-arrow"
              viewBox="0 0 8 8"
              refX="7"
              refY="4"
              markerWidth="7"
              markerHeight="7"
              orient="auto"
            >
              <path d="M 0 0 L 8 4 L 0 8 z" fill="var(--color-border-strong)" />
            </marker>
            <marker
              id="detection-arrow-on"
              viewBox="0 0 8 8"
              refX="7"
              refY="4"
              markerWidth="7"
              markerHeight="7"
              orient="auto"
            >
              <path d="M 0 0 L 8 4 L 0 8 z" fill="var(--color-primary)" />
            </marker>
          </defs>

          {edges.map((edge) => {
            const from = placed.get(edge.source);
            const to = placed.get(edge.target);
            // An edge that points back or sideways stays in the table below.
            if (!from || !to || to.node.layer <= from.node.layer) return null;
            const active = onPath(edge.source, edge.target);
            const dim = selected !== null && !active;
            return (
              <g key={`${edge.source}|${edge.target}|${edge.relation}`}>
                <path
                  d={edgePath(from, to)}
                  fill="none"
                  stroke={active ? 'var(--color-primary)' : 'var(--color-border-strong)'}
                  strokeWidth={active ? 2 : 1}
                  opacity={dim ? 0.15 : 0.9}
                  markerEnd={`url(#${active ? 'detection-arrow-on' : 'detection-arrow'})`}
                />
                {active ? (
                  <text
                    x={(from.x + NODE_W + to.x) / 2}
                    y={(from.y + to.y) / 2 + NODE_H / 2 - 4}
                    textAnchor="middle"
                    fontSize={10}
                    fill="var(--color-primary)"
                    stroke="var(--color-surface-sunken)"
                    strokeWidth={3}
                    paintOrder="stroke"
                  >
                    {words(edge.relation)}
                  </text>
                ) : null}
              </g>
            );
          })}

          {[...placed.values()].map(({ node, x, y }) => {
            const isAnalyzer = node.kind === 'analyzer';
            const stopped = isAnalyzer && String(node.data.status ?? '') !== 'SUCCESS';
            const dim = selected !== null && !pathIds.has(node.id);
            return (
              <g
                key={node.id}
                transform={`translate(${x} ${y})`}
                tabIndex={0}
                role="button"
                aria-label={`${node.kind} ${node.label}`}
                aria-pressed={selected === node.id}
                opacity={dim ? 0.35 : 1}
                className="cursor-pointer outline-none focus-visible:opacity-80"
                onClick={() => select(node.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    select(node.id);
                  }
                }}
              >
                <title>{`${node.kind}: ${node.label}`}</title>
                <rect
                  width={NODE_W}
                  height={NODE_H}
                  rx={isAnalyzer ? 15 : 6}
                  fill="var(--color-surface-raised)"
                  stroke={strokeOf(node)}
                  strokeWidth={node.id === graph.root || selected === node.id ? 2.5 : 1.5}
                  strokeDasharray={stopped ? '4 3' : undefined}
                />
                <text
                  x={NODE_W / 2}
                  y={NODE_H / 2 + 4}
                  textAnchor="middle"
                  fontSize={11}
                  fill="var(--color-content)"
                  className={isAnalyzer ? undefined : 'font-mono'}
                >
                  {shorten(node.label)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <p className="text-xs text-faint">
        Read left to right: the observable, the sources that looked at it, what they found, and what
        that led to. Select an element to follow it back to where it came from. A dashed outline is
        a source that did not return a result.
      </p>

      {graph.truncated ? (
        <p className="text-xs text-warning">
          The graph was capped at its size limit; some elements are not shown.
        </p>
      ) : null}

      {focus ? (
        <div className="rounded-lg border border-border bg-surface p-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
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
          <h4 className="mt-3 text-xs font-medium text-faint">How it was reached</h4>
          <ol className="mt-1 space-y-1">
            {chain.map((step) => (
              <li key={step.id} className="text-xs">
                {step.via ? (
                  <span className="flex items-center gap-1 pl-1 text-muted">
                    <ArrowDown className="h-3 w-3" aria-hidden />
                    {words(step.via.relation)}
                    {step.via.plugin ? ` · ${step.via.plugin}` : ''}
                  </span>
                ) : null}
                <span className="mt-0.5 flex items-center gap-2">
                  <Badge>{step.kind}</Badge>
                  <span className="break-all font-mono">{step.label}</span>
                </span>
              </li>
            ))}
          </ol>
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
                  <td className="break-all py-1 pr-3 font-mono">
                    {placed.get(edge.source)?.node.label}
                  </td>
                  <td className="py-1 pr-3">{words(edge.relation)}</td>
                  <td className="break-all py-1 pr-3 font-mono">
                    {placed.get(edge.target)?.node.label}
                  </td>
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
