/**
 * A small, safe renderer for the Markdown a model writes in an answer.
 *
 * It understands what answers actually use: paragraphs, **bold**, `code`,
 * nested bullet and numbered lists, headings and fenced code blocks. Anything
 * else is shown as the text it is.
 *
 * It is deliberately not a Markdown engine. There are no links and no images:
 * an auto-loaded remote image in an answer is a way to send the conversation
 * somewhere else, one request at a time. Every piece of text goes through
 * React as a string, so raw HTML in an answer is shown, never executed.
 */

import { Fragment } from 'react';

interface Item {
  text: string;
  ordered: boolean;
  children: Item[];
}

type Block =
  | { kind: 'paragraph'; text: string }
  | { kind: 'heading'; text: string }
  | { kind: 'code'; text: string }
  | { kind: 'list'; ordered: boolean; items: Item[] };

const BULLET = /^(\s*)[-*•]\s+(.*)$/;
const NUMBERED = /^(\s*)\d{1,3}[.)]\s+(.*)$/;
const HEADING = /^#{1,4}\s+(.*)$/;
const FENCE = /^\s*```/;

interface Entry {
  indent: number;
  item: Item;
}

/** Turn the flat list of lines into a tree, following the indentation. */
function nest(entries: Entry[]): Item[] {
  const roots: Item[] = [];
  const stack: Entry[] = [];
  for (const entry of entries) {
    while (stack.length > 0 && (stack[stack.length - 1]?.indent ?? -1) >= entry.indent) stack.pop();
    const parent = stack[stack.length - 1];
    if (parent) parent.item.children.push(entry.item);
    else roots.push(entry.item);
    stack.push(entry);
  }
  return roots;
}

export function parseBlocks(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, '\n').split('\n');
  const blocks: Block[] = [];
  let paragraph: string[] = [];
  let entries: Entry[] = [];
  let listOrdered = false;
  let code: string[] | null = null;

  const flushParagraph = () => {
    if (paragraph.length > 0) blocks.push({ kind: 'paragraph', text: paragraph.join('\n') });
    paragraph = [];
  };
  const flushList = () => {
    if (entries.length > 0) {
      blocks.push({ kind: 'list', ordered: listOrdered, items: nest(entries) });
    }
    entries = [];
  };

  for (const line of lines) {
    if (code !== null) {
      if (FENCE.test(line)) {
        blocks.push({ kind: 'code', text: code.join('\n') });
        code = null;
      } else {
        code.push(line);
      }
      continue;
    }
    if (FENCE.test(line)) {
      flushParagraph();
      flushList();
      code = [];
      continue;
    }

    const bullet = BULLET.exec(line);
    const numbered = bullet ? null : NUMBERED.exec(line);
    if (bullet || numbered) {
      flushParagraph();
      const match = bullet ?? numbered;
      const indent = (match?.[1] ?? '').length;
      const text = (bullet ? bullet[2] : numbered?.[2]) ?? '';
      const ordered = numbered !== null;
      if (entries.length > 0 && ordered !== listOrdered) flushList();
      listOrdered = ordered;
      entries.push({ indent, item: { text, ordered, children: [] } });
      continue;
    }

    if (line.trim() === '') {
      flushParagraph();
      flushList();
      continue;
    }

    const heading = HEADING.exec(line);
    if (heading) {
      flushParagraph();
      flushList();
      blocks.push({ kind: 'heading', text: heading[1] ?? '' });
      continue;
    }

    flushList();
    paragraph.push(line.trim());
  }

  if (code !== null) blocks.push({ kind: 'code', text: code.join('\n') });
  flushParagraph();
  flushList();
  return blocks;
}

/** Bold and code, split out of a line. Everything else is plain text. */
function Inline({ text }: { text: string }) {
  const parts = text.split(/(`[^`\n]+`|\*\*[^*\n]+?\*\*)/g);
  return (
    <>
      {parts.map((part, index) => {
        if (part.length > 2 && part.startsWith('`') && part.endsWith('`')) {
          return (
            <code
              // Parts never reorder, so position is a stable key here.
              key={index}
              className="rounded bg-surface-sunken px-1 py-0.5 font-mono text-[0.85em]"
            >
              {part.slice(1, -1)}
            </code>
          );
        }
        if (part.length > 4 && part.startsWith('**') && part.endsWith('**')) {
          return <strong key={index}>{part.slice(2, -2)}</strong>;
        }
        return <Fragment key={index}>{part}</Fragment>;
      })}
    </>
  );
}

function ItemList({ items, ordered }: { items: Item[]; ordered: boolean }) {
  const List = ordered ? 'ol' : 'ul';
  return (
    <List className={`space-y-1 pl-5 ${ordered ? 'list-decimal' : 'list-disc'} marker:text-faint`}>
      {items.map((item, index) => (
        <li key={index}>
          <Inline text={item.text} />
          {item.children.length > 0 ? (
            <ItemList items={item.children} ordered={item.children[0]?.ordered ?? false} />
          ) : null}
        </li>
      ))}
    </List>
  );
}

export function RichText({ text }: { text: string }) {
  const blocks = parseBlocks(text);
  return (
    <div className="space-y-2.5 break-words text-sm leading-relaxed">
      {blocks.map((block, index) => {
        if (block.kind === 'paragraph') {
          return (
            <p key={index} className="whitespace-pre-line">
              <Inline text={block.text} />
            </p>
          );
        }
        if (block.kind === 'heading') {
          return (
            <p key={index} className="pt-1 font-semibold">
              <Inline text={block.text} />
            </p>
          );
        }
        if (block.kind === 'code') {
          return (
            <pre
              key={index}
              className="max-h-72 overflow-auto rounded-md bg-surface-sunken p-2.5 font-mono text-xs leading-relaxed"
            >
              {block.text}
            </pre>
          );
        }
        return <ItemList key={index} items={block.items} ordered={block.ordered} />;
      })}
    </div>
  );
}
