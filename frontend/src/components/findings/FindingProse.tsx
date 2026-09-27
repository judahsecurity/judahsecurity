import { Fragment } from 'react';

function inline(text: string) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, index) =>
    part.startsWith('**') && part.endsWith('**') ? <strong key={index} className="font-semibold text-foreground">{part.slice(2, -2)}</strong>
      : part.startsWith('`') && part.endsWith('`') ? <code key={index} className="rounded bg-muted px-1 text-xs">{part.slice(1, -1)}</code>
        : <Fragment key={index}>{part}</Fragment>,
  );
}

/** The writeup's common emphasis and lists, rendered as text without trusting embedded HTML. */
export function FindingProse({ text }: { text: string }) {
  return <div className="space-y-3 text-sm text-muted-foreground leading-relaxed break-words">
    {text.split(/\n\s*\n/).filter(Boolean).map((block, index) => {
      const lines = block.trim().split('\n');
      if (lines.every(line => /^\s*[-*]\s+/.test(line))) return <ul key={index} className="list-disc pl-5 space-y-1">{lines.map((line, i) => <li key={i}>{inline(line.replace(/^\s*[-*]\s+/, ''))}</li>)}</ul>;
      if (lines.every(line => /^\s*\d+[.)]\s+/.test(line))) return <ol key={index} className="list-decimal pl-5 space-y-1">{lines.map((line, i) => <li key={i}>{inline(line.replace(/^\s*\d+[.)]\s+/, ''))}</li>)}</ol>;
      return <p key={index} className="whitespace-pre-wrap">{inline(block.replace(/^#{1,6}\s+/gm, ''))}</p>;
    })}
  </div>;
}
