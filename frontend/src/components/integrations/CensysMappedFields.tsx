'use client';

export function CensysMappedFields({ values }: { values?: Record<string, unknown> | null }) {
  const fields = Object.entries(values || {});
  if (!fields.length) return null;
  return (
    <div className="rounded-lg border border-border p-3 space-y-2">
      <p className="text-sm font-medium">Censys mapped fields</p>
      <dl className="grid gap-2 text-sm">
        {fields.map(([name, value]) => (
          <div key={name} className="grid grid-cols-[minmax(100px,1fr)_2fr] gap-2 border-t border-border pt-2">
            <dt className="text-muted-foreground break-all">{name}</dt>
            <dd className="font-mono text-xs break-all whitespace-pre-wrap max-h-32 overflow-auto">
              {typeof value === 'string' ? value : JSON.stringify(value)}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
