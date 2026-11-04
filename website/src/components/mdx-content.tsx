import { MDXRemote } from 'next-mdx-remote/rsc'
import remarkGfm from 'remark-gfm'

interface MDXContentProps {
  source: string
}

const components = {
  pre: ({ children, ...props }: React.HTMLAttributes<HTMLPreElement>) => (
    <pre className="overflow-x-auto rounded-lg border border-border bg-card p-4 text-xs font-mono" {...props}>
      {children}
    </pre>
  ),
  code: ({ children, className, ...props }: React.HTMLAttributes<HTMLElement>) => {
    if (className?.startsWith('language-')) {
      return <code className={className} {...props}>{children}</code>
    }
    return (
      <code className="text-primary bg-accent px-1.5 py-0.5 rounded text-xs font-mono before:content-none after:content-none" {...props}>
        {children}
      </code>
    )
  },
  table: ({ children, ...props }: React.HTMLAttributes<HTMLTableElement>) => (
    <div className="overflow-x-auto my-6">
      <table className="w-full text-sm border-collapse" {...props}>{children}</table>
    </div>
  ),
  th: ({ children, ...props }: React.HTMLAttributes<HTMLTableCellElement>) => (
    <th className="text-left px-4 py-2 border-b border-border text-foreground font-semibold text-xs uppercase tracking-wider" {...props}>
      {children}
    </th>
  ),
  td: ({ children, ...props }: React.HTMLAttributes<HTMLTableCellElement>) => (
    <td className="px-4 py-2 border-b border-border/50 text-muted-foreground text-sm" {...props}>
      {children}
    </td>
  ),
}

export function MDXContent({ source }: MDXContentProps) {
  return (
    <MDXRemote
      source={source}
      components={components}
      options={{ mdxOptions: { remarkPlugins: [remarkGfm] } }}
    />
  )
}
