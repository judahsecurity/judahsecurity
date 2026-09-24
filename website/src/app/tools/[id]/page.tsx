import { notFound } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, ExternalLink, Github, Star, Tag } from 'lucide-react'
import { getToolById, TOOLS } from '@/lib/tools'
import { cn, formatDate } from '@/lib/utils'
import type { Metadata } from 'next'

interface Props {
  params: Promise<{ id: string }>
}

export async function generateStaticParams() {
  return TOOLS.map((t) => ({ id: t.id }))
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params
  const tool = getToolById(id)
  if (!tool) return {}
  return {
    title: `${tool.name} Review`,
    description: tool.description,
  }
}

export default async function ToolDetailPage({ params }: Props) {
  const { id } = await params
  const tool = getToolById(id)
  if (!tool) notFound()

  const relatedTools = TOOLS.filter(
    (t) => t.id !== tool.id && t.category === tool.category
  ).slice(0, 3)

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="max-w-4xl mx-auto">
        {/* Back */}
        <Link
          href="/tools"
          className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Tools
        </Link>

        {/* Header */}
        <div className="flex items-start gap-5 mb-8">
          <div className="w-16 h-16 rounded-xl bg-accent border border-border flex items-center justify-center flex-shrink-0">
            <span className="text-3xl font-bold text-primary font-mono">
              {tool.name.charAt(0)}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h1 className="text-3xl font-bold text-foreground">{tool.name}</h1>
                <p className="text-muted-foreground mt-1">{tool.tagline}</p>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                {tool.github && (
                  <a
                    href={tool.github}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border bg-card text-sm text-muted-foreground hover:text-foreground hover:border-border/80 transition-colors"
                  >
                    <Github className="w-4 h-4" />
                    GitHub
                  </a>
                )}
                <a
                  href={tool.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
                >
                  <ExternalLink className="w-4 h-4" />
                  Visit Site
                </a>
              </div>
            </div>

            {tool.rating && (
              <div className="flex items-center gap-1 mt-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Star
                    key={i}
                    className={cn(
                      'w-4 h-4',
                      i < tool.rating! ? 'text-warning fill-warning' : 'text-border'
                    )}
                  />
                ))}
                <span className="text-xs text-muted-foreground ml-2">
                  {tool.rating}/5 — Judah Security Rating
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Meta grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-border rounded-xl overflow-hidden mb-10">
          {[
            { label: 'Category', value: tool.category },
            { label: 'Pricing', value: tool.pricing },
            { label: 'Open Source', value: tool.github ? 'Yes' : 'No' },
            { label: 'Last Reviewed', value: tool.lastReviewed ? formatDate(tool.lastReviewed) : 'N/A' },
          ].map((item) => (
            <div key={item.label} className="bg-card p-4">
              <p className="text-xs text-muted-foreground mb-1">{item.label}</p>
              <p className="text-sm font-medium text-foreground">{item.value}</p>
            </div>
          ))}
        </div>

        {/* Description */}
        <div className="prose prose-invert prose-sm max-w-none mb-8">
          <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
          <p className="text-muted-foreground leading-relaxed">{tool.description}</p>
        </div>

        {/* Tags */}
        <div className="mb-10">
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Tags</h3>
          <div className="flex flex-wrap gap-2">
            {tool.tags.map((tag) => (
              <span key={tag} className="flex items-center gap-1 tag text-muted-foreground border-border bg-accent/50">
                <Tag className="w-2.5 h-2.5" />
                {tag}
              </span>
            ))}
          </div>
        </div>

        {/* Related tools */}
        {relatedTools.length > 0 && (
          <div className="pt-8 border-t border-border">
            <h3 className="text-sm font-semibold text-foreground mb-5">
              More in {tool.category}
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {relatedTools.map((related) => (
                <Link
                  key={related.id}
                  href={`/tools/${related.id}`}
                  className="p-4 rounded-lg border border-border bg-card hover:border-primary/25 transition-colors"
                >
                  <p className="font-medium text-foreground text-sm mb-1">{related.name}</p>
                  <p className="text-xs text-muted-foreground line-clamp-2">{related.tagline}</p>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
