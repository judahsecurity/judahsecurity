import { notFound } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, Shield } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import {
  Globe,
  Network,
  Cloud,
  AppWindow,
  Code2,
  GitBranch,
  BrainCircuit,
  Smartphone,
  Users,
} from 'lucide-react'
import { getSurfaceBySlug, getAllSurfaces } from '@/lib/surfaces'
import { cn } from '@/lib/utils'
import { MDXContent } from '@/components/mdx-content'
import type { Metadata } from 'next'

interface Props {
  params: { slug: string }
}

const ICONS: Record<string, LucideIcon> = {
  Globe,
  Network,
  Cloud,
  AppWindow,
  Code2,
  GitBranch,
  BrainCircuit,
  Smartphone,
  Users,
  Shield,
}

export async function generateStaticParams() {
  return getAllSurfaces().map((s) => ({ slug: s.slug }))
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const item = getSurfaceBySlug(params.slug)
  if (!item) return {}
  return { title: `${item.label} Attack Surface`, description: item.excerpt }
}

export default function SurfaceDetailPage({ params }: Props) {
  const item = getSurfaceBySlug(params.slug)
  if (!item) notFound()

  const all = getAllSurfaces()
  const idx = all.findIndex((s) => s.slug === item.slug)
  const next = idx >= 0 ? all[(idx + 1) % all.length] : undefined
  const Icon = ICONS[item.icon] ?? Shield

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="max-w-3xl mx-auto">
        <Link
          href="/surfaces"
          className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Attack Surfaces
        </Link>

        <header className="mb-10">
          <div className="flex items-center gap-3 mb-5">
            <div className={cn('w-11 h-11 rounded-lg flex items-center justify-center border', item.accent)}>
              <Icon className="w-5 h-5" />
            </div>
            <span className={cn('tag', item.accent)}>{item.label}</span>
          </div>

          <h1 className="text-3xl md:text-4xl font-bold text-foreground leading-tight mb-5">
            {item.title}
          </h1>

          <p className="text-base text-muted-foreground leading-relaxed pb-8 border-b border-border">
            {item.excerpt}
          </p>
        </header>

        <div
          className="prose prose-invert prose-sm max-w-none
          prose-headings:font-semibold prose-headings:tracking-tight
          prose-h2:text-xl prose-h2:mt-10 prose-h2:mb-4 prose-h2:text-foreground
          prose-h3:text-base prose-h3:mt-8 prose-h3:mb-3 prose-h3:text-foreground
          prose-h4:text-sm prose-h4:mt-6 prose-h4:mb-2 prose-h4:text-foreground
          prose-p:text-muted-foreground prose-p:leading-relaxed
          prose-a:text-primary prose-a:no-underline hover:prose-a:underline
          prose-code:text-primary prose-code:bg-accent prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-xs prose-code:font-mono prose-code:before:content-none prose-code:after:content-none
          prose-pre:bg-card prose-pre:border prose-pre:border-border prose-pre:rounded-lg prose-pre:text-xs
          prose-blockquote:border-l-primary/50 prose-blockquote:text-muted-foreground
          prose-strong:text-foreground prose-strong:font-semibold
          prose-ul:text-muted-foreground prose-ol:text-muted-foreground
          prose-li:marker:text-primary/50
          prose-hr:border-border
          prose-table:text-sm prose-thead:border-border prose-tr:border-border prose-th:text-foreground prose-td:text-muted-foreground"
        >
          <MDXContent source={item.content} />
        </div>

        <div className="mt-16 pt-8 border-t border-border flex items-center justify-between">
          <Link
            href="/surfaces"
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            All Surfaces
          </Link>
          {next && (
            <Link
              href={`/surfaces/${next.slug}`}
              className="inline-flex items-center gap-1.5 text-sm text-primary hover:text-primary/80 transition-colors font-medium"
            >
              {next.label} <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}
