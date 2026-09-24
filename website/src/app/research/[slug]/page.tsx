import { notFound } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, Clock, Calendar, Download, Tag } from 'lucide-react'
import { getResearchBySlug, getAllResearch } from '@/lib/research'
import { formatDate, cn } from '@/lib/utils'
import { MDXContent } from '@/components/mdx-content'
import type { Metadata } from 'next'

interface Props {
  params: Promise<{ slug: string }>
}

const TYPE_COLORS: Record<string, string> = {
  Whitepaper: 'text-primary border-primary/30 bg-primary/5',
  'Technical Report': 'text-blue-400 border-blue-400/30 bg-blue-400/5',
  'Tool Evaluation': 'text-warning border-warning/30 bg-warning/5',
  'Field Guide': 'text-green-400 border-green-400/30 bg-green-400/5',
  Advisory: 'text-destructive border-destructive/30 bg-destructive/5',
}

export async function generateStaticParams() {
  return getAllResearch().map((r) => ({ slug: r.slug }))
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params
  const item = getResearchBySlug(slug)
  if (!item) return {}
  return { title: item.title, description: item.excerpt }
}

export default async function ResearchDetailPage({ params }: Props) {
  const { slug } = await params
  const item = getResearchBySlug(slug)
  if (!item) notFound()

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="max-w-3xl mx-auto">
        <Link href="/research" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors mb-8">
          <ArrowLeft className="w-4 h-4" />
          Back to Research
        </Link>

        <header className="mb-10">
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <span className={cn('tag', TYPE_COLORS[item.type] ?? 'text-muted-foreground border-border')}>
              {item.type}
            </span>
            {item.downloadable && (
              <span className="flex items-center gap-1.5 tag text-muted-foreground border-border bg-accent/50 cursor-pointer hover:border-primary/30 hover:text-primary transition-colors">
                <Download className="w-3 h-3" />
                PDF Available
              </span>
            )}
            {item.tags.slice(0, 3).map((tag) => (
              <span key={tag} className="tag text-muted-foreground border-border bg-accent/50">
                <Tag className="w-2.5 h-2.5 mr-1" />
                {tag}
              </span>
            ))}
          </div>

          <h1 className="text-3xl md:text-4xl font-bold text-foreground leading-tight mb-5">
            {item.title}
          </h1>

          <p className="text-base text-muted-foreground leading-relaxed mb-8">
            {item.excerpt}
          </p>

          <div className="flex items-center gap-6 pb-8 border-b border-border">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center">
                <span className="text-sm font-bold text-primary">{item.author.charAt(0)}</span>
              </div>
              <div>
                <p className="text-sm font-medium text-foreground">{item.author}</p>
                <p className="text-xs text-muted-foreground">{item.authorRole}</p>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs text-muted-foreground ml-auto">
              <span className="flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5" />
                {formatDate(item.date)}
              </span>
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" />
                {item.readTime} min read
              </span>
            </div>
          </div>
        </header>

        <div className="prose prose-invert prose-sm max-w-none
          prose-headings:font-semibold prose-headings:tracking-tight
          prose-h2:text-xl prose-h2:mt-10 prose-h2:mb-4 prose-h2:text-foreground
          prose-h3:text-base prose-h3:mt-8 prose-h3:mb-3 prose-h3:text-foreground
          prose-p:text-muted-foreground prose-p:leading-relaxed
          prose-a:text-primary prose-a:no-underline hover:prose-a:underline
          prose-code:text-primary prose-code:bg-accent prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-xs prose-code:font-mono prose-code:before:content-none prose-code:after:content-none
          prose-pre:bg-card prose-pre:border prose-pre:border-border prose-pre:rounded-lg prose-pre:text-xs
          prose-blockquote:border-l-primary/50 prose-blockquote:text-muted-foreground
          prose-strong:text-foreground prose-strong:font-semibold
          prose-ul:text-muted-foreground prose-ol:text-muted-foreground
          prose-li:marker:text-primary/50
          prose-hr:border-border
          prose-table:text-sm prose-thead:border-border prose-tr:border-border prose-th:text-foreground prose-td:text-muted-foreground">
          <MDXContent source={item.content} />
        </div>

        <div className="mt-16 pt-8 border-t border-border flex items-center justify-between">
          <Link href="/research" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors">
            <ArrowLeft className="w-4 h-4" />
            All Research
          </Link>
          <Link href="/blog" className="text-sm text-primary hover:text-primary/80 transition-colors font-medium">
            Read the Blog →
          </Link>
        </div>
      </div>
    </div>
  )
}
