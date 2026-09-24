import { notFound } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, Clock, Calendar, Tag } from 'lucide-react'
import { getPostBySlug, getAllPosts } from '@/lib/blog'
import { formatDate } from '@/lib/utils'
import { MDXContent } from '@/components/mdx-content'
import type { Metadata } from 'next'

interface Props {
  params: Promise<{ slug: string }>
}

export async function generateStaticParams() {
  const posts = getAllPosts()
  return posts.map((p) => ({ slug: p.slug }))
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params
  const post = getPostBySlug(slug)
  if (!post) return {}
  return {
    title: post.title,
    description: post.excerpt,
  }
}

export default async function BlogPostPage({ params }: Props) {
  const { slug } = await params
  const post = getPostBySlug(slug)
  if (!post) notFound()

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="max-w-3xl mx-auto">
        {/* Back */}
        <Link
          href="/blog"
          className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Blog
        </Link>

        {/* Header */}
        <header className="mb-10">
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <span className="tag text-primary border-primary/30 bg-primary/5">
              {post.category}
            </span>
            {post.tags.slice(0, 3).map((tag) => (
              <span key={tag} className="tag text-muted-foreground border-border bg-accent/50">
                <Tag className="w-2.5 h-2.5 mr-1" />
                {tag}
              </span>
            ))}
          </div>

          <h1 className="text-3xl md:text-4xl font-bold text-foreground leading-tight mb-6">
            {post.title}
          </h1>

          <p className="text-lg text-muted-foreground leading-relaxed mb-8">
            {post.excerpt}
          </p>

          <div className="flex items-center gap-6 pb-8 border-b border-border">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center">
                <span className="text-sm font-bold text-primary">
                  {post.author.charAt(0)}
                </span>
              </div>
              <div>
                <p className="text-sm font-medium text-foreground">{post.author}</p>
                <p className="text-xs text-muted-foreground">{post.authorRole}</p>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs text-muted-foreground ml-auto">
              <span className="flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5" />
                {formatDate(post.date)}
              </span>
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" />
                {post.readTime} min read
              </span>
            </div>
          </div>
        </header>

        {/* Content */}
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
          <MDXContent source={post.content} />
        </div>

        {/* Footer */}
        <div className="mt-16 pt-8 border-t border-border">
          <div className="flex items-center justify-between">
            <Link
              href="/blog"
              className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              All Posts
            </Link>
            <Link
              href="/tools"
              className="text-sm text-primary hover:text-primary/80 transition-colors font-medium"
            >
              Browse Tools →
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
