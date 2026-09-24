import { getAllPosts } from '@/lib/blog'
import { BlogCard } from '@/components/blog-card'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Blog',
  description: 'Security research, tool reviews, and practical guides from Judah Security.',
}

const BLOG_CATEGORIES = ['All', 'Tool Review', 'Research', 'Tutorials', 'News']

export default async function BlogPage({
  searchParams,
}: {
  searchParams: Promise<{ category?: string }>
}) {
  const allPosts = getAllPosts()
  const { category: activeCategory } = await searchParams

  const posts = activeCategory && activeCategory !== 'All'
    ? allPosts.filter((p) => p.category === activeCategory)
    : allPosts

  const featured = posts.filter((p) => p.featured)
  const rest = posts.filter((p) => !p.featured)

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-10">
        <h1 className="text-3xl font-bold text-foreground mb-2">Security Research & Reviews</h1>
        <p className="text-muted-foreground">
          In-depth analysis, tool reviews, and practitioner guides
        </p>
      </div>

      {/* Category filter */}
      <div className="flex flex-wrap gap-2 mb-10">
        {BLOG_CATEGORIES.map((cat) => {
          const isActive = !activeCategory ? cat === 'All' : cat === activeCategory
          return (
            <a
              key={cat}
              href={cat === 'All' ? '/blog' : `/blog?category=${encodeURIComponent(cat)}`}
              className={`px-4 py-2 rounded-lg border text-sm font-medium transition-colors ${
                isActive
                  ? 'border-primary/50 bg-primary/10 text-primary'
                  : 'border-border bg-card text-muted-foreground hover:text-foreground hover:border-border/80'
              }`}
            >
              {cat}
            </a>
          )
        })}
      </div>

      {posts.length === 0 ? (
        <div className="text-center py-20">
          <p className="text-foreground font-medium mb-1">No posts found</p>
          <p className="text-sm text-muted-foreground">Check back soon</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-10">
          {/* Main content */}
          <div className="lg:col-span-2">
            {featured.length > 0 && (
              <div className="mb-10">
                <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-5">
                  Featured
                </h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
                  {featured.map((post) => (
                    <BlogCard key={post.slug} post={post} featured />
                  ))}
                </div>
              </div>
            )}

            {rest.length > 0 && (
              <div>
                <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-5">
                  All Posts
                </h2>
                <div className="rounded-xl border border-border bg-card px-3 py-1">
                  {rest.map((post) => (
                    <BlogCard key={post.slug} post={post} />
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <aside className="space-y-6">
            <div className="rounded-xl border border-border bg-card p-5">
              <h3 className="text-sm font-semibold text-foreground mb-4">Categories</h3>
              <div className="space-y-2">
                {BLOG_CATEGORIES.filter((c) => c !== 'All').map((cat) => {
                  const count = allPosts.filter((p) => p.category === cat).length
                  if (count === 0) return null
                  return (
                    <a
                      key={cat}
                      href={`/blog?category=${encodeURIComponent(cat)}`}
                      className="flex items-center justify-between text-sm text-muted-foreground hover:text-foreground transition-colors py-1"
                    >
                      <span>{cat}</span>
                      <span className="text-xs text-muted-foreground/60 font-mono">{count}</span>
                    </a>
                  )
                })}
              </div>
            </div>

            <div className="rounded-xl border border-border bg-card p-5">
              <h3 className="text-sm font-semibold text-foreground mb-2">About This Blog</h3>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Written by practitioners at Judah Security — an attack surface management,
                offensive security, and advisory company built for decisive teams.
              </p>
            </div>
          </aside>
        </div>
      )}
    </div>
  )
}
