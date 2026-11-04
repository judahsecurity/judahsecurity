import fs from 'fs'
import path from 'path'
import matter from 'gray-matter'

const SURFACES_DIR = path.join(process.cwd(), 'src/content/surfaces')

export interface SurfaceItem {
  slug: string
  title: string
  label: string
  excerpt: string
  order: number
  icon: string
  accent: string
  tags: string[]
  content: string
}

export type SurfaceMeta = Omit<SurfaceItem, 'content'>

function parse(file: string): { slug: string; data: matter.GrayMatterFile<string>['data']; content: string } {
  const slug = file.replace(/\.(mdx|md)$/, '')
  const raw = fs.readFileSync(path.join(SURFACES_DIR, file), 'utf-8')
  const { data, content } = matter(raw)
  return { slug, data, content }
}

function toMeta(slug: string, data: matter.GrayMatterFile<string>['data']): SurfaceMeta {
  return {
    slug,
    title: data.title ?? 'Untitled',
    label: data.label ?? data.title ?? 'Untitled',
    excerpt: data.excerpt ?? '',
    order: data.order ?? 999,
    icon: data.icon ?? 'Shield',
    accent: data.accent ?? 'text-primary border-primary/30 bg-primary/5',
    tags: data.tags ?? [],
  }
}

export function getAllSurfaces(): SurfaceMeta[] {
  if (!fs.existsSync(SURFACES_DIR)) return []

  const files = fs.readdirSync(SURFACES_DIR).filter((f) => f.endsWith('.mdx') || f.endsWith('.md'))

  return files
    .map((file) => {
      const { slug, data } = parse(file)
      return toMeta(slug, data)
    })
    .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title))
}

export function getSurfaceBySlug(slug: string): SurfaceItem | null {
  const candidates = [
    path.join(SURFACES_DIR, `${slug}.mdx`),
    path.join(SURFACES_DIR, `${slug}.md`),
  ]
  const filePath = candidates.find((p) => fs.existsSync(p))
  if (!filePath) return null

  const raw = fs.readFileSync(filePath, 'utf-8')
  const { data, content } = matter(raw)

  return {
    ...toMeta(slug, data),
    content,
  }
}
