import Link from 'next/link'
import { ArrowRight, Shield } from 'lucide-react'
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
import { getAllSurfaces } from '@/lib/surfaces'
import { cn } from '@/lib/utils'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Attack Surfaces',
  description:
    'How Guard discovers, maps, and tests every attack surface — external, internal, cloud, application, source code, CI/CD, LLM, mobile, and user.',
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

export default function SurfacesPage() {
  const surfaces = getAllSurfaces()

  return (
    <div>
      {/* Header */}
      <section className="border-b border-border bg-card/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <p className="text-xs font-mono text-primary uppercase tracking-widest mb-4">Platform</p>
          <h1 className="text-4xl font-bold text-foreground mb-4">Attack Surfaces</h1>
          <p className="text-muted-foreground text-base max-w-2xl leading-relaxed">
            Guard treats each class of exposure as a distinct attack surface — discovered,
            mapped, and tested with purpose-built capabilities, then correlated into a single
            risk picture. Explore how each one works.
          </p>
        </div>
      </section>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {surfaces.map((s) => {
            const Icon = ICONS[s.icon] ?? Shield
            return (
              <Link
                key={s.slug}
                href={`/surfaces/${s.slug}`}
                className="flex flex-col rounded-xl border border-border bg-card p-7 hover:border-primary/30 transition-colors group"
              >
                <div className="flex items-center gap-3 mb-5">
                  <div className={cn('w-9 h-9 rounded-lg flex items-center justify-center border', s.accent)}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className={cn('tag text-xs', s.accent)}>{s.label}</span>
                </div>

                <h2 className="font-bold text-foreground text-lg leading-snug mb-3 group-hover:text-primary transition-colors">
                  {s.title}
                </h2>
                <p className="text-sm text-muted-foreground leading-relaxed line-clamp-4 mb-6 flex-1">
                  {s.excerpt}
                </p>

                <span className="flex items-center gap-1.5 text-sm text-primary font-medium mt-auto">
                  Explore <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                </span>
              </Link>
            )
          })}
        </div>

        {surfaces.length === 0 && (
          <div className="text-center py-24">
            <Shield className="w-10 h-10 text-muted-foreground/20 mx-auto mb-4" />
            <p className="text-muted-foreground text-sm">Attack surface documentation coming soon.</p>
          </div>
        )}

        {/* CTA */}
        <div className="mt-16 rounded-xl border border-primary/20 bg-primary/5 px-8 py-10 text-center">
          <h3 className="text-xl font-bold text-foreground mb-3">Want to see your own attack surface?</h3>
          <p className="text-sm text-muted-foreground max-w-lg mx-auto mb-6">
            Guard maps what attackers see across every surface — and tells you which exposures to
            fix first. Get in touch to see it against your organization.
          </p>
          <Link
            href="mailto:hello@judahsecurity.com"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors"
          >
            Reach Out <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>
    </div>
  )
}
