'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import { ScanLine, CalendarClock, SlidersHorizontal } from 'lucide-react';

interface NavTab {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}

const tabs: NavTab[] = [
  {
    name: 'Scans',
    href: '/scans',
    icon: ScanLine,
    description: 'Active and completed scans',
  },
  {
    name: 'Schedules',
    href: '/schedules',
    icon: CalendarClock,
    description: 'Recurring scan schedules',
  },
  {
    name: 'Profiles',
    href: '/scan-profiles',
    icon: SlidersHorizontal,
    description: 'Reusable scan settings',
  },
];

export function ScanNavTabs() {
  const pathname = usePathname();

  return (
    <div className="border-b border-border/50 bg-card/30">
      <nav className="flex gap-1 px-6 py-2" aria-label="Scan navigation">
        {tabs.map((tab) => {
          const isActive = pathname.startsWith(tab.href);
          const Icon = tab.icon;

          return (
            <Link
              key={tab.name}
              href={tab.href}
              className={cn(
                'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all',
                isActive
                  ? 'bg-primary/15 text-primary border border-primary/30'
                  : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
              )}
            >
              <Icon className="h-4 w-4" />
              <span>{tab.name}</span>
            </Link>
          );
        })}
      </nav>
    </div>
  );
}
