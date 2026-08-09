'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
  LayoutDashboard,
  Building2,
  Globe,
  Shield,
  Camera,
  ScanLine,
  Network,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Search,
  Users,
  ServerCrash,
  CalendarClock,
  Wrench,
  FileText,
  GitBranch,
  MessageSquare,
  Crosshair,
  Plug,
  Radio,
  FileCode,
  ShieldOff,
  Workflow,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/store/auth';
import { useState } from 'react';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Organizations', href: '/organizations', icon: Building2 },
  { name: 'Assets', href: '/assets', icon: Globe },
  { name: 'Inventory', href: '/inventory', icon: ServerCrash },
  { name: 'Graph', href: '/graph', icon: GitBranch },
  { name: 'Findings', href: '/findings', icon: Shield },
  { name: 'Vulnerability Intel', href: '/vulnerability-intel', icon: Radio },
  { name: 'Detection Coverage', href: '/nuclei-templates', icon: FileCode },
  { name: 'Detection Patterns', href: '/detection-patterns', icon: ShieldOff },
  { name: 'Exceptions', href: '/exceptions', icon: FileText },
  { name: 'Remediation', href: '/remediation', icon: Wrench },
  { name: 'Screenshots', href: '/screenshots', icon: Camera },
  { name: 'Scans', href: '/scans', icon: ScanLine },
  { name: 'Loom', href: '/workflows', icon: Workflow },
  { name: 'Schedules', href: '/schedules', icon: CalendarClock },
  { name: 'Ports', href: '/ports', icon: Network },
  { name: 'Discovery', href: '/discovery', icon: Search },
  { name: 'Agent', href: '/agent', icon: MessageSquare },
  { name: 'Pentest', href: '/pentest', icon: Crosshair },
  { name: 'Integrations', href: '/integrations', icon: Plug },
];

const adminNavigation = [
  { name: 'Users', href: '/users', icon: Users },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div
      className={cn(
        'flex flex-col h-screen bg-card border-r border-border transition-all duration-300',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="flex items-center justify-between h-16 px-3 border-b border-border">
        <div className="flex items-center gap-3 min-w-0">
          {/* Lion head — using pre-cropped favicon.png (clean square, no text) */}
          <div className="relative shrink-0">
            <div className="w-9 h-9 rounded-lg overflow-hidden ring-1 ring-primary/40 shadow-[0_0_14px_hsl(213,100%,62%,0.35)]">
              <img
                src="/favicon.png"
                alt="Judah Security"
                className="w-full h-full object-cover"
              />
            </div>
            {/* Online indicator dot */}
            <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-primary border-2 border-background shadow-[0_0_6px_hsl(213,100%,62%,0.8)]" />
          </div>

          {!collapsed && (
            <div className="flex flex-col min-w-0">
              <span className="font-bold text-sm tracking-wider leading-tight page-title">
                JUDAH SECURITY
              </span>
              <span className="text-[9px] text-primary/60 tracking-[0.2em] uppercase leading-tight">
                ASM Platform
              </span>
            </div>
          )}
        </div>

        <Button
          variant="ghost"
          size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className="ml-auto shrink-0 h-8 w-8"
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </Button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {navigation.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`)
            || (item.href === '/agent' && pathname === '/oracle');
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150',
                isActive
                  ? 'bg-primary/15 text-primary border border-primary/25 shadow-[0_0_12px_hsl(213,100%,62%,0.12)]'
                  : 'text-foreground/90 hover:bg-muted/80 hover:text-foreground border border-transparent'
              )}
            >
              <item.icon className={cn('h-5 w-5 shrink-0', isActive ? 'text-primary drop-shadow-[0_0_6px_hsl(213,100%,62%,0.8)]' : 'text-primary/40')} />
              {!collapsed && <span>{item.name}</span>}
            </Link>
          );
        })}

        {user?.role === 'admin' && (
          <>
            <div className={cn('pt-4 pb-2', !collapsed && 'px-3')}>
              {!collapsed && (
                <span className="text-xs font-semibold uppercase text-primary/50 tracking-widest">
                  Admin
                </span>
              )}
              {collapsed && <div className="border-t border-border" />}
            </div>
            {adminNavigation.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={cn(
                    'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150',
                    isActive
                      ? 'bg-primary/15 text-primary border border-primary/25 shadow-[0_0_12px_hsl(213,100%,62%,0.12)]'
                      : 'text-foreground/90 hover:bg-muted/80 hover:text-foreground border border-transparent'
                  )}
                >
                  <item.icon className={cn('h-5 w-5 shrink-0', isActive ? 'text-primary drop-shadow-[0_0_6px_hsl(213,100%,62%,0.8)]' : 'text-primary/40')} />
                  {!collapsed && <span>{item.name}</span>}
                </Link>
              );
            })}
          </>
        )}
      </nav>

      {/* User section */}
      <div className="border-t border-border p-4">
        {!collapsed ? (
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center">
              <span className="text-sm font-medium">
                {user?.full_name?.charAt(0) || user?.email?.charAt(0) || 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{user?.full_name || user?.email}</p>
              <p className="text-xs text-primary/60 capitalize">{user?.role}</p>
            </div>
            <Button variant="ghost" size="icon" onClick={() => logout()}>
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        ) : (
          <Button variant="ghost" size="icon" onClick={() => logout()} className="w-full">
            <LogOut className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  );
}

