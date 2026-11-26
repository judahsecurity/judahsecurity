'use client';

import type { ReactNode } from 'react';
import { Bell, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

interface HeaderProps {
  title: string;
  subtitle?: string;
  /** Page-level actions (e.g. a primary button), shown before search. */
  actions?: ReactNode;
}

export function Header({ title, subtitle, actions }: HeaderProps) {
  return (
    <header className="flex items-center justify-between h-16 px-6 border-b border-border bg-card/50 backdrop-blur-sm">
      <div className="flex items-center gap-3">
        <div className="w-1 h-7 rounded-full bg-primary shadow-[0_0_8px_hsl(213,100%,62%,0.7)]" />
        <div>
          <h1 className="text-xl font-bold page-title">{title}</h1>
          {subtitle && <p className="text-xs text-muted-foreground mt-0.5 tracking-wide">{subtitle}</p>}
        </div>
      </div>

      <div className="flex items-center gap-4">
        {actions}
        <div className="relative w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Search..." className="pl-9 bg-background" />
        </div>

        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-5 w-5" />
          <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-destructive text-[10px] font-medium flex items-center justify-center text-white">
            3
          </span>
        </Button>
      </div>
    </header>
  );
}














