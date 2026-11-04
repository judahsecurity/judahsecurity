'use client';

import { Suspense, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { CheckCircle2, Clock, Loader2, XCircle } from 'lucide-react';

import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { api, getApiErrorMessage } from '@/lib/api';

type Outcome =
  | { kind: 'working'; message: string }
  | { kind: 'connected' | 'requested' | 'error'; message: string };

/**
 * GitHub returns here after an App install (setup URL / OAuth callback URL).
 * The backend links the installation only after confirming the user owns or
 * administers it, which may first require a GitHub authorization round trip.
 */
function GitHubCallbackContent() {
  const params = useSearchParams();
  const router = useRouter();
  const started = useRef(false);
  const [outcome, setOutcome] = useState<Outcome>({ kind: 'working', message: 'Finishing the GitHub connection…' });

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const state = params.get('state');
    const oauthError = params.get('error');
    if (oauthError) {
      setOutcome({ kind: 'error', message: params.get('error_description') || 'GitHub authorization was cancelled.' });
      return;
    }
    if (!state) {
      setOutcome({ kind: 'error', message: 'GitHub did not return the install state. Start the install again from Integrations.' });
      return;
    }
    const installationId = params.get('installation_id');
    void (async () => {
      try {
        const result = await api.completeGitHubAppInstall({
          state,
          installation_id: installationId && /^\d+$/.test(installationId) ? Number(installationId) : undefined,
          setup_action: params.get('setup_action') || undefined,
          code: params.get('code') || undefined,
        });
        if (result.status === 'authorize' && result.authorize_url) {
          setOutcome({ kind: 'working', message: 'Redirecting to GitHub to confirm your account…' });
          window.location.assign(result.authorize_url);
          return;
        }
        if (result.status === 'connected') {
          setOutcome({ kind: 'connected', message: result.message });
          setTimeout(() => router.replace('/integrations'), 2500);
          return;
        }
        setOutcome({ kind: 'requested', message: result.message });
      } catch (error) {
        setOutcome({ kind: 'error', message: getApiErrorMessage(error) });
      }
    })();
  }, [params, router]);

  const icon = {
    working: <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />,
    connected: <CheckCircle2 className="h-6 w-6 text-green-400" />,
    requested: <Clock className="h-6 w-6 text-amber-400" />,
    error: <XCircle className="h-6 w-6 text-red-400" />,
  }[outcome.kind];

  return (
    <MainLayout>
      <Header title="GitHub" subtitle="Source code manager integration" />
      <div className="p-6 flex justify-center">
        <Card className="w-full max-w-lg border border-border">
          <CardContent className="py-8 flex flex-col items-center gap-4 text-center">
            {icon}
            <p className="text-sm" role="status">{outcome.message}</p>
            {outcome.kind !== 'working' && (
              <Link href="/integrations">
                <Button variant="outline">Back to Integrations</Button>
              </Link>
            )}
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}

export default function GitHubCallbackPage() {
  return (
    <Suspense fallback={<div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin" /></div>}>
      <GitHubCallbackContent />
    </Suspense>
  );
}
