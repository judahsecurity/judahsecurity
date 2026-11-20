"use client";

import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

/**
 * Hand Prowl a logged-in session the agent cannot create itself (captcha,
 * OTP, 2FA, SSO). Either stream it with the Judah Capture extension or upload
 * a DevTools HAR. Credentials go to the identity registry, not the model.
 */
export function CaptureSessionPanel({ sessionId }: { sessionId: string }) {
  const [identity, setIdentity] = useState("user_a");
  const [role, setRole] = useState("");
  const [token, setToken] = useState<{ token: string; expires_at: number } | null>(null);
  const [message, setMessage] = useState("");
  const [pending, setPending] = useState(0);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const apiBase = typeof window !== "undefined" ? `${window.location.origin}/api/v1` : "";

  useEffect(() => {
    let active = true;
    const refresh = () =>
      api.getCaptureStatus(sessionId)
        .then((s) => { if (active) setPending(s.pending_batches); })
        .catch(() => {});
    refresh();
    const timer = setInterval(refresh, 10000);
    return () => { active = false; clearInterval(timer); };
  }, [sessionId]);

  const errorText = (err: unknown) => {
    const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
    return typeof detail === "string" ? detail : "Request failed";
  };

  const issueToken = async () => {
    setBusy(true);
    setMessage("");
    try {
      const issued = await api.createCaptureToken(sessionId, { identity, role });
      setToken(issued);
    } catch (err) {
      setMessage(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const uploadHar = async (file: File) => {
    setBusy(true);
    setMessage("");
    try {
      const har = JSON.parse(await file.text());
      const result = await api.uploadCaptureHar(sessionId, { identity, role, har });
      setMessage(`Queued ${result.accepted} exchanges as "${result.identity}". The running assessment picks them up on its next step.`);
      setPending((n) => n + result.batches);
    } catch (err) {
      setMessage(err instanceof SyntaxError ? "That file is not a valid HAR (JSON)." : errorText(err));
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Capture a logged-in session</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-xs">
        <p className="text-muted-foreground">
          Log in to the target yourself, then hand that session to Prowl as a named test identity.
          Use two identities (for example user_a and user_b) so Prowl can test cross-user access.
          Only in-scope traffic is kept; cookies and tokens are never shown to the model.
        </p>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <Label htmlFor="capture-identity">Identity name</Label>
            <Input id="capture-identity" value={identity} maxLength={40}
                   onChange={(e) => { setIdentity(e.target.value); setToken(null); }} />
          </div>
          <div>
            <Label htmlFor="capture-role">Role (optional)</Label>
            <Input id="capture-role" value={role} maxLength={40} placeholder="customer, admin…"
                   onChange={(e) => { setRole(e.target.value); setToken(null); }} />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" disabled={busy || !identity} onClick={issueToken}>
            Get extension token
          </Button>
          <Button size="sm" variant="outline" disabled={busy || !identity}
                  onClick={() => fileRef.current?.click()}>
            Upload HAR
          </Button>
          <input ref={fileRef} type="file" accept=".har,application/json" className="hidden"
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) uploadHar(f); }} />
        </div>
        {token && (
          <div className="space-y-1 rounded border border-border p-2">
            <p>In the Judah Capture extension, set the API base URL and paste this token
              (valid until {new Date(token.expires_at * 1000).toLocaleTimeString()}):</p>
            <p className="break-all font-mono">{apiBase}</p>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded bg-muted px-1 py-0.5">{token.token}</code>
              <Button size="sm" variant="ghost"
                      onClick={() => navigator.clipboard?.writeText(token.token)
                        .then(() => setMessage("Token copied."))
                        .catch(() => setMessage("Copy failed; select the token instead."))}>
                Copy
              </Button>
            </div>
          </div>
        )}
        {pending > 0 && (
          <p className="text-muted-foreground">{pending} captured batch{pending === 1 ? "" : "es"} waiting for the assessment to pick up.</p>
        )}
        {message && <p role="status">{message}</p>}
      </CardContent>
    </Card>
  );
}
