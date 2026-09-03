import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios';

/** Resolve the URL Axios actually requested (baseURL + path), for error text. */
export function resolveAxiosRequestUrl(error: { config?: { baseURL?: string; url?: string; method?: string } } | null | undefined): string {
  const cfg = error?.config;
  if (!cfg) return '';
  const path = String(cfg.url || '');
  if (/^https?:\/\//i.test(path)) return path;
  const base = String(cfg.baseURL || '').replace(/\/+$/, '');
  const rel = path.replace(/^\/+/, '');
  let joined = base && rel ? `${base}/${rel}` : (base || path);
  if (joined.startsWith('/') && typeof window !== 'undefined') {
    joined = `${window.location.origin}${joined}`;
  }
  const method = String(cfg.method || '').toUpperCase();
  return method ? `${method} ${joined}` : joined;
}

/**
 * Extract a user-friendly error message from an API error response.
 * Handles FastAPI's validation error format (detail as array of objects)
 * as well as simple string detail messages.
 */
export function getApiErrorMessage(error: any, fallback: string = 'An error occurred'): string {
  const detail = error?.response?.data?.detail;
  const status = error?.response?.status;
  const data = error?.response?.data;

  // 504 from nginx/ALB while the hunt is still running on the worker.
  if (status === 504) {
    if (typeof detail === 'string' && !/try a more specific/i.test(detail)) return detail;
    return 'The proxy closed the HTTP request. The hunt may still be running — wait for Live steps or reopen this chat. Do not retry yet.';
  }

  // Axios network timeout (no response received)
  if (error?.code === 'ECONNABORTED' || error?.message?.includes('timeout')) {
    return 'The request timed out. The agent may still be running — check back shortly.';
  }

  // No HTTP response at all (DNS, TLS, mixed content, connection refused, CORS,
  // or Chrome net::ERR_HTTP2_PROTOCOL_ERROR from nginx hop-by-hop Connection).
  if (!error?.response && (error?.code === 'ERR_NETWORK' || error?.message === 'Network Error')) {
    const target = resolveAxiosRequestUrl(error);
    const directBackend = /:8000\b|\/\/backend(?:\/|:|\b)|localhost:8000/i.test(target);
    if (directBackend) {
      return `Network Error — the browser never reached ${target}. Use the HTTPS site (nginx on 443), not host:8000.`;
    }
    return target
      ? `Network Error — no HTTP response from ${target}. Yellow REST means WebSocket failed; this is usually nginx HTTP/2 + Connection headers on /api/. Reload nginx, do not retry against :8000.`
      : 'Network Error — no HTTP response from the API. Yellow REST means WebSocket failed; reload nginx so /api/v1/agent/ws/ upgrades.';
  }

  // Cloud LLM credits exhausted (Ollama fallback may also have been unavailable)
  if (status === 402) {
    if (typeof detail === 'string' && detail.trim()) return detail;
    return 'Cloud LLM credits are exhausted. Top up the provider or enable local Ollama fallback.';
  }

  // Cloud LLM API key invalid (agent route). Historically 401; now 502 so the
  // session interceptor does not treat it as a logged-out user.
  if (
    (status === 401 || status === 502) &&
    typeof detail === 'string' &&
    /api key|anthropic|openai|ollama|llm/i.test(detail)
  ) {
    return detail;
  }

  // AI provider (e.g. Anthropic) overloaded - 529 or 503 with overloaded message
  if (status === 529 || status === 503) {
    if (typeof detail === 'string' && (detail.toLowerCase().includes('overloaded') || detail.includes('try again')))
      return detail;
    if (data?.error?.type === 'overloaded_error' || (typeof detail === 'string' && detail.includes('529')))
      return 'The AI provider is temporarily overloaded. Please try again in a few minutes.';
  }
  const rawStr = typeof data === 'string' ? data : JSON.stringify(data || {});
  if (rawStr.includes('overloaded_error') || (rawStr.includes('529') && rawStr.includes('Overloaded')))
    return 'The AI provider is temporarily overloaded. Please try again in a few minutes.';

  if (typeof detail === 'string') {
    return detail;
  }

  if (Array.isArray(detail) && detail.length > 0) {
    // FastAPI validation error format: [{type, loc, msg, input, url}, ...]
    return detail.map((e: any) => {
      if (typeof e === 'string') return e;
      return e.msg || e.message || JSON.stringify(e);
    }).join(', ');
  }
  
  if (error?.response?.data?.message) {
    return error.response.data.message;
  }
  
  if (error?.message) {
    return error.message;
  }
  
  return fallback;
}

// Determine API URL based on environment
// In browser: use same origin (nginx proxies /api to backend)
// In Node.js (SSR): use environment variable or localhost
const getApiUrl = () => {
  if (typeof window !== 'undefined') {
    // Running in browser - use the same origin, nginx proxies /api/ to backend
    const { origin } = window.location;
    return origin;
  }
  // Running on server (SSR) - use env var or default to localhost:8000 for direct access
  return process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
};

const API_URL = getApiUrl();

const ACCESS_TOKEN_STORAGE_KEY = 'token';
const REFRESH_TOKEN_STORAGE_KEY = 'refresh_token';
/** Refresh this many ms before access-token expiry so in-flight UI calls stay valid. */
const ACCESS_TOKEN_REFRESH_SKEW_MS = 60_000;

type RetryableRequestConfig = InternalAxiosRequestConfig & { _authRetry?: boolean };

function decodeJwtPayload(token: string): { exp?: number } | null {
  try {
    const part = token.split('.')[1];
    if (!part) return null;
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function isAccessTokenExpiringSoon(token: string | null, skewMs = ACCESS_TOKEN_REFRESH_SKEW_MS): boolean {
  if (!token) return true;
  const payload = decodeJwtPayload(token);
  if (!payload?.exp) return false;
  return payload.exp * 1000 - Date.now() < skewMs;
}

function isAuthEndpointUrl(url: string | undefined): boolean {
  const u = url || '';
  return u.includes('/auth/login') || u.includes('/auth/refresh') || u.includes('/auth/register');
}

function isNonSessionUnauthorized(error: AxiosError): boolean {
  const data = error.response?.data as { detail?: unknown } | undefined;
  const detail = data?.detail;
  const text = typeof detail === 'string' ? detail : JSON.stringify(detail ?? '');
  return /api key|anthropic|openai|ollama|\bllm\b|x-api-key|worker token|tfasm_/i.test(text);
}

function isRefreshAuthFailure(error: unknown): boolean {
  const status = (error as AxiosError)?.response?.status;
  return status === 401 || status === 403;
}

/** Same-origin API root in the browser so we never call :8000 or a Docker hostname. */
function browserApiOrigin(): string | null {
  if (typeof window === 'undefined') return null;
  return window.location.origin;
}

/**
 * WebSocket origin. Production nginx terminates TLS on 443 and upgrades
 * /api/v1/agent/ws/*. Next.js on :3000 cannot proxy WebSocket upgrades, so
 * talk to the published backend on :8000. Never use a Docker hostname
 * (`backend`) — the browser cannot resolve it (Axios "Network Error" / REST badge).
 */
function browserWebSocketOrigin(): string {
  if (typeof window === 'undefined') {
    return 'ws://localhost:8000';
  }
  const { protocol, hostname, host, port } = window.location;
  const wsProto = protocol === 'https:' ? 'wss:' : 'ws:';
  // Compose override publishes the frontend on :3000 without nginx. Next.js
  // rewrites HTTP /api/* but does not upgrade WebSockets.
  if (port === '3000') {
    return `${wsProto}//${hostname}:8000`;
  }
  return `${wsProto}//${host}`;
}

// ── Jira shared types ─────────────────────────────────────────────────────

export interface JiraIntegration {
  id: number;
  organization_id: number;
  hostname: string;
  email: string;
  default_project_key?: string;
  default_issue_type?: string;
  auto_create_enabled: boolean;
  auto_create_min_severity?: string;
  open_to_close_transitions: string[];
  close_to_open_transitions: string[];
  close_custom_fields: Record<string, string>;
  reopen_custom_fields: Record<string, string>;
  is_active: boolean;
  last_tested_at?: string;
  last_test_ok?: boolean;
  created_at: string;
  updated_at: string;
}

export interface JiraTicket {
  id: number;
  vulnerability_id: number;
  jira_issue_key: string;
  jira_issue_url: string;
  jira_project_key: string;
  jira_issue_type?: string;
  jira_status?: string;
  jira_assignee?: string;
  is_associated: boolean;
  disconnected_at?: string;
  created_at: string;
}

// ── ServiceNow shared types ────────────────────────────────────────────────

export interface ServiceNowIntegration {
  id: number;
  organization_id: number;
  webhook_url: string;
  username?: string;
  has_password: boolean;
  auto_create_enabled: boolean;
  auto_create_min_severity?: string;
  sync_enabled: boolean;
  table_name: string;
  close_state: string;
  reopen_state: string;
  remote_closed_states: string[];
  validate_on_remote_close: boolean;
  accept_close_as: string;
  is_active: boolean;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_delivery_at?: string;
  last_pull_at?: string;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface ServiceNowDelivery {
  id: number;
  vulnerability_id: number;
  snow_sys_id?: string;
  snow_number?: string;
  snow_url?: string;
  snow_state?: string;
  snow_state_label?: string;
  last_synced_at?: string;
  pending_close_validation: boolean;
  pending_close_validation_id?: number;
  last_close_validation_verdict?: string;
  http_status?: number;
  disconnected_at?: string;
  created_at: string;
}

export interface ServiceNowSyncResult {
  ok: boolean;
  message: string;
  state_updated?: boolean;
  work_note_added?: boolean;
  validation_queued?: boolean;
  asm_status_updated?: boolean;
  snow_state?: string;
  snow_state_label?: string;
}

export interface JiraProject {
  key: string;
  name: string;
  project_type?: string;
}

export interface JiraTransition {
  id: string;
  name: string;
  to_status?: string;
}

// ── Censys ASM shared types ────────────────────────────────────────────────

export interface CensysIntegration {
  id: number;
  organization_id: number;
  workspace_name: string;
  import_vulnerabilities: boolean;
  import_assets: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface CensysSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  vulns_created: number;
  vulns_updated: number;
  hosts_seen: number;
  domains_seen: number;
  subdomains_seen: number;
  certificates_seen: number;
  risks_seen: number;
}

// ── HackerOne shared types ─────────────────────────────────────────────────

export interface HackerOneIntegration {
  id: number;
  organization_id: number;
  connection_name: string;
  api_identifier: string;
  import_vulnerabilities: boolean;
  import_scopes: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface HackerOneSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  vulns_created: number;
  vulns_updated: number;
  programs_seen: number;
  scopes_seen: number;
  reports_seen: number;
  reports_skipped: number;
}

export interface HackerOneReportLink {
  id: number;
  vulnerability_id: number;
  integration_id: number;
  hackerone_report_id: string;
  hackerone_report_url: string;
  hackerone_program?: string;
  hackerone_title?: string;
  hackerone_state?: string;
  hackerone_severity?: string;
  hackerone_reporter?: string;
  is_associated: boolean;
  disconnected_at?: string;
  created_at: string;
  updated_at?: string;
}

export interface AkamaiIntegration {
  id: number;
  organization_id: number;
  connection_name: string;
  api_host: string;
  import_configurations: boolean;
  import_hostnames: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface AkamaiSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  configs_seen: number;
  policies_seen: number;
  hostnames_seen: number;
}

export interface CloudflareIntegration {
  id: number;
  organization_id: number;
  connection_name: string;
  zones: string[];
  scanner_ips: string[];
  scan_header_name: string;
  scanner_user_agent: string;
  effective_scanner_ips: string[];
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface CloudflareSyncResult {
  ok: boolean;
  message: string;
  zones_seen: number;
  rules_created: number;
  rules_updated: number;
  rules_skipped: number;
  rules_failed: number;
}

export type PanoramaConnectionMode = 'api' | 'config_export';

export interface PanoramaIntegration {
  id: number;
  organization_id: number;
  name: string;
  connection_mode: PanoramaConnectionMode;
  panorama_host?: string | null;
  device_group?: string | null;
  api_version: string;
  verify_ssl: boolean;
  export_filename?: string | null;
  export_file_size?: number | null;
  export_uploaded_at?: string | null;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface PanoramaSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  addresses_seen: number;
  address_groups_seen: number;
  ips_imported: number;
  cidrs_imported: number;
  fqdns_imported: number;
  ranges_seeded: number;
  assets_missing_from_source: number;
  source?: string;
}

export interface PanoramaUploadResult {
  ok: boolean;
  message: string;
  filename?: string;
  file_size?: number;
  address_count?: number;
  address_groups_count?: number;
  sync?: PanoramaSyncResult | null;
}

export interface F5Integration {
  id: number;
  organization_id: number;
  name: string;
  bigip_host: string;
  partition?: string | null;
  verify_ssl: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface F5SyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  virtuals_seen: number;
  vips_imported: number;
  members_imported: number;
  mappings_seen: number;
  assets_missing_from_source: number;
}

export interface FortiGateIntegration {
  id: number;
  organization_id: number;
  name: string;
  fortigate_host: string;
  vdom?: string | null;
  verify_ssl: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface FortiGateSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  addresses_seen: number;
  address_groups_seen: number;
  ips_imported: number;
  cidrs_imported: number;
  fqdns_imported: number;
  ranges_seeded: number;
  assets_missing_from_source: number;
}

export interface CheckPointIntegration {
  id: number;
  organization_id: number;
  name: string;
  management_host: string;
  domain?: string | null;
  verify_ssl: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface CheckPointSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  hosts_seen: number;
  networks_seen: number;
  ranges_seen: number;
  ips_imported: number;
  cidrs_imported: number;
  ranges_seeded: number;
  assets_missing_from_source: number;
}

export interface CiscoFmcIntegration {
  id: number;
  organization_id: number;
  name: string;
  fmc_host: string;
  domain_uuid?: string | null;
  verify_ssl: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface CiscoFmcSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  hosts_seen: number;
  networks_seen: number;
  ranges_seen: number;
  fqdns_seen: number;
  ips_imported: number;
  cidrs_imported: number;
  fqdns_imported: number;
  ranges_seeded: number;
  assets_missing_from_source: number;
}

export interface SonicWallIntegration {
  id: number;
  organization_id: number;
  name: string;
  sonicwall_host: string;
  verify_ssl: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface SonicWallSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  addresses_seen: number;
  ips_imported: number;
  cidrs_imported: number;
  fqdns_imported: number;
  ranges_seeded: number;
  assets_missing_from_source: number;
}

export interface PfSenseIntegration {
  id: number;
  organization_id: number;
  name: string;
  pfsense_host: string;
  verify_ssl: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface PfSenseSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  aliases_seen: number;
  entries_seen: number;
  ips_imported: number;
  cidrs_imported: number;
  fqdns_imported: number;
  assets_missing_from_source: number;
}

export interface CiscoAsaIntegration {
  id: number;
  organization_id: number;
  name: string;
  asa_host: string;
  verify_ssl: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface CiscoAsaSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  objects_seen: number;
  ips_imported: number;
  cidrs_imported: number;
  fqdns_imported: number;
  ranges_seeded: number;
  assets_missing_from_source: number;
}

export interface AwsWafIntegration {
  id: number;
  organization_id: number;
  name: string;
  regions: string[];
  include_cloudfront: boolean;
  include_regional: boolean;
  is_active: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  last_tested_at?: string;
  last_test_ok?: boolean;
  last_sync_at?: string;
  last_sync_ok?: boolean;
  next_sync_at?: string;
  last_sync_stats?: Record<string, number>;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface AwsWafSyncResult {
  ok: boolean;
  message: string;
  assets_created: number;
  assets_updated: number;
  web_acls_seen: number;
  hostnames_seen: number;
  resources_seen: number;
  assets_missing_from_source: number;
}

class ApiClient {
  private client: AxiosInstance;
  private token: string | null = null;
  private refreshToken: string | null = null;
  private refreshInFlight: Promise<string> | null = null;

  constructor() {
    this.client = axios.create({
      // In browser: nginx proxies /api/v1 -> backend /api/v1
      // In SSR: direct to backend at localhost:8000/api/v1
      baseURL: `${API_URL}/api/v1`,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor to add auth token and pin the browser to same-origin.
    // Module-level API_URL can be baked to localhost:8000 / http://backend:8000
    // at build time; that never reaches nginx and shows up as Axios "Network Error".
    this.client.interceptors.request.use(async (config) => {
      // Relative /api/v1 stays same-origin (nginx or Next rewrites). Never bake
      // http://backend:8000 or :8000 into browser requests.
      if (typeof window !== 'undefined') {
        config.baseURL = '/api/v1';
      }
      if (!isAuthEndpointUrl(config.url) && this.refreshToken && isAccessTokenExpiringSoon(this.token)) {
        try {
          await this.refreshSession();
        } catch {
          // Let the request proceed; the response interceptor handles a 401.
        }
      }
      if (this.token) {
        config.headers.Authorization = `Bearer ${this.token}`;
      }
      return config;
    });

    // Refresh on session 401, then retry once. Never treat LLM/worker 401s as logout.
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const original = error.config as RetryableRequestConfig | undefined;
        if (error.response?.status !== 401 || !original) {
          return Promise.reject(error);
        }
        if (isAuthEndpointUrl(original.url) || original._authRetry || isNonSessionUnauthorized(error)) {
          return Promise.reject(error);
        }
        if (!this.refreshToken) {
          this.forceLogout();
          return Promise.reject(error);
        }

        original._authRetry = true;
        try {
          const newToken = await this.refreshSession();
          original.headers = original.headers ?? {};
          original.headers.Authorization = `Bearer ${newToken}`;
          return this.client(original);
        } catch (refreshError) {
          if (isRefreshAuthFailure(refreshError)) {
            this.forceLogout();
          }
          return Promise.reject(error);
        }
      }
    );

    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
      this.refreshToken = localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY);
    }
  }

  setToken(token: string | null) {
    this.token = token;
    if (typeof window !== 'undefined') {
      if (token) {
        localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, token);
      } else {
        localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
      }
    }
  }

  setRefreshToken(token: string | null) {
    this.refreshToken = token;
    if (typeof window !== 'undefined') {
      if (token) {
        localStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, token);
      } else {
        localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
      }
    }
  }

  getToken() {
    return this.token;
  }

  hasRefreshToken(): boolean {
    return Boolean(this.refreshToken);
  }

  clearSession() {
    this.setToken(null);
    this.setRefreshToken(null);
  }

  /**
   * Return a non-expired access token, refreshing if needed.
   * Used by WebSocket init which cannot go through the Axios interceptor.
   */
  async ensureFreshToken(): Promise<string | null> {
    if (this.token && !isAccessTokenExpiringSoon(this.token)) {
      return this.token;
    }
    if (!this.refreshToken) {
      return this.token;
    }
    try {
      return await this.refreshSession();
    } catch (refreshError) {
      if (isRefreshAuthFailure(refreshError)) {
        this.forceLogout();
        return null;
      }
      return this.token;
    }
  }

  private forceLogout() {
    this.clearSession();
    if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
      window.location.href = '/login';
    }
  }

  private async refreshSession(): Promise<string> {
    if (this.refreshInFlight) {
      return this.refreshInFlight;
    }
    this.refreshInFlight = this.performRefresh().finally(() => {
      this.refreshInFlight = null;
    });
    return this.refreshInFlight;
  }

  private async performRefresh(): Promise<string> {
    const refreshToken = this.refreshToken;
    if (!refreshToken) {
      throw new Error('No refresh token');
    }
    const refreshUrl = typeof window !== 'undefined'
      ? '/api/v1/auth/refresh'
      : `${browserApiOrigin() || API_URL}/api/v1/auth/refresh`;
    const response = await axios.post(
      refreshUrl,
      { refresh_token: refreshToken },
      { headers: { 'Content-Type': 'application/json' } },
    );
    const access = response.data?.access_token as string | undefined;
    const nextRefresh = response.data?.refresh_token as string | undefined;
    if (!access || !nextRefresh) {
      throw new Error('Refresh response missing tokens');
    }
    this.setToken(access);
    this.setRefreshToken(nextRefresh);
    return access;
  }

  // Auth
  async getAuthConfig() {
    const response = await this.client.get('/auth/config');
    return response.data as {
      captcha: { enabled: boolean; provider: string; site_key: string | null };
      public_registration: boolean;
    };
  }

  async login(email: string, password: string, captchaToken?: string) {
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };
    if (captchaToken) {
      headers['X-Captcha-Token'] = captchaToken;
    }

    const response = await this.client.post('/auth/login', formData, { headers });
    this.setToken(response.data.access_token);
    this.setRefreshToken(response.data.refresh_token ?? null);
    return response.data;
  }

  async logout() {
    try {
      await this.client.post('/auth/logout');
    } finally {
      this.clearSession();
    }
  }

  async getCurrentUser() {
    const response = await this.client.get('/auth/me');
    return response.data;
  }

  // Organizations
  async getOrganizations(params?: { skip?: number; limit?: number }) {
    const response = await this.client.get('/organizations/', { params });
    return response.data;
  }

  async getOrganization(id: number) {
    const response = await this.client.get(`/organizations/${id}`);
    return response.data;
  }

  async createOrganization(data: { name: string; description?: string; domains: string[] }) {
    const response = await this.client.post('/organizations/', data);
    return response.data;
  }

  async updateOrganization(id: number, data: { name?: string; description?: string; domains?: string[] }) {
    const response = await this.client.put(`/organizations/${id}`, data);
    return response.data;
  }

  async deleteOrganization(id: number) {
    const response = await this.client.delete(`/organizations/${id}`);
    return response.data;
  }

  async getDiscoverySettings(organizationId: number) {
    const response = await this.client.get(`/organizations/${organizationId}/discovery-settings`);
    return response.data;
  }

  async updateDiscoverySettings(organizationId: number, data: {
    commoncrawl_org_name?: string;
    commoncrawl_keywords?: string[];
    sni_keywords?: string[];
  }) {
    const response = await this.client.put(`/organizations/${organizationId}/discovery-settings`, data);
    return response.data;
  }

  async getProjectSettings(organizationId: number, module: string) {
    const response = await this.client.get(`/organizations/${organizationId}/settings/${module}`);
    return response.data;
  }

  async updateProjectSettingsModule(organizationId: number, module: string, config: Record<string, any>) {
    const response = await this.client.put(`/organizations/${organizationId}/settings/${module}`, { config });
    return response.data;
  }

  // Assets
  async getAssets(params?: { 
    organization_id?: number; 
    skip?: number; 
    limit?: number; 
    search?: string;
    asset_type?: string;
    status?: string;
    is_live?: boolean;
    in_scope?: boolean;
    has_open_ports?: boolean;
    has_risky_ports?: boolean;
    include_cidr?: boolean;
    has_geo?: boolean;
  }) {
    const response = await this.client.get('/assets/', { params });
    return response.data;
  }

  async getAsset(id: number) {
    const response = await this.client.get(`/assets/${id}`);
    return response.data;
  }

  async downloadAssetOpenapi(assetId: number) {
    const response = await this.client.get(`/assets/${assetId}/openapi.yaml`, {
      responseType: 'blob',
    });
    return response.data as Blob;
  }

  async getAssetApiSpec(assetId: number, index: number = 0) {
    const response = await this.client.get(`/assets/${assetId}/api-specs/${index}`);
    return response.data;
  }

  async updateAsset(id: number, data: { 
    in_scope?: boolean; 
    is_monitored?: boolean;
    criticality?: string;
    tags?: string[];
    description?: string;
  }) {
    const response = await this.client.put(`/assets/${id}`, data);
    return response.data;
  }

  async getAssetsByOrganization(orgId: number) {
    const response = await this.client.get(`/organizations/${orgId}/assets`);
    return response.data;
  }

  async getAssetsSummary(organizationId?: number, groupBy?: string) {
    const response = await this.client.get('/assets/stats/summary', {
      params: {
        ...(organizationId ? { organization_id: organizationId } : {}),
        ...(groupBy ? { group_by: groupBy } : {}),
      },
    });
    return response.data;
  }

  /** Lean geo payload for the dashboard world map (not full asset documents). */
  async getGeoAssets(params?: {
    organization_id?: number;
    skip?: number;
    limit?: number;
  }) {
    const response = await this.client.get('/assets/geo', { params });
    return response.data;
  }

  // Findings (Vulnerabilities)
  async getFindings(params?: { 
    organization_id?: number; 
    asset_id?: number;
    severity?: string;
    /** OPES priority category — preferred over scanner severity for triage filters */
    opes_category?: string;
    detected_by?: string;
    skip?: number; 
    limit?: number;
  }) {
    const response = await this.client.get('/vulnerabilities/', { params });
    return response.data;
  }

  async getFindingsSummary(params?: {
    organizationId?: number;
    groupBy?: string;
    includeOutOfScope?: boolean;
  }) {
    const response = await this.client.get('/vulnerabilities/stats/summary', {
      params: {
        ...(params?.organizationId ? { organization_id: params.organizationId } : {}),
        ...(params?.groupBy ? { group_by: params.groupBy } : {}),
        ...(params?.includeOutOfScope ? { include_out_of_scope: true } : {}),
      },
    });
    return response.data;
  }

  // Legacy aliases for backwards compatibility
  async getVulnerabilities(params?: { 
    organization_id?: number; 
    asset_id?: number;
    severity?: string;
    opes_category?: string;
    skip?: number; 
    limit?: number;
  }) {
    return this.getFindings(params);
  }

  async getVulnerabilitiesSummary(organizationId?: number, groupBy?: string) {
    return this.getFindingsSummary({ organizationId, groupBy });
  }

  async getVulnerabilitiesForAsset(assetId: number, params?: { skip?: number; limit?: number }) {
    const response = await this.client.get('/vulnerabilities/', {
      params: { asset_id: assetId, ...params }
    });
    return response.data;
  }

  async getRemediationEfficiency(days: number = 30) {
    const response = await this.client.get('/vulnerabilities/stats/remediation-efficiency', {
      params: { days }
    });
    return response.data;
  }

  async getVulnerabilityExposure() {
    const response = await this.client.get('/vulnerabilities/stats/exposure');
    return response.data;
  }

  async getPrioritizationFunnel(params?: { organizationId?: number; includeOutOfScope?: boolean }) {
    const response = await this.client.get('/vulnerabilities/stats/prioritization-funnel', {
      params: {
        ...(params?.organizationId ? { organization_id: params.organizationId } : {}),
        ...(params?.includeOutOfScope ? { include_out_of_scope: true } : {}),
      },
    });
    return response.data;
  }

  async getVulnerability(vulnId: number) {
    const response = await this.client.get(`/vulnerabilities/${vulnId}`);
    return response.data;
  }

  async updateVulnerability(vulnId: number, data: {
    status?: string;
    assigned_to?: string;
    remediation?: string;
    remediation_deadline?: string;
  }) {
    const response = await this.client.put(`/vulnerabilities/${vulnId}`, data);
    return response.data;
  }

  async createVulnerability(data: {
    title: string;
    severity: string;
    asset_id: number;
    description?: string;
    cvss_score?: number;
    cvss_vector?: string;
    cve_id?: string;
    cwe_id?: string;
    references?: string[];
    detected_by?: string;
    evidence?: string;
    proof_of_concept?: string;
    remediation?: string;
    tags?: string[];
    metadata?: Record<string, any>;
    is_manual?: boolean;
    impact?: string;
    affected_component?: string;
    steps_to_reproduce?: string;
  }) {
    const response = await this.client.post('/vulnerabilities/', data);
    return response.data;
  }

  async deleteVulnerability(vulnId: number) {
    const response = await this.client.delete(`/vulnerabilities/${vulnId}`);
    return response.data;
  }

  async bulkUpdateVulnerabilities(data: {
    vulnerability_ids: number[];
    status?: string;
    assigned_to?: string;
    remediation_deadline?: string;
  }) {
    const response = await this.client.post('/vulnerabilities/bulk-update', data);
    return response.data;
  }

  // Finding validation (native detector / steps replay on scanner)
  async validateFinding(vulnId: number) {
    const response = await this.client.post(`/vulnerabilities/${vulnId}/validate`);
    return response.data;
  }

  async askMarcus(vulnId: number) {
    const response = await this.client.post(`/vulnerabilities/${vulnId}/risk-assessment/ask`);
    return response.data;
  }

  async writeRiskAssessment(vulnId: number, assessment: Record<string, unknown>) {
    const response = await this.client.post(`/vulnerabilities/${vulnId}/risk-assessment`, {
      assessment,
    });
    return response.data;
  }

  async getValidationResult(vulnId: number) {
    const response = await this.client.get(`/vulnerabilities/${vulnId}/validation`);
    return response.data;
  }

  async createDetectionFeedback(vulnId: number, data: { logic_issue: string; verdict?: string }) {
    const response = await this.client.post(`/vulnerabilities/${vulnId}/detection-feedback`, data);
    return response.data;
  }

  async getDetectionFeedback(params?: { template_id?: string; limit?: number }) {
    const response = await this.client.get('/detection-feedback', { params });
    return response.data;
  }

  // Pattern-based detection suppression
  async getDetectionSuppressions(params?: {
    status?: string;
    template_id?: string;
    include_coverage?: boolean;
    limit?: number;
  }) {
    const response = await this.client.get('/detection-suppression', { params });
    return response.data;
  }

  async evaluateDetectionPatterns() {
    const response = await this.client.post('/detection-suppression/evaluate');
    return response.data;
  }

  async approveDetectionSuppression(suppressionId: number) {
    const response = await this.client.post(`/detection-suppression/${suppressionId}/approve`);
    return response.data;
  }

  async dismissDetectionSuppression(suppressionId: number) {
    const response = await this.client.post(`/detection-suppression/${suppressionId}/dismiss`);
    return response.data;
  }

  async validateSuppressionSample(suppressionId: number, limit?: number) {
    const response = await this.client.post(
      `/detection-suppression/${suppressionId}/validate-sample`,
      null,
      { params: limit ? { limit } : undefined }
    );
    return response.data;
  }

  // Scans
  async getScans(params?: { organization_id?: number; skip?: number; limit?: number }) {
    const response = await this.client.get('/scans/', { params });
    return response.data;
  }

  async getScanQueueStatus() {
    const response = await this.client.get('/scans/queue/status');
    return response.data;
  }

  async getScan(id: number) {
    const response = await this.client.get(`/scans/${id}`);
    return response.data;
  }

  async createScan(data: {
    name: string;
    organization_id: number;
    scan_type: string;
    targets?: string[];
    label_ids?: number[];
    match_all_labels?: boolean;
    profile_id?: number;
    config?: Record<string, any>;
  }) {
    const response = await this.client.post('/scans/', data);
    return response.data;
  }

  async createScanByLabel(data: {
    name: string;
    organization_id: number;
    scan_type: string;
    label_ids: number[];
    match_all_labels?: boolean;
    config?: Record<string, any>;
  }) {
    const response = await this.client.post('/scans/by-label', data);
    return response.data;
  }

  async cancelScan(id: number) {
    const response = await this.client.post(`/scans/${id}/cancel`);
    return response.data;
  }

  async retryScan(id: number) {
    const response = await this.client.post(`/scans/${id}/retry`);
    return response.data;
  }

  async rescan(id: number) {
    const response = await this.client.post(`/scans/${id}/rescan`);
    return response.data;
  }

  async previewScanByLabels(labelIds: number[], organizationId: number, matchAll: boolean = false) {
    const response = await this.client.get('/scans/labels/preview', {
      params: { label_ids: labelIds, organization_id: organizationId, match_all: matchAll }
    });
    return response.data;
  }

  // Scan Schedules (Continuous Monitoring)
  async getScanSchedules(params?: { organization_id?: number; scan_type?: string; is_enabled?: boolean }) {
    const response = await this.client.get('/scan-schedules/', { params });
    return response.data;
  }

  async getScanSchedulesSummary(organizationId?: number) {
    const response = await this.client.get('/scan-schedules/summary', {
      params: organizationId ? { organization_id: organizationId } : {}
    });
    return response.data;
  }

  async getScanScheduleTypes() {
    const response = await this.client.get('/scan-schedules/scan-types');
    return response.data;
  }

  async createScanSchedule(data: {
    name: string;
    organization_id: number;
    scan_type: string;
    frequency: string;
    targets?: string[];
    label_ids?: number[];
    match_all_labels?: boolean;
    config?: Record<string, any>;
    run_at_hour?: number;
    run_on_day?: number;
    is_enabled?: boolean;
    notify_on_findings?: boolean;
    notification_emails?: string[];
  }) {
    const response = await this.client.post('/scan-schedules/', data);
    return response.data;
  }

  async updateScanSchedule(scheduleId: number, data: Record<string, any>) {
    const response = await this.client.put(`/scan-schedules/${scheduleId}`, data);
    return response.data;
  }

  async deleteScanSchedule(scheduleId: number) {
    const response = await this.client.delete(`/scan-schedules/${scheduleId}`);
    return response.data;
  }

  async toggleScanSchedule(scheduleId: number) {
    const response = await this.client.post(`/scan-schedules/${scheduleId}/toggle`);
    return response.data;
  }

  async triggerScanSchedule(scheduleId: number, overrides?: { override_targets?: string[]; override_config?: Record<string, any> }) {
    const response = await this.client.post(`/scan-schedules/${scheduleId}/trigger`, overrides || {});
    return response.data;
  }

  async getScanScheduleHistory(scheduleId: number, limit: number = 20) {
    const response = await this.client.get(`/scan-schedules/${scheduleId}/history`, {
      params: { limit }
    });
    return response.data;
  }

  // Tools Status
  async getToolsStatus() {
    const response = await this.client.get('/tools/status');
    return response.data;
  }

  async getToolStatus(toolId: string) {
    const response = await this.client.get(`/tools/${toolId}`);
    return response.data;
  }

  async testTool(toolId: string, target: string = 'example.com') {
    const response = await this.client.post(`/tools/${toolId}/test`, null, {
      params: { target }
    });
    return response.data;
  }

  // Discovery
  async runDiscovery(organizationId: number, domain: string) {
    const response = await this.client.post('/discovery/run', {
      organization_id: organizationId,
      domain,
    });
    return response.data;
  }

  // Geo-location enrichment
  async enrichAssetsGeolocation(options?: {
    organizationId?: number;
    limit?: number;
    provider?: 'ip-api' | 'ipinfo' | 'whoisxml';
    ipinfoToken?: string;
    whoisxmlApiKey?: string;
    force?: boolean;
  }) {
    const params: any = { limit: options?.limit || 50 };
    if (options?.organizationId) params.organization_id = options.organizationId;
    if (options?.provider) params.provider = options.provider;
    if (options?.ipinfoToken) params.ipinfo_token = options.ipinfoToken;
    if (options?.whoisxmlApiKey) params.whoisxml_api_key = options.whoisxmlApiKey;
    if (options?.force) params.force = true;
    const response = await this.client.post('/assets/enrich-geolocation', null, { params });
    return response.data;
  }

  async enrichAssetGeolocation(assetId: number, options?: {
    provider?: 'ip-api' | 'ipinfo' | 'whoisxml';
    ipinfoToken?: string;
    whoisxmlApiKey?: string;
  }) {
    const params: any = {};
    if (options?.provider) params.provider = options.provider;
    if (options?.ipinfoToken) params.ipinfo_token = options.ipinfoToken;
    if (options?.whoisxmlApiKey) params.whoisxml_api_key = options.whoisxmlApiKey;
    const response = await this.client.post(`/assets/${assetId}/enrich-geolocation`, null, { params });
    return response.data;
  }

  async getGeoStats(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/assets/geo-stats', { params });
    return response.data;
  }

  // Screenshots
  async getScreenshots(params?: { organization_id?: number; asset_id?: number; skip?: number; limit?: number }) {
    const response = await this.client.get('/screenshots/', { params });
    return response.data;
  }

  async getAssetScreenshots(assetId: number) {
    const response = await this.client.get(`/screenshots/asset/${assetId}`);
    return response.data;
  }

  getScreenshotImageUrl(screenshotId: number): string {
    const token = this.getToken();
    // Use same origin - nginx proxies /api/ to backend
    let apiUrl = 'http://localhost:8000';
    if (typeof window !== 'undefined') {
      apiUrl = window.location.origin;
    }
    return `${apiUrl}/api/v1/screenshots/image/${screenshotId}?token=${token}`;
  }

  async captureScreenshot(assetId: number) {
    const response = await this.client.post(`/screenshots/capture/asset/${assetId}`);
    return response.data;
  }

  async getScreenshotStatus() {
    const response = await this.client.get('/screenshots/status');
    return response.data;
  }

  async getScreenshotSchedules() {
    const response = await this.client.get('/screenshots/schedules');
    return response.data;
  }

  // Nuclei
  async getNucleiFindings(params?: { organization_id?: number; severity?: string; skip?: number; limit?: number }) {
    const response = await this.client.get('/nuclei/findings', { params });
    return response.data;
  }

  async runNucleiScan(data: { organization_id: number; targets: string[]; severity?: string[] }) {
    const response = await this.client.post('/nuclei/scan', data);
    return response.data;
  }

  // External Discovery
  async getExternalDiscoveryServices(organizationId: number) {
    const response = await this.client.get('/external-discovery/services', {
      params: { organization_id: organizationId }
    });
    return response.data;
  }

  async runExternalDiscovery(data: { 
    organization_id: number; 
    domain: string; 
    include_paid_sources?: boolean;
    include_free_sources?: boolean;
    organization_names?: string[];
    registration_emails?: string[];
    create_assets?: boolean;
    skip_existing?: boolean;
    enumerate_discovered_domains?: boolean;
    max_domains_to_enumerate?: number;
    // Common Crawl comprehensive search options
    commoncrawl_org_name?: string;
    commoncrawl_keywords?: string[];
    // SNI IP Ranges - Cloud Asset Discovery
    include_sni_discovery?: boolean;
    sni_keywords?: string[];
    // Technology fingerprinting options
    run_technology_scan?: boolean;
    max_technology_scan?: number;
    // Screenshot capture options
    run_screenshots?: boolean;
    max_screenshots?: number;
    screenshot_timeout?: number;
  }) {
    // Discovery can take a long time with multiple sources (Common Crawl, SNI, etc.)
    // Use a 5-minute timeout for this operation
    const response = await this.client.post('/external-discovery/run', data, {
      timeout: 300000  // 5 minutes
    });
    return response.data;
  }

  async runSingleSourceDiscovery(data: {
    organization_id: number;
    domain: string;
    source: string;
    create_assets?: boolean;
  }) {
    const response = await this.client.post('/external-discovery/run/source', data);
    return response.data;
  }

  // Read-only preview of what reverse-NS/MX/WHOIS discovery would pivot on.
  // Spends no purchase credits (reverse-WHOIS uses free preview mode).
  async getReversePivots(organizationId: number, domain?: string, whoisPreview: boolean = true) {
    const response = await this.client.get(`/external-discovery/reverse-pivots/${organizationId}`, {
      params: { domain: domain || undefined, whois_preview: whoisPreview },
    });
    return response.data;
  }

  // Run reverse-NS/MX discovery on an explicitly-selected set of pivots.
  // This spends provider credits, bounded by the selected hosts.
  async runReverseDiscovery(data: {
    organization_id: number;
    domain?: string;
    nameservers: string[];
    mailservers: string[];
    create_assets?: boolean;
    enumerate_discovered_domains?: boolean;
    max_domains_to_enumerate?: number;
  }) {
    const response = await this.client.post('/external-discovery/run/reverse', data, {
      timeout: 300000,  // reverse lookups can page through many results
    });
    return response.data;
  }

  async getApiConfigs(organizationId: number) {
    const response = await this.client.get(`/external-discovery/configs/${organizationId}`);
    return response.data;
  }

  async saveApiConfig(organizationId: number, data: {
    service_name: string;
    api_key?: string;
    api_user?: string;
    api_secret?: string;
    config?: Record<string, any>;
  }) {
    const response = await this.client.post(`/external-discovery/configs/${organizationId}`, data);
    return response.data;
  }

  async enrichDomainsDns(options?: {
    organizationId?: number;
    domainIds?: number[];
    limit?: number;
  }) {
    const params: any = {};
    if (options?.organizationId) params.organization_id = options.organizationId;
    if (options?.limit) params.limit = options.limit;
    
    const body: any = {};
    if (options?.domainIds) body.domain_ids = options.domainIds;
    
    const response = await this.client.post('/external-discovery/enrich-dns', body, { params });
    return response.data;
  }

  async getAssetDnsRecords(assetId: number, refresh: boolean = false) {
    const response = await this.client.get(`/external-discovery/dns/${assetId}`, {
      params: { refresh }
    });
    return response.data;
  }

  async enrichDomainsWhois(options?: {
    organizationId?: number;
    domainIds?: number[];
    expectedRegistrant?: string;
    limit?: number;
  }) {
    const params: any = {};
    if (options?.organizationId) params.organization_id = options.organizationId;
    if (options?.expectedRegistrant) params.expected_registrant = options.expectedRegistrant;
    if (options?.limit) params.limit = options.limit;
    
    const body: any = {};
    if (options?.domainIds) body.domain_ids = options.domainIds;
    
    const response = await this.client.post('/external-discovery/enrich-whois', body, { params });
    return response.data;
  }

  async getAssetWhois(assetId: number, refresh: boolean = false) {
    const response = await this.client.get(`/external-discovery/whois/${assetId}`, {
      params: { refresh }
    });
    return response.data;
  }

  async deleteAsset(assetId: number) {
    await this.client.delete(`/assets/${assetId}`);
  }

  async bulkDeleteAssets(assetIds: number[]) {
    const results = { deleted: 0, failed: 0, errors: [] as string[] };
    for (const id of assetIds) {
      try {
        await this.client.delete(`/assets/${id}`);
        results.deleted++;
      } catch (error: any) {
        results.failed++;
        results.errors.push(`Asset ${id}: ${error?.response?.data?.detail || error.message}`);
      }
    }
    return results;
  }

  // Cascading Scope Management
  async setAssetScopeWithCascade(assetId: number, inScope: boolean, cascadeToSubdomains: boolean = true) {
    const response = await this.client.post(`/assets/${assetId}/set-scope`, null, {
      params: { in_scope: inScope, cascade_to_subdomains: cascadeToSubdomains }
    });
    return response.data;
  }

  async cleanupUnattributedPaas(params: {
    organization_id: number;
    action?: 'preview' | 'out_of_scope' | 'delete';
    confirm?: boolean;
    include_already_out_of_scope?: boolean;
  }) {
    const response = await this.client.post('/assets/cleanup-unattributed-paas', null, {
      params: {
        organization_id: params.organization_id,
        action: params.action ?? 'preview',
        confirm: params.confirm ?? false,
        include_already_out_of_scope: params.include_already_out_of_scope ?? false,
      },
    });
    return response.data as {
      organization_id: number;
      action: string;
      matched: number;
      updated: number;
      deleted: number;
      findings_closed: number;
      attribution_tokens: string[];
      preview: Array<{
        id: number;
        value: string;
        asset_type?: string;
        in_scope?: boolean;
        discovery_source?: string;
        reason: string;
        paas_suffix?: string;
      }>;
    };
  }

  async deleteAssetWithSubdomains(assetId: number, confirm: boolean = false) {
    const response = await this.client.delete(`/assets/${assetId}/with-subdomains`, {
      params: { confirm }
    });
    return response.data;
  }

  async bulkSetScopeWithCascade(assetIds: number[], inScope: boolean, cascadeToSubdomains: boolean = true) {
    const response = await this.client.post('/assets/bulk-set-scope', assetIds, {
      params: { in_scope: inScope, cascade_to_subdomains: cascadeToSubdomains }
    });
    return response.data;
  }

  // VirusTotal lookups
  async lookupVirusTotal(assetId: number) {
    const response = await this.client.post(`/assets/${assetId}/virustotal-lookup`);
    return response.data;
  }

  async bulkLookupVirusTotal(assetIds: number[]) {
    const response = await this.client.post('/assets/bulk-virustotal-lookup', assetIds);
    return response.data;
  }

  // Create Asset (add domain manually)
  async createAsset(data: {
    organization_id: number;
    name: string;
    value: string;
    asset_type?: string;
    in_scope?: boolean;
    discovery_source?: string;
    association_reason?: string;
  }) {
    const response = await this.client.post('/assets/', data);
    return response.data;
  }

  async createAssetsBulk(assets: Array<{
    organization_id: number;
    name: string;
    value: string;
    asset_type?: string;
    in_scope?: boolean;
  }>) {
    const response = await this.client.post('/assets/bulk', assets);
    return response.data;
  }

  // Acquisitions / M&A
  async getAcquisitions(params?: { 
    organization_id?: number; 
    status?: string;
    skip?: number; 
    limit?: number 
  }) {
    const response = await this.client.get('/acquisitions/', { params });
    return response.data;
  }

  async getAcquisitionsSummary(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/acquisitions/summary', { params });
    return response.data;
  }

  async getAcquisition(acquisitionId: number) {
    const response = await this.client.get(`/acquisitions/${acquisitionId}`);
    return response.data;
  }

  async createAcquisition(data: {
    organization_id: number;
    target_name: string;
    target_domain?: string;
    target_domains?: string[];
    target_description?: string;
    target_industry?: string;
    target_country?: string;
    acquisition_type?: string;
    status?: string;
    announced_date?: string;
    closed_date?: string;
    deal_value?: number;
    website_url?: string;
    linkedin_url?: string;
  }) {
    const response = await this.client.post('/acquisitions/', data);
    return response.data;
  }

  async updateAcquisition(acquisitionId: number, data: Record<string, any>) {
    const response = await this.client.put(`/acquisitions/${acquisitionId}`, data);
    return response.data;
  }

  async deleteAcquisition(acquisitionId: number) {
    const response = await this.client.delete(`/acquisitions/${acquisitionId}`);
    return response.data;
  }

  async importAcquisitionsFromTracxn(organizationName: string, organizationId: number = 1, limit: number = 20) {
    const response = await this.client.post('/acquisitions/import-from-tracxn', null, {
      params: { organization_id: organizationId, organization_name: organizationName, limit }
    });
    return response.data;
  }

  async discoverDomainsForAcquisition(acquisitionId: number) {
    const response = await this.client.post(`/acquisitions/${acquisitionId}/discover-domains`);
    return response.data;
  }

  async getAcquisitionAssets(acquisitionId: number) {
    const response = await this.client.get(`/acquisitions/${acquisitionId}/assets`);
    return response.data;
  }

  async addDomainToAcquisition(acquisitionId: number, domain: string) {
    const response = await this.client.post(`/acquisitions/${acquisitionId}/add-domain`, null, {
      params: { domain }
    });
    return response.data;
  }

  // Ports
  async getPorts(params?: { 
    organization_id?: number; 
    asset_id?: number; 
    skip?: number; 
    limit?: number;
    is_risky?: boolean;
    state?: string;
    port?: number;
    service?: string;
  }) {
    const response = await this.client.get('/ports/', { params });
    return response.data;
  }

  async runPortScan(data: { organization_id: number; targets: string[]; ports?: string }) {
    const response = await this.client.post('/ports/scan', data);
    return response.data;
  }

  // Users (Admin)
  async getUsers() {
    const response = await this.client.get('/users');
    return response.data;
  }

  async createUser(data: { email: string; username: string; password: string; full_name: string; role?: string; organization_id?: number | null; must_change_password?: boolean }) {
    const response = await this.client.post('/users', data);
    return response.data;
  }

  async changePassword(currentPassword: string, newPassword: string) {
    const response = await this.client.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
    return response.data;
  }

  async forcePasswordReset(userId: number) {
    const response = await this.client.post(`/users/${userId}/force-password-reset`);
    return response.data;
  }

  // Wayback URLs
  async getWaybackStatus() {
    const response = await this.client.get('/waybackurls/status');
    return response.data;
  }

  async fetchWaybackUrls(data: {
    domain: string;
    no_subs?: boolean;
    timeout?: number;
  }) {
    const response = await this.client.post('/waybackurls/fetch', data);
    return response.data;
  }

  async fetchWaybackUrlsBatch(data: {
    domains: string[];
    no_subs?: boolean;
    timeout?: number;
    max_concurrent?: number;
  }) {
    const response = await this.client.post('/waybackurls/fetch/batch', data);
    return response.data;
  }

  async fetchWaybackUrlsForOrganization(data: {
    organization_id: number;
    include_subdomains?: boolean;
    timeout_per_domain?: number;
    max_concurrent?: number;
  }) {
    const response = await this.client.post('/waybackurls/fetch/organization', data);
    return response.data;
  }

  // Netblocks / CIDR ranges
  async getNetblocks(params?: { 
    organization_id?: number; 
    is_owned?: boolean; 
    in_scope?: boolean;
    ip_version?: string;
    skip?: number; 
    limit?: number 
  }) {
    const response = await this.client.get('/netblocks/', { params });
    return response.data;
  }

  async getNetblockSummary(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/netblocks/summary', { params });
    return response.data;
  }

  async getNetblock(netblockId: number) {
    const response = await this.client.get(`/netblocks/${netblockId}`);
    return response.data;
  }

  async discoverNetblocks(data: {
    organization_id: number;
    search_terms: string[];
    include_variations?: boolean;
  }) {
    const response = await this.client.post('/netblocks/discover', data);
    return response.data;
  }

  async updateNetblock(netblockId: number, data: {
    is_owned?: boolean;
    in_scope?: boolean;
    description?: string;
    tags?: string[];
  }) {
    const response = await this.client.put(`/netblocks/${netblockId}`, data);
    return response.data;
  }

  async toggleNetblockScope(netblockId: number) {
    const response = await this.client.put(`/netblocks/${netblockId}/toggle-scope`);
    return response.data;
  }

  async toggleNetblockOwnership(netblockId: number) {
    const response = await this.client.put(`/netblocks/${netblockId}/toggle-ownership`);
    return response.data;
  }

  async bulkUpdateNetblockScope(netblockIds: number[], inScope: boolean) {
    const response = await this.client.post('/netblocks/bulk-scope', null, {
      params: { netblock_ids: netblockIds, in_scope: inScope }
    });
    return response.data;
  }

  // Label API methods
  async getLabels(params?: { organization_id?: number; search?: string }) {
    const response = await this.client.get('/labels/', { params });
    return response.data;
  }

  async getLabelColors() {
    const response = await this.client.get('/labels/colors');
    return response.data;
  }

  async getLabel(labelId: number) {
    const response = await this.client.get(`/labels/${labelId}`);
    return response.data;
  }

  async createLabel(data: { name: string; color?: string; description?: string; organization_id: number }) {
    const response = await this.client.post('/labels/', data);
    return response.data;
  }

  async quickCreateLabel(name: string, organizationId: number, color?: string) {
    const response = await this.client.post('/labels/quick-create', null, {
      params: { name, organization_id: organizationId, color }
    });
    return response.data;
  }

  async updateLabel(labelId: number, data: { name?: string; color?: string; description?: string }) {
    const response = await this.client.put(`/labels/${labelId}`, data);
    return response.data;
  }

  async deleteLabel(labelId: number) {
    const response = await this.client.delete(`/labels/${labelId}`);
    return response.data;
  }

  async assignAssetsToLabel(labelId: number, assetIds: number[]) {
    const response = await this.client.post(`/labels/${labelId}/assets`, assetIds);
    return response.data;
  }

  async removeAssetsFromLabel(labelId: number, assetIds: number[]) {
    const response = await this.client.delete(`/labels/${labelId}/assets`, {
      params: { asset_ids: assetIds }
    });
    return response.data;
  }

  async bulkAssignLabels(data: { asset_ids: number[]; add_labels: number[]; remove_labels: number[] }) {
    const response = await this.client.post('/labels/bulk-assign', data);
    return response.data;
  }

  async getLabelsForAsset(assetId: number) {
    const response = await this.client.get(`/labels/by-asset/${assetId}`);
    return response.data;
  }

  async searchAssetsByLabels(labelIds: number[], matchAll: boolean = false, organizationId?: number) {
    const response = await this.client.get('/labels/search-assets', {
      params: { label_ids: labelIds, match_all: matchAll, organization_id: organizationId }
    });
    return response.data;
  }

  // Generic methods for direct API calls
  async get(url: string, params?: any, config?: { timeout?: number; headers?: Record<string, string> }) {
    return this.client.get(url, { params, ...config });
  }

  async post(url: string, data?: any, config?: { params?: any; headers?: Record<string, string> }) {
    return this.client.post(url, data, config);
  }

  async put(url: string, data?: any) {
    return this.client.put(url, data);
  }

  async delete(url: string) {
    return this.client.delete(url);
  }

  // Generic request method for flexible API calls
  async request(url: string, options?: { 
    method?: string; 
    body?: string; 
    params?: any;
    headers?: Record<string, string>;
  }) {
    const method = options?.method?.toUpperCase() || 'GET';
    const config: any = {
      headers: options?.headers || {},
    };
    
    if (options?.params) {
      config.params = options.params;
    }

    let data: any = undefined;
    if (options?.body) {
      try {
        data = JSON.parse(options.body);
      } catch {
        data = options.body;
      }
    }

    switch (method) {
      case 'POST':
        const postRes = await this.client.post(url, data, config);
        return postRes.data;
      case 'PUT':
        const putRes = await this.client.put(url, data, config);
        return putRes.data;
      case 'DELETE':
        const delRes = await this.client.delete(url, config);
        return delRes.data;
      case 'PATCH':
        const patchRes = await this.client.patch(url, data, config);
        return patchRes.data;
      default:
        const getRes = await this.client.get(url, config);
        return getRes.data;
    }
  }

  // ==================== REMEDIATION ====================

  async getRemediationPlaybooks() {
    const response = await this.client.get('/remediation/playbooks');
    return response.data;
  }

  async getRemediationPlaybook(playbookId: string) {
    const response = await this.client.get(`/remediation/playbooks/${playbookId}`);
    return response.data;
  }

  async searchRemediationPlaybooks(query: string) {
    const response = await this.client.get('/remediation/playbooks/search', {
      params: { query }
    });
    return response.data;
  }

  async getRemediationForFinding(findingId: number) {
    const response = await this.client.get(`/remediation/for-finding/${findingId}`);
    return response.data;
  }

  async assignPlaybookToFinding(findingId: number, playbookId: string) {
    const response = await this.client.post(`/remediation/for-finding/${findingId}/assign`, null, {
      params: { playbook_id: playbookId }
    });
    return response.data;
  }

  async getRemediationStats() {
    const response = await this.client.get('/remediation/stats');
    return response.data;
  }

  /** Get CWE (Common Weakness Enumeration) details from MITRE for remediation guidance. */
  async getCweInfo(cweId: string) {
    const response = await this.client.get(`/remediation/cwe/${encodeURIComponent(cweId)}`);
    return response.data;
  }

  // ==================== DELPHI (CISA KEV + FIRST EPSS) ====================

  /** Catalog stats for KEV + EPSS enrichment. */
  async getDelphiStatus() {
    const response = await this.client.get('/delphi/status');
    return response.data;
  }

  /** Force an immediate refresh of the KEV + EPSS feeds. */
  async refreshDelphi() {
    const response = await this.client.post('/delphi/refresh');
    return response.data;
  }

  /** Look up CISA KEV + EPSS signals for a single CVE. */
  async lookupCveDelphi(cveId: string) {
    const response = await this.client.get(`/delphi/lookup/${encodeURIComponent(cveId)}`);
    return response.data;
  }

  /** Enrich a single vulnerability by id. */
  async enrichVulnerabilityDelphi(vulnerabilityId: number) {
    const response = await this.client.post(`/delphi/enrich/${vulnerabilityId}`);
    return response.data;
  }

  /** Batch-enrich every CVE-bearing finding for the caller's org. */
  async batchEnrichDelphi(limit?: number) {
    const response = await this.client.post('/delphi/batch-enrich', null, {
      params: limit ? { limit } : undefined,
    });
    return response.data;
  }

  /** Top N open findings ranked by Delphi exploitation-likelihood (tier → score). */
  async getDelphiPriorities(limit: number = 50, includeResolved: boolean = false) {
    const response = await this.client.get('/delphi/priorities', {
      params: { limit, include_resolved: includeResolved },
    });
    return response.data;
  }

  // ==================== EXCEPTIONS ====================

  async getExceptions(params?: {
    organization_id?: number;
    exception_type?: string;
    status?: string;
    include_expired?: boolean;
    skip?: number;
    limit?: number;
  }) {
    const response = await this.client.get('/exceptions/', { params });
    return response.data;
  }

  async getExceptionStats(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/exceptions/stats', { params });
    return response.data;
  }

  async getException(exceptionId: number) {
    const response = await this.client.get(`/exceptions/${exceptionId}`);
    return response.data;
  }

  async createException(data: {
    title: string;
    exception_type: string;
    justification: string;
    organization_id: number;
    business_impact?: string;
    compensating_controls?: string;
    residual_risk?: string;
    expiration_date?: string;
    review_date?: string;
    finding_ids?: number[];
    tags?: string[];
  }) {
    const response = await this.client.post('/exceptions/', data);
    return response.data;
  }

  async updateException(exceptionId: number, data: {
    title?: string;
    exception_type?: string;
    status?: string;
    justification?: string;
    business_impact?: string;
    compensating_controls?: string;
    residual_risk?: string;
    expiration_date?: string;
    review_date?: string;
    approved_by?: string;
    tags?: string[];
  }) {
    const response = await this.client.put(`/exceptions/${exceptionId}`, data);
    return response.data;
  }

  async deleteException(exceptionId: number, unlinkFindings: boolean = true) {
    const response = await this.client.delete(`/exceptions/${exceptionId}`, {
      params: { unlink_findings: unlinkFindings }
    });
    return response.data;
  }

  async linkFindingsToException(exceptionId: number, findingIds: number[]) {
    const response = await this.client.post(`/exceptions/${exceptionId}/link-findings`, findingIds);
    return response.data;
  }

  async unlinkFindingsFromException(exceptionId: number, findingIds: number[], resetStatus: boolean = true) {
    const response = await this.client.post(`/exceptions/${exceptionId}/unlink-findings`, findingIds, {
      params: { reset_status: resetStatus }
    });
    return response.data;
  }

  // Health check
  async healthCheck() {
    const response = await axios.get(`${API_URL}/health`);
    return response.data;
  }

  // ==================== APPLICATION STRUCTURE ====================

  async getAppStructure(params?: {
    organization_id?: number;
    item_type?: string;
    search?: string;
    limit?: number;
  }) {
    const response = await this.client.get('/app-structure/', { params });
    return response.data;
  }

  async getAppStructureSummary(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/app-structure/summary', { params });
    return response.data;
  }

  async getAppStructureByDomain(domain: string, organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get(`/app-structure/by-domain/${domain}`, { params });
    return response.data;
  }

  async getAppStructureScans(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/app-structure/scans', { params });
    return response.data;
  }

  async getAppStructureByAsset(assetId: number) {
    const response = await this.client.get(`/app-structure/by-asset/${assetId}`);
    return response.data;
  }

  // ==================== GRAPH (Neo4j) ====================

  async getGraphStatus() {
    const response = await this.client.get('/graph/status');
    return response.data;
  }

  async syncGraph(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.post('/graph/sync', null, { params });
    return response.data;
  }

  async getAssetRelationships(assetId: number, depth: number = 2) {
    const response = await this.client.get(`/graph/asset/${assetId}/relationships`, {
      params: { depth }
    });
    return response.data;
  }

  async getAttackPaths(params: {
    source_id?: number;
    target_id?: number;
    organization_id?: number;
    max_paths?: number;
  }) {
    const response = await this.client.get('/graph/attack-paths', { params });
    return response.data;
  }

  async getAttackWorkspace(organizationId?: number) {
    const response = await this.client.get('/attacks/workspace', {
      params: organizationId ? { organization_id: organizationId } : undefined,
    });
    return response.data;
  }

  async getDiscoveryTree(assetId: number, organizationId?: number) {
    const params: any = { asset_id: assetId };
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/graph/discovery-tree', { params });
    return response.data;
  }

  async getDiscoverySources(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/graph/discovery-sources', { params });
    return response.data;
  }

  async getSharedInfrastructure(ip: string, organizationId?: number) {
    const params: any = { ip };
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/graph/shared-infrastructure', { params });
    return response.data;
  }

  async getAssetsByTechnology(params?: { organization_id?: number; category?: string }, useFallback?: boolean) {
    try {
      // Try Neo4j first if not explicitly requesting fallback
      if (!useFallback) {
        const response = await this.client.get('/graph/group-by-technology', { params });
        return response.data;
      }
    } catch (error) {
      // Fall through to PostgreSQL fallback
    }
    // Use PostgreSQL fallback
    const response = await this.client.get('/graph/fallback/group-by-technology', { params });
    return response.data;
  }

  async getAssetsByPort(params?: { organization_id?: number; risky_only?: boolean }, useFallback?: boolean) {
    try {
      // Try Neo4j first if not explicitly requesting fallback
      if (!useFallback) {
        const response = await this.client.get('/graph/group-by-port', { params });
        return response.data;
      }
    } catch (error) {
      // Fall through to PostgreSQL fallback
    }
    // Use PostgreSQL fallback
    const response = await this.client.get('/graph/fallback/group-by-port', { params });
    return response.data;
  }

  async getAttackSurfaceOverview(organizationId?: number, useFallback?: boolean) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    try {
      // Try Neo4j first if not explicitly requesting fallback
      if (!useFallback) {
        const response = await this.client.get('/graph/attack-surface-overview', { params });
        return response.data;
      }
    } catch (error) {
      // Fall through to PostgreSQL fallback
    }
    // Use PostgreSQL fallback
    const response = await this.client.get('/graph/fallback/attack-surface-overview', { params });
    return response.data;
  }

  async getVulnerabilityImpact(vulnerabilityId: number) {
    const response = await this.client.get(`/graph/vulnerability/${vulnerabilityId}/impact`);
    return response.data;
  }

  async queryGraph(cypher: string, params?: Record<string, any>) {
    const response = await this.client.post('/graph/query', { cypher, params });
    return response.data;
  }

  async getGraphOverview(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/graph/overview', { params });
    return response.data;
  }

  // ---------------------------------------------------------------------------
  // Agent (ask a question → agent uses MCP tools for testing)
  // ---------------------------------------------------------------------------

  async getAgentStatus() {
    const response = await this.client.get('/agent/status');
    return response.data;
  }

  async getAgentPlaybooks(): Promise<{ id: string; name: string; description: string }[]> {
    const response = await this.client.get('/agent/playbooks');
    return response.data;
  }

  async queryAgent(
    question: string,
    sessionId?: string,
    options?: {
      playbookId?: string;
      target?: string;
      mode?: 'assist' | 'agent';
      loadSessionId?: string;
      priceLimitUsd?: number;
    }
  ) {
    const response = await this.client.post('/agent/query', {
      question,
      session_id: sessionId ?? undefined,
      playbook_id: options?.playbookId ?? undefined,
      target: options?.target ?? undefined,
      mode: options?.mode ?? 'assist',
      load_session_id: options?.loadSessionId ?? undefined,
      price_limit_usd: options?.priceLimitUsd ?? undefined,
    }, { timeout: 180000 });
    return response.data;
  }

  async approveAgent(sessionId: string, decision: 'approve' | 'modify' | 'abort', modification?: string) {
    const response = await this.client.post('/agent/approve', {
      session_id: sessionId,
      decision,
      modification: modification ?? undefined,
    }, { timeout: 720000 });
    return response.data;
  }

  async answerAgentQuestion(sessionId: string, answer: string) {
    const response = await this.client.post('/agent/answer', {
      session_id: sessionId,
      answer,
    }, { timeout: 720000 });
    return response.data;
  }

  async stopAgentRun(sessionId: string) {
    const response = await this.client.post(`/agent/sessions/${sessionId}/stop`);
    return response.data as { ok: boolean; cancelled: boolean; session_id: string };
  }

  async steerAgentRun(sessionId: string, message: string) {
    const response = await this.client.post(`/agent/sessions/${sessionId}/steer`, {
      session_id: sessionId,
      message,
    });
    return response.data as { ok: boolean; queued: boolean; run_in_progress: boolean; session_id: string };
  }

  async compactAgentRun(sessionId: string) {
    const response = await this.client.post(`/agent/sessions/${sessionId}/compact`);
    return response.data as { ok: boolean; compact_queued: boolean; session_id: string };
  }

  async loadPriorHunt(sessionId: string, sourceSessionId: string) {
    const response = await this.client.post(`/agent/sessions/${sessionId}/load`, {
      session_id: sessionId,
      source_session_id: sourceSessionId,
    });
    return response.data as { ok: boolean; session_id: string; source_session_id: string };
  }

  // ---------------------------------------------------------------------------
  // Agent Conversation History
  // ---------------------------------------------------------------------------

  async getAgentConversations(limit: number = 50) {
    const response = await this.client.get('/agent/conversations', { params: { limit } });
    return response.data;
  }

  async getAgentConversation(sessionId: string) {
    const response = await this.client.get(`/agent/conversations/${sessionId}`);
    return response.data;
  }

  async deleteAgentConversation(sessionId: string) {
    const response = await this.client.delete(`/agent/conversations/${sessionId}`);
    return response.data;
  }

  async getAgentSessionChain(sessionId: string, includeAttackPaths = false) {
    const response = await this.client.get(`/agent/sessions/${sessionId}/chain`, {
      params: includeAttackPaths ? { include_attack_paths: true } : undefined,
    });
    return response.data;
  }

  /**
   * Build a WebSocket URL for the agent endpoint.
   * Same-origin through nginx in production; localhost:8000 only for `next dev`.
   */
  getAgentWebSocketUrl(sessionId: string): string {
    return `${browserWebSocketOrigin()}/api/v1/agent/ws/${sessionId}`;
  }

  async listAgentConfirmations(params?: { organization_id?: number; session_id?: string }) {
    const response = await this.client.get('/agent/confirmations', { params });
    return response.data;
  }

  async decideAgentConfirmation(
    token: string,
    approved: boolean,
    reason?: string,
  ) {
    const response = await this.client.post(`/agent/confirmations/${token}/decide`, {
      approved,
      reason,
    });
    return response.data;
  }

  // ---------------------------------------------------------------------------
  // Reports (PDF/HTML report generation)
  // ---------------------------------------------------------------------------

  async generateAssetReport(
    assetId: number,
    options?: { format?: 'pdf' | 'html'; include_info?: boolean }
  ): Promise<ArrayBuffer> {
    const params: any = {};
    if (options?.format) params.format = options.format;
    if (options?.include_info !== undefined) params.include_info = options.include_info;
    
    const response = await this.client.get(`/reports/assets/${assetId}/report`, {
      params,
      responseType: 'arraybuffer',
    });
    return response.data;
  }

  async generateFindingsReport(
    findingIds: number[],
    options?: { format?: 'pdf' | 'html'; report_title?: string; organization_name?: string }
  ): Promise<ArrayBuffer> {
    const response = await this.client.post(
      '/reports/findings/report',
      {
        finding_ids: findingIds,
        report_title: options?.report_title,
        organization_name: options?.organization_name,
      },
      {
        params: { format: options?.format || 'pdf' },
        responseType: 'arraybuffer',
      }
    );
    return response.data;
  }

  async getAssetFindingsCount(assetId: number) {
    const response = await this.client.get(`/reports/assets/${assetId}/findings/count`);
    return response.data;
  }

  // ── Aegis Oracle ────────────────────────────────────────────────────
  // All Oracle calls go through the ASM backend proxy at /api/v1/oracle/
  // which forwards to the aegis-oracle service on :8742.

  async oracleChat(question: string): Promise<{
    answer: string;
    finding?: any;
    iterations?: number;
    trace?: Array<{
      iteration: number;
      thought: string;
      tool_name: string;
      tool_args: Record<string, any>;
      observation: string;
      elapsed_ms: number;
    }>;
  }> {
    const response = await this.client.post('/oracle/chat', { question });
    return response.data;
  }

  async oracleAnalyze(cveId: string, assetId: string): Promise<any> {
    const response = await this.client.post('/oracle/analyze', { cve_id: cveId, asset_id: assetId });
    return response.data;
  }

  async oracleGetFindings(cveId?: string, assetId?: string): Promise<{ findings: any[]; count: number }> {
    const params: Record<string, string> = {};
    if (cveId) params.cve_id = cveId;
    if (assetId) params.asset_id = assetId;
    const response = await this.client.get('/oracle/findings', { params });
    return response.data;
  }

  async oracleHealth(): Promise<{ status: string }> {
    const response = await this.client.get('/oracle/health');
    return response.data;
  }

  // CVE-only Phase-A lookup — no asset required. Returns the canonical CVE
  // record, intrinsic analysis (analyst brief, attack path, preconditions,
  // CVSS reconciliation), and observed exploitation evidence.
  async oracleCveLookup(cveId: string): Promise<{
    cve: any;
    analysis: any;
    exploitation: any;
  }> {
    // First-time lookups can trigger upstream CVE ingest (vulnx/NVD) + a
    // fresh Phase A LLM call. Allow 3 minutes; cached subsequent calls
    // return in <1s.
    const response = await this.client.get(`/oracle/cve/${encodeURIComponent(cveId)}`, {
      timeout: 180000,
    });
    return response.data;
  }

  // Trigger Oracle enrichment for a single ASM vulnerability. Picks the
  // strongest path automatically (full /analyze when the vulnerability
  // has an asset, /cve/{id} intrinsic otherwise).
  async oracleEnrichVulnerability(vulnId: number, force = false): Promise<{
    vulnerability_id: number;
    cve_id?: string;
    mode: string;
    enriched_at?: string;
    opes_score?: number;
    opes_category?: string;
    opes_label?: string;
    attack_path_class?: string;
    analysis_status?: string;
    analysis_error?: string;
  }> {
    const response = await this.client.post(
      `/oracle/enrich/${vulnId}`,
      null,
      { params: { force }, timeout: 180000 },
    );
    return response.data;
  }

  // Kick off a bulk-enrich pass over open vulnerabilities. Returns counts
  // synchronously for small batches; queues a background task for large ones.
  async oracleEnrichBatch(limit = 200, force = false, organizationId?: number): Promise<{
    queued: boolean;
    selected: number;
    enriched?: number;
    enriched_generic?: number;
    skipped_cached?: number;
    errors?: number;
    message?: string;
  }> {
    // Synchronous batches can take a while; backend caps the sync size and
    // hands larger batches to a background task. 5 minutes is plenty.
    const response = await this.client.post('/oracle/enrich/batch', {
      limit,
      force,
      organization_id: organizationId,
    }, { timeout: 300000 });
    return response.data;
  }

  // ── Jira Integration ─────────────────────────────────────────────────────

  // ── Jira Integration ─────────────────────────────────────────────────────

  async getJiraIntegration(orgId?: number): Promise<JiraIntegration> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.get('/integrations/jira', { params });
    return response.data;
  }

  async createJiraIntegration(payload: Partial<JiraIntegration> & { api_token: string; hostname: string; email: string }, orgId?: number): Promise<JiraIntegration> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post('/integrations/jira', payload, { params });
    return response.data;
  }

  async updateJiraIntegration(payload: Partial<JiraIntegration> & { api_token?: string }, orgId?: number): Promise<JiraIntegration> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.put('/integrations/jira', payload, { params });
    return response.data;
  }

  async deleteJiraIntegration(orgId?: number): Promise<void> {
    const params = orgId ? { org_id: orgId } : {};
    await this.client.delete('/integrations/jira', { params });
  }

  async testJiraConnection(orgId?: number): Promise<{ ok: boolean; message: string; display_name?: string }> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post('/integrations/jira/test', undefined, { params });
    return response.data;
  }

  async getJiraProjects(orgId?: number, query?: string): Promise<{ projects: JiraProject[] }> {
    const params: Record<string, string | number> = {};
    if (orgId) params.org_id = orgId;
    if (query && query.trim()) params.query = query.trim();
    const response = await this.client.get('/integrations/jira/projects', { params });
    return response.data;
  }

  async getJiraIssueTypes(projectKey: string, orgId?: number): Promise<{ issue_types: { id: string; name: string; description?: string }[] }> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.get(`/integrations/jira/projects/${projectKey}/issue-types`, { params });
    return response.data;
  }

  async getJiraIssueTransitions(issueKey: string, orgId?: number): Promise<{ transitions: JiraTransition[] }> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.get(`/integrations/jira/issues/${issueKey}/transitions`, { params });
    return response.data;
  }

  async createJiraTicket(vulnerabilityId: number, payload: {
    project_key: string;
    issue_type: string;
    include_description?: boolean;
    include_evidence?: boolean;
    include_remediation?: boolean;
    include_references?: boolean;
    include_enrichment?: boolean;
    assignee_account_id?: string;
    extra_labels?: string[];
  }, orgId?: number): Promise<JiraTicket> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post(`/integrations/jira/vulnerabilities/${vulnerabilityId}/ticket`, payload, { params });
    return response.data;
  }

  async associateJiraTicket(vulnerabilityId: number, issueKey: string, projectKey?: string, orgId?: number): Promise<JiraTicket> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post(`/integrations/jira/vulnerabilities/${vulnerabilityId}/associate`, {
      issue_key: issueKey,
      project_key: projectKey,
    }, { params });
    return response.data;
  }

  async getJiraTicketsForVulnerability(vulnerabilityId: number, orgId?: number): Promise<JiraTicket[]> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.get(`/integrations/jira/vulnerabilities/${vulnerabilityId}/tickets`, { params });
    return response.data;
  }

  async disconnectJiraTicket(ticketId: number, orgId?: number): Promise<{ ok: boolean; message: string }> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.delete(`/integrations/jira/tickets/${ticketId}`, { params });
    return response.data;
  }

  async refreshJiraTicketStatus(ticketId: number, orgId?: number): Promise<JiraTicket> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post(`/integrations/jira/tickets/${ticketId}/refresh`, undefined, { params });
    return response.data;
  }

  async syncJiraVulnerabilityStatus(vulnerabilityId: number, orgId?: number): Promise<{
    ok: boolean; message: string; transitions_executed: string[]; comment_added: boolean;
  }> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post(`/integrations/jira/vulnerabilities/${vulnerabilityId}/sync`, undefined, { params });
    return response.data;
  }

  // ── ServiceNow Integration ─────────────────────────────────────────────────

  async getServiceNowIntegration(orgId?: number): Promise<ServiceNowIntegration> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.get('/integrations/servicenow', { params });
    return response.data;
  }

  async createServiceNowIntegration(payload: {
    webhook_url: string;
    username?: string;
    password?: string;
    auto_create_enabled?: boolean;
    auto_create_min_severity?: string;
    sync_enabled?: boolean;
    table_name?: string;
    close_state?: string;
    reopen_state?: string;
    remote_closed_states?: string[];
    validate_on_remote_close?: boolean;
    accept_close_as?: string;
  }, orgId?: number): Promise<ServiceNowIntegration> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post('/integrations/servicenow', payload, { params });
    return response.data;
  }

  async updateServiceNowIntegration(payload: {
    webhook_url?: string;
    username?: string;
    password?: string;
    is_active?: boolean;
    auto_create_enabled?: boolean;
    auto_create_min_severity?: string;
    sync_enabled?: boolean;
    table_name?: string;
    close_state?: string;
    reopen_state?: string;
    remote_closed_states?: string[];
    validate_on_remote_close?: boolean;
    accept_close_as?: string;
  }, orgId?: number): Promise<ServiceNowIntegration> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.put('/integrations/servicenow', payload, { params });
    return response.data;
  }

  async deleteServiceNowIntegration(orgId?: number): Promise<void> {
    const params = orgId ? { org_id: orgId } : {};
    await this.client.delete('/integrations/servicenow', { params });
  }

  async testServiceNowConnection(orgId?: number): Promise<{
    ok: boolean;
    message: string;
    http_status?: number;
    table_api_ok?: boolean;
  }> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post('/integrations/servicenow/test', undefined, { params });
    return response.data;
  }

  async pushServiceNowVulnerability(vulnerabilityId: number, payload: {
    include_description?: boolean;
    include_evidence?: boolean;
    include_remediation?: boolean;
    include_references?: boolean;
    include_enrichment?: boolean;
  } = {}, orgId?: number): Promise<ServiceNowDelivery> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post(
      `/integrations/servicenow/vulnerabilities/${vulnerabilityId}/push`,
      payload,
      { params },
    );
    return response.data;
  }

  async getServiceNowDeliveriesForVulnerability(vulnerabilityId: number, orgId?: number): Promise<ServiceNowDelivery[]> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.get(
      `/integrations/servicenow/vulnerabilities/${vulnerabilityId}/deliveries`,
      { params },
    );
    return response.data;
  }

  async disconnectServiceNowDelivery(deliveryId: number, orgId?: number): Promise<{ ok: boolean; message: string }> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.delete(`/integrations/servicenow/deliveries/${deliveryId}`, { params });
    return response.data;
  }

  async associateServiceNowDelivery(
    vulnerabilityId: number,
    payload: { sys_id?: string; number?: string },
    orgId?: number,
  ): Promise<ServiceNowDelivery> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post(
      `/integrations/servicenow/vulnerabilities/${vulnerabilityId}/associate`,
      payload,
      { params },
    );
    return response.data;
  }

  async refreshServiceNowDelivery(deliveryId: number, orgId?: number): Promise<ServiceNowSyncResult> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post(
      `/integrations/servicenow/deliveries/${deliveryId}/refresh`,
      undefined,
      { params },
    );
    return response.data;
  }

  async syncServiceNowVulnerability(vulnerabilityId: number, orgId?: number): Promise<ServiceNowSyncResult> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post(
      `/integrations/servicenow/vulnerabilities/${vulnerabilityId}/sync`,
      undefined,
      { params },
    );
    return response.data;
  }

  async pullServiceNowDeliveries(orgId?: number): Promise<ServiceNowSyncResult> {
    const params = orgId ? { org_id: orgId } : {};
    const response = await this.client.post('/integrations/servicenow/pull', undefined, { params });
    return response.data;
  }

  // ── Censys ASM Integration ─────────────────────────────────────────────────

  async getCensysIntegrations(): Promise<CensysIntegration[]> {
    const response = await this.client.get('/integrations/censys');
    return response.data;
  }

  async createCensysIntegration(payload: {
    workspace_name: string;
    api_key: string;
    import_vulnerabilities: boolean;
    import_assets: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CensysIntegration> {
    const response = await this.client.post('/integrations/censys', payload);
    return response.data;
  }

  async updateCensysIntegration(id: number, payload: {
    workspace_name?: string;
    api_key?: string;
    import_vulnerabilities?: boolean;
    import_assets?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CensysIntegration> {
    const response = await this.client.put(`/integrations/censys/${id}`, payload);
    return response.data;
  }

  async deleteCensysIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/censys/${id}`);
  }

  async testCensysConnection(id: number): Promise<{ ok: boolean; message: string; workspace_id?: string }> {
    const response = await this.client.post(`/integrations/censys/${id}/test`);
    return response.data;
  }

  async syncCensysIntegration(id: number): Promise<CensysSyncResult> {
    const response = await this.client.post(`/integrations/censys/${id}/sync`);
    return response.data;
  }

  // ── HackerOne Integration ──────────────────────────────────────────────────

  async getHackerOneIntegrations(orgId?: number): Promise<HackerOneIntegration[]> {
    const params = orgId ? { org_id: orgId } : undefined;
    const response = await this.client.get('/integrations/hackerone', { params });
    return response.data;
  }

  async createHackerOneIntegration(payload: {
    connection_name: string;
    api_identifier: string;
    api_token: string;
    import_vulnerabilities: boolean;
    import_scopes: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<HackerOneIntegration> {
    const response = await this.client.post('/integrations/hackerone', payload);
    return response.data;
  }

  async updateHackerOneIntegration(id: number, payload: {
    connection_name?: string;
    api_identifier?: string;
    api_token?: string;
    import_vulnerabilities?: boolean;
    import_scopes?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<HackerOneIntegration> {
    const response = await this.client.put(`/integrations/hackerone/${id}`, payload);
    return response.data;
  }

  async deleteHackerOneIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/hackerone/${id}`);
  }

  async testHackerOneConnection(id: number): Promise<{ ok: boolean; message: string; program_count?: number }> {
    const response = await this.client.post(`/integrations/hackerone/${id}/test`);
    return response.data;
  }

  async syncHackerOneIntegration(id: number): Promise<HackerOneSyncResult> {
    const response = await this.client.post(`/integrations/hackerone/${id}/sync`);
    return response.data;
  }

  async associateHackerOneReport(
    vulnerabilityId: number,
    reportIdOrUrl: string,
    orgId?: number,
    integrationId?: number,
  ): Promise<HackerOneReportLink> {
    const params = orgId ? { org_id: orgId } : undefined;
    const response = await this.client.post(
      `/integrations/hackerone/vulnerabilities/${vulnerabilityId}/associate`,
      {
        report_id_or_url: reportIdOrUrl,
        ...(integrationId ? { integration_id: integrationId } : {}),
      },
      { params },
    );
    return response.data;
  }

  async getHackerOneReportsForVulnerability(
    vulnerabilityId: number,
    orgId?: number,
  ): Promise<HackerOneReportLink[]> {
    const params = orgId ? { org_id: orgId } : undefined;
    const response = await this.client.get(
      `/integrations/hackerone/vulnerabilities/${vulnerabilityId}/reports`,
      { params },
    );
    return response.data;
  }

  async disconnectHackerOneReport(linkId: number, orgId?: number): Promise<{ ok: boolean; message: string }> {
    const params = orgId ? { org_id: orgId } : undefined;
    const response = await this.client.delete(`/integrations/hackerone/reports/${linkId}`, { params });
    return response.data;
  }

  async refreshHackerOneReport(linkId: number, orgId?: number): Promise<HackerOneReportLink> {
    const params = orgId ? { org_id: orgId } : undefined;
    const response = await this.client.post(
      `/integrations/hackerone/reports/${linkId}/refresh`,
      undefined,
      { params },
    );
    return response.data;
  }

  // ── Akamai WAF Integration ─────────────────────────────────────────────────

  async getAkamaiIntegrations(): Promise<AkamaiIntegration[]> {
    const response = await this.client.get('/integrations/akamai');
    return response.data;
  }

  async createAkamaiIntegration(payload: {
    connection_name: string;
    api_host: string;
    client_token: string;
    client_secret: string;
    access_token: string;
    import_configurations: boolean;
    import_hostnames: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<AkamaiIntegration> {
    const response = await this.client.post('/integrations/akamai', payload);
    return response.data;
  }

  async updateAkamaiIntegration(id: number, payload: {
    connection_name?: string;
    api_host?: string;
    client_token?: string;
    client_secret?: string;
    access_token?: string;
    import_configurations?: boolean;
    import_hostnames?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<AkamaiIntegration> {
    const response = await this.client.put(`/integrations/akamai/${id}`, payload);
    return response.data;
  }

  async deleteAkamaiIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/akamai/${id}`);
  }

  async testAkamaiConnection(id: number): Promise<{ ok: boolean; message: string; configs_found?: number }> {
    const response = await this.client.post(`/integrations/akamai/${id}/test`);
    return response.data;
  }

  async syncAkamaiIntegration(id: number): Promise<AkamaiSyncResult> {
    const response = await this.client.post(`/integrations/akamai/${id}/sync`);
    return response.data;
  }

  // ── Palo Alto Panorama Integration ─────────────────────────────────────────

  async getPanoramaIntegrations(): Promise<PanoramaIntegration[]> {
    const response = await this.client.get('/integrations/panorama');
    return response.data;
  }

  async createPanoramaIntegration(payload: {
    name: string;
    connection_mode?: PanoramaConnectionMode;
    panorama_host?: string | null;
    api_key?: string | null;
    device_group?: string | null;
    api_version?: string;
    verify_ssl?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<PanoramaIntegration> {
    const response = await this.client.post('/integrations/panorama', payload);
    return response.data;
  }

  async updatePanoramaIntegration(id: number, payload: {
    name?: string;
    connection_mode?: PanoramaConnectionMode;
    panorama_host?: string | null;
    api_key?: string;
    device_group?: string | null;
    api_version?: string;
    verify_ssl?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<PanoramaIntegration> {
    const response = await this.client.put(`/integrations/panorama/${id}`, payload);
    return response.data;
  }

  async deletePanoramaIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/panorama/${id}`);
  }

  async testPanoramaConnection(id: number): Promise<{ ok: boolean; message: string; address_count?: number }> {
    const response = await this.client.post(`/integrations/panorama/${id}/test`);
    return response.data;
  }

  async uploadPanoramaConfigExport(id: number, file: File, sync = true): Promise<PanoramaUploadResult> {
    const form = new FormData();
    form.append('file', file);
    const response = await this.client.post(`/integrations/panorama/${id}/upload`, form, {
      params: { sync },
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  }

  async syncPanoramaIntegration(id: number): Promise<PanoramaSyncResult> {
    const response = await this.client.post(`/integrations/panorama/${id}/sync`);
    return response.data;
  }

  // ── F5 BIG-IP Reachability Integration ─────────────────────────────────────

  async getF5Integrations(): Promise<F5Integration[]> {
    const response = await this.client.get('/integrations/f5');
    return response.data;
  }

  async createF5Integration(payload: {
    name: string;
    bigip_host: string;
    username: string;
    password: string;
    partition?: string | null;
    verify_ssl?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<F5Integration> {
    const response = await this.client.post('/integrations/f5', payload);
    return response.data;
  }

  async updateF5Integration(id: number, payload: {
    name?: string;
    bigip_host?: string;
    username?: string;
    password?: string;
    partition?: string | null;
    verify_ssl?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<F5Integration> {
    const response = await this.client.put(`/integrations/f5/${id}`, payload);
    return response.data;
  }

  async deleteF5Integration(id: number): Promise<void> {
    await this.client.delete(`/integrations/f5/${id}`);
  }

  async testF5Connection(id: number): Promise<{ ok: boolean; message: string; virtual_count?: number }> {
    const response = await this.client.post(`/integrations/f5/${id}/test`);
    return response.data;
  }

  async syncF5Integration(id: number): Promise<F5SyncResult> {
    const response = await this.client.post(`/integrations/f5/${id}/sync`);
    return response.data;
  }

  // ── Fortinet FortiGate Integration ─────────────────────────────────────────

  async getFortiGateIntegrations(): Promise<FortiGateIntegration[]> {
    const response = await this.client.get('/integrations/fortigate');
    return response.data;
  }

  async createFortiGateIntegration(payload: {
    name: string;
    fortigate_host: string;
    api_token: string;
    vdom?: string | null;
    verify_ssl?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<FortiGateIntegration> {
    const response = await this.client.post('/integrations/fortigate', payload);
    return response.data;
  }

  async updateFortiGateIntegration(id: number, payload: {
    name?: string;
    fortigate_host?: string;
    api_token?: string;
    vdom?: string | null;
    verify_ssl?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<FortiGateIntegration> {
    const response = await this.client.put(`/integrations/fortigate/${id}`, payload);
    return response.data;
  }

  async deleteFortiGateIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/fortigate/${id}`);
  }

  async testFortiGateConnection(id: number): Promise<{ ok: boolean; message: string; address_count?: number }> {
    const response = await this.client.post(`/integrations/fortigate/${id}/test`);
    return response.data;
  }

  async syncFortiGateIntegration(id: number): Promise<FortiGateSyncResult> {
    const response = await this.client.post(`/integrations/fortigate/${id}/sync`);
    return response.data;
  }

  // ── Check Point Integration ────────────────────────────────────────────────

  async getCheckPointIntegrations(): Promise<CheckPointIntegration[]> {
    const response = await this.client.get('/integrations/checkpoint');
    return response.data;
  }

  async createCheckPointIntegration(payload: {
    name: string;
    management_host: string;
    username: string;
    password: string;
    domain?: string | null;
    verify_ssl?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CheckPointIntegration> {
    const response = await this.client.post('/integrations/checkpoint', payload);
    return response.data;
  }

  async updateCheckPointIntegration(id: number, payload: {
    name?: string;
    management_host?: string;
    username?: string;
    password?: string;
    domain?: string | null;
    verify_ssl?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CheckPointIntegration> {
    const response = await this.client.put(`/integrations/checkpoint/${id}`, payload);
    return response.data;
  }

  async deleteCheckPointIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/checkpoint/${id}`);
  }

  async testCheckPointConnection(id: number): Promise<{ ok: boolean; message: string; object_count?: number }> {
    const response = await this.client.post(`/integrations/checkpoint/${id}/test`);
    return response.data;
  }

  async syncCheckPointIntegration(id: number): Promise<CheckPointSyncResult> {
    const response = await this.client.post(`/integrations/checkpoint/${id}/sync`);
    return response.data;
  }

  // ── Cisco Firepower Management Center Integration ──────────────────────────

  async getCiscoFmcIntegrations(): Promise<CiscoFmcIntegration[]> {
    const response = await this.client.get('/integrations/cisco-fmc');
    return response.data;
  }

  async createCiscoFmcIntegration(payload: {
    name: string;
    fmc_host: string;
    username: string;
    password: string;
    domain_uuid?: string | null;
    verify_ssl?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CiscoFmcIntegration> {
    const response = await this.client.post('/integrations/cisco-fmc', payload);
    return response.data;
  }

  async updateCiscoFmcIntegration(id: number, payload: {
    name?: string;
    fmc_host?: string;
    username?: string;
    password?: string;
    domain_uuid?: string | null;
    verify_ssl?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CiscoFmcIntegration> {
    const response = await this.client.put(`/integrations/cisco-fmc/${id}`, payload);
    return response.data;
  }

  async deleteCiscoFmcIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/cisco-fmc/${id}`);
  }

  async testCiscoFmcConnection(id: number): Promise<{ ok: boolean; message: string; object_count?: number }> {
    const response = await this.client.post(`/integrations/cisco-fmc/${id}/test`);
    return response.data;
  }

  async syncCiscoFmcIntegration(id: number): Promise<CiscoFmcSyncResult> {
    const response = await this.client.post(`/integrations/cisco-fmc/${id}/sync`);
    return response.data;
  }

  // ── SonicWall Integration ──────────────────────────────────────────────────

  async getSonicWallIntegrations(): Promise<SonicWallIntegration[]> {
    const response = await this.client.get('/integrations/sonicwall');
    return response.data;
  }

  async createSonicWallIntegration(payload: {
    name: string;
    sonicwall_host: string;
    username: string;
    password: string;
    verify_ssl?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<SonicWallIntegration> {
    const response = await this.client.post('/integrations/sonicwall', payload);
    return response.data;
  }

  async updateSonicWallIntegration(id: number, payload: {
    name?: string;
    sonicwall_host?: string;
    username?: string;
    password?: string;
    verify_ssl?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<SonicWallIntegration> {
    const response = await this.client.put(`/integrations/sonicwall/${id}`, payload);
    return response.data;
  }

  async deleteSonicWallIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/sonicwall/${id}`);
  }

  async testSonicWallConnection(id: number): Promise<{ ok: boolean; message: string; address_count?: number }> {
    const response = await this.client.post(`/integrations/sonicwall/${id}/test`);
    return response.data;
  }

  async syncSonicWallIntegration(id: number): Promise<SonicWallSyncResult> {
    const response = await this.client.post(`/integrations/sonicwall/${id}/sync`);
    return response.data;
  }

  // ── pfSense Integration ────────────────────────────────────────────────────

  async getPfSenseIntegrations(): Promise<PfSenseIntegration[]> {
    const response = await this.client.get('/integrations/pfsense');
    return response.data;
  }

  async createPfSenseIntegration(payload: {
    name: string;
    pfsense_host: string;
    api_key: string;
    verify_ssl?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<PfSenseIntegration> {
    const response = await this.client.post('/integrations/pfsense', payload);
    return response.data;
  }

  async updatePfSenseIntegration(id: number, payload: {
    name?: string;
    pfsense_host?: string;
    api_key?: string;
    verify_ssl?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<PfSenseIntegration> {
    const response = await this.client.put(`/integrations/pfsense/${id}`, payload);
    return response.data;
  }

  async deletePfSenseIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/pfsense/${id}`);
  }

  async testPfSenseConnection(id: number): Promise<{ ok: boolean; message: string; alias_count?: number }> {
    const response = await this.client.post(`/integrations/pfsense/${id}/test`);
    return response.data;
  }

  async syncPfSenseIntegration(id: number): Promise<PfSenseSyncResult> {
    const response = await this.client.post(`/integrations/pfsense/${id}/sync`);
    return response.data;
  }

  // ── Cisco ASA Integration ──────────────────────────────────────────────────

  async getCiscoAsaIntegrations(): Promise<CiscoAsaIntegration[]> {
    const response = await this.client.get('/integrations/cisco-asa');
    return response.data;
  }

  async createCiscoAsaIntegration(payload: {
    name: string;
    asa_host: string;
    username: string;
    password: string;
    verify_ssl?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CiscoAsaIntegration> {
    const response = await this.client.post('/integrations/cisco-asa', payload);
    return response.data;
  }

  async updateCiscoAsaIntegration(id: number, payload: {
    name?: string;
    asa_host?: string;
    username?: string;
    password?: string;
    verify_ssl?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CiscoAsaIntegration> {
    const response = await this.client.put(`/integrations/cisco-asa/${id}`, payload);
    return response.data;
  }

  async deleteCiscoAsaIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/cisco-asa/${id}`);
  }

  async testCiscoAsaConnection(id: number): Promise<{ ok: boolean; message: string; object_count?: number }> {
    const response = await this.client.post(`/integrations/cisco-asa/${id}/test`);
    return response.data;
  }

  async syncCiscoAsaIntegration(id: number): Promise<CiscoAsaSyncResult> {
    const response = await this.client.post(`/integrations/cisco-asa/${id}/sync`);
    return response.data;
  }

  // ── AWS WAF Integration ────────────────────────────────────────────────────

  async getAwsWafIntegrations(): Promise<AwsWafIntegration[]> {
    const response = await this.client.get('/integrations/aws-waf');
    return response.data;
  }

  async createAwsWafIntegration(payload: {
    name: string;
    access_key_id: string;
    secret_access_key: string;
    session_token?: string | null;
    regions?: string[];
    include_cloudfront?: boolean;
    include_regional?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<AwsWafIntegration> {
    const response = await this.client.post('/integrations/aws-waf', payload);
    return response.data;
  }

  async updateAwsWafIntegration(id: number, payload: {
    name?: string;
    access_key_id?: string;
    secret_access_key?: string;
    session_token?: string | null;
    regions?: string[];
    include_cloudfront?: boolean;
    include_regional?: boolean;
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<AwsWafIntegration> {
    const response = await this.client.put(`/integrations/aws-waf/${id}`, payload);
    return response.data;
  }

  async deleteAwsWafIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/aws-waf/${id}`);
  }

  async testAwsWafConnection(id: number): Promise<{ ok: boolean; message: string; web_acls_found?: number }> {
    const response = await this.client.post(`/integrations/aws-waf/${id}/test`);
    return response.data;
  }

  async syncAwsWafIntegration(id: number): Promise<AwsWafSyncResult> {
    const response = await this.client.post(`/integrations/aws-waf/${id}/sync`);
    return response.data;
  }

  // ── Cloudflare WAF Integration ─────────────────────────────────────────────

  async getCloudflareIntegrations(): Promise<CloudflareIntegration[]> {
    const response = await this.client.get('/integrations/cloudflare');
    return response.data;
  }

  async createCloudflareIntegration(payload: {
    connection_name: string;
    api_token: string;
    zones?: string[];
    scanner_ips?: string[];
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CloudflareIntegration> {
    const response = await this.client.post('/integrations/cloudflare', payload);
    return response.data;
  }

  async updateCloudflareIntegration(id: number, payload: {
    connection_name?: string;
    api_token?: string;
    zones?: string[];
    scanner_ips?: string[];
    is_active?: boolean;
    continuous_sync_enabled?: boolean;
    sync_interval_minutes?: number;
  }): Promise<CloudflareIntegration> {
    const response = await this.client.put(`/integrations/cloudflare/${id}`, payload);
    return response.data;
  }

  async deleteCloudflareIntegration(id: number): Promise<void> {
    await this.client.delete(`/integrations/cloudflare/${id}`);
  }

  async testCloudflareConnection(id: number): Promise<{ ok: boolean; message: string; zones_found?: number }> {
    const response = await this.client.post(`/integrations/cloudflare/${id}/test`);
    return response.data;
  }

  async syncCloudflareIntegration(id: number): Promise<CloudflareSyncResult> {
    const response = await this.client.post(`/integrations/cloudflare/${id}/sync`);
    return response.data;
  }

  // ---------------------------------------------------------------------------
  // Judah Loom — DAG workflow builder
  // ---------------------------------------------------------------------------

  async getWorkflowTools() {
    const response = await this.client.get('/workflow-tools');
    return response.data;
  }

  async getWorkflows(params?: { organization_id?: number; kind?: string; seed_library?: boolean }) {
    const response = await this.client.get('/workflows', { params });
    return response.data;
  }

  async getWorkflow(id: number) {
    const response = await this.client.get(`/workflows/${id}`);
    return response.data;
  }

  async createWorkflow(data: {
    name: string;
    description?: string;
    kind?: string;
    organization_id: number;
    graph?: { nodes: any[]; edges: any[]; viewport?: any };
    input_ports?: any[];
    output_ports?: any[];
  }) {
    const response = await this.client.post('/workflows', data);
    return response.data;
  }

  async updateWorkflow(id: number, data: { name?: string; description?: string }) {
    const response = await this.client.patch(`/workflows/${id}`, data);
    return response.data;
  }

  async deleteWorkflow(id: number) {
    await this.client.delete(`/workflows/${id}`);
  }

  async saveWorkflowVersion(
    workflowId: number,
    data: { graph: { nodes: any[]; edges: any[]; viewport?: any }; input_ports?: any[]; output_ports?: any[] }
  ) {
    const response = await this.client.post(`/workflows/${workflowId}/versions`, data);
    return response.data;
  }

  async seedWorkflowLibrary(organizationId?: number) {
    const response = await this.client.post('/workflows/seed-library', null, {
      params: organizationId ? { organization_id: organizationId } : {},
    });
    return response.data;
  }

  async runWorkflow(
    workflowId: number,
    data?: { inputs?: Record<string, any>; continue_on_error?: boolean; version_id?: number }
  ) {
    const response = await this.client.post(`/workflows/${workflowId}/run`, data || {});
    return response.data;
  }

  async getWorkflowRuns(params?: { organization_id?: number; workflow_id?: number; limit?: number }) {
    const response = await this.client.get('/workflow-runs', { params });
    return response.data;
  }

  async getWorkflowRun(runId: number) {
    const response = await this.client.get(`/workflow-runs/${runId}`);
    return response.data;
  }

  async cancelWorkflowRun(runId: number) {
    const response = await this.client.post(`/workflow-runs/${runId}/cancel`);
    return response.data;
  }

  async getWorkflowScripts(organizationId?: number) {
    const response = await this.client.get('/workflow-scripts', {
      params: organizationId ? { organization_id: organizationId } : {},
    });
    return response.data;
  }

  async createWorkflowScript(data: {
    name: string;
    description?: string;
    language?: string;
    source?: string;
    organization_id: number;
    input_ports?: any[];
    output_ports?: any[];
    params_schema?: Record<string, any>;
  }) {
    const response = await this.client.post('/workflow-scripts', data);
    return response.data;
  }

  async updateWorkflowScript(id: number, data: Record<string, any>) {
    const response = await this.client.patch(`/workflow-scripts/${id}`, data);
    return response.data;
  }

  async deleteWorkflowScript(id: number) {
    await this.client.delete(`/workflow-scripts/${id}`);
  }

  getWorkflowArtifactContentUrl(artifactId: number) {
    return `${this.client.defaults.baseURL}/workflow-artifacts/${artifactId}/content`;
  }
}

export const api = new ApiClient();
export default api;

