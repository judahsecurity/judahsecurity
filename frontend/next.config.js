/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // FastAPI collection routes use a trailing slash. Preserve it so Next does
  // not trigger redirects to Docker's internal backend hostname.
  skipTrailingSlashRedirect: true,
  eslint: {
    ignoreDuringBuilds: true,
  },
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  },
  // Increase proxy timeout for agent requests (default is ~30s, agent can take 5 min)
  experimental: {
    proxyTimeout: 720000, // 12 minutes in ms — must exceed backend AGENT_REQUEST_TIMEOUT_SECONDS (11 min)
    optimizePackageImports: ['lucide-react'],
  },
  // Keep HTTP connections alive longer so long-running agent calls don't drop
  httpAgentOptions: {
    keepAlive: true,
  },
  async redirects() {
    return [
      {
        source: '/threat-intel',
        destination: '/vulnerability-intel',
        permanent: true,
      },
    ];
  },
  async rewrites() {
    const apiOrigin = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    return [
      // FastAPI defines the asset collection at `/assets/`. An explicit rule
      // prevents its 307 Location header from leaking Docker's `backend` host
      // to the browser when Next normalizes the incoming path.
      {
        source: '/api/v1/assets',
        destination: `${apiOrigin}/api/v1/assets/`,
      },
      {
        source: '/api/:path*',
        destination: `${apiOrigin}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
