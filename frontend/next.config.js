/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
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
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;

