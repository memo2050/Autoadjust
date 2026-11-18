const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Strict-Transport-Security", value: "max-age=31536000" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

module.exports = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  async rewrites() {
    // Home page = the static landing page in /public (SOC and NOC are hash routes inside it)
    return { beforeFiles: [{ source: "/", destination: "/landing.html" }, { source: "/demo", destination: "/landing.html" }] };
  },
};
