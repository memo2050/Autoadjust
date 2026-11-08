module.exports = {
  async rewrites() {
    // Home page = the static landing page in /public (builder calls /api/generate)
    return { beforeFiles: [{ source: "/", destination: "/landing.html" }] };
  },
};
