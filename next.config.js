module.exports = {
  async rewrites() {
    // Home page = the static landing page in /public (SOC and NOC are hash routes inside it)
    return { beforeFiles: [{ source: "/", destination: "/landing.html" }] };
  },
};
