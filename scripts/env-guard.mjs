#!/usr/bin/env node
// Deterministic guard for database migrations and deployments. Fails CLOSED. It is the FIRST step of .github/workflows/db-migrate.yml and must pass before any SQL runs.
// Inputs (env): TARGET (staging|production), DATABASE_URL, EXPECTED_PROJECT_REF (variable of the GitHub environment), CONFIRM_PROJECT_REF (typed by the person who starts the run),
//               PRODUCTION_PROJECT_REF (repository variable), RELEASE_APPROVAL (production only; must be APPROVED-BY-OWNER).
// It never prints the URL, password or any secret; only the project ref (which is not secret) and the verdict.
import { fileURLToPath } from "node:url";
export function projectRef(databaseUrl) {
  try { const u = new URL(databaseUrl); const m1 = /^db\.([a-z0-9]{15,30})\.supabase\.co$/.exec(u.hostname); if (m1) return m1[1];
    const m2 = /^postgres\.([a-z0-9]{15,30})$/.exec(decodeURIComponent(u.username)); if (m2 && /\.pooler\.supabase\.com$/.test(u.hostname)) return m2[1]; } catch {}
  return null;
}
export function checkTarget(e) {
  const err = [], ref = projectRef(e.DATABASE_URL ?? "");
  if (e.TARGET !== "staging" && e.TARGET !== "production") err.push("TARGET must be exactly 'staging' or 'production'");
  if (!ref) err.push("DATABASE_URL is not a recognisable Supabase connection string (project ref could not be read)");
  if (!e.PRODUCTION_PROJECT_REF) err.push("PRODUCTION_PROJECT_REF (repository variable) is not set: refusing to run without knowing which project is production");
  if (!e.EXPECTED_PROJECT_REF || e.EXPECTED_PROJECT_REF !== ref) err.push("EXPECTED_PROJECT_REF of this GitHub environment does not match the database in DATABASE_URL");
  if (!e.CONFIRM_PROJECT_REF || e.CONFIRM_PROJECT_REF !== ref) err.push("the project ref typed at run time does not match the database in DATABASE_URL");
  if (ref && e.PRODUCTION_PROJECT_REF) {
    if (e.TARGET === "staging" && ref === e.PRODUCTION_PROJECT_REF) err.push("TARGET is staging but the database IS the production project");
    if (e.TARGET === "production" && ref !== e.PRODUCTION_PROJECT_REF) err.push("TARGET is production but the database is not the production project");
  }
  if (e.TARGET === "production" && e.RELEASE_APPROVAL !== "APPROVED-BY-OWNER") err.push("production requires RELEASE_APPROVAL=APPROVED-BY-OWNER (and the GitHub environment's required reviewer)");
  return { ok: err.length === 0, ref, errors: err };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const r = checkTarget(process.env);
  if (!r.ok) { console.error("GUARD FAILED:\n - " + r.errors.join("\n - ")); process.exit(1); }
  console.log(`GUARD OK: target=${process.env.TARGET} project=${r.ref}`);
}
