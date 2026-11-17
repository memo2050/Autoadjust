// Runtime guard: staging and production must never share a database or payment account. Returns the list of violations (empty = fine). Never returns secret values.
// APP_ENV = "staging" | "production" (set on each host). PRODUCTION_PROJECT_REF = the production Supabase project ref (not secret).
const refOf = (url?: string) => /^https:\/\/([a-z0-9]{15,30})\.supabase\.co/i.exec(url ?? "")?.[1]?.toLowerCase();
export function envViolations(env: NodeJS.ProcessEnv): string[] {
  const v: string[] = [], app = (env.APP_ENV ?? "").toLowerCase(), prod = (env.PRODUCTION_PROJECT_REF ?? "").toLowerCase(), ref = refOf(env.SUPABASE_URL);
  if (app && app !== "staging" && app !== "production") v.push("APP_ENV must be staging or production");
  if (app === "staging") {
    if (prod && ref === prod) v.push("staging is configured with the PRODUCTION Supabase project");
    if ((env.STRIPE_SECRET_KEY ?? "").startsWith("sk_live_")) v.push("staging is configured with a LIVE Stripe key");
    if (env.BILLING_ENFORCE === "on" && !prod) v.push("PRODUCTION_PROJECT_REF is not set on staging (cannot prove isolation)");
  }
  if (app === "production") { if (prod && ref && ref !== prod) v.push("production is not using the production Supabase project"); if ((env.STRIPE_SECRET_KEY ?? "").startsWith("sk_test_") && env.BILLING_ENFORCE === "on") v.push("production billing enforcement is on with a TEST Stripe key"); }
  return v;
}
