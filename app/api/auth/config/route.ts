// Public sign-in settings for the account page. Only the Supabase URL and the PUBLIC anon key are returned (both are designed to be public).
// The service-role key and the JWT secret never leave the server.
export const dynamic = "force-dynamic";
export async function GET() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || "";
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || "";
  const configured = !!(url && anonKey);
  return new Response(JSON.stringify({ configured, url: configured ? url : null, anonKey: configured ? anonKey : null, legacyTokens: (process.env.SOC_LEGACY_TOKENS ?? "on").toLowerCase() !== "off" }), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
}
