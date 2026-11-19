import { signOutToken } from "../../../../lib/tenant/auth";

// Sign out: revokes the caller's session on this server immediately and deletes it at Supabase Auth, so the access token stops working
// (instead of staying valid until it expires). Needs the Bearer token being signed out; no other credentials.
export const dynamic = "force-dynamic";
export async function POST(req: Request) {
  const h = req.headers.get("authorization") ?? "", tok = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  const ok = tok.length >= 16 && tok.length <= 4096 && tok.split(".").length === 3 && (await signOutToken(tok));
  return new Response(JSON.stringify({ ok }), { status: ok ? 200 : 401, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}
