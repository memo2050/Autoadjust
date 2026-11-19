import { createSalesHandlers } from "../../../../lib/sales/handlers";
import { identifyUser } from "../../../../lib/tenant/auth";
import { createAssistant } from "../../../../lib/support/assistant";
export const dynamic = "force-dynamic";
const assistant = createAssistant({ env: process.env });
const h = createSalesHandlers({
  env: process.env,
  user: (req) => identifyUser(req, { raw: null as never }),
  ask: async (message, lang, key) => { const r = await assistant.ask({ message, lang, tier: "anon", key, ticketsEnabled: false }); return r.mode === "refused" || r.mode === "limited" ? null : r.answer; },
});
async function route(req: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const [a, ...rest] = (await ctx.params).path ?? [];
  if (req.method === "POST" && rest.length === 0) { if (a === "recommend") return h.recommend(req); if (a === "intake") return h.intake(req); if (a === "agent") return h.agent(req); }
  return h.console(req, [a, ...rest].filter(Boolean));
}
export { route as GET, route as POST, route as PATCH };
