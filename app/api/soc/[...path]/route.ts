import { handleSoc } from "@/lib/soc/api";

export const maxDuration = 120;
export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ path: string[] }> };
const h = async (req: Request, ctx: Ctx) => handleSoc(req, (await ctx.params).path);
export const GET = h, POST = h, PATCH = h;
