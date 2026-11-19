import { createSupportHandlers } from "./handlers";
import { identifyUser } from "../tenant/auth";
export const support = createSupportHandlers({ env: process.env, userId: async (req) => ((req.headers.get("authorization") ?? "").startsWith("Bearer ") ? (await identifyUser(req, { raw: null as never }))?.id ?? null : null) });
