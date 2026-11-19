import { createSupportHandlers } from "../../../../lib/support/handlers";
export const dynamic = "force-dynamic";
const h = createSupportHandlers({ env: process.env });
export const POST = (req: Request) => h.chat(req);
