import { NextResponse, type NextRequest } from "next/server";

// APP_HOST: where the dashboard lives (e.g. app.spark.com or localhost:3000)
// SITES_DOMAIN: separate domain for user sites (e.g. sparksites.com) — keep it
// different from the app domain so user JavaScript can never touch your app's cookies.
const APP_HOST = process.env.APP_HOST;
const SITES_DOMAIN = process.env.SITES_DOMAIN;

export function middleware(req: NextRequest) {
  if (!APP_HOST || !SITES_DOMAIN) return NextResponse.next(); // hosting disabled until configured
  const host = (req.headers.get("host") ?? "").toLowerCase();
  if (host === APP_HOST) return NextResponse.next();

  const url = req.nextUrl.clone();
  url.pathname = "/serve";
  url.search = "";
  if (host.endsWith("." + SITES_DOMAIN)) {
    url.searchParams.set("slug", host.slice(0, -(SITES_DOMAIN.length + 1)));
  } else {
    url.searchParams.set("domain", host.split(":")[0]); // customer's own domain
  }
  return NextResponse.rewrite(url);
}

export const config = { matcher: ["/((?!_next|api|favicon.ico).*)"] };
