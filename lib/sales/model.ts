// AI Sales Agent: pure business logic (no I/O). Lead validation, qualification scoring, plan recommendation, follow-up templates, status machine.
import { TIERS, FEATURES, ADDONS, ANNUAL_DISCOUNT, annualUsd, includes, type TierId } from "../billing/pricing";

export type Lang = "en" | "ar";
export const STATUSES = ["new", "contacted", "qualified", "demo_requested", "demo_scheduled", "proposal", "won", "lost", "disqualified"] as const;
export type Status = (typeof STATUSES)[number];
export const OPEN: Status[] = ["new", "contacted", "qualified", "demo_requested", "demo_scheduled", "proposal"];
export const CLOSED: Status[] = ["won", "lost", "disqualified"];
const FWD: Record<Status, Status[]> = {
  new: ["contacted", "qualified", "demo_requested", "lost", "disqualified"],
  contacted: ["qualified", "demo_requested", "lost", "disqualified"],
  qualified: ["demo_requested", "demo_scheduled", "proposal", "lost", "disqualified"],
  demo_requested: ["demo_scheduled", "qualified", "lost", "disqualified"],
  demo_scheduled: ["proposal", "qualified", "lost", "disqualified"],
  proposal: ["won", "lost", "demo_scheduled", "disqualified"],
  won: [], lost: [], disqualified: [],
};
/** Allowed transitions. Closed leads can only be reopened (to "contacted") by an admin. */
export function canMove(from: Status, to: Status, admin: boolean): boolean {
  if (from === to) return false; if (CLOSED.includes(from)) return admin && to === "contacted"; return FWD[from].includes(to);
}
export const NEEDS = ["soc", "noc", "edr", "ndr", "ueba", "soar", "wazuh", "zabbix", "elastic", "ai", "windows", "syslog", "prtg"] as const;
export type Need = (typeof NEEDS)[number];
export const TIMELINES = ["now", "1-3m", "3-6m", "later", "unknown"] as const;
export type Timeline = (typeof TIMELINES)[number];

export interface LeadInput { name: string; email: string; company: string; job_title: string; country: string; lang: Lang; endpoints: number | null; devices: number | null; users: number | null; retention_days: number | null; needs: Need[]; timeline: Timeline; budget_monthly_usd: number | null; message: string; demo_slots: string[]; consent_contact: boolean }
const EMAIL = /^[^\s@<>]{1,64}@[^\s@<>]{1,190}\.[^\s@<>]{2,}$/;
const clean = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max) : "");
const num = (v: unknown, max: number): number | null => { if (v === null || v === undefined || v === "") return null; const n = typeof v === "number" ? v : Number(String(v).replace(/,/g, "")); return Number.isFinite(n) && n >= 0 && n <= max ? Math.round(n) : NaN as any; };
const DISPOSABLE = /(^|\.)(mailinator|guerrillamail|10minutemail|tempmail|yopmail|trashmail|sharklasers|getnada|dispostable)\./i;
const FREE = new Set(["gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com", "icloud.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "msn.com", "qq.com"]);
export const emailDomain = (e: string) => e.split("@")[1]?.toLowerCase() ?? "";
export const isFreeEmail = (e: string) => FREE.has(emailDomain(e));
export const isDisposable = (e: string) => DISPOSABLE.test("." + emailDomain(e) + ".");

/** Validates and cleans a lead submission. Honeypot `website` must be empty. */
export function parseLead(b: unknown): { ok: true; value: LeadInput } | { ok: false; error: string } {
  if (!b || typeof b !== "object" || Array.isArray(b)) return { ok: false, error: "Invalid request." };
  const o = b as Record<string, any>; if (typeof o.website === "string" && o.website.length) return { ok: false, error: "Invalid request." };
  const name = clean(o.name, 120), email = clean(o.email, 200).toLowerCase();
  if (!name) return { ok: false, error: "Please enter your name." }; if (!EMAIL.test(email)) return { ok: false, error: "Please enter a valid email address." };
  if (isDisposable(email)) return { ok: false, error: "Please use a work email address." };
  if (o.consent_contact !== true) return { ok: false, error: "Please agree to be contacted so we can follow up." };
  const f = { endpoints: num(o.endpoints, 100000), devices: num(o.devices, 100000), users: num(o.users, 10000), retention_days: num(o.retention_days, 3650), budget_monthly_usd: num(o.budget_monthly_usd, 10_000_000) };
  for (const [k, v] of Object.entries(f)) if (Number.isNaN(v as number)) return { ok: false, error: `Invalid value for ${k}.` };
  const needs = Array.isArray(o.needs) ? [...new Set(o.needs.map((x: unknown) => String(x).toLowerCase()).filter((x: string) => (NEEDS as readonly string[]).includes(x)))].slice(0, 13) as Need[] : [];
  const timeline = (TIMELINES as readonly string[]).includes(o.timeline) ? (o.timeline as Timeline) : "unknown";
  const slots = (Array.isArray(o.demo_slots) ? o.demo_slots : []).slice(0, 3).map((s: unknown) => clean(s, 40)).filter((s: string) => s && !Number.isNaN(Date.parse(s)));
  return { ok: true, value: { name, email, company: clean(o.company, 160), job_title: clean(o.job_title, 120), country: clean(o.country, 80), lang: o.lang === "ar" ? "ar" : "en", ...f, needs, timeline, message: clean(o.message, 2000), demo_slots: slots, consent_contact: true } };
}

// ---- qualification ---------------------------------------------------------------------------------------------------------
export interface Qualification { score: number; grade: "A" | "B" | "C" | "D"; qualified: boolean; disqualified: boolean; reasons: string[]; missing: string[]; breakdown: { fit: number; intent: number; authority: number; contact: number } }
const SENIOR = /\b(owner|founder|co-?founder|ceo|cto|cio|ciso|coo|president|vp|vice president|director|head|chief|manager|lead)\b|مدير|رئيس|مؤسس|مالك|مسؤول/i;
const TECH = /\b(engineer|analyst|admin|administrator|architect|specialist|consultant|developer|devops|soc|noc|security)\b|مهندس|محلل|خبير|اخصائي|أخصائي/i;
export function qualify(l: Pick<LeadInput, "email" | "company" | "job_title" | "endpoints" | "devices" | "users" | "needs" | "timeline" | "consent_contact" | "message"> & { demo_slots?: string[]; demo_requested?: boolean }): Qualification {
  const reasons: string[] = [], missing: string[] = [];
  let fit = 0; const ep = l.endpoints ?? 0;
  if (l.endpoints === null) missing.push("endpoints"); else { fit += ep >= 200 ? 25 : ep >= 75 ? 20 : ep >= 25 ? 15 : ep > 0 ? 8 : 0; reasons.push(`${ep} endpoints`); }
  if (l.devices === null) missing.push("devices"); else if (l.devices > 0) fit += 5;
  const core = l.needs.filter((n) => n === "soc" || n === "noc").length; fit += core * 5; if (!l.needs.length) missing.push("needs"); else reasons.push("needs: " + l.needs.join(", "));
  fit = Math.min(40, fit + (l.needs.length > 2 ? 0 : 0));
  const tl: Record<Timeline, number> = { now: 20, "1-3m": 15, "3-6m": 8, later: 2, unknown: 0 }; let intent = tl[l.timeline]; if (l.timeline === "unknown") missing.push("timeline"); else reasons.push("timeline " + l.timeline);
  const demo = l.demo_requested || (l.demo_slots?.length ?? 0) > 0; if (demo) { intent += 10; reasons.push("asked for a demo"); } intent = Math.min(30, intent);
  let authority = 0; if (!l.job_title) missing.push("job_title"); else { authority = SENIOR.test(l.job_title) ? 15 : TECH.test(l.job_title) ? 8 : 3; reasons.push("title " + l.job_title); }
  let contact = 0; const disp = isDisposable(l.email), free = isFreeEmail(l.email);
  if (!disp && !free) { contact += 8; reasons.push("business email"); } else if (free) reasons.push("free email provider"); else reasons.push("disposable email");
  if (l.company) contact += 4; else missing.push("company"); if (l.consent_contact) contact += 3;
  const score = disp ? 0 : Math.max(0, Math.min(100, fit + intent + authority + contact));
  const grade = score >= 75 ? "A" : score >= 55 ? "B" : score >= 35 ? "C" : "D";
  const disqualified = disp || !l.consent_contact;
  return { score, grade, qualified: !disqualified && score >= 55, disqualified, reasons, missing, breakdown: { fit, intent, authority, contact } };
}

// ---- plan recommendation ---------------------------------------------------------------------------------------------------
export interface RecInput { endpoints: number | null; devices: number | null; users: number | null; retention_days: number | null; needs: Need[] }
export interface PlanOption { tier: TierId; name: string; addons: Array<{ name: string; qty: number; monthlyUsd: number }>; monthlyUsd: number | null; annualUsd: number | null; fits: boolean }
export interface Recommendation { plan: TierId; planName: string; monthlyUsd: number | null; annualUsd: number | null; addons: PlanOption["addons"]; reasons: string[]; alternatives: PlanOption[]; features: Array<{ name: string; status: string; included: boolean }>; notAvailable: string[]; caveats: string[]; contactSales: boolean; confidence: "high" | "medium" | "low" }
const NEED_FEATURE: Partial<Record<Need, string>> = { wazuh: "Wazuh integration", zabbix: "Zabbix integration (SNMP via Zabbix)", ai: "AI assistance and AI agents", windows: "Windows monitoring and collector", syslog: "Syslog collector", prtg: "PRTG and Nagios connectors" };
const R = ["basic", "standard", "professional", "business", "enterprise"] as TierId[];
const fitsTier = (t: (typeof TIERS)[number], r: RecInput, extra = { ep: 0, dev: 0 }) => t.id !== "enterprise" && (r.endpoints === null || r.endpoints <= (t.endpoints ?? 0) + extra.ep) && (r.devices === null || r.devices <= (t.devices ?? 0) + extra.dev) && (r.users === null || r.users <= (t.users ?? 0)) && (r.retention_days === null || r.retention_days <= (t.retentionDays ?? 0));
export function recommend(r: RecInput): Recommendation {
  const reasons: string[] = [], caveats = ["Prices are a USD launch proposal. Online payment is not enabled and nobody can be charged yet.", "Features marked coming soon or planned are not sold and carry no price today."], notAvailable: string[] = [];
  let minTier = 0;   // features push the minimum tier up (only for features that can be sold)
  const wanted = r.needs.map((n) => NEED_FEATURE[n]).filter(Boolean).map((n) => FEATURES.find((f) => f.name === n)!).filter(Boolean);
  for (const f of wanted) { if (f.status === "planned") { notAvailable.push(`${f.name} is planned and not built yet, so it is not included or priced.`); continue; } if (f.status === "soon") caveats.push(`${f.name} is coming soon and not yet validated against real systems; it is not sold today.`); minTier = Math.max(minTier, R.indexOf(f.from)); }
  const opts: PlanOption[] = [];
  const mk = (t: (typeof TIERS)[number], addons: PlanOption["addons"], fits: boolean): PlanOption => { const m = t.monthlyUsd === null ? null : t.monthlyUsd + addons.reduce((s, a) => s + a.monthlyUsd * a.qty, 0); return { tier: t.id, name: t.name, addons, monthlyUsd: m, annualUsd: m === null ? null : annualUsd(m), fits }; };
  for (const t of TIERS) {
    if (t.id === "enterprise" || R.indexOf(t.id) < minTier) continue;
    if (fitsTier(t, r)) { opts.push(mk(t, [], true)); continue; }
    // lower tier + add-ons: only endpoints and devices can be topped up; users and retention cannot
    if (r.users !== null && r.users > (t.users ?? 0) || r.retention_days !== null && r.retention_days > (t.retentionDays ?? 0)) continue;
    const eN = r.endpoints !== null && r.endpoints > (t.endpoints ?? 0) ? Math.ceil((r.endpoints - (t.endpoints ?? 0)) / 25) : 0, dN = r.devices !== null && r.devices > (t.devices ?? 0) ? Math.ceil((r.devices - (t.devices ?? 0)) / 10) : 0;
    if (eN + dN === 0 || eN > 8 || dN > 8) continue; const addons = []; if (eN) addons.push({ name: ADDONS[0].name, qty: eN, monthlyUsd: ADDONS[0].monthlyUsd }); if (dN) addons.push({ name: ADDONS[1].name, qty: dN, monthlyUsd: ADDONS[1].monthlyUsd });
    opts.push(mk(t, addons, true));
  }
  opts.sort((a, b) => (a.monthlyUsd ?? 1e9) - (b.monthlyUsd ?? 1e9));
  const ent = TIERS.find((t) => t.id === "enterprise")!, best = opts[0];
  const rec = best ?? mk(ent, [], true);
  if (best) { reasons.push(`${best.name} covers ${[r.endpoints !== null ? r.endpoints + " endpoints" : null, r.devices !== null ? r.devices + " network devices" : null, r.users !== null ? r.users + " users" : null, r.retention_days !== null ? r.retention_days + "-day retention" : null].filter(Boolean).join(", ") || "the sizes you gave"}${best.addons.length ? " with add-ons" : ""}.`); if (minTier > 0 && R.indexOf(best.tier) === minTier) reasons.push("Chosen tier is the lowest one that includes the integrations you asked about."); }
  else reasons.push("Your size or retention needs exceed the Business tier, so a custom Enterprise quote is the right path.");
  const known = [r.endpoints, r.devices, r.users, r.retention_days].filter((x) => x !== null).length, confidence = known >= 3 ? "high" : known >= 2 ? "medium" : "low";
  if (confidence === "low") caveats.push("This is a rough suggestion: tell us your endpoints, network devices and users for a firmer recommendation.");
  return { plan: rec.tier, planName: rec.name, monthlyUsd: rec.monthlyUsd, annualUsd: rec.annualUsd, addons: rec.addons, reasons, alternatives: opts.slice(1, 3), features: FEATURES.map((f) => ({ name: f.name, status: f.status, included: includes(rec.tier, f) })), notAvailable, caveats, contactSales: !best || rec.tier === "enterprise", confidence };
}

// ---- follow-up sequence ----------------------------------------------------------------------------------------------------
export interface Draft { step: number; template: string; subject: string; body: string; lang: Lang; due_offset_days: number }
const T = {
  en: {
    thanks: (n: string, c: string, p: string) => ({ subject: "Thanks for your interest in AutoAdjust", body: `Hi ${n},\n\nThank you for contacting AutoAdjust${c ? " about " + c : ""}. Based on what you shared, the ${p} plan looks like the closest fit. Pricing is a launch proposal and online payment is not enabled yet, so nothing is charged.\n\nA member of our team will review your request and reply personally. If you have questions in the meantime, just reply to this message.\n\nBest regards,\nThe AutoAdjust team` }),
    recap: (n: string, _c: string, p: string) => ({ subject: "Your AutoAdjust plan recap and next steps", body: `Hi ${n},\n\nA short recap: we suggested the ${p} plan for your environment. We would be glad to walk you through the SOC and NOC views in a short demo and answer questions about integrations and what is available today versus coming soon.\n\nWould a 30-minute call this week work?\n\nBest regards,\nThe AutoAdjust team` }),
    checkin: (n: string, _c: string, _p: string) => ({ subject: "Still interested in AutoAdjust?", body: `Hi ${n},\n\nJust checking in on your request. If timing has changed or you have questions, reply here and we will help. If you would rather not hear from us, tell us and we will stop.\n\nBest regards,\nThe AutoAdjust team` }),
    demo: (n: string, _c: string, _p: string) => ({ subject: "We received your demo request", body: `Hi ${n},\n\nThanks for requesting a demo. Our team will confirm a time with you personally; no meeting is booked until you hear from us.\n\nBest regards,\nThe AutoAdjust team` }),
    foot: "\n\nIf you do not want further emails from us, reply with \"unsubscribe\" and we will stop.",
  },
  ar: {
    thanks: (n: string, c: string, p: string) => ({ subject: "شكرًا لاهتمامك بـ AutoAdjust", body: `مرحبًا ${n}،\n\nشكرًا لتواصلك مع AutoAdjust${c ? " بخصوص " + c : ""}. بناءً على ما ذكرته، تبدو باقة ${p} الأقرب لاحتياجك. الأسعار عرض إطلاق ولم يتم تفعيل الدفع الإلكتروني بعد، لذلك لا يتم خصم أي مبلغ.\n\nسيراجع أحد أعضاء فريقنا طلبك ويردّ عليك شخصيًا. إن كانت لديك أسئلة فيمكنك الرد على هذه الرسالة.\n\nمع التحية،\nفريق AutoAdjust` }),
    recap: (n: string, _c: string, p: string) => ({ subject: "ملخص باقتك والخطوات التالية في AutoAdjust", body: `مرحبًا ${n}،\n\nملخص سريع: اقترحنا لك باقة ${p}. يسعدنا أن نعرض لك واجهات SOC وNOC في عرض قصير ونجيب عن أسئلتك حول التكاملات وما هو متاح اليوم وما هو قادم قريبًا.\n\nهل يناسبك اتصال مدته 30 دقيقة هذا الأسبوع؟\n\nمع التحية،\nفريق AutoAdjust` }),
    checkin: (n: string, _c: string, _p: string) => ({ subject: "هل ما زلت مهتمًا بـ AutoAdjust؟", body: `مرحبًا ${n}،\n\nنتابع معك بخصوص طلبك. إذا تغيّر التوقيت أو كانت لديك أسئلة فيمكنك الرد هنا. وإن كنت لا ترغب في تلقي رسائل منا فأخبرنا وسنتوقف.\n\nمع التحية،\nفريق AutoAdjust` }),
    demo: (n: string, _c: string, _p: string) => ({ subject: "استلمنا طلب العرض التجريبي", body: `مرحبًا ${n}،\n\nشكرًا لطلبك عرضًا تجريبيًا. سيؤكد فريقنا الموعد معك شخصيًا، ولا يتم حجز أي اجتماع قبل أن يصلك ردّنا.\n\nمع التحية،\nفريق AutoAdjust` }),
    foot: "\n\nإذا كنت لا ترغب في تلقي رسائل أخرى منا فأرسل كلمة \"إلغاء الاشتراك\" وسنتوقف.",
  },
};
/** The sequence is DRAFTS only. Nothing is ever sent without a human approving it and the email mode being switched on by the owner. */
export function followupDrafts(l: { name: string; company: string; lang: Lang; demo: boolean }, planName: string): Draft[] {
  const t = T[l.lang], first = l.name.split(" ")[0] || l.name, mkd = (step: number, template: string, fn: (n: string, c: string, p: string) => { subject: string; body: string }, due: number): Draft => { const x = fn(first, l.company, planName); return { step, template, subject: x.subject, body: x.body + t.foot, lang: l.lang, due_offset_days: due }; };
  const out: Draft[] = [mkd(0, "thanks", t.thanks, 0)]; if (l.demo) out.push(mkd(1, "demo", t.demo, 0));
  out.push(mkd(out.length, "recap", t.recap, 2), mkd(out.length + 1, "checkin", t.checkin, 7)); return out.map((d, i) => ({ ...d, step: i }));
}
export const DISCOUNT = ANNUAL_DISCOUNT;
