// Bilingual (English / Arabic) support knowledge base. Deterministic: no AI call, no cost, no data leaves the server. Answers only describe what the product does TODAY.
export type Lang = "en" | "ar";
export const detectLang = (s: string): Lang => { const ar = (s.match(/[؀-ۿ]/g) ?? []).length; const lat = (s.match(/[A-Za-z]/g) ?? []).length; return ar > lat ? "ar" : "en"; };
interface Entry { id: string; kw: string[]; en: string; ar: string }
export const KB: Entry[] = [
  { id: "pricing", kw: ["price", "pricing", "cost", "plan", "plans", "subscription", "سعر", "اسعار", "أسعار", "تسعير", "خطة", "خطط", "اشتراك"],
    en: "Our launch pricing has five tiers: Basic $49, Standard $99, Professional $199, Business $399 per month, and Enterprise (custom). Annual billing is 15% off. Online payment is not enabled yet; see the Pricing page or request a demo.",
    ar: "لدينا خمس باقات: الأساسية 49$ والقياسية 99$ والاحترافية 199$ والأعمال 399$ شهريًا، والمؤسسات بسعر مخصص. الدفع السنوي بخصم 15%. الدفع الإلكتروني غير مفعّل حاليًا؛ راجع صفحة الأسعار أو اطلب عرضًا تجريبيًا." },
  { id: "signin", kw: ["sign in", "login", "log in", "password", "cant login", "can't login", "تسجيل الدخول", "دخول", "كلمة المرور", "كلمة السر", "لا استطيع الدخول"],
    en: "Sign in with your email and password on the Sign In page. If you see 'not in an organization', create an organization or ask your owner for an invitation. If you cannot sign in, open a support ticket and we will help (never send us your password).",
    ar: "سجّل الدخول بالبريد الإلكتروني وكلمة المرور من صفحة تسجيل الدخول. إذا ظهرت رسالة عدم الانتماء لمؤسسة فأنشئ مؤسسة أو اطلب دعوة من المالك. إذا تعذّر الدخول افتح تذكرة دعم ولا ترسل لنا كلمة المرور أبدًا." },
  { id: "demo", kw: ["demo", "trial", "try", "تجريبي", "عرض", "تجربة"],
    en: "The Live Demo (/demo) uses simulated sample data and needs no account. 'Request a Demo' sends your details to our team. The free trial is coming soon.",
    ar: "العرض الحي (/demo) يستخدم بيانات تجريبية محاكاة ولا يحتاج حسابًا. زر طلب عرض تجريبي يرسل بياناتك إلى فريقنا. التجربة المجانية قادمة قريبًا." },
  { id: "integrations", kw: ["wazuh", "zabbix", "elastic", "integration", "integrations", "connect", "تكامل", "ربط", "واتسوه", "زابكس"],
    en: "Wazuh, Zabbix and Elastic connectors exist and are being validated against real systems; they are listed as 'Coming soon' on the pricing page until validated. Ask us for the current status.",
    ar: "موصّلات Wazuh وZabbix وElastic موجودة وقيد التحقق على أنظمة حقيقية، وهي معروضة كـ«قريبًا» في صفحة الأسعار حتى اكتمال التحقق. اسألنا عن الحالة الحالية." },
  { id: "security", kw: ["security", "isolation", "tenant", "data", "privacy", "أمان", "امن", "أمن", "خصوصية", "بيانات", "عزل"],
    en: "Each organization's data is isolated; every request is checked on the server for sign-in, organization membership and role. Sign-out revokes your session. Report any security concern through a ticket marked 'Security'.",
    ar: "بيانات كل مؤسسة معزولة، ويُتحقق في الخادم من تسجيل الدخول والعضوية والدور في كل طلب. تسجيل الخروج يُنهي الجلسة. بلّغ عن أي مخاوف أمنية عبر تذكرة بتصنيف «أمان»." },
  { id: "billing", kw: ["invoice", "refund", "payment", "billing", "charge", "فاتورة", "استرداد", "دفع", "مدفوعات"],
    en: "Online payments are not active yet, so no one is being charged. For billing questions please open a ticket in the Billing category.",
    ar: "المدفوعات الإلكترونية غير مفعّلة بعد ولا يتم تحصيل أي مبالغ. لأسئلة الفوترة افتح تذكرة بتصنيف «الفوترة»." },
];
export const FALLBACK: Record<Lang, string> = {
  en: "I could not find a confident answer. I can create a support ticket so our team follows up — tap 'Create a ticket'.",
  ar: "لم أجد إجابة مؤكدة. يمكنني إنشاء تذكرة دعم ليتابع فريقنا معك — اضغط «إنشاء تذكرة».",
};
export function answer(q: string, lang?: Lang): { lang: Lang; topic: string | null; answer: string; offerTicket: boolean } {
  const l = lang ?? detectLang(q), t = q.toLowerCase(); let best: Entry | null = null, bs = 0;
  for (const e of KB) { const s = e.kw.filter((k) => t.includes(k.toLowerCase())).length; if (s > bs) { bs = s; best = e; } }
  return best ? { lang: l, topic: best.id, answer: best[l], offerTicket: true } : { lang: l, topic: null, answer: FALLBACK[l], offerTicket: true };
}
