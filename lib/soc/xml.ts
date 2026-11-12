// Minimal, safe XML reader for scanner reports. No DTD/entity expansion (blocks XXE and "billion laughs").
export interface XNode { name: string; attrs: Record<string, string>; children: XNode[]; text: string }

const ENT: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
const dec = (s: string) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
  if (e[0] === "#") { const n = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ""; }
  return ENT[e.toLowerCase()] ?? m;
});

export function parseXml(src: string): XNode {
  if (src.length > 25_000_000) throw new Error("XML file too large (limit 25 MB).");
  if (/<!ENTITY/i.test(src)) throw new Error("XML with entity declarations is rejected for safety.");
  const root: XNode = { name: "#root", attrs: {}, children: [], text: "" };
  const stack: XNode[] = [root];
  const re = /<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<\/([\w:.-]+)\s*>|<([\w:.-]+)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    const top = stack[stack.length - 1];
    if (m[1] !== undefined) top.text += m[1];
    else if (m[2]) { if (stack.length > 1) stack.pop(); }
    else if (m[3]) {
      const attrs: Record<string, string> = {};
      for (const a of m[4].matchAll(/([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) attrs[a[1]] = dec(a[2] ?? a[3] ?? "");
      const n: XNode = { name: m[3], attrs, children: [], text: "" };
      top.children.push(n);
      if (!m[5]) stack.push(n);
    } else if (m[6] !== undefined) top.text += dec(m[6]);
  }
  return root;
}
export const kids = (n: XNode | undefined, name: string) => (n ? n.children.filter((c) => c.name === name) : []);
export const kid = (n: XNode | undefined, name: string) => kids(n, name)[0];
export const txt = (n: XNode | undefined) => (n ? n.text.trim() : "");
export function findAll(n: XNode, name: string, out: XNode[] = []): XNode[] {
  for (const c of n.children) { if (c.name === name) out.push(c); findAll(c, name, out); }
  return out;
}
