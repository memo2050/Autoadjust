// Tenant filter for the Wazuh bridge. One bridge instance serves ONE AutoAdjust organization. When several organizations share one Wazuh server,
// the instance is bound to that organization's Wazuh agent group (and optionally an agent label) so it can only list and read that tenant's data.
// Three independent layers keep tenants apart: (1) Wazuh roles for the bridge's own users (see deploy/wazuh), (2) the request filters built here,
// (3) the verification here of every row that comes back (a misconfigured or misbehaving Wazuh can never push another tenant's data), then AutoAdjust's per-organization API key.
const NAME = /^[A-Za-z0-9._-]{1,64}$/, VALUE = /^[A-Za-z0-9._:-]{1,80}$/;
export function tenantFilterFromEnv(E) {
  const group = String(E.WAZUH_TENANT_GROUP ?? "").trim(), label = String(E.WAZUH_TENANT_LABEL ?? "").trim(), key = String(E.WAZUH_TENANT_LABEL_KEY ?? "tenant").trim() || "tenant", require = E.REQUIRE_TENANT_FILTER === "1";
  const problem = (() => {
    if (group && !NAME.test(group)) return "WAZUH_TENANT_GROUP may contain only letters, digits, dot, dash and underscore (max 64).";
    if (label && !group) return "WAZUH_TENANT_LABEL needs WAZUH_TENANT_GROUP too: the agent list can only be limited by group.";
    if (label && !VALUE.test(label)) return "WAZUH_TENANT_LABEL has characters that are not allowed.";
    if (!NAME.test(key)) return "WAZUH_TENANT_LABEL_KEY has characters that are not allowed.";
    if (require && !group) return "REQUIRE_TENANT_FILTER=1 but WAZUH_TENANT_GROUP is not set; refusing to read every tenant's data.";
    return null;
  })();
  return { group, label, key, require, active: !!group, problem };
}
const groupsOf = (a) => (Array.isArray(a?.group) ? a.group : a?.group ? [a.group] : []).map(String);
export const agentInTenant = (a, f) => !f.active || groupsOf(a).includes(f.group);
/** An alert belongs to the tenant only if its agent is one of the tenant's agents (manager-level alerts, agent 000, never do) and, when a label is set, carries that label. */
export function alertInTenant(al, f, ids) {
  if (!f.active) return true;
  const id = String(al?.agent?.id ?? ""); if (!id || id === "000" || !ids.has(id)) return false;
  return !f.label || String(al?.agent?.labels?.[f.key] ?? "") === f.label;
}
export function alertQuery(f, ids, range) {
  if (!f.active) return { range };
  const filter = [{ range }, { terms: { "agent.id": [...ids] } }]; if (f.label) filter.push({ term: { [`agent.labels.${f.key}`]: f.label } });
  return { bool: { filter } };
}
