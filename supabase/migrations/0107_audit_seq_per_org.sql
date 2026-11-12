-- 0107_audit_seq_per_org.sql  |  The SOC audit hash chain is now one chain PER ORGANIZATION, so its sequence number must be unique per organization, not globally.
-- Without this, the second organization's first audit record (seq = 1) is rejected. Only an index is replaced; no row is read, changed or deleted.
-- Existing rows all belong to the Default organization, so the new index cannot conflict with them (a global-unique set is also unique per org).
begin;
create unique index if not exists soc_audit_org_seq on public.soc_audit (org_id, seq) where seq is not null;
drop index if exists public.soc_audit_seq;
insert into private.app_migrations (version, name) values ('0107', 'audit_seq_per_org') on conflict do nothing;
commit;
