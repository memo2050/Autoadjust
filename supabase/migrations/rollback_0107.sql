-- Rollback for 0107. Restores the global unique index. FAILS (safely, nothing changes) if two organizations already hold the same seq; that is
-- the point of 0107, so only roll back before a second organization writes audit records.
begin;
create unique index if not exists soc_audit_seq on public.soc_audit (seq) where seq is not null;
drop index if exists public.soc_audit_org_seq;
delete from private.app_migrations where version = '0107';
commit;
