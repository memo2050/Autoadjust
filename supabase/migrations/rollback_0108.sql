-- Rollback of 0108: removes the Phase 5 diagnostic tables. Export noc_diag_jobs first if the history matters.
begin; drop table if exists public.noc_diag_jobs; drop table if exists public.noc_executors; delete from private.app_migrations where version = '0108'; commit;
