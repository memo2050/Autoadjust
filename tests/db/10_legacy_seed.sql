-- Data that exists BEFORE multi-tenancy: seeded through the legacy tables exactly as the current app would.
insert into soc_assets (id, hostname, source) values ('legacy-asset-1', 'srv-legacy', 'test');
insert into soc_events (id, source, asset_id, "time", event_id) values ('legacy-event-1', 'test', 'legacy-asset-1', '2026-11-01T00:00:00Z', 4625);
insert into noc_devices (id, name, type, ip) values ('legacy-dev-1', 'core-sw', 'switch', '10.0.0.2');
insert into noc_scopes (id, name) values ('legacy-scope', 'old scope');
