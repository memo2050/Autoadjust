insert into auth.users (id, instance_id, aud, role, email) values
 ('aaaaaaaa-0000-4000-8000-00000000000a','00000000-0000-0000-0000-000000000000','authenticated','authenticated','a@example.invalid'),
 ('bbbbbbbb-0000-4000-8000-00000000000b','00000000-0000-0000-0000-000000000000','authenticated','authenticated','b@example.invalid');
insert into public.projects(id,user_id,name) values ('11111111-1111-4111-8111-111111111111','aaaaaaaa-0000-4000-8000-00000000000a','A'),('22222222-2222-4222-8222-222222222222','bbbbbbbb-0000-4000-8000-00000000000b','B');
insert into public.versions(project_id,prompt,html) values ('11111111-1111-4111-8111-111111111111','p','<a>'),('22222222-2222-4222-8222-222222222222','p','<b>');
insert into public.sites(slug,project_id,html,custom_domain) values ('site-a','11111111-1111-4111-8111-111111111111','<p>A</p>','a.example.test'),('site-b','22222222-2222-4222-8222-222222222222','<p>B</p>',null);
insert into public.usage(user_id,generations) values ('aaaaaaaa-0000-4000-8000-00000000000a',3);
insert into public.app_records(app_id,collection,data) values ('x','y','{"k":1}');
insert into public.soc_kev(id) values ('CVE-1'); insert into public.soc_meta(id) values ('kev');
