# Safe live testing of Viewer, Analyst and the other lower roles (staging only)

Goal: test every role against the live staging API **without touching the clean A/B tenant-isolation setup**.

## Design
- Org A (owner staging-a) and Org B (owner staging-b) stay exactly as they are.
- Create ONE extra staging user, `staging-c@example.com` (Supabase dashboard of the **staging** project, Auto Confirm User on; the owner types the password, nobody else sees it).
- staging-c has **no organization of its own**. staging-a invites it into Org A; the owner then changes its role through the five roles one at a time (account page, "Members" table). staging-c can therefore only ever see Org A; it is never a member of Org B.
- Two browser tabs (each tab has its own session): tab 1 = staging-a (owner, changes roles), tab 2 = staging-c (runs the probe).

## Steps (the owner does the typing of passwords and clicking Join; Claude runs the probes)
1. Owner: create `staging-c@example.com` in the staging Supabase Authentication > Users.
2. Tab 1 (staging-a, account page): Invitations > invite staging-c as `executive_readonly` (Viewer). The invitation token is shown once.
3. Tab 2: sign in as staging-c, paste the token under "Join with an invitation".
4. Claude runs `AA_ROLE_MATRIX("executive_readonly")` in tab 2 (scripts/live/role-matrix.js): 8 harmless probes, expected allowed/403 per role.
5. Tab 1: change staging-c's role to `security_analyst`; tab 2: Claude runs the probe again. Repeat for `noc_operator`, `it_admin`, and finally `owner` is NOT used (c is never made owner).
6. Isolation re-check: staging-c asks for Org B's id (`x-org-id`) and must get 403 for every endpoint; Org B's audit log must be unchanged.
7. Cleanup (owner's choice, nothing is deleted without approval): leave staging-c as a Viewer in Org A, or remove the membership from the account page.

## Safety
- Probes are GETs or POSTs with an empty body that validation rejects (no data is created, changed or deleted).
- Expected results come from `lib/tenant/auth.ts` (ROLE_MAP, DOMAIN, PERMS); `tests/role-matrix.test.ts` fails if the probe table and the code ever disagree.
- No production resource is involved; production project and DNS are untouched.
