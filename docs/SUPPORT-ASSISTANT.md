# Support assistant (AI + RAG)

## What it is
A bilingual (English/Arabic, auto-detected, RTL aware) customer support assistant on the public site (`public/support-widget.js` -> `POST /api/support/chat`).
Answers come from **verified product documentation** (`lib/support/knowledge.ts`, the RAG corpus) passed to an LLM. Each document carries an implementation status
(`available`, `unvalidated`, `planned`, `info`); the prompt forbids describing anything that is not `available` as working. Pricing and feature status are generated from
`lib/billing/pricing.ts`, so the assistant cannot drift from the pricing page. **Update `knowledge.ts` whenever a feature's real status changes** (e.g. after Wazuh/Zabbix/Windows/AI live validation).

## Provider and configuration
| Item | Value |
|---|---|
| Provider | Anthropic Messages API, called server-side (`lib/support/assistant.ts`, no SDK needed) |
| Key | `ANTHROPIC_API_KEY` (server env only; never sent to the browser, logged or returned). **Not set => AI is off and nothing is invented** |
| Model | `SUPPORT_MODEL`, else `BUILD_MODEL`, else `claude-sonnet-5-5` |
| `SUPPORT_AI_ANON_HOUR` / `SUPPORT_AI_USER_HOUR` | AI answers per hour per client (default 10 / 60; signed-in = verified session) |
| `SUPPORT_AI_GLOBAL_DAY` | Hard daily cap on provider calls for the whole site (default 400) |
| `SUPPORT_AI_MAX_TOKENS` | Output cap per answer (default 600, max 1200) |
| `SUPPORT_EMAIL` | Optional human-support address shown on escalation (validated; never invented) |

Use a **dedicated, spend-capped, development-only key** (see `docs/LIVE-AI-TEST.md`). Setting it costs money per answer: that is the owner's decision.

## Behaviour without AI
With no key or when the provider fails, the assistant answers from the top matching documentation chunk (labelled "From documentation"), escalates unknown questions to human support and never errors out.

## Safeguards (layered; none relies on the model behaving)
1. Input: 500-char cap, control characters stripped, history validated (roles, alternation, length); forged or injected turns are dropped.
2. Screening: instruction-override, system-prompt/secret extraction, other-customer data requests, role/markup spoofing, jailbreak and "execute this action now" requests (English + Arabic) are refused **without calling the model**.
3. Quotas: per-client hourly limit (anonymous vs signed-in), site-wide daily cap, output token cap, same-origin only, IP rate limit.
4. Prompt: docs are data, not instructions; status rules; no tools; a random canary marker is embedded and any answer containing it is discarded.
5. Output: secrets/JWTs/keys redacted, HTML and images stripped, all links removed, length capped; the widget renders with `textContent` only.
6. **No tenant data**: the assistant is given only public documentation and the current conversation. The signed-in user id affects only the quota tier and is never sent to the model. It has no tools and cannot perform, approve or schedule any action.
7. Escalation: breach/legal/billing-dispute/account-compromise/"talk to a human" requests, model uncertainty (`[[ESCALATE]]`) and questions with no documentation hit are directed to human support.

## Tickets
Creation/tracking/replies are implemented (`lib/support/tickets.ts`) but **disabled** until migration `0116` is separately approved and `SUPPORT_TICKETS_ENABLED=on`. Until then the assistant states the limitation and points to the Contact section / Request a Demo form (and `SUPPORT_EMAIL` if set).

## Tests
`tests/support.test.ts`, `tests/support-assistant.test.ts` (RAG accuracy, status honesty, Arabic/English, context, injection and extraction, output screening, escalation, provider outage, quotas, tenant isolation). The model is a stub there: they prove the guardrails, **not live-model answer quality**. Live AI verification requires the key above.
