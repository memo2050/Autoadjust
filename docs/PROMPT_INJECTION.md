# Prompt-injection protection (AI SOC/NOC analysts)

Logs, alerts and command lines are written by whoever controls the monitored systems, so they are treated as hostile data.

Controls (all enforced by the server; none depends on the model behaving):
1. **Clean:** invisible/bidi/control characters removed, text normalised (NFKC) so look-alikes cannot hide instructions; every string capped.
2. **Fence:** the packet is JSON in which `<` and `>` are escaped, so no log text can close the `<evidence>` block or open a fake tag. The system prompt says the block is data only.
3. **Detect:** instruction-like text is found by pattern (including base64-wrapped text); matching field *paths* (never the text) are passed to the model as hostile data and written to the audit log as `ai.injection_suspected`.
4. **Validate output:** unknown evidence ids are stripped; unsupported findings are flagged; action types are allowlisted; output is rendered escaped.
5. **Targets must be real:** a disruptive proposal (isolate, disable, block, reset, scan) is queued for approval only if its target is a host/account/address from an identity field of the evidence that was not itself instruction-like. Otherwise it is shown but never queued.
6. **Humans decide:** every disruptive proposal still needs explicit approval; the analyst never executes anything.

Tested (`tests/prompt-injection.test.ts`): 360 templated hostile payloads x a deliberately hijacked stub model, plus 30 paraphrase/foreign-language/encoded payloads. Detection is heuristic and incomplete by nature (it flags 100% of the templated set and about half of the evasion set); the structural controls (2, 4, 5, 6) held in every case. This does **not** show how a real model behaves: the live suite (`tests/live`, workflow `ai-live`) must be run with a spend-limited key and is **NOT TESTED** yet.
