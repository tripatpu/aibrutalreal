# AI / MCP / Skills Endpoint Discovery Pipeline

A two-stage recon toolkit: **ffuf-based content discovery** → **content-aware verification** that strips false positives and classifies each surviving hit as MCP, AI API, Skills, Tools, or OpenAPI.

> **Authorized testing only.** Run only against hosts you own or have explicit written permission to test. Content discovery generates real, logged traffic.

## Files

| File | Purpose |
|------|---------|
| `ai_recon_pipeline.sh` | ffuf wrapper (clusterbomb: every URL × every path), then calls the verifier |
| `verify_endpoints.py` | Re-probes hits, kills false positives, fingerprints & classifies (stdlib only) |
| `ai_endpoint_wordlist.txt` | ~140 curated AI / MCP / skills / plugin / OpenAPI paths |

## Requirements

- [`ffuf`](https://github.com/ffuf/ffuf) in `PATH`
- `python3` 3.8+ (no pip packages needed — stdlib only)

## Quick start

```bash
# 1. urls.txt — one base URL per line, scheme included:
#    https://target-a.example.com
#    https://target-b.example.com:8080

chmod +x ai_recon_pipeline.sh
./ai_recon_pipeline.sh -l urls.txt -w ai_endpoint_wordlist.txt
```

Mirrors your original ffuf pattern:

```
ffuf -w urls.txt:URL -w ai_endpoint_wordlist.txt:FUZZ -u URL/FUZZ -mc 200 -c -rate 50 -t 100 -o aidataendpoint
```

## Options

```
-l FILE     URL list (required)
-w FILE     wordlist              (default ./ai_endpoint_wordlist.txt)
-o DIR      output dir            (default ./ai_recon_<timestamp>)
-r N        rate req/sec          (default 50)
-t N        threads               (default 100)
-mc CODES   match status codes    (default 200,201,204,301,302,307,401,403,405,406)
-H 'K: V'   extra header (repeatable, e.g. auth token)
-F          follow redirects
--no-verify raw ffuf output only
```

Example with auth + exact-original match codes:

```bash
./ai_recon_pipeline.sh -l urls.txt -mc 200 -H 'Authorization: Bearer TOKEN'
```

## Output (in `<OUTDIR>/`)

- `ffuf_raw.json` — full raw ffuf result set
- `aidataendpoint.json` — verified + classified endpoints (with evidence)
- `aidataendpoint.csv` — flat table
- `summary.txt` — rollup + list of confirmed endpoints

## How false positives are reduced (better precision)

1. **Per-host soft-404 baseline.** Before judging hits, the verifier requests several random non-existent paths per host. Any hit whose status + normalized body + length matches that baseline is dropped as a **wildcard / catch-all**, even if ffuf saw `200`.
2. **Body normalization.** Volatile tokens (ids, hashes, timestamps) are stripped before similarity comparison, so dynamic pages don't dodge the baseline check.
3. **Redirect-to-login detection.** Hits that redirect to the same place as the baseline (a login wall) are flagged.
4. **Re-probe.** Every hit is fetched fresh; transient ffuf hits that no longer resolve are marked dead.

## How coverage is improved (better recall)

1. **Wider match codes by default.** Real AI/MCP endpoints answer discovery with `401/403/405/406` (auth required, wrong method/Accept). `-mc 200` alone misses them; the verifier confirms them by content.
2. **Active protocol probes**, not just status codes:
   - **MCP** → POST JSON-RPC `initialize`; looks for `jsonrpc:"2.0"`, `serverInfo`/`capabilities`, and `text/event-stream` (SSE transport).
   - **AI API** → `/v1/models` shape (`object:"list"`, model ids), Ollama `models[]`, chat/completions probe, API-key auth errors.
   - **Skills/Tools** → `skills[]`/`tools[]`/`plugins[]` manifests, `ai-plugin.json`, agent cards.
   - **OpenAPI** → `openapi`/`swagger` schema; extracts AI-related paths for a second-pass wordlist.
3. **Confidence scoring.** Each hit gets a per-category score → `confirmed` (≥4), `suspected` (2–3), or `weak/live`. Borderline hits are surfaced as *suspected* rather than silently dropped, so you review them instead of missing them.
4. **Catch-all awareness.** The fingerprinters are also run against a random baseline path. If that path fingerprints as the same category, the host is an AI-shaped catch-all: hits that don't clearly beat the baseline are dropped, and hits that only *just* beat it are capped at `suspected` with a `catchall_warning` field (`"host baseline also fingerprints ... (possible catch-all)"`) so you review rather than trust them.
5. **Skill/tool manifests are validated by shape.** A `skills`/`tools` list only scores when its elements are descriptor objects (with `name`/`description`/`inputSchema`), so `{"skills":["hiking","cooking"]}` (a hobbies list) is not mistaken for an AI skills manifest. Generic `response`/`content` keys only count toward AI classification alongside a real LLM co-signal (`model`, `usage`, `choices`, …).

Filter output by confidence:

```bash
python3 verify_endpoints.py --ffuf ffuf_raw.json --out aidataendpoint --min-verdict suspected
```

## Tuning notes

- **Feedback loop:** if the OpenAPI fingerprinter finds a schema, its `paths` are logged in the evidence — feed those back into the wordlist for a deeper second pass.
- **Rate/threads:** defaults (50/100) are aggressive for a lab. Lower `-r` on production targets to stay under WAF/rate limits.
- **Auth:** pass session/bearer headers with `-H`; they're forwarded to both ffuf and the verifier so auth-gated endpoints classify correctly.
