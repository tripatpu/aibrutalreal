#!/usr/bin/env python3
"""
verify_endpoints.py — verify & classify AI / MCP / Skills endpoints found by ffuf.

Goal: take ffuf's raw hits and answer two questions per hit, with evidence:
  1) Is it a FALSE POSITIVE? (wildcard / soft-404 / catch-all SPA / redirect-to-login)
  2) If real, WHAT is it? -> MCP | AI_API | SKILLS | TOOLS | OPENAPI | OTHER

Approach (why this beats trusting ffuf status codes):
  * Per-host BASELINE: probe several random non-existent paths. Any hit whose
    response matches the baseline (status + body similarity + length) is a
    wildcard false positive, regardless of the 200 ffuf saw.
  * ACTIVE FINGERPRINTING: don't just look at status — send protocol-correct
    probes (JSON-RPC initialize for MCP, GET /v1/models shape for OpenAI-compat,
    Accept: text/event-stream for SSE, etc.) and score the *content*.
  * CONFIDENCE SCORE per category from weighted signals, so borderline hits are
    flagged rather than silently trusted -> fewer false positives, better recall.

Stdlib only (urllib) — no pip install required. Python 3.8+.

AUTHORIZED TESTING ONLY.
"""
import argparse
import concurrent.futures as cf
import csv
import hashlib
import json
import random
import re
import ssl
import string
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit

# ---------------------------------------------------------------------------
# HTTP helper (stdlib, tolerant of any status code, captures body + headers)
# ---------------------------------------------------------------------------
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE  # recon targets often have self-signed certs

UA = "ai-recon-verifier/1.0 (+authorized-testing-only)"
BODY_CAP = 65536  # bytes of body we keep for fingerprinting


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do NOT follow redirects: we need the raw 3xx + Location to detect
    login-wall catch-alls. Turn the redirect into a returnable response."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(
    _NoRedirect(), urllib.request.HTTPSHandler(context=_CTX))


def http(url, method="GET", headers=None, data=None, timeout=12):
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    t0 = time.time()
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            raw = r.read(BODY_CAP)
            return {
                "ok": True, "status": r.status, "url": r.geturl(),
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": raw.decode("utf-8", "replace"),
                "len": len(raw), "elapsed": round(time.time() - t0, 3), "error": None,
            }
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(BODY_CAP)
        except Exception:
            pass
        return {
            "ok": True, "status": e.code, "url": url,
            "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
            "body": raw.decode("utf-8", "replace"),
            "len": len(raw), "elapsed": round(time.time() - t0, 3), "error": None,
        }
    except Exception as e:
        return {"ok": False, "status": 0, "url": url, "headers": {}, "body": "",
                "len": 0, "elapsed": round(time.time() - t0, 3), "error": str(e)}


_UUID = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
_HEXID = re.compile(r'\b[0-9a-fA-F]{8,}\b')
_ISO = re.compile(r'\d{4}-\d{2}-\d{2}[ T][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?')
_EPOCH = re.compile(r'\b1[5-9]\d{8}(?:\d{3})?\b')   # unix seconds/millis ~2017-2033
_NUM = re.compile(r'\b\d{4,}\b')                     # long numeric ids/counters


def norm_body(b):
    """Normalize a body for similarity comparison (mask volatile bits so dynamic
    pages don't dodge the baseline check)."""
    b = _UUID.sub('U', b)
    b = _ISO.sub('DATE', b)
    b = _EPOCH.sub('TS', b)
    b = _HEXID.sub('X', b)
    b = _NUM.sub('N', b)
    b = re.sub(r'\s+', ' ', b)
    return b[:8000]


def sig(b):
    return hashlib.sha1(norm_body(b).encode("utf-8", "replace")).hexdigest()


def _tokset(b):
    return set(re.findall(r'[A-Za-z_]{3,}', norm_body(b).lower()))


def token_jaccard(a, b):
    """Vocabulary overlap — robust to random-word volatility that fools
    positional (SequenceMatcher) comparison."""
    ta, tb = _tokset(a), _tokset(b)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def similar(a, b):
    if not a and not b:
        return 1.0
    # Take the stronger of positional similarity and vocabulary overlap, so a
    # catch-all is caught whether it varies by word order OR by random tokens.
    return max(SequenceMatcher(None, norm_body(a), norm_body(b)).ratio(),
               token_jaccard(a, b))


def base_of(u):
    p = urlsplit(u)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


# ---------------------------------------------------------------------------
# Per-host baseline: what does a definitely-nonexistent path look like?
# ---------------------------------------------------------------------------
def rand_path(n=18):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def build_baseline(host, headers):
    samples = []
    sample_urls = []
    for _ in range(3):
        u = host.rstrip("/") + "/" + rand_path() + "/" + rand_path()
        r = http(u, headers=headers)
        if r["ok"]:
            samples.append(r)
            sample_urls.append(u)
    if not samples:
        return None

    # KEY ANTI-FALSE-POSITIVE STEP: run the SAME fingerprinters against a random
    # nonexistent path. On a normal host this scores ~0. On an "AI-shaped
    # catch-all" (a host that returns MCP/LLM-looking JSON on every path, e.g. a
    # gateway that echoes a trace-id), the random path scores high — telling us
    # any positive hit here is indistinguishable from noise and must be dropped.
    fp_scores = {}
    if sample_urls:
        for name, fn in CATEGORY_FPS:
            try:
                s, _ = fn(sample_urls[0], samples[0], headers)
            except Exception:
                s = 0
            fp_scores[name] = s

    return {
        "statuses": {s["status"] for s in samples},
        "lens": [s["len"] for s in samples],
        "bodies": [s["body"] for s in samples],
        "sigs": {sig(s["body"]) for s in samples},
        "redirect_locations": {s["headers"].get("location", "") for s in samples},
        "fp_scores": fp_scores,
    }


def is_false_positive(resp, baseline):
    """Return (bool, reason). Compares a real hit against the host baseline."""
    if baseline is None:
        return False, ""
    st = resp["status"]
    # Same status as a random 404-ish path + body looks the same -> wildcard.
    if st in baseline["statuses"]:
        if sig(resp["body"]) in baseline["sigs"]:
            return True, "identical-to-baseline"
        for bb in baseline["bodies"]:
            r = similar(resp["body"], bb)
            if r >= 0.90:   # positional OR token-jaccard (see similar())
                return True, "body~=baseline(%.2f)" % r
        # near-identical length + generic/empty body => catch-all
        if resp["len"] in baseline["lens"] and resp["len"] < 8:
            return True, "empty-catchall"
    # redirect that lands on the same place as the baseline redirect (login wall).
    # Works now that the HTTP helper does NOT auto-follow 3xx.
    loc = resp["headers"].get("location", "")
    if 300 <= st < 400 and loc:
        # strip volatile query tokens (?next=, csrf) before comparing
        bare = loc.split("?")[0]
        for bl in baseline["redirect_locations"]:
            if bl and bl.split("?")[0] == bare:
                return True, "redirect==baseline(%s)" % bare
        if re.search(r'/(login|signin|auth|sso|account/login)', bare, re.I):
            return True, "redirect-to-login(%s)" % bare
    return False, ""


# ---------------------------------------------------------------------------
# Fingerprinting: active probes + content signatures per category
# ---------------------------------------------------------------------------
JSON_CT = re.compile(r'application/(json|.*\+json)', re.I)
SSE_CT = re.compile(r'text/event-stream', re.I)


def try_json(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def fp_mcp(url, base_resp, headers):
    """Model Context Protocol: JSON-RPC 2.0 + optional SSE transport."""
    score, ev = 0, []
    ct = base_resp["headers"].get("content-type", "")
    if SSE_CT.search(ct):
        score += 3; ev.append("SSE content-type on GET")
    # Correct MCP handshake: POST JSON-RPC initialize
    init = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05",
                   "capabilities": {}, "clientInfo": {"name": "recon", "version": "1.0"}},
    })
    r = http(url, method="POST", data=init,
             headers={**(headers or {}), "Content-Type": "application/json",
                      "Accept": "application/json, text/event-stream"})
    if r["ok"]:
        j = try_json(r["body"])
        if isinstance(j, dict) and j.get("jsonrpc") == "2.0":
            score += 4; ev.append("JSON-RPC 2.0 response to initialize")
            res = j.get("result", {})
            if isinstance(res, dict) and ("capabilities" in res or "serverInfo" in res or "protocolVersion" in res):
                score += 4; ev.append("MCP initialize result (serverInfo/capabilities)")
            if "error" in j and isinstance(j["error"], dict):
                score += 2; ev.append("JSON-RPC error object (endpoint speaks JSON-RPC)")
        if SSE_CT.search(r["headers"].get("content-type", "")):
            score += 2; ev.append("SSE content-type on POST")
        if re.search(r'"jsonrpc"\s*:\s*"2\.0"', r["body"]):
            score += 1; ev.append("jsonrpc marker in body")
    # tools/list is an MCP-flavored method
    if re.search(r'tools?/list|resources?/list|prompts?/list', base_resp["body"], re.I):
        score += 1; ev.append("mcp method names in body")
    return score, ev


def fp_ai_api(url, base_resp, headers):
    """OpenAI-compatible / generic LLM inference API."""
    score, ev = 0, []
    body = base_resp["body"]
    j = try_json(body)
    # /v1/models shape
    if isinstance(j, dict):
        if j.get("object") == "list" and isinstance(j.get("data"), list):
            score += 3; ev.append('object:"list" data:[] (models listing)')
            if any(isinstance(m, dict) and "id" in m for m in j.get("data", [])):
                score += 2; ev.append("model objects with id")
        if "models" in j and isinstance(j["models"], list):
            score += 3; ev.append("Ollama-style models[]")
            # Ollama /api/tags entries carry name+model+digest — unambiguous enough
            # to confirm a self-hosted model server rather than leave it suspected.
            if any(isinstance(m, dict) and ({"name", "model", "digest", "modified_at"} & set(m))
                   for m in j["models"]):
                score += 2; ev.append("Ollama model entries (name/model/digest)")
        # Strong, unambiguous LLM-completion keys.
        keys = set(j.keys())
        if keys & {"choices", "completion", "generated_text"}:
            score += 2; ev.append("LLM completion keys")
        # Weak/generic keys ("response","content") only count WITH a co-signal —
        # otherwise any support-bot or CMS JSON with a "response" field over-triggers.
        elif keys & {"content", "response"} and (
                keys & {"model", "usage", "tokens", "finish_reason", "role", "prompt"}):
            score += 2; ev.append("generic response key + LLM co-signal")
        # Bare version blob: Ollama /api/version is exactly {"version":"x"}. Treat a
        # tiny version-only object as a suspected model server WITHOUT requiring a
        # model keyword; boost it when the path itself signals a model server.
        if "version" in j and len(j) <= 3:
            if re.search(r'ollama|llama|gpt|model|tgi|vllm|triton', body, re.I):
                score += 2; ev.append("model-server version blob")
            elif re.search(r'/api/version|/api/tags|/api/ps|internal/model', url, re.I):
                score += 2; ev.append("version blob at model-server path")
            else:
                score += 1; ev.append("minimal version object")
    # Error bodies from LLM gateways are very recognizable
    if re.search(r'"(error|message)"\s*:.*(model|api[_-]?key|token|prompt|completion|max_tokens)', body, re.I):
        score += 2; ev.append("LLM-style error body")
    if re.search(r'invalid_api_key|missing.*api.*key|authorization.*bearer|Incorrect API key', body, re.I):
        score += 2; ev.append("API-key auth error (LLM gateway)")
    # Active probe: chat/completions style POST
    if re.search(r'chat/completions|completions|/generate|/invoke|/predict', url):
        probe = json.dumps({"model": "gpt-3.5-turbo",
                            "messages": [{"role": "user", "content": "ping"}],
                            "max_tokens": 1})
        r = http(url, method="POST", data=probe,
                 headers={**(headers or {}), "Content-Type": "application/json"})
        if r["ok"]:
            if re.search(r'model|api[_-]?key|max_tokens|messages|prompt|choices', r["body"], re.I):
                score += 2; ev.append("chat-completions probe -> LLM-shaped response/error")
            if r["status"] in (401, 403) and re.search(r'key|auth|token', r["body"], re.I):
                score += 1; ev.append("auth-gated inference endpoint")
    return score, ev


def fp_skills_tools(url, base_resp, headers):
    """Skills / tools / plugin manifests & agent cards."""
    score, ev = 0, []
    body = base_resp["body"]
    j = try_json(body)
    # A tool/skill manifest is a list of DESCRIPTOR OBJECTS, not bare strings.
    # {"skills":["hiking","cooking"]} is a hobbies list, not an AI skills manifest,
    # so only credit lists whose elements are dicts carrying descriptor keys.
    DESC = {"name", "description", "inputschema", "input_schema", "parameters",
            "arguments", "schema", "endpoint", "operation", "function"}
    if isinstance(j, dict):
        for key in ("skills", "tools", "plugins", "functions"):
            v = j.get(key)
            if isinstance(v, list) and v:
                obj_items = [x for x in v if isinstance(x, dict)]
                described = [x for x in obj_items if {k.lower() for k in x} & DESC]
                if described:
                    score += 3; ev.append(f'"{key}":[] manifest of descriptor objects')
                    if any({"name", "description"} & {k.lower() for k in x} for x in described):
                        score += 2; ev.append(f"{key} entries have name/description")
                elif obj_items:
                    score += 1; ev.append(f'"{key}":[] list of objects (weak)')
                # bare-string lists (hobbies, tags) get no credit
        if {"schema_version", "name_for_model", "api"} & set(j.keys()):
            score += 4; ev.append("ai-plugin.json manifest")
        if {"name", "url", "capabilities", "skills"} & set(j.keys()) and "agent" in url.lower():
            score += 2; ev.append("agent card fields")
    if isinstance(j, list) and j and all(isinstance(x, dict) for x in j):
        if any({"name", "description", "inputSchema", "parameters"} & set(x.keys()) for x in j):
            score += 3; ev.append("array of tool/skill descriptors")
    return score, ev


def fp_openapi(url, base_resp, headers):
    """OpenAPI / Swagger schema (helps confirm the backend & enumerate more)."""
    # Scope gate: this toolkit hunts AI/MCP/skills. A valid OpenAPI schema is only
    # CONFIRMED (>=4) when it actually exposes AI-related paths; a generic schema
    # (billing, users, etc.) stays SUSPECTED so it doesn't inflate confirmed hits.
    score, ev = 0, []
    body = base_resp["body"]
    j = try_json(body)
    ai_re = r'chat|complet|embed|model|mcp|generate|inference|predict|skill|tool|prompt|assistant|llm|agent'
    if isinstance(j, dict):
        is_schema = "openapi" in j or "swagger" in j
        if is_schema:
            score += 2; ev.append("openapi/swagger version key")
        if "paths" in j and isinstance(j["paths"], dict):
            score += 1; ev.append("paths{} object")
            hits = [p for p in j["paths"] if re.search(ai_re, p, re.I)]
            if hits:
                score += 3; ev.append("AI-related paths in schema: " + ", ".join(hits[:5]))
            elif is_schema:
                ev.append("no AI paths in schema (non-AI API)")
    elif re.search(r'^\s*openapi\s*:', body, re.M) or re.search(r'^\s*swagger\s*:', body, re.M):
        score += 2; ev.append("openapi/swagger YAML")
        if re.search(ai_re, body, re.I):
            score += 2; ev.append("AI-related terms in YAML schema")
    return score, ev


CATEGORY_FPS = [
    ("MCP", fp_mcp),
    ("AI_API", fp_ai_api),
    ("SKILLS", fp_skills_tools),
    ("OPENAPI", fp_openapi),
]

# Score >= this to call a category confirmed; between LOW and CONFIRM = "suspected".
CONFIRM = 4
LOW = 2


def classify(url, headers):
    """Fetch fresh, run all fingerprinters, return the best category + evidence."""
    base = http(url, headers=headers)
    if not base["ok"]:
        return {"reachable": False, "error": base["error"], "resp": base}
    # capture Allow header via OPTIONS for method coverage
    opt = http(url, method="OPTIONS", headers=headers)
    allow = opt["headers"].get("allow", "") if opt["ok"] else ""

    scores = {}
    evidence = {}
    for name, fn in CATEGORY_FPS:
        try:
            s, ev = fn(url, base, headers)
        except Exception as e:
            s, ev = 0, [f"probe-error:{e}"]
        scores[name] = s
        evidence[name] = ev

    best = max(scores, key=scores.get)
    best_score = scores[best]
    if best_score >= CONFIRM:
        verdict = "confirmed"
    elif best_score >= LOW:
        verdict = "suspected"
    else:
        best, verdict = "OTHER", ("live" if best_score == 0 else "weak")

    return {
        "reachable": True,
        "status": base["status"],
        "content_type": base["headers"].get("content-type", ""),
        "len": base["len"],
        "server": base["headers"].get("server", ""),
        "allow": allow,
        "category": best,
        "verdict": verdict,
        "score": best_score,
        "all_scores": scores,
        "evidence": {k: v for k, v in evidence.items() if v},
        "resp": base,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def load_ffuf(path):
    data = json.load(open(path))
    out = []
    for r in data.get("results", []):
        u = r.get("url") or ""
        if not u:
            continue
        out.append({"url": u, "ffuf_status": r.get("status"),
                    "ffuf_len": r.get("length"), "ffuf_words": r.get("words")})
    # de-dup
    seen, uniq = set(), []
    for r in out:
        if r["url"] not in seen:
            seen.add(r["url"]); uniq.append(r)
    return uniq


def parse_headers(pairs):
    h = {}
    for p in pairs or []:
        if ":" in p:
            k, v = p.split(":", 1)
            h[k.strip()] = v.strip()
    return h


def main():
    ap = argparse.ArgumentParser(description="Verify & classify AI/MCP/Skills endpoints from ffuf output.")
    ap.add_argument("--ffuf", required=True, help="ffuf JSON output (-of json)")
    ap.add_argument("--out", default="aidataendpoint", help="output basename (writes .json and .csv)")
    ap.add_argument("--rate", type=int, default=50, help="approx worker count / parallelism")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra header 'K: V' (repeatable)")
    ap.add_argument("--min-verdict", choices=["all", "suspected", "confirmed"], default="all",
                    help="only write results at/above this confidence (default: all)")
    args = ap.parse_args()

    headers = parse_headers(args.header)
    hits = load_ffuf(args.ffuf)
    if not hits:
        print("[!] No hits in ffuf output.")
        # still emit empty files
        json.dump([], open(args.out + ".json", "w"), indent=2)
        open(args.out + ".csv", "w").close()
        return
    print(f"[*] Loaded {len(hits)} unique hits from ffuf.")

    # Build per-host baselines once.
    hosts = sorted({base_of(h["url"]) for h in hits})
    print(f"[*] Building soft-404 baselines for {len(hosts)} host(s)...")
    baselines = {}
    workers = max(2, min(args.rate, 32))
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for host, bl in zip(hosts, ex.map(lambda h: build_baseline(h, headers), hosts)):
            baselines[host] = bl

    # Verify + classify each hit.
    print(f"[*] Verifying {len(hits)} hits (parallel={workers})...")
    results = []

    def work(hit):
        cls = classify(hit["url"], headers)
        rec = {"url": hit["url"], "ffuf_status": hit["ffuf_status"], "ffuf_len": hit["ffuf_len"]}
        if not cls.get("reachable"):
            rec.update({"reachable": False, "false_positive": True,
                        "fp_reason": "unreachable-on-reprobe", "error": cls.get("error"),
                        "category": "DEAD", "verdict": "dead", "score": 0, "evidence": {}})
            return rec
        baseline = baselines.get(base_of(hit["url"]))
        fp, reason = is_false_positive(cls["resp"], baseline)

        # Fingerprint-baseline suppression: run the fingerprinters against a random
        # nonexistent path too. If that random path already fingerprints as the same
        # category, the host is an AI-shaped catch-all. Require the real hit to beat
        # the baseline by a MARGIN (not merely tie it) so a path-sensitive catch-all
        # that returns richer AI JSON on model-looking paths can't leak through; and
        # if the baseline itself CONFIRMS the category, suppress unconditionally.
        catchall_note = None
        adj_verdict = cls["verdict"]
        if not fp and baseline:
            cat = cls["category"]
            bscore = (baseline.get("fp_scores") or {}).get(cat, 0)
            MARGIN = 2
            if cat not in ("OTHER",) and bscore >= LOW:
                if bscore >= CONFIRM or cls["score"] < bscore + MARGIN:
                    fp = True
                    reason = "fingerprint-fires-on-baseline(%s: base=%d hit=%d need>=%d)" % (
                        cat, bscore, cls["score"], bscore + MARGIN)
                else:
                    # Hit beat the baseline by the margin, so we don't drop it — but
                    # the host still answers random paths with the same category, so
                    # we never CONFIRM here: cap at suspected for analyst review.
                    catchall_note = "host baseline also fingerprints %s=%d (possible catch-all)" % (cat, bscore)
                    if adj_verdict == "confirmed":
                        adj_verdict = "suspected"

        rec.update({
            "reachable": True,
            "status": cls["status"], "content_type": cls["content_type"],
            "len": cls["len"], "server": cls["server"], "allow": cls["allow"],
            "false_positive": fp, "fp_reason": reason,
            "category": ("FALSE_POSITIVE" if fp else cls["category"]),
            "verdict": ("false_positive" if fp else adj_verdict),
            "score": cls["score"], "all_scores": cls["all_scores"],
            "baseline_scores": (baseline.get("fp_scores") if baseline else {}),
            "catchall_warning": catchall_note,
            "evidence": cls["evidence"],
        })
        return rec

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for i, rec in enumerate(ex.map(work, hits), 1):
            results.append(rec)
            tag = rec["category"]
            mark = "x" if rec.get("false_positive") else ("+" if rec["verdict"] == "confirmed" else ".")
            print(f"  [{mark}] {rec['url']}  -> {tag}/{rec['verdict']} (score {rec.get('score',0)})")

    # Rank: confirmed real endpoints first.
    order = {"confirmed": 0, "suspected": 1, "live": 2, "weak": 3, "false_positive": 4, "dead": 5}
    results.sort(key=lambda r: (order.get(r["verdict"], 9), -(r.get("score") or 0)))

    # Filter for output if requested (but always keep full set in .json).
    def keep(r):
        if args.min_verdict == "all":
            return True
        if args.min_verdict == "suspected":
            return r["verdict"] in ("confirmed", "suspected")
        return r["verdict"] == "confirmed"

    written = [r for r in results if keep(r)]
    json.dump(written, open(args.out + ".json", "w"), indent=2)

    # CSV (flat, no nested evidence)
    cols = ["url", "category", "verdict", "score", "status", "content_type", "len",
            "server", "allow", "false_positive", "fp_reason", "ffuf_status"]
    with open(args.out + ".csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in written:
            w.writerow(r)

    # Summary rollup
    by_cat = defaultdict(int)
    confirmed = suspected = fps = dead = 0
    for r in results:
        by_cat[r["category"]] += 1
        if r["verdict"] == "confirmed": confirmed += 1
        elif r["verdict"] == "suspected": suspected += 1
        elif r["verdict"] == "false_positive": fps += 1
        elif r["verdict"] == "dead": dead += 1

    lines = []
    lines.append("AI / MCP / Skills endpoint verification summary")
    lines.append("=" * 48)
    lines.append(f"ffuf hits examined : {len(results)}")
    lines.append(f"confirmed real     : {confirmed}")
    lines.append(f"suspected          : {suspected}")
    lines.append(f"false positives    : {fps}")
    lines.append(f"dead/unreachable   : {dead}")
    lines.append("")
    lines.append("By category:")
    for k in sorted(by_cat, key=lambda x: -by_cat[x]):
        lines.append(f"  {k:<16} {by_cat[k]}")
    lines.append("")
    lines.append("Confirmed endpoints:")
    for r in results:
        if r["verdict"] == "confirmed":
            ev = "; ".join(sum(r.get("evidence", {}).values(), [])[:2])
            lines.append(f"  [{r['category']}] {r['url']}  ({ev})")
    summary = "\n".join(lines)

    import os
    outdir = os.path.dirname(os.path.abspath(args.out)) or "."
    with open(os.path.join(outdir, "summary.txt"), "w") as f:
        f.write(summary + "\n")

    print("\n" + summary)
    print(f"\n[+] Wrote {len(written)} records -> {args.out}.json / {args.out}.csv")


if __name__ == "__main__":
    main()
