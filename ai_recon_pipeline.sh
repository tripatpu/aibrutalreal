#!/usr/bin/env bash
#
# ai_recon_pipeline.sh — AI / MCP / Skills endpoint discovery pipeline
# ---------------------------------------------------------------------------
# Wraps ffuf in the clusterbomb pattern you specified:
#
#     ffuf -w urllist:URL -w aiwordlist:FUZZ -u URL/FUZZ -mc 200 -c -rate 50 -t 100
#
# then hands the raw hits to verify_endpoints.py to strip false positives and
# classify each surviving hit as MCP / AI-API / SKILLS / DOCS / OTHER.
#
# AUTHORIZED TESTING ONLY. Run this only against hosts you own or have explicit
# written permission to test. Content discovery generates real traffic and logs.
# ---------------------------------------------------------------------------
set -euo pipefail

# ---------- Defaults (override via flags) ----------
URLLIST=""                       # -l  file of base URLs, one per line (scheme required)
WORDLIST="./ai_endpoint_wordlist.txt"   # -w  path wordlist
OUTDIR="./ai_recon_$(date +%Y%m%d_%H%M%S)"  # -o  output directory
RATE=50                          # -r  requests/sec (ffuf -rate)
THREADS=100                      # -t  concurrency (ffuf -t)
MATCH_CODES="200,201,204,301,302,307,401,403,405,406"  # -mc  (wider than 200 on purpose: see notes)
EXTRA_HEADERS=()                 # -H  repeatable, passed straight to ffuf
FOLLOW_REDIRECTS=0               # -F  add -r to ffuf (follow redirects)
NO_VERIFY=0                      # --no-verify  skip the python verification stage
PYTHON_BIN="${PYTHON_BIN:-python3}"
VERIFY_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify_endpoints.py"

usage() {
  cat <<'EOF'
Usage: ./ai_recon_pipeline.sh -l <urllist> [options]

Required:
  -l FILE     URL list (one base URL per line, scheme included, e.g. https://host:8080)

Options:
  -w FILE     Path wordlist            (default: ./ai_endpoint_wordlist.txt)
  -o DIR      Output directory         (default: ./ai_recon_<timestamp>)
  -r N        Rate limit req/sec       (default: 50)
  -t N        Threads / concurrency    (default: 100)
  -mc CODES   Match HTTP status codes  (default: 200,201,204,301,302,307,401,403,405,406)
  -H 'K: V'   Extra header (repeatable, e.g. -H 'Authorization: Bearer x')
  -F          Follow redirects (ffuf -r)
  --no-verify Skip verification stage (raw ffuf output only)
  -h          Show this help

Why match more than 200?
  AI/MCP endpoints frequently answer discovery probes with 401 (auth required),
  403 (present but forbidden), 405/406 (wrong method/Accept — MCP wants POST +
  text/event-stream). Capturing these and letting the verifier confirm them by
  content gives far better coverage than -mc 200 alone. Pass '-mc 200' to mimic
  your original command exactly.

Output:
  <OUTDIR>/ffuf_raw.json        full ffuf result set
  <OUTDIR>/aidataendpoint.json  verified + classified endpoints
  <OUTDIR>/aidataendpoint.csv   same, flat CSV
  <OUTDIR>/summary.txt          human-readable rollup
EOF
}

# ---------- Arg parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l) URLLIST="$2"; shift 2 ;;
    -w) WORDLIST="$2"; shift 2 ;;
    -o) OUTDIR="$2"; shift 2 ;;
    -r) RATE="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -mc) MATCH_CODES="$2"; shift 2 ;;
    -H) EXTRA_HEADERS+=("$2"); shift 2 ;;
    -F) FOLLOW_REDIRECTS=1; shift ;;
    --no-verify) NO_VERIFY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[!] Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

# ---------- Preflight ----------
command -v ffuf >/dev/null 2>&1 || { echo "[!] ffuf not found in PATH. Install: https://github.com/ffuf/ffuf" >&2; exit 1; }
[[ -n "$URLLIST" ]] || { echo "[!] -l <urllist> is required." >&2; usage; exit 1; }
[[ -f "$URLLIST" ]] || { echo "[!] URL list not found: $URLLIST" >&2; exit 1; }
[[ -f "$WORDLIST" ]] || { echo "[!] Wordlist not found: $WORDLIST" >&2; exit 1; }

mkdir -p "$OUTDIR"

# ffuf ignores '#' comments in wordlists by default, but normalize to be safe:
CLEAN_WL="$OUTDIR/wordlist.clean.txt"
grep -vE '^\s*(#|$)' "$WORDLIST" | sed 's#^/##' | sort -u > "$CLEAN_WL"

CLEAN_URLS="$OUTDIR/urls.clean.txt"
grep -vE '^\s*(#|$)' "$URLLIST" | sed 's#/*$##' | sort -u > "$CLEAN_URLS"

WL_COUNT=$(wc -l < "$CLEAN_WL" | tr -d ' ')
URL_COUNT=$(wc -l < "$CLEAN_URLS" | tr -d ' ')
echo "[*] URLs: $URL_COUNT   Words: $WL_COUNT   Combinations: $((URL_COUNT * WL_COUNT))"
echo "[*] Output dir: $OUTDIR"

RAW_JSON="$OUTDIR/ffuf_raw.json"

# ---------- Build ffuf command ----------
# Clusterbomb (ffuf default with multiple -w) = every URL x every word.
FFUF_ARGS=(
  -w "$CLEAN_URLS:URL"
  -w "$CLEAN_WL:FUZZ"
  -u "URL/FUZZ"
  -mc "$MATCH_CODES"
  -c
  -rate "$RATE"
  -t "$THREADS"
  -ac                      # auto-calibrate to filter wildcard/soft-404 noise
  -timeout 10
  -json                    # machine-readable stdout (kept quiet; file is authoritative)
  -o "$RAW_JSON"
  -of json
)
[[ "$FOLLOW_REDIRECTS" -eq 1 ]] && FFUF_ARGS+=( -r )
for h in "${EXTRA_HEADERS[@]:-}"; do
  [[ -n "$h" ]] && FFUF_ARGS+=( -H "$h" )
done

echo "[*] Running: ffuf ${FFUF_ARGS[*]}"
# Do not let a non-zero ffuf exit (e.g. no matches) kill the pipeline.
set +e
ffuf "${FFUF_ARGS[@]}"
FFUF_RC=$?
set -e
[[ "$FFUF_RC" -ne 0 ]] && echo "[!] ffuf exited with code $FFUF_RC (continuing)."

if [[ ! -s "$RAW_JSON" ]]; then
  echo "[!] No ffuf output produced. Nothing to verify." >&2
  exit 0
fi

RAW_HITS=$("$PYTHON_BIN" -c "import json,sys;print(len(json.load(open(sys.argv[1])).get('results',[])))" "$RAW_JSON" 2>/dev/null || echo "?")
echo "[*] ffuf raw hits: $RAW_HITS  -> $RAW_JSON"

# ---------- Verification stage ----------
if [[ "$NO_VERIFY" -eq 1 ]]; then
  echo "[*] --no-verify set. Skipping verification. Raw results in $RAW_JSON"
  exit 0
fi

[[ -f "$VERIFY_SCRIPT" ]] || { echo "[!] verify_endpoints.py not found next to this script." >&2; exit 1; }

VERIFY_ARGS=(
  "$VERIFY_SCRIPT"
  --ffuf "$RAW_JSON"
  --out "$OUTDIR/aidataendpoint"
  --rate "$RATE"
)
[[ "${#EXTRA_HEADERS[@]}" -gt 0 ]] && for h in "${EXTRA_HEADERS[@]}"; do VERIFY_ARGS+=( -H "$h" ); done

echo "[*] Verifying + classifying hits ..."
"$PYTHON_BIN" "${VERIFY_ARGS[@]}"

echo
echo "[+] Done."
echo "    Verified JSON : $OUTDIR/aidataendpoint.json"
echo "    Verified CSV  : $OUTDIR/aidataendpoint.csv"
echo "    Summary       : $OUTDIR/summary.txt"
[[ -f "$OUTDIR/summary.txt" ]] && { echo; cat "$OUTDIR/summary.txt"; }
