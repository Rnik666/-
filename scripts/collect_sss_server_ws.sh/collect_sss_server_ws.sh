#!/usr/bin/env bash
set -euo pipefail

BASE=/root/.config/github-sss
WORK=$(mktemp -d)
API='https://api.github.com/repos/Rnik666/-/contents/SSS'
BRANCH='2024/3'
RAW='https://raw.githubusercontent.com/Rnik666/-/refs/heads/main/scripts/collect_sss.py'
PYTHON="$BASE/venv/bin/python"

cleanup() {
  local status=$?
  trap - EXIT
  rm -rf "$WORK"
  if (( status != 0 )); then
    echo "Run failed (exit $status); old SSS was preserved."
  fi
  exit "$status"
}
trap cleanup EXIT

if [[ -r "$BASE/task.env" ]]; then
  source "$BASE/task.env"
fi
if [[ -r "$BASE/starvpn.env" ]]; then
  source "$BASE/starvpn.env"
fi
: "${GITHUB_TOKEN:?GITHUB_TOKEN is missing}"
: "${STARVPN_AES_KEY:?STARVPN_AES_KEY is missing}"
: "${STARVPN_AES_IV:?STARVPN_AES_IV is missing}"
: "${STARVPN_ACCOUNT_ID:?STARVPN_ACCOUNT_ID is missing}"

curl -fL --retry 10 --connect-timeout 15 \
  "https://gh-proxy.com/$RAW?t=$(date +%s)" \
  -o "$WORK/collect_sss.py" ||
curl -fL --retry 10 --connect-timeout 15 \
  "$RAW?t=$(date +%s)" \
  -o "$WORK/collect_sss.py"

"$PYTHON" -c 'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$WORK/collect_sss.py"

curl -fsSL --retry 5 \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "$API?ref=2024%2F3&t=$(date +%s)" \
  > "$WORK/current.json"

jq -r '.content // empty' "$WORK/current.json" | tr -d '\n' | base64 -d > "$WORK/SSS"

(
  cd "$WORK"
  env \
    STARVPN_AES_KEY="$STARVPN_AES_KEY" \
    STARVPN_AES_IV="$STARVPN_AES_IV" \
    STARVPN_ACCOUNT_ID="$STARVPN_ACCOUNT_ID" \
    STARVPN_BASE_URL="${STARVPN_BASE_URL:-http://47.129.170.28}" \
    STARVPN_NODE_MODE="${STARVPN_NODE_MODE:-ws}" \
    STARVPN_MAX_NODES="${STARVPN_MAX_NODES:-150}" \
    STARVPN_BATCHES="${STARVPN_BATCHES:-5}" \
    "$PYTHON" "$WORK/collect_sss.py"
)

test -s "$WORK/SSS"
CONTENT=$(base64 -w 0 "$WORK/SSS")
SHA=$(jq -r '.sha // empty' "$WORK/current.json")
jq -n \
  --arg message "Collect WS SSS nodes from server" \
  --arg content "$CONTENT" \
  --arg branch "$BRANCH" \
  --arg sha "$SHA" \
  '{message:$message,content:$content,branch:$branch} + (if $sha == "" then {} else {sha:$sha} end)' \
  > "$WORK/upload.json"

curl -fsSL -X PUT \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" \
  "$API" --data-binary @"$WORK/upload.json" \
  > "$WORK/result.json"

jq -er '.commit.html_url' "$WORK/result.json"
echo "Uploaded server-generated ${STARVPN_NODE_MODE:-ws} SSS"
