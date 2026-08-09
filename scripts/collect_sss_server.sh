#!/usr/bin/env bash
set -euo pipefail

BASE=/root/.config/github-sss
WORK="$(mktemp -d)"
API='https://api.github.com/repos/Rnik666/-/contents/SSS'
BRANCH='2024/3'
MAX_NODES=100

trap 'rm -rf "$WORK"' EXIT

source /root/.config/github-ios/github.env

# Read the existing subscription for fallback nodes and its update SHA.
curl -fsSL \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "${API}?ref=2024%2F3&t=$(date +%s)" \
  > "$WORK/github.json"

SHA="$(jq -r '.sha // empty' "$WORK/github.json")"

jq -r '.content // empty' "$WORK/github.json" \
  | tr -d '\n' \
  | base64 -d \
  | base64 -d \
  > "$WORK/old.txt" 2>/dev/null || true

echo "Existing nodes: $(grep -cve '^[[:space:]]*$' "$WORK/old.txt" || true)"

# Take three snapshots five minutes apart instead of repeating the same API round.
for n in 1 2 3; do
  echo "Collecting batch $n/3 at $(date '+%F %T')"
  python3 "$BASE/source.py" \
    --region "新加坡" \
    --output-dir "$WORK/new-$n" \
    >/dev/null

  if [ "$n" -lt 3 ]; then
    sleep 300
  fi
done

for n in 1 2 3; do
  test -s "$WORK/new-$n/trojan_uris_tcp.txt"
done

# Prefer the newest snapshots; use old SSS only to fill any remaining slots.
awk -v max="$MAX_NODES" '
  NF && !seen[$0]++ {
    print
    count++
    if (count >= max) exit
  }
' \
  "$WORK/new-3/trojan_uris_tcp.txt" \
  "$WORK/new-2/trojan_uris_tcp.txt" \
  "$WORK/new-1/trojan_uris_tcp.txt" \
  "$WORK/old.txt" \
  > "$WORK/merged.txt"

TOTAL="$(grep -cve '^[[:space:]]*$' "$WORK/merged.txt")"
test "$TOTAL" -gt 0
echo "Merged unique nodes: $TOTAL"

# Store a base64 subscription inside the GitHub Contents API payload.
base64 -w 0 "$WORK/merged.txt" > "$WORK/subscription.txt"
base64 -w 0 "$WORK/subscription.txt" > "$WORK/api-content.txt"

jq -n \
  --arg message "Refresh SSS with ${TOTAL} rolling nodes" \
  --arg content "$(cat "$WORK/api-content.txt")" \
  --arg branch "$BRANCH" \
  --arg sha "$SHA" \
  '{message:$message, content:$content, branch:$branch, sha:$sha}' \
  > "$WORK/upload.json"

curl -fsSL -X PUT \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "$API" \
  --data-binary @"$WORK/upload.json" \
  > "$WORK/result.json"

echo "Uploaded $TOTAL unique nodes to $BRANCH/SSS"
jq -r '.commit.html_url // empty' "$WORK/result.json"
