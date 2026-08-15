#!/usr/bin/env bash
set -euo pipefail

BASE=/root/.config/github-sss
install -d -m 700 "$BASE"

cat > "$BASE/collect.sh" <<'RUN'
#!/usr/bin/env bash
set -euo pipefail

BASE=/root/.config/github-sss
WORK="$(mktemp -d)"
API='https://api.github.com/repos/Rnik666/-/contents/SSS'
BRANCH='2024/3'
MAX_NODES=100
RAW='https://raw.githubusercontent.com/Rnik666/-/refs/heads/main/scripts/source_sss.py'

cleanup() {
  local status=$?
  trap - EXIT
  rm -rf "$WORK"
  if (( status != 0 )); then
    echo "Run failed (exit $status); SSS was not uploaded; next cron will retry."
  fi
  exit "$status"
}
trap cleanup EXIT

if [[ -r "$BASE/task.env" ]]; then
  source "$BASE/task.env"
elif [[ -r /root/.config/github-ios/github.env ]]; then
  source /root/.config/github-ios/github.env
else
  echo "GitHub token environment file was not found." >&2
  exit 1
fi

curl -fL --retry 10 --connect-timeout 15 \
  "https://gh-proxy.com/$RAW?t=$(date +%s)" \
  -o "$WORK/source.py" ||
curl -fL --retry 10 --connect-timeout 15 \
  "$RAW?t=$(date +%s)" \
  -o "$WORK/source.py"

curl -fsSL --retry 5 \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "$API?ref=2024%2F3&t=$(date +%s)" \
  > "$WORK/github.json"

SHA="$(jq -r '.sha // empty' "$WORK/github.json")"
test -n "$SHA"

jq -r '.content // empty' "$WORK/github.json" |
  tr -d '\n' |
  base64 -d |
  base64 -d > "$WORK/old.txt"

echo "Existing nodes: $(grep -cve '^[[:space:]]*$' "$WORK/old.txt" || true)"

PYTHON="$BASE/venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON=python3
fi

"$PYTHON" "$WORK/source.py" \
  --region "新加坡" \
  --output-dir "$WORK/new" \
  >/dev/null

NEW_FILE="$WORK/new/trojan_uris_tcp.txt"
test -s "$NEW_FILE"
echo "New nodes: $(grep -cve '^[[:space:]]*$' "$NEW_FILE")"

# New nodes first, then old nodes. Duplicates are intentionally retained.
awk -v max="$MAX_NODES" '
  NF {
    print
    count++
    if (count >= max) exit
  }
' "$NEW_FILE" "$WORK/old.txt" > "$WORK/merged.txt"

TOTAL="$(grep -cve '^[[:space:]]*$' "$WORK/merged.txt")"
test "$TOTAL" -gt 0
echo "Merged nodes (duplicates allowed): $TOTAL"

# Build the complete replacement payload only after collection succeeds.
base64 -w 0 "$WORK/merged.txt" > "$WORK/subscription.txt"
base64 -w 0 "$WORK/subscription.txt" > "$WORK/api-content.txt"

jq -n \
  --arg message "Accumulate SSS nodes: $TOTAL" \
  --arg content "$(cat "$WORK/api-content.txt")" \
  --arg branch "$BRANCH" \
  --arg sha "$SHA" \
  '{message:$message,content:$content,branch:$branch,sha:$sha}' \
  > "$WORK/upload.json"

curl -fsSL -X PUT \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" \
  "$API" --data-binary @"$WORK/upload.json" \
  > "$WORK/result.json"

COMMIT_URL="$(jq -er '.commit.html_url' "$WORK/result.json")"
echo "$COMMIT_URL"
echo "Uploaded $TOTAL nodes to $BRANCH/SSS"
RUN

chmod 700 "$BASE/collect.sh"
bash -n "$BASE/collect.sh"

cat > /etc/cron.d/github-sss <<'CRON'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

*/3 * * * * root flock -n /run/github-sss.lock timeout 1800s /root/.config/github-sss/collect.sh >> /root/.config/github-sss/cron.log 2>&1
CRON

chmod 644 /etc/cron.d/github-sss
touch "$BASE/cron.log"
chmod 600 "$BASE/cron.log"

systemctl enable --now cron
systemctl reload cron 2>/dev/null || systemctl restart cron

echo "Installed SSS cron: every 3 minutes, up to 150 nodes, duplicates allowed."
