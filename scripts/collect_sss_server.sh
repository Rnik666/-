#!/usr/bin/env bash
set -euo pipefail

if (( EUID != 0 )); then
  echo "Run this installer as root (use sudo)." >&2
  exit 1
fi

BASE=/root/.config/github-sss

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  curl jq cron util-linux coreutils ca-certificates python3 python3-pycryptodome

install -d -m 700 "$BASE"

if [[ -n "${1:-}" ]]; then
  GITHUB_TOKEN="$1"
else
  read -rsp 'GitHub Token: ' GITHUB_TOKEN </dev/tty
  echo >/dev/tty
fi

if [[ "$GITHUB_TOKEN" != github_pat_* ]]; then
  echo "Expected a fine-grained GitHub token beginning with github_pat_." >&2
  exit 1
fi

umask 077
printf 'export GITHUB_TOKEN=%q\n' "$GITHUB_TOKEN" > "$BASE/task.env"
chmod 600 "$BASE/task.env"

cat > "$BASE/collect.sh" <<'RUN'
#!/usr/bin/env bash
set -euo pipefail

BASE=/root/.config/github-sss
WORK="$(mktemp -d)"
API='https://api.github.com/repos/Rnik666/-/contents/SSS'
BRANCH='2024/3'
REF='2024%2F3'
MAX_NODES=200
RAW='https://raw.githubusercontent.com/Rnik666/-/refs/heads/main/scripts/source_sss.py'

trap 'rm -rf "$WORK"' EXIT
source "$BASE/task.env"

curl -fL --retry 10 --connect-timeout 15 \
  "https://gh-proxy.com/$RAW?t=$(date +%s)" \
  -o "$WORK/source.py" ||
curl -fL --retry 10 --connect-timeout 15 \
  "$RAW?t=$(date +%s)" \
  -o "$WORK/source.py"

curl -fsSL --retry 5 \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "$API?ref=$REF&t=$(date +%s)" > "$WORK/github.json"

SHA="$(jq -r '.sha // empty' "$WORK/github.json")"
test -n "$SHA"
jq -r '.content // empty' "$WORK/github.json" |
  tr -d '\n' |
  base64 -d |
  base64 -d > "$WORK/old.txt" 2>/dev/null || true

echo "Existing nodes: $(grep -cve '^[[:space:]]*$' "$WORK/old.txt" || true)"

/usr/bin/python3 "$WORK/source.py" \
  --region "新加坡" \
  --output-dir "$WORK/new" \
  >/dev/null

NEW_FILE="$WORK/new/trojan_uris_tcp.txt"
test -s "$NEW_FILE"
echo "New nodes: $(grep -cve '^[[:space:]]*$' "$NEW_FILE")"

awk -v max="$MAX_NODES" '
  NF && !seen[$0]++ {
    print
    count++
    if (count >= max) exit
  }
' "$NEW_FILE" "$WORK/old.txt" > "$WORK/merged.txt"

TOTAL="$(grep -cve '^[[:space:]]*$' "$WORK/merged.txt")"
echo "Merged unique nodes: $TOTAL"

base64 -w 0 "$WORK/merged.txt" > "$WORK/subscription.txt"
CONTENT="$(base64 -w 0 "$WORK/subscription.txt")"
jq -n \
  --arg message "Accumulate SSS nodes: $TOTAL" \
  --arg content "$CONTENT" \
  --arg branch "$BRANCH" \
  --arg sha "$SHA" \
  '{message:$message,content:$content,branch:$branch,sha:$sha}' \
  > "$WORK/upload.json"

curl -fsSL -X PUT \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" \
  "$API" --data-binary @"$WORK/upload.json" |
  jq -er '.commit.html_url'

echo "Uploaded $TOTAL unique nodes to $BRANCH/SSS"
RUN

chmod 700 "$BASE/collect.sh"
bash -n "$BASE/collect.sh"

sed -i '\#collect.sh#d' /etc/cron.d/github-nodes 2>/dev/null || true
cat > /etc/cron.d/github-sss <<'CRON'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * root flock -n /run/github-sss.lock timeout 290s /root/.config/github-sss/collect.sh >> /root/.config/github-sss/cron.log 2>&1
CRON

chmod 644 /etc/cron.d/github-sss
touch "$BASE/cron.log"
chmod 600 "$BASE/cron.log"

systemctl enable --now cron
systemctl restart cron
timeout 290s "$BASE/collect.sh" 2>&1 | tee -a "$BASE/cron.log"

systemctl is-active cron
grep -R "collect.sh" /etc/cron.d/
tail -n 30 "$BASE/cron.log"
