#!/usr/bin/env bash
set -euo pipefail

if (( EUID != 0 )); then
  echo "Run this installer as root (use sudo)." >&2
  exit 1
fi

BASE=/root/.config/github-sss
RAW_BASE='https://raw.githubusercontent.com/Rnik666/-/refs/heads/main/scripts'

fetch_script() {
  local name="$1"
  local output="$2"
  local nonce
  nonce="$(date +%s)"

  curl -fL --retry 10 --connect-timeout 15 \
    "https://gh-proxy.com/$RAW_BASE/$name?t=$nonce" \
    -o "$output" ||
  curl -fL --retry 10 --connect-timeout 15 \
    "$RAW_BASE/$name?t=$nonce" \
    -o "$output"
}

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

fetch_script source_sss.py "$BASE/source_sss.py.ref"

STARVPN_AES_KEY="$(sed -n 's/^AES_KEY *= *b"\([^"]*\)".*/\1/p' "$BASE/source_sss.py.ref" | head -n1)"
STARVPN_AES_IV="$(sed -n 's/^AES_IV *= *b"\([^"]*\)".*/\1/p' "$BASE/source_sss.py.ref" | head -n1)"
STARVPN_ACCOUNT_ID="$(sed -n 's/^DEFAULT_ACCOUNT *= *"\([^"]*\)".*/\1/p' "$BASE/source_sss.py.ref" | head -n1)"

test -n "$STARVPN_AES_KEY"
test -n "$STARVPN_AES_IV"
test -n "$STARVPN_ACCOUNT_ID"
rm -f "$BASE/source_sss.py.ref"

umask 077
{
  printf 'export GITHUB_TOKEN=%q\n' "$GITHUB_TOKEN"
  printf 'export STARVPN_AES_KEY=%q\n' "$STARVPN_AES_KEY"
  printf 'export STARVPN_AES_IV=%q\n' "$STARVPN_AES_IV"
  printf 'export STARVPN_ACCOUNT_ID=%q\n' "$STARVPN_ACCOUNT_ID"
} > "$BASE/task.env"
chmod 600 "$BASE/task.env"

cat > "$BASE/collect.sh" <<'RUN'
#!/usr/bin/env bash
set -euo pipefail

BASE=/root/.config/github-sss
WORK="$(mktemp -d)"
API='https://api.github.com/repos/Rnik666/-/contents/SSS'
BRANCH='2024/3'
REF='2024%2F3'
RAW='https://raw.githubusercontent.com/Rnik666/-/refs/heads/main/scripts/collect_sss.py'

trap 'rm -rf "$WORK"' EXIT
source "$BASE/task.env"

curl -fL --retry 10 --connect-timeout 15 \
  "https://gh-proxy.com/$RAW?t=$(date +%s)" \
  -o "$WORK/collect_sss.py" ||
curl -fL --retry 10 --connect-timeout 15 \
  "$RAW?t=$(date +%s)" \
  -o "$WORK/collect_sss.py"

curl -fsSL --retry 5 \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "$API?ref=$REF&t=$(date +%s)" > "$WORK/github.json"

SHA="$(jq -r '.sha // empty' "$WORK/github.json")"
test -n "$SHA"
jq -r '.content // empty' "$WORK/github.json" |
  tr -d '\n' | base64 -d > "$WORK/SSS"

(cd "$WORK" && python3 collect_sss.py)

CONTENT="$(base64 -w 0 "$WORK/SSS")"
jq -n \
  --arg message "Update SSS from 5-minute server task" \
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
