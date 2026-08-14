cat > /root/.config/github-sss/collect.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

BASE=/root/.config/github-sss
WORK="$(mktemp -d)"
API='https://api.github.com/repos/Rnik666/-/contents/SSS'
BRANCH='2024/3'
MAX_NODES=160

trap 'rm -rf "$WORK"' EXIT

source /root/.config/github-ios/github.env

# 读取GitHub当前SSS文件及SHA
curl -fsSL \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "${API}?ref=2024%2F3&t=$(date +%s)" \
  > "$WORK/github.json"

SHA="$(jq -r '.sha // empty' "$WORK/github.json")"

# GitHub API解码一次得到订阅，再解码一次得到节点列表
jq -r '.content // empty' "$WORK/github.json" |
  tr -d '\n' |
  base64 -d |
  base64 -d > "$WORK/old.txt" 2>/dev/null || true

echo "Existing nodes: $(grep -cve '^[[:space:]]*$' "$WORK/old.txt" || true)"

# 只执行一次Python采集
python3 "$BASE/source.py" \
  --region "新加坡" \
  --output-dir "$WORK/new" \
  >/dev/null

NEW_FILE="$WORK/new/trojan_uris_tcp.txt"
test -s "$NEW_FILE"

echo "New nodes: $(grep -cve '^[[:space:]]*$' "$NEW_FILE")"

# 新节点 + 旧节点，按完整链接去重，最多保留200条
awk -v max="$MAX_NODES" '
  NF && !seen[$0]++ {
    print
    count++
    if (count >= max) exit
  }
' "$NEW_FILE" "$WORK/old.txt" > "$WORK/merged.txt"

TOTAL="$(grep -cve '^[[:space:]]*$' "$WORK/merged.txt")"
echo "Merged unique nodes: $TOTAL"

# 二次Base64编码，符合GitHub API要求
base64 -w 0 "$WORK/merged.txt" > "$WORK/subscription.txt"
base64 -w 0 "$WORK/subscription.txt" > "$WORK/api-content.txt"

jq -n \
  --arg message "Accumulate SSS nodes: ${TOTAL}" \
  --arg content "$(cat "$WORK/api-content.txt")" \
  --arg branch "$BRANCH" \
  --arg sha "$SHA" \
  '{
    message: $message,
    content: $content,
    branch: $branch,
    sha: $sha
  }' > "$WORK/upload.json"

curl -fsSL \
  -X PUT \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "$API" \
  --data-binary @"$WORK/upload.json" \
  > "$WORK/result.json"

echo "Uploaded $TOTAL unique nodes to $BRANCH/SSS"
jq -r '.commit.html_url // empty' "$WORK/result.json"
EOF

chmod 700 /root/.config/github-sss/collect.sh