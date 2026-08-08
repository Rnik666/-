#!/usr/bin/env python3
import base64
import json
import pathlib
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO = "Rnik666/-"
BRANCH = "2024/3"
SOURCE_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/Rnik666/-/refs/heads/2024/3/SSS"
TARGETS_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/Rnik666/-/refs/heads/main/config/targets.conf"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def curl(proxy, *args, timeout=20):
    return subprocess.run(
        ["curl", "-4fsS", "--proxy", proxy, "--max-time", str(timeout),
         "--connect-timeout", "7", *args],
        capture_output=True, text=True, timeout=timeout + 3,
    )


def test_node(node):
    parsed = urllib.parse.urlsplit(node)
    if not parsed.hostname or not parsed.port or not parsed.username:
        return None
    local_port = free_port()
    proxy = f"socks5h://127.0.0.1:{local_port}"
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port,
                       "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [{
            "protocol": "trojan",
            "settings": {"servers": [{"address": parsed.hostname,
                                         "port": parsed.port,
                                         "password": urllib.parse.unquote(parsed.username)}]},
            "streamSettings": {"network": "tcp", "security": "tls",
                               "tlsSettings": {"serverName": parsed.hostname,
                                               "allowInsecure": False}},
        }],
    }
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "config.json"
        path.write_text(json.dumps(config))
        process = subprocess.Popen(["xray", "run", "-config", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.8)
            delays = []
            exit_ip = ""
            for round_no in range(3):
                started = time.monotonic()
                check = curl(proxy, "-o", "/dev/null", "-w", "%{http_code}",
                             "https://www.gstatic.com/generate_204")
                if check.returncode or check.stdout.strip() != "204":
                    return None
                current_ip = curl(proxy, "https://api.ipify.org").stdout.strip()
                if not current_ip or (exit_ip and current_ip != exit_ip):
                    return None
                exit_ip = current_ip
                download = curl(proxy, "-o", "/dev/null", "-w", "%{size_download}",
                                "https://speed.cloudflare.com/__down?bytes=131072", timeout=25)
                if download.returncode or int(float(download.stdout.strip() or 0)) < 131072:
                    return None
                delays.append((time.monotonic() - started) * 1000)
                if round_no < 2:
                    time.sleep(2)
            base = node.split("#", 1)[0].split("?", 1)[0]
            query = urllib.parse.urlencode({"security": "tls", "type": "tcp",
                                            "headerType": "none", "sni": parsed.hostname})
            median_ms = statistics.median(delays)
            jitter_ms = max(delays) - min(delays)
            score_ms = median_ms + jitter_ms * 0.5
            return score_ms, f"{base}?{query}"
        except Exception:
            return None
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


def github_token():
    for line in pathlib.Path("/root/.config/github-ios/github.env").read_text().splitlines():
        if line.startswith("GITHUB_TOKEN="):
            return line.split("=", 1)[1]
    raise RuntimeError("GITHUB_TOKEN is missing")


def api_request(url, token, method="GET", data=None):
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": f"Bearer {token}",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read() or b"{}")


raw = urllib.request.urlopen(SOURCE_URL, timeout=30).read()
decoded = base64.b64decode(raw).decode()
candidates = list(dict.fromkeys(line.strip() for line in decoded.splitlines()
                                if line.strip().startswith("trojan://")))
print(f"Testing {len(candidates)} SSS candidates", flush=True)

passed = []
with ThreadPoolExecutor(max_workers=6) as executor:
    futures = [executor.submit(test_node, node) for node in candidates]
    for future in as_completed(futures):
        result = future.result()
        if result:
            passed.append(result)
            print(f"PASS {result[0]:.0f}ms", flush=True)

passed.sort(key=lambda item: item[0])
if not passed:
    raise SystemExit("No node passed; all target files preserved")

# Different source links can normalize to the same tested URI. Keep only the
# fastest result for each final URI before assigning disjoint target slices.
unique_passed = []
seen_nodes = set()
for delay, node in passed:
    if node in seen_nodes:
        continue
    seen_nodes.add(node)
    unique_passed.append((delay, node))
passed = unique_passed


def load_targets():
    targets = []
    config_text = urllib.request.urlopen(TARGETS_URL, timeout=30).read().decode()
    for number, raw_line in enumerate(config_text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise RuntimeError(f"Invalid targets.conf line {number}: {raw_line}")
        target, count = line.rsplit("=", 1)
        target = target.strip()
        count = int(count.strip())
        if not target or "/" in target or count < 1:
            raise RuntimeError(f"Invalid targets.conf line {number}: {raw_line}")
        targets.append((target, count))
    if not targets:
        raise RuntimeError("targets.conf has no targets")
    return targets


def publish(target, requested, selected, token):
    links = []
    for index, (_, node) in enumerate(selected, 1):
        label = urllib.parse.quote(f"🇸🇬新加坡{index}", safe="")
        links.append(f"{node}#{label}")
    subscription = base64.b64encode(("\n".join(links) + "\n").encode()).decode() + "\n"
    encoded_target = urllib.parse.quote(target, safe="")
    path_url = f"https://api.github.com/repos/{REPO}/contents/{encoded_target}"
    try:
        current = api_request(f"{path_url}?ref={urllib.parse.quote(BRANCH, safe='')}", token)
        sha = current.get("sha")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        sha = None
    payload = {
        "message": f"Update {target} with {len(links)} server-tested nodes",
        "content": base64.b64encode(subscription.encode()).decode(),
        "branch": BRANCH,
    }
    if sha:
        payload["sha"] = sha
    result = api_request(path_url, token, "PUT", json.dumps(payload).encode())
    print(f"Uploaded {len(links)}/{requested} nodes to {BRANCH}/{target}")
    print(result.get("commit", {}).get("html_url", ""))


token = github_token()
offset = 0
for target, requested in load_targets():
    selected = passed[offset:offset + requested]
    if not selected:
        print(f"Skipped {target}: no unused tested nodes remain", flush=True)
        continue
    publish(target, requested, selected, token)
    offset += len(selected)