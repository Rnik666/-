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
from datetime import datetime, timedelta, timezone

# ==================== 可调参数 ====================
MAX_WORKERS = 20                # 并发测试线程数（原6）
TEST_ROUNDS = 2                 # 每节点测试轮数（原3）
DOWNLOAD_BYTES = 64 * 1024      # 下载测试文件大小（原128KB）
CURL_TIMEOUT = 12               # 常规请求超时（原20）
CONNECT_TIMEOUT = 4             # 连接超时（原7）
DOWNLOAD_TIMEOUT = 15           # 下载测试超时（原25）
ROUND_SLEEP = 1                 # 轮间等待秒数（原2）
MAX_CANDIDATES = 200            # 最大测试候选数（超出部分丢弃）
# ==================================================

REPO = "Rnik666/-"
BRANCH = "2024/3"
SOURCE_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/Rnik666/-/refs/heads/2024/3/SSS"
BY_SOURCE_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/Rnik666/-/refs/heads/2024/3/SSS-BY"
TARGETS_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/Rnik666/-/refs/heads/main/config/targets.conf"
CHINA_TZ = timezone(timedelta(hours=8))


def free_port():
    """获取本机空闲 TCP 端口。"""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def curl(proxy, *args, timeout=CURL_TIMEOUT):
    """
    使用指定代理执行 curl 命令。
    timeout: 请求最大时长（秒）
    """
    return subprocess.run(
        ["curl", "-4fsS", "--proxy", proxy, "--max-time", str(timeout),
         "--connect-timeout", str(CONNECT_TIMEOUT), *args],
        capture_output=True, text=True, timeout=timeout + 3,
    )


def test_node(node):
    """
    测试单个 trojan 节点，返回 (score_ms, normalized_node) 或 None。
    优化：缩短每轮时间，减少轮数，快速失败。
    """
    parsed = urllib.parse.urlsplit(node)
    if not parsed.hostname or not parsed.port or not parsed.username:
        return None

    local_port = free_port()
    proxy = f"socks5h://127.0.0.1:{local_port}"

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "socks",
            "settings": {"udp": False}
        }],
        "outbounds": [{
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "password": urllib.parse.unquote(parsed.username)
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": parsed.hostname,
                    "allowInsecure": False
                }
            },
        }],
    }

    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "config.json"
        path.write_text(json.dumps(config))

        process = subprocess.Popen(
            ["xray", "run", "-config", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        try:
            time.sleep(0.8)  # 等待 xray 就绪
            delays = []
            exit_ip = ""

            for round_no in range(TEST_ROUNDS):
                started = time.monotonic()

                # 连通性检查（generate_204）
                check = curl(proxy, "-o", "/dev/null", "-w", "%{http_code}",
                             "https://www.gstatic.com/generate_204")
                if check.returncode or check.stdout.strip() != "204":
                    return None

                # 出口 IP 检查
                current_ip = curl(proxy, "https://api.ipify.org").stdout.strip()
                if not current_ip or (exit_ip and current_ip != exit_ip):
                    return None
                exit_ip = current_ip

                # 下载测速（文件大小由 DOWNLOAD_BYTES 控制）
                download_url = f"https://speed.cloudflare.com/__down?bytes={DOWNLOAD_BYTES}"
                download = curl(proxy, "-o", "/dev/null", "-w", "%{size_download}",
                                download_url, timeout=DOWNLOAD_TIMEOUT)
                if download.returncode or int(float(download.stdout.strip() or 0)) < DOWNLOAD_BYTES:
                    return None

                delays.append((time.monotonic() - started) * 1000)

                if round_no < TEST_ROUNDS - 1:
                    time.sleep(ROUND_SLEEP)

            # 构造标准化节点链接
            base = node.split("#", 1)[0].split("?", 1)[0]
            query = urllib.parse.urlencode({
                "security": "tls",
                "type": "tcp",
                "headerType": "none",
                "sni": parsed.hostname
            })
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
    """从配置文件读取 GitHub Token。"""
    for line in pathlib.Path("/root/.config/github-ios/github.env").read_text().splitlines():
        if line.startswith("GITHUB_TOKEN="):
            return line.split("=", 1)[1]
    raise RuntimeError("GITHUB_TOKEN is missing")


def api_request(url, token, method="GET", data=None):
    """调用 GitHub API 并返回 JSON。"""
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read() or b"{}")


def load_targets():
    """加载目标订阅配置。"""
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
    """生成订阅并上传到 GitHub。"""
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


def run_once():
    """执行一次完整的测试-筛选-发布流程。"""
    now = datetime.now(CHINA_TZ)
    by_mode = now.hour == 10
    source_url = BY_SOURCE_URL if by_mode else SOURCE_URL
    source_name = "SSS-BY" if by_mode else "SSS"
    print(f"Source mode: {source_name} at {now:%Y-%m-%d %H:%M:%S} UTC+8", flush=True)

    raw = urllib.request.urlopen(source_url, timeout=30).read()
    decoded = base64.b64decode(raw).decode()
    candidates = list(dict.fromkeys(
        line.strip() for line in decoded.splitlines()
        if line.strip().startswith("trojan://")
    ))
    original_count = len(candidates)
    if original_count > MAX_CANDIDATES:
        candidates = candidates[:MAX_CANDIDATES]
        print(f"Limiting candidates from {original_count} to {MAX_CANDIDATES}", flush=True)
    print(f"Testing {len(candidates)} {source_name} candidates", flush=True)

    passed = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_node, node) for node in candidates]
        for future in as_completed(futures):
            result = future.result()
            if result:
                passed.append(result)
                print(f"PASS {result[0]:.0f}ms", flush=True)

    passed.sort(key=lambda item: item[0])

    # 去重（保留评分最优）
    unique_passed = []
    seen_nodes = set()
    for score, node in passed:
        if node in seen_nodes:
            continue
        seen_nodes.add(node)
        unique_passed.append((score, node))
    passed = unique_passed

    targets = load_targets()
    total_required = sum(requested for _, requested in targets)

    ready_at = datetime.now(CHINA_TZ)
    if (ready_at.hour == 10) != by_mode:
        raise RuntimeError(
            "source window changed during testing; discarding results before upload"
        )

    if by_mode:
        if not passed:
            raise RuntimeError("no live SSS-BY nodes passed")
        live_count = len(passed)
        passed = [passed[index % live_count] for index in range(total_required)]
        print(
            f"Repeating {live_count} live SSS-BY nodes to fill {total_required} target slots",
            flush=True,
        )
    elif len(passed) < total_required:
        raise RuntimeError(
            f"only {len(passed)}/{total_required} unique nodes passed"
        )

    token = github_token()
    offset = 0
    for target, requested in targets:
        selected = passed[offset:offset + requested]
        publish(target, requested, selected, token)
        offset += requested


def main():
    """程序入口，最多尝试两次完整运行。"""
    max_attempts = 2
    for attempt in range(1, max_attempts + 1):
        print(f"Full run attempt {attempt}/{max_attempts}", flush=True)
        try:
            run_once()
            print("Full run completed", flush=True)
            return 0
        except Exception as error:
            print(f"Full run failed: {error}", flush=True)
            if attempt < max_attempts:
                print("Retrying complete run in 10 seconds", flush=True)
                time.sleep(10)

    print("All attempts failed; existing subscriptions preserved", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())