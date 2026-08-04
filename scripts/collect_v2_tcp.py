import base64
import gzip
import json
import os
import pathlib
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from Crypto.Cipher import AES

KEY = os.environ["STARVPN_AES_KEY"].encode()
IV = os.environ["STARVPN_AES_IV"].encode()
ACCOUNT = os.environ["STARVPN_ACCOUNT_ID"]
API = "http://47.129.170.28/service/line.php"
TARGET = pathlib.Path("-V2")
TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.google.com/generate_204",
)


def pad(data):
    size = 16 - len(data) % 16
    return data + bytes([size]) * size


def unpad(data):
    return data[: -data[-1]]


def encrypt(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    encrypted = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(raw))
    return base64.b64encode(encrypted).decode()


def decrypt(text):
    encrypted = base64.b64decode("".join(text.split()))
    raw = AES.new(KEY, AES.MODE_CBC, IV).decrypt(encrypted)
    return json.loads(unpad(raw).decode("utf-8-sig"))


def call(payload):
    body = json.dumps({"key": encrypt(payload)}, separators=(",", ":")).encode()
    request = urllib.request.Request(
        API,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip",
            "User-Agent": "Postpop/1 CFNetwork-compatible",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read()
        if "gzip" in response.headers.get("Content-Encoding", "") or data.startswith(b"\x1f\x8b"):
            data = gzip.decompress(data)
    text = data.decode("utf-8-sig").strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return decrypt(text)
    if isinstance(value, dict):
        for field in ("msg", "key", "data"):
            item = value.get(field)
            if isinstance(item, str):
                try:
                    return decrypt(item)
                except Exception:
                    pass
    return value


def nodes(value):
    if not isinstance(value, dict) or not isinstance(value.get("data"), list):
        raise RuntimeError("Invalid API response")
    return [item for item in value["data"] if isinstance(item, dict)]


def singapore(node):
    fields = ("region_cn", "name_cn", "country", "region_en", "name_en")
    values = " ".join(str(node.get(field, "")) for field in fields).lower()
    return "新加坡" in values or "singapore" in values or values.strip() == "sg"


def collect_once(run):
    device = str(uuid.uuid4()).upper()
    payload = {"task": "vps_info", "account_ID": ACCOUNT, "device_id": device}
    initial = [node for node in nodes(call(payload)) if singapore(node)]
    servers = list(dict.fromkeys(str(node.get("server", "")).strip() for node in initial if node.get("server")))
    for server in servers:
        call({"account_ID": ACCOUNT, "task": "register_host", "way": 2, "server": server})
    result = []
    for node in nodes(call(payload)):
        host = str(node.get("server", "")).strip()
        port = str(node.get("port", "")).strip()
        if host in servers and port:
            label = urllib.parse.quote(f"🇸🇬 新加坡 TCP R{run}", safe="")
            password = urllib.parse.quote(ACCOUNT, safe="")
            result.append(f"trojan://{password}@{host}:{port}?mux=1#{label}")
    print(f"Collection {run}: {len(result)} TCP nodes", flush=True)
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_node(node):
    parsed = urllib.parse.urlsplit(node)
    local_port = free_port()
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [{
            "protocol": "trojan",
            "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "password": urllib.parse.unquote(parsed.username)}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": parsed.hostname, "allowInsecure": False}},
        }],
    }
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "config.json"
        path.write_text(json.dumps(config))
        process = subprocess.Popen(["xray", "run", "-config", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.45)
            delays = []
            for _ in range(3):
                for url in TEST_URLS:
                    started = time.monotonic()
                    result = subprocess.run(
                        ["curl", "-fsS", "--max-time", "8", "--connect-timeout", "5", "--socks5-hostname", f"127.0.0.1:{local_port}", "-o", "/dev/null", "-w", "%{http_code}", url],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode or result.stdout.strip() != "204":
                        return None
                    delays.append((time.monotonic() - started) * 1000)
            ordered = sorted(delays)
            p90 = ordered[max(0, int(len(ordered) * 0.9) - 1)]
            return p90 + statistics.pstdev(delays) * 0.5, node
        except Exception:
            return None
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


if len(KEY) not in (16, 24, 32) or len(IV) != 16:
    raise SystemExit("Invalid secret lengths")

candidates = []
for run in range(1, 4):
    candidates.extend(collect_once(run))
candidates = list(dict.fromkeys(candidates))
print(f"Unique TCP candidates: {len(candidates)}")

passed = []
with ThreadPoolExecutor(max_workers=6) as executor:
    futures = [executor.submit(test_node, node) for node in candidates]
    for future in as_completed(futures):
        result = future.result()
        if result:
            passed.append(result)
            print(f"Passed 9/9 score={result[0]:.0f}", flush=True)

passed.sort(key=lambda item: item[0])
if not passed:
    raise SystemExit("No TCP node passed all tests; old -V2 preserved")
output = "\n".join(node for _, node in passed) + "\n"
TARGET.write_text(base64.b64encode(output.encode()).decode() + "\n")
print(f"Saved all {len(passed)} working TCP nodes sorted fastest-first")
  
