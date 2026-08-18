#!/usr/bin/env python3
import base64
import gzip
import json
import os
import socket
import sys
import time
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from Crypto.Cipher import AES


AES_KEY = os.environ["STARVPN_AES_KEY"].encode()
AES_IV = os.environ["STARVPN_AES_IV"].encode()
ACCOUNT = os.environ["STARVPN_ACCOUNT_ID"]
BASE_URL = os.environ.get("STARVPN_BASE_URL", "http://47.129.170.28")
NODE_MODE = os.environ.get("STARVPN_NODE_MODE", "ws").strip().lower()
MAX_NODES = int(os.environ.get("STARVPN_MAX_NODES", "150"))
BATCHES = int(os.environ.get("STARVPN_BATCHES", "5"))
CHECK_TIMEOUT = 5.0
WORKERS = 30
TARGET = Path("SSS")


if len(AES_KEY) not in (16, 24, 32) or len(AES_IV) != 16:
    raise SystemExit("Invalid STARVPN_AES_KEY or STARVPN_AES_IV length")
if NODE_MODE not in {"ws", "tcp", "all"}:
    raise SystemExit("STARVPN_NODE_MODE must be ws, tcp, or all")
if MAX_NODES < 1 or BATCHES < 1:
    raise SystemExit("STARVPN_MAX_NODES and STARVPN_BATCHES must be positive")


def pkcs7_pad(data, block=16):
    size = block - len(data) % block
    return data + bytes([size]) * size


def pkcs7_unpad(data):
    size = data[-1]
    if not 1 <= size <= 16 or data[-size:] != bytes([size]) * size:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-size]


def aes_encrypt(data):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pkcs7_pad(data))


def aes_decrypt(data):
    raw = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(data)
    return pkcs7_unpad(raw)


def encrypt(payload):
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    return base64.b64encode(aes_encrypt(raw)).decode()


def decrypt(text):
    encrypted = base64.b64decode("".join(text.split()), validate=True)
    return json.loads(aes_decrypt(encrypted).decode("utf-8-sig"))


def decode_body(body, encoding=""):
    if "gzip" in encoding.lower() or body.startswith(b"\x1f\x8b"):
        body = gzip.decompress(body)
    text = body.decode("utf-8-sig").strip()
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


class Client:
    def __init__(self, base_url, timeout=15, retries=2):
        self.url = base_url.rstrip("/") + "/service/line.php"
        self.timeout = timeout
        self.retries = retries

    def call(self, payload):
        body = json.dumps({"key": encrypt(payload)}, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept-Encoding": "gzip"},
        )
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return decode_body(response.read(), response.headers.get("Content-Encoding", ""))
            except Exception as error:
                if attempt >= self.retries:
                    raise RuntimeError(f"request failed: {error}") from error
                time.sleep(0.5 * (attempt + 1))


def get_nodes(value):
    if not isinstance(value, dict):
        raise RuntimeError("API response is not an object")
    if value.get("status") not in (None, "success"):
        raise RuntimeError(f"API status: {value}")
    data = value.get("data")
    if not isinstance(data, list):
        raise RuntimeError("API response has no data[]")
    return [item for item in data if isinstance(item, dict)]


def is_singapore(node):
    values = " ".join(
        str(node.get(field, ""))
        for field in ("region_cn", "name_cn", "country", "region_en", "name_en")
    ).lower()
    return "新加坡" in values or "singapore" in values or values.strip() == "sg"


def node_label(node, index):
    name = (
        node.get("name_cn")
        or node.get("region_cn")
        or node.get("name_en")
        or node.get("country")
        or f"node-{index}"
    )
    return f"{name} #{index}"


def make_uri(host, port, label, ws=False):
    account = urllib.parse.quote(ACCOUNT, safe="")
    encoded_label = urllib.parse.quote(label, safe="")
    if ws:
        query = urllib.parse.urlencode(
            {
                "security": "tls",
                "sni": host,
                "type": "ws",
                "host": host,
                "path": "/img/ser/",
            }
        )
    else:
        query = urllib.parse.urlencode({"mux": "1"})
    return f"trojan://{account}@{host}:{port}?{query}#{encoded_label}"


def check_alive(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=CHECK_TIMEOUT):
            return True
    except Exception:
        return False


def mode_is_ws(uri):
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)
    return query.get("type", [""])[0].lower() == "ws"


def keep_previous(uri):
    if not uri.startswith("trojan://"):
        return False
    if NODE_MODE == "all":
        return True
    return mode_is_ws(uri) if NODE_MODE == "ws" else not mode_is_ws(uri)


def uri_key(uri):
    return uri.split("#", 1)[0]


def collect_once(client, run_number):
    payload = {
        "task": "vps_info",
        "account_ID": ACCOUNT,
        "device_id": str(uuid.uuid4()).upper(),
    }
    initial = [node for node in get_nodes(client.call(payload)) if is_singapore(node)]
    servers = list(dict.fromkeys(str(node.get("server", "")).strip() for node in initial if node.get("server")))
    print(f"Collection {run_number}: {len(initial)} Singapore nodes, {len(servers)} servers", flush=True)
    for server in servers:
        client.call({"account_ID": ACCOUNT, "task": "register_host", "way": 2, "server": server})
        time.sleep(0.1)

    final_nodes = get_nodes(client.call(payload))
    server_set = set(servers)
    entries = []
    for index, node in enumerate(final_nodes, 1):
        server = str(node.get("server", "")).strip()
        port = str(node.get("port", "")).strip()
        spare = str(node.get("spare_server", "")).strip()
        if not server or not port or server not in server_set:
            continue
        if NODE_MODE in {"tcp", "all"}:
            label = node_label(node, index)
            entries.append(("tcp", server, port, make_uri(server, port, label)))
        if NODE_MODE in {"ws", "all"} and spare:
            label = node_label(node, index) + " WS"
            entries.append(("ws", spare, port, make_uri(spare, port, label, ws=True)))
    print(f"Collection {run_number}: built {len(entries)} {NODE_MODE} entries", flush=True)
    return entries


def main():
    client = Client(BASE_URL)
    entries = []
    for run_number in range(1, BATCHES + 1):
        entries.extend(collect_once(client, run_number))

    unique_entries = []
    seen = set()
    for entry in entries:
        key = uri_key(entry[3])
        if key not in seen:
            seen.add(key)
            unique_entries.append(entry)

    addresses = {(entry[1], entry[2]) for entry in unique_entries}
    print(f"Testing {len(addresses)} unique addresses", flush=True)
    alive = set()
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(check_alive, host, port): (host, port) for host, port in addresses}
        for future in as_completed(futures):
            address = futures[future]
            try:
                if future.result():
                    alive.add(address)
            except Exception:
                pass

    fresh = [entry[3] for entry in unique_entries if (entry[1], entry[2]) in alive]
    print(f"Live {NODE_MODE} entries: {len(fresh)}", flush=True)

    candidates = []
    if TARGET.exists():
        try:
            previous = base64.b64decode(TARGET.read_text().strip()).decode().splitlines()
            candidates.extend(uri_key(line) for line in previous if keep_previous(line))
            print(f"Loaded {len(candidates)} previous {NODE_MODE} candidates", flush=True)
        except Exception as error:
            print(f"Ignored invalid previous SSS: {error}", flush=True)

    candidates.extend(fresh)
    candidates = list(dict.fromkeys(candidates))
    if not candidates:
        raise SystemExit("No live candidates collected; old SSS preserved")
    candidates = candidates[-MAX_NODES:]

    renamed = []
    for index, uri in enumerate(candidates, 1):
        renamed.append(f"{uri}#{urllib.parse.quote(f'🇸🇬新加坡{index}', safe='')}")
    output = "\n".join(renamed) + "\n"
    TARGET.write_text(base64.b64encode(output.encode()).decode() + "\n")
    print(f"Saved {len(renamed)} cumulative unique {NODE_MODE} nodes to SSS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Collection failed: {error}", file=sys.stderr, flush=True)
        raise
