import base64
import gzip
import json
import os
import pathlib
import urllib.parse
import urllib.request
import uuid

from Crypto.Cipher import AES

KEY = os.environ["STARVPN_AES_KEY"].encode()
IV = os.environ["STARVPN_AES_IV"].encode()
ACCOUNT = os.environ["STARVPN_ACCOUNT_ID"]
API = "http://47.129.170.28/service/line.php"
TARGET = pathlib.Path("SSS")


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
            password = urllib.parse.quote(ACCOUNT, safe="")
            result.append(f"trojan://{password}@{host}:{port}?security=tls&type=tcp&sni={host}")
    print(f"Collection {run}: {len(result)} TCP nodes", flush=True)
    return result


if len(KEY) not in (16, 24, 32) or len(IV) != 16:
    raise SystemExit("Invalid secret lengths")

candidates = []
for run in range(1, 6):
    candidates.extend(collect_once(run))
candidates = list(dict.fromkeys(candidates))
if not candidates:
    raise SystemExit("No candidates collected; old SSS preserved")

output = "\n".join(candidates) + "\n"
TARGET.write_text(base64.b64encode(output.encode()).decode() + "\n")
print(f"Saved {len(candidates)} unique TCP candidates to SSS")
