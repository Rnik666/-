#!/usr/bin/env python3
"""Fetch Star VPN nodes - early region filter, supports Chinese/English names."""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES

# ----- 固定参数 -----
AES_KEY = b"odjwiejwu2ieo929d923ifi9qK9wiOJK"
AES_IV  = b"Oe9935kjso393024"
DEFAULT_ACCOUNT = "VK467891201"
DEFAULT_BASE_URL = "http://47.129.170.28"

# ----- 国旗映射 -----
FLAG_MAP = {
    "United States": "🇺🇸", "US": "🇺🇸", "USA": "🇺🇸",
    "China": "🇨🇳", "CN": "🇨🇳",
    "Japan": "🇯🇵", "JP": "🇯🇵",
    "South Korea": "🇰🇷", "Korea": "🇰🇷", "KR": "🇰🇷",
    "United Kingdom": "🇬🇧", "UK": "🇬🇧", "GB": "🇬🇧",
    "France": "🇫🇷", "FR": "🇫🇷",
    "Germany": "🇩🇪", "DE": "🇩🇪",
    "Canada": "🇨🇦", "CA": "🇨🇦",
    "Australia": "🇦🇺", "AU": "🇦🇺",
    "Singapore": "🇸🇬", "SG": "🇸🇬",
    "Hong Kong": "🇭🇰", "HK": "🇭🇰",
    "Taiwan": "🇹🇼", "TW": "🇹🇼",
    "India": "🇮🇳", "IN": "🇮🇳",
    "Russia": "🇷🇺", "RU": "🇷🇺",
    "Brazil": "🇧🇷", "BR": "🇧🇷",
}
DEFAULT_FLAG = "🏳️"

EN_TO_CN_REGION = {
    "Singapore": "新加坡",
    "United States": "美国",
    "USA": "美国",
    "China": "中国",
    "Japan": "日本",
    "South Korea": "韩国",
    "Korea": "韩国",
    "United Kingdom": "英国",
    "France": "法国",
    "Germany": "德国",
    "Canada": "加拿大",
    "Australia": "澳大利亚",
    "Hong Kong": "香港",
    "Taiwan": "台湾",
    "India": "印度",
    "Russia": "俄罗斯",
    "Brazil": "巴西",
}

def get_region_name(node: dict[str, Any]) -> str:
    region = node.get("region_cn") or node.get("name_cn")
    if region:
        return region.strip()
    country = node.get("country") or node.get("region_en") or node.get("name_en") or ""
    if country:
        cn_name = EN_TO_CN_REGION.get(country)
        if cn_name:
            return cn_name
        return country.strip()
    return "未知地区"

def get_country_code(node: dict[str, Any]) -> str:
    country = node.get("country") or node.get("region_en") or node.get("name_en") or ""
    if country:
        return country.strip()
    region_cn = node.get("region_cn") or node.get("name_cn") or ""
    if region_cn:
        cn_to_en = {
            "美国": "United States", "中国": "China", "日本": "Japan",
            "韩国": "South Korea", "英国": "United Kingdom", "法国": "France",
            "德国": "Germany", "加拿大": "Canada", "澳大利亚": "Australia",
            "新加坡": "Singapore", "香港": "Hong Kong", "台湾": "Taiwan",
            "印度": "India", "俄罗斯": "Russia", "巴西": "Brazil",
        }
        return cn_to_en.get(region_cn, region_cn)
    return ""

def get_flag(country: str) -> str:
    if not country:
        return DEFAULT_FLAG
    if country in FLAG_MAP:
        return FLAG_MAP[country]
    for key, flag in FLAG_MAP.items():
        if key.upper() == country.upper() or key.startswith(country):
            return flag
    return DEFAULT_FLAG

# ----- AES 加解密 -----
def pkcs7_pad(data: bytes, block_size: int = AES.block_size) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def pkcs7_unpad(data: bytes, block_size: int = AES.block_size) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Invalid padding")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def aes_crypt(data: bytes, *, decrypt: bool = False) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    if decrypt:
        decrypted = cipher.decrypt(data)
        return pkcs7_unpad(decrypted)
    else:
        padded = pkcs7_pad(data)
        return cipher.encrypt(padded)

def encrypt(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    return base64.b64encode(aes_crypt(raw)).decode()

def decrypt(text: str) -> Any:
    raw = base64.b64decode("".join(text.split()), validate=True)
    return json.loads(aes_crypt(raw, decrypt=True).decode("utf-8-sig"))

def decode_body(body: bytes, encoding: str = "") -> Any:
    if "gzip" in encoding.lower() or body.startswith(b"\x1f\x8b"):
        body = gzip.decompress(body)
    text = body.decode("utf-8-sig").strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return decrypt(text)
    if isinstance(value, dict):
        for field in ("msg", "key", "data"):
            encrypted = value.get(field)
            if isinstance(encrypted, str):
                try:
                    return decrypt(encrypted)
                except Exception:
                    pass
    return value

# ----- 客户端 -----
class Client:
    def __init__(self, base_url: str, timeout: float, retries: int):
        if base_url.endswith("/service/line.php"):
            base_url = base_url[:-len("/service/line.php")]
        self.line_url = base_url.rstrip("/") + "/service/line.php"
        self.timeout = timeout
        self.retries = retries

    def call(self, payload: dict[str, Any]) -> Any:
        body = json.dumps({"key": encrypt(payload)}, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.line_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept-Encoding": "gzip",
                "User-Agent": "Postpop/1 CFNetwork-compatible",
            },
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return decode_body(response.read(), response.headers.get("Content-Encoding", ""))
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(0.5 * (attempt + 1))
        raise RuntimeError(f"request failed after {self.retries + 1} attempt(s): {last_error}")

def nodes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        raise RuntimeError("line.php returned a non-object response")
    if value.get("status") not in (None, "success"):
        raise RuntimeError(f"line.php error: {value}")
    data = value.get("data")
    if not isinstance(data, list):
        raise RuntimeError("line.php response is missing data[]")
    return [item for item in data if isinstance(item, dict)]

# ----- 节点名称生成 -----
def label(node: dict[str, Any], index: int, suffix: str = "", order: int | None = None) -> str:
    country = get_country_code(node)
    flag = get_flag(country) if country else ""
    name = str(
        node.get("name_cn") or node.get("region_cn") or node.get("name_en")
        or node.get("country") or f"node-{index}"
    ).strip()
    base = f"{flag} {name}".strip() if flag else name
    if suffix:
        base = f"{base} {suffix}".strip()
    if order is not None:
        base = f"{base} #{order}"
    return base

# ----- 生成 URI -----
def uri(account: str, host: str, port: str, name: str, ws: bool = False) -> str:
    if ws:
        return (
            f"trojan://{urllib.parse.quote(account, safe='')}@{host}:{port}?"
            f"security=tls&sni={urllib.parse.quote(host)}&type=ws&host={urllib.parse.quote(host)}"
            f"&path=%2Fimg%2Fser%2F#{urllib.parse.quote(name, safe='')}"
        )
    else:
        return (
            f"trojan://{urllib.parse.quote(account, safe='')}@{host}:{port}?"
            f"mux=1#{urllib.parse.quote(name, safe='')}"
        )

def safe_filename(region: str) -> str:
    illegal_chars = r'[\\/:*?"<>|]'
    safe = re.sub(illegal_chars, '_', region)
    return safe.strip()

# ----- 构建输出(分组、排序)-----
def build_outputs(account: str, source: list[dict[str, Any]]) -> tuple[
    list[dict[str, Any]],      # result: 所有节点详细信息
    list[str],                 # configs: 所有配置
    dict[str, dict[str, list[dict[str, Any]]]]  # grouped: region -> {'tcp': [...], 'ws': [...]}
]:
    result: list[dict[str, Any]] = []
    configs: list[str] = []
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}

    for index, node in enumerate(source, 1):
        port = str(node.get("port", "")).strip()
        server = str(node.get("server", "")).strip()
        if not port or not server:
            continue

        region = get_region_name(node)
        if region not in grouped:
            grouped[region] = {"tcp": [], "ws": []}

        tcp_name = label(node, index, order=index)
        tcp_uri = uri(account, server, port, tcp_name, ws=False)
        result.append({"type": "tcp", "name": tcp_name, "server": server, "port": port, "uri": tcp_uri, "source": node})
        configs.append(f"{tcp_name} = trojan, {server}, {port}, password={account}, mux=true")
        grouped[region]["tcp"].append({"name": tcp_name, "uri": tcp_uri, "order": index})

        spare = str(node.get("spare_server", "")).strip()
        if spare:
            ws_name = label(node, index, suffix="WS", order=index)
            ws_uri = uri(account, spare, port, ws_name, ws=True)
            result.append({"type": "ws", "name": ws_name, "server": spare, "port": port, "uri": ws_uri, "source": node})
            configs.append(
                f"{ws_name} = trojan, {spare}, {port}, password={account}, "
                "ws=true, ws-path=/img/ser/, mux=true, concurrency=8, idle_timeout=60"
            )
            grouped[region]["ws"].append({"name": ws_name, "uri": ws_uri, "order": index})

    for region in grouped:
        grouped[region]["tcp"].sort(key=lambda x: x["order"])
        grouped[region]["ws"].sort(key=lambda x: x["order"])

    return result, configs, grouped

# ----- 端口连通性测试 -----
def test_node(server: str, port: str, timeout: float = 3.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((server, int(port)))
        sock.close()
        return result == 0
    except Exception:
        return False

# ----- 智能地区匹配 -----
def is_matching_region(node: dict[str, Any], target: str) -> bool:
    """检查节点是否属于目标地区(支持中文/英文/代码)"""
    region_cn = get_region_name(node)  # 优先中文
    # 1. 直接检查中文名
    if target in region_cn or region_cn in target:
        return True

    # 2. 如果 target 是中文,尝试英文匹配
    target_en = None
    for en, cn in EN_TO_CN_REGION.items():
        if cn == target:
            target_en = en
            break
    if target_en:
        # 检查节点的英文字段
        for field in ("country", "region_en", "name_en"):
            val = node.get(field, "")
            if val and target_en.lower() in val.lower():
                return True

    # 3. 如果 target 是英文,直接查英文字段
    for field in ("country", "region_en", "name_en"):
        val = node.get(field, "")
        if val and target.lower() in val.lower():
            return True

    # 4. 检查 region_cn 是否包含 target(可能 target 是 "Singapore" 但 region_cn 是 "新加坡" 已处理过)
    # 这里再补一个:如果 target 是英文,且 region_cn 是中文但映射后英文包含 target
    for en, cn in EN_TO_CN_REGION.items():
        if target.lower() in en.lower() and region_cn == cn:
            return True

    return False

# ----- 命令行参数 -----
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--account-id", default=DEFAULT_ACCOUNT)
    parser.add_argument("--device-id", default=str(uuid.uuid4()).upper())
    parser.add_argument("--way", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--start-at", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, default=Path("starvpn_singapore"))
    parser.add_argument("--region", default="新加坡", help="目标地区,支持中文或英文,如‘新加坡’或‘Singapore’")
    parser.add_argument("--test", action="store_true", help="开启端口连通性测试")
    parser.add_argument("--test-timeout", type=float, default=3.0)
    return parser.parse_args()

# ----- 主函数 -----
def main() -> int:
    args = parse_args()
    if not args.account_id:
        raise RuntimeError("account ID is empty")

    client = Client(args.base_url, args.timeout, args.retries)

    # 1. 获取初始节点列表
    vps_info_payload = {"task": "vps_info", "account_ID": args.account_id, "device_id": args.device_id}
    initial = nodes(client.call(vps_info_payload))
    print(f"初始获取到 {len(initial)} 个节点记录", file=sys.stderr)

    # ---- 调试:打印所有地区名(去重) ----
    all_regions = sorted({get_region_name(n) for n in initial if get_region_name(n)})
    print(f"所有出现的地区名: {', '.join(all_regions)}", file=sys.stderr)

    # 2. 使用智能匹配筛选
    target_nodes = []
    for n in initial:
        if is_matching_region(n, args.region):
            target_nodes.append(n)

    if not target_nodes:
        print(f"⚠️ 没有找到地区匹配 '{args.region}' 的节点,请检查上面打印的地区名,调整 --region 参数", file=sys.stderr)
        return 0

    # 3. 提取唯一服务器
    servers = list(dict.fromkeys(str(n.get("server", "")).strip() for n in target_nodes if n.get("server")))
    servers = [s for s in servers if s]
    if not servers:
        print("⚠️ 筛选后的节点中没有有效的 server 地址", file=sys.stderr)
        return 0
    print(f"筛选出 {len(target_nodes)} 个 {args.region} 节点,对应 {len(servers)} 个唯一服务器", file=sys.stderr)

    if args.start_at < 1 or args.start_at > len(servers) + 1:
        print(f"警告: --start-at 超出范围,自动调整为 1", file=sys.stderr)
        start_idx = 1
    else:
        start_idx = args.start_at

    # 4. 只注册这些服务器
    register_results = []
    for idx, server in enumerate(servers[start_idx - 1:], start_idx):
        response = client.call({
            "account_ID": args.account_id,
            "task": "register_host",
            "way": args.way,
            "server": server
        })
        if isinstance(response, dict) and response.get("status") not in (None, "success"):
            raise RuntimeError(f"register_host failed for {server}: {response}")
        register_results.append({"server": server, "response": response})
        print(f"[{idx}/{len(servers)}] 注册 {server}", file=sys.stderr)
        if args.delay > 0:
            time.sleep(args.delay)

    # 5. 再次获取完整列表
    final_response = client.call(vps_info_payload)
    final_nodes_raw = nodes(final_response)

    # 6. 从最终列表中筛选出我们注册过的服务器
    server_set = set(servers)
    filtered_final = [n for n in final_nodes_raw if n.get("server") in server_set]
    server_order = {server: idx for idx, server in enumerate(servers)}
    filtered_final.sort(key=lambda n: server_order.get(n.get("server", ""), 999999))

    print(f"最终得到 {len(filtered_final)} 个 {args.region} 节点", file=sys.stderr)

    # 7. 可选连通性测试
    if args.test:
        print(f"⏳ 正在测试端口连通性(超时 {args.test_timeout}s)...", file=sys.stderr)
        alive = []
        for node in filtered_final:
            server = node.get("server", "")
            port = str(node.get("port", ""))
            if not server or not port:
                continue
            if test_node(server, port, args.test_timeout):
                alive.append(node)
                print(f"  ✅ {server}:{port} 可达")
            else:
                print(f"  ❌ {server}:{port} 不可达")
        filtered_final = alive
        print(f"📊 可达节点数: {len(filtered_final)}", file=sys.stderr)
        if not filtered_final:
            print("❌ 没有可达节点,退出", file=sys.stderr)
            return 0

    # 8. 生成输出
    rendered, configs, grouped_data = build_outputs(args.account_id, filtered_final)
    if not rendered:
        raise RuntimeError("没有可用的节点")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    all_uris = [item["uri"] for item in rendered]
    (args.output_dir / "trojan_uris.txt").write_text("\n".join(all_uris) + "\n", encoding="utf-8")
    (args.output_dir / "proxy_configs.txt").write_text("\n".join(configs) + "\n", encoding="utf-8")
    (args.output_dir / "nodes.json").write_text(json.dumps({
        "account_ID": args.account_id,
        "device_id": args.device_id,
        "registered_servers": register_results,
        "line_response": final_response,
        "nodes": rendered,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    all_tcp = [item["uri"] for item in rendered if item["type"] == "tcp"]
    all_ws  = [item["uri"] for item in rendered if item["type"] == "ws"]
    (args.output_dir / "trojan_uris_tcp.txt").write_text("\n".join(all_tcp) + "\n", encoding="utf-8")
    (args.output_dir / "trojan_uris_ws.txt").write_text("\n".join(all_ws) + "\n", encoding="utf-8")

    for region, types in grouped_data.items():
        safe_name = safe_filename(region)
        tcp_items = types["tcp"]
        if tcp_items:
            tcp_uris = [item["uri"] for item in tcp_items]
            (args.output_dir / f"{safe_name}_trojan_tcp.txt").write_text(
                "\n".join(tcp_uris) + "\n", encoding="utf-8"
            )
        ws_items = types["ws"]
        if ws_items:
            ws_uris = [item["uri"] for item in ws_items]
            (args.output_dir / f"{safe_name}_trojan_ws.txt").write_text(
                "\n".join(ws_uris) + "\n", encoding="utf-8"
            )

    print("\n".join(all_uris))
    print(f"✅ 已保存 {len(rendered)} 条可用链接到 {args.output_dir.resolve()}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        print("\n✅ 脚本执行完毕,5 秒后自动关闭...")
        time.sleep(5)
        raise SystemExit(exit_code)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"\n❌ 错误: {exc}")
        print("5 秒后自动关闭...")
        time.sleep(5)
        raise SystemExit(1)
