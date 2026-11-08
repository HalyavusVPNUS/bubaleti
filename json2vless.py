#!/usr/bin/env python3
"""
Берёт подписку с Xray-JSON конфигами и собирает новую подписку из vless:// ссылок.

Выход:
  vless.txt         - обычный список ссылок (по одной на строку)
  vless_base64.txt  - то же самое, но в base64 (классический формат подписки)
"""
import base64
import json
import sys
import urllib.request
from urllib.parse import quote, urlencode

SOURCE_URL = (
    "https://raw.githubusercontent.com/gooseteam-hackers/freevpn-cracks/"
    "refs/heads/main/subscription_auto.txt"
)
OUT_PLAIN = "vless.txt"
OUT_B64 = "vless_base64.txt"

# Название подписки в клиентах (Happ, v2rayTun и т.п. читают эти строки).
# Пустая строка - не добавлять заголовок.
PROFILE_TITLE = "VLESS Sub"
UPDATE_INTERVAL_HOURS = 1


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def build_vless(outbound: dict, name: str):
    """Xray outbound -> vless:// ссылка. Возвращает None, если это не vless."""
    if outbound.get("protocol") != "vless":
        return None
    try:
        vnext = outbound["settings"]["vnext"][0]
        user = vnext["users"][0]
        host, port, uuid = vnext["address"], vnext["port"], user["id"]
    except (KeyError, IndexError, TypeError):
        return None

    ss = outbound.get("streamSettings", {}) or {}
    net = ss.get("network", "tcp")
    sec = ss.get("security", "none")

    params = {"encryption": user.get("encryption", "none")}
    if user.get("flow"):
        params["flow"] = user["flow"]

    # в новом Xray tcp называется raw, в ссылках остаётся tcp
    params["type"] = "tcp" if net == "raw" else net
    params["security"] = sec

    if sec == "tls":
        t = ss.get("tlsSettings", {}) or {}
        if t.get("serverName"):
            params["sni"] = t["serverName"]
        if t.get("fingerprint"):
            params["fp"] = t["fingerprint"]
        if t.get("alpn"):
            params["alpn"] = ",".join(t["alpn"])
        if t.get("allowInsecure"):
            params["allowInsecure"] = "1"
    elif sec == "reality":
        r = ss.get("realitySettings", {}) or {}
        if r.get("serverName"):
            params["sni"] = r["serverName"]
        if r.get("fingerprint"):
            params["fp"] = r["fingerprint"]
        if r.get("publicKey"):
            params["pbk"] = r["publicKey"]
        if r.get("shortId"):
            params["sid"] = r["shortId"]
        if r.get("spiderX"):
            params["spx"] = r["spiderX"]

    if net == "xhttp":
        x = ss.get("xhttpSettings", {}) or {}
        if x.get("path"):
            params["path"] = x["path"]
        if x.get("host"):
            params["host"] = x["host"]
        if x.get("mode"):
            params["mode"] = x["mode"]
        if x.get("extra"):
            params["extra"] = json.dumps(x["extra"], separators=(",", ":"))
    elif net == "ws":
        w = ss.get("wsSettings", {}) or {}
        if w.get("path"):
            params["path"] = w["path"]
        h = (w.get("headers") or {}).get("Host")
        if h:
            params["host"] = h
    elif net == "grpc":
        g = ss.get("grpcSettings", {}) or {}
        if g.get("serviceName"):
            params["serviceName"] = g["serviceName"]
        params["mode"] = "multi" if g.get("multiMode") else "gun"
    elif net in ("tcp", "raw"):
        params["headerType"] = "none"

    query = urlencode(params, quote_via=quote)
    return f"vless://{uuid}@{host}:{port}?{query}#{quote(name, safe='')}"


def convert(configs) -> list:
    if isinstance(configs, dict):
        configs = [configs]

    links, seen = [], set()
    for cfg in configs:
        remarks = (cfg.get("remarks") or "vless").strip()
        proxies = [o for o in cfg.get("outbounds", []) if o.get("protocol") == "vless"]
        for i, ob in enumerate(proxies):
            # у "Автовыбора" много прокси в одном конфиге - нумеруем
            name = remarks if len(proxies) == 1 else f"{remarks} #{i + 1}"
            link = build_vless(ob, name)
            if not link:
                continue
            key = link.split("#", 1)[0]  # дубли определяем без имени
            if key in seen:
                continue
            seen.add(key)
            links.append(link)
    return links


def main() -> int:
    raw = fetch(SOURCE_URL)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Источник не JSON: {e}", file=sys.stderr)
        return 1

    links = convert(data)
    if not links:
        print("Не нашлось ни одной vless-ссылки, файлы не трогаю", file=sys.stderr)
        return 1

    header = []
    if PROFILE_TITLE:
        header = [
            f"#profile-title: {PROFILE_TITLE}",
            f"#profile-update-interval: {UPDATE_INTERVAL_HOURS}",
        ]
    plain = "\n".join(header + links) + "\n"

    with open(OUT_PLAIN, "w", encoding="utf-8") as f:
        f.write(plain)
    with open(OUT_B64, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())

    print(f"Готово: {len(links)} vless-ссылок")
    return 0


if __name__ == "__main__":
    sys.exit(main())
