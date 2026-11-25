#!/usr/bin/env python3
"""Build one Happ subscription from independent, upstream-checked pools."""
import copy
import ipaddress
import json
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

SOURCES = {
    "regular": [
        "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt",
        "https://raw.githubusercontent.com/pie-with-jam/PulseProxy/main/githubmirror/6.txt",
        "https://raw.githubusercontent.com/wlunlocker/vpn-configs/main/blacklist_all.txt",
    ],
    "whitelist": [
        "https://raw.githubusercontent.com/wlunlocker/vpn-configs/main/whitelist_all.txt",
    ],
}
WHITELIST_HAPP_JSON = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Export/Happ/GLOBAL/Vless-Reality-White-Lists-Rus-Mobile-Happ-global.json"
BASE_HAPP = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Export/Happ/GLOBAL/Vless-Reality-White-Lists-Rus-Mobile-Happ-global.json"
PROBE_URL = "https://www.gstatic.com/generate_204"
MAX_PER_POOL = 40
MAX_CANDIDATES_PER_SOURCE = 100
MIN_PER_POOL = 5
TIMEOUT = 35

def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AVYRN-VPN-sync/2.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", errors="replace")

def fetch_json(url):
    return json.loads(fetch_text(url))

def parse_uri(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        u = urlsplit(line)
        scheme = u.scheme.lower()
        if scheme not in ("vless", "trojan"):
            return None
        host, port = u.hostname, u.port
        if not host or not port or not u.username:
            return None
        q = parse_qs(u.query, keep_blank_values=True)
        get = lambda key, default="": q.get(key, [default])[0]
        network = get("type", "tcp") or "tcp"
        if network not in ("tcp", "ws", "grpc"):
            return None
        security = get("security", "none") or "none"
        name = unquote(u.fragment) or host
        if scheme == "vless":
            user = {"id": unquote(u.username), "encryption": get("encryption", "none") or "none"}
            if get("flow"):
                user["flow"] = get("flow")
            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            }
        else:
            outbound = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": unquote(u.username)}]},
            }
        stream = {"network": network}
        if security == "tls":
            tls = {"serverName": get("sni") or get("host") or host}
            if get("fp"):
                tls["fingerprint"] = get("fp")
            if get("alpn"):
                tls["alpn"] = [x for x in get("alpn").split(",") if x]
            tls["allowInsecure"] = False
            stream["security"] = "tls"
            stream["tlsSettings"] = tls
        elif security == "reality":
            reality = {
                "serverName": get("sni") or host,
                "fingerprint": get("fp", "chrome") or "chrome",
                "publicKey": get("pbk"),
                "shortId": get("sid"),
            }
            if get("spx"):
                reality["spiderX"] = get("spx")
            if not reality["publicKey"]:
                return None
            stream["security"] = "reality"
            stream["realitySettings"] = reality
        else:
            stream["security"] = "none"
        if network == "ws":
            ws = {"path": unquote(get("path", "/")) or "/"}
            host_header = get("host")
            if host_header:
                ws["headers"] = {"Host": host_header}
            stream["wsSettings"] = ws
        elif network == "grpc":
            grpc = {"serviceName": get("serviceName")}
            if get("mode"):
                grpc["multiMode"] = get("mode") == "multi"
            stream["grpcSettings"] = grpc
        elif network == "tcp" and get("headerType"):
            stream["tcpSettings"] = {"header": {"type": get("headerType")}}
        if get("flow") and scheme == "vless":
            stream.setdefault("sockopt", {})
        outbound["streamSettings"] = stream
        return {"outbound": outbound, "name": name, "host": host, "port": port}
    except (ValueError, UnicodeError):
        return None

def collect(urls):
    groups, seen = [], set()
    for url in urls:
        group = []
        try:
            raw = fetch_text(url)
            for line in raw.splitlines():
                item = parse_uri(line)
                if not item:
                    continue
                key = (item["outbound"]["protocol"], item["host"], item["port"],
                       json.dumps(item["outbound"]["settings"], sort_keys=True))
                if key in seen:
                    continue
                seen.add(key)
                item["source"] = url
                group.append(item)
                if len(group) >= MAX_CANDIDATES_PER_SOURCE:
                    break
            print(f"Source {url}: parsed {len(group)} unique nodes")
        except Exception as exc:
            print(f"Source unavailable {url}: {exc}")
        groups.append(group)
    # Interleave upstreams so the first feed cannot monopolize the final 40 nodes.
    merged = []
    for index in range(max((len(group) for group in groups), default=0)):
        for group in groups:
            if index < len(group):
                merged.append(group[index])
    return merged

def collect_happ_json(url):
    """Import proxy outbounds from a dedicated Happ whitelist feed."""
    try:
        config = fetch_json(url)
    except Exception as exc:
        print(f"Whitelist Happ source unavailable {url}: {exc}")
        return []
    items = []
    for outbound in config.get("outbounds", []):
        if not str(outbound.get("tag", "")).startswith("igareck-node-"):
            continue
        protocol = outbound.get("protocol")
        settings = outbound.get("settings", {})
        if protocol == "vless":
            servers = settings.get("vnext", [])
        elif protocol == "trojan":
            servers = settings.get("servers", [])
        else:
            continue
        if not servers:
            continue
        host, port = servers[0].get("address"), servers[0].get("port")
        if not host or not port:
            continue
        items.append({"outbound": copy.deepcopy(outbound), "name": outbound.get("tag", "whitelist"), "host": host, "port": int(port), "source": url})
    print(f"Whitelist Happ source {url}: imported {len(items)} nodes")
    return items

def deduplicate(items):
    seen, result = set(), []
    for item in items:
        key = (item["outbound"].get("protocol"), item["host"], item["port"], json.dumps(item["outbound"].get("settings", {}), sort_keys=True))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result

def tcp_check(item):
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=4):
            return True
    except Exception:
        return False

def live_filter(items):
    # Upstreams already run protocol/health checks; this adds a fresh TCP reachability check.
    with ThreadPoolExecutor(max_workers=64) as pool:
        flags = list(pool.map(tcp_check, items))
    return [item for item, ok in zip(items, flags) if ok]

def geo_codes(items):
    hosts = []
    for item in items:
        # ip-api accepts hostnames as well as literal IP addresses.
        # Avoid serial DNS lookups on the runner for large public feeds.
        hosts.append(item["host"])
    unique = list(dict.fromkeys(x for x in hosts if x))
    result = {}
    for start in range(0, len(unique), 100):
        batch = unique[start:start + 100]
        req = urllib.request.Request(
            "http://ip-api.com/batch",
            data=json.dumps([{"query": h, "fields": "status,countryCode"} for h in batch]).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                rows = json.loads(response.read().decode())
            for host, row in zip(batch, rows):
                if row.get("status") == "success" and row.get("countryCode"):
                    result[host] = row["countryCode"].upper()
        except Exception as exc:
            print("GeoIP lookup failed:", exc)
    return [result.get(host) for host in hosts]

FLAGS = {
    "DE":"🇩🇪","US":"🇺🇸","GB":"🇬🇧","NL":"🇳🇱","FR":"🇫🇷","FI":"🇫🇮",
    "SE":"🇸🇪","NO":"🇳🇴","PL":"🇵🇱","CZ":"🇨🇿","CH":"🇨🇭","AT":"🇦🇹",
    "BE":"🇧🇪","ES":"🇪🇸","IT":"🇮🇹","PT":"🇵🇹","CA":"🇨🇦","TR":"🇹🇷",
    "RU":"🇷🇺","UA":"🇺🇦","KZ":"🇰🇿","JP":"🇯🇵","SG":"🇸🇬","HK":"🇭🇰",
    "IN":"🇮🇳","AL":"🇦🇱","AE":"🇦🇪","BR":"🇧🇷","AU":"🇦🇺","BG":"🇧🇬",
    "CY":"🇨🇾","RO":"🇷🇴","GR":"🇬🇷","IE":"🇮🇪","IS":"🇮🇸","LU":"🇱🇺",
    "LT":"🇱🇹","LV":"🇱🇻","EE":"🇪🇪","MD":"🇲🇩","RS":"🇷🇸","HR":"🇭🇷",
    "SI":"🇸🇮","SK":"🇸🇰","HU":"🇭🇺","DK":"🇩🇰","IL":"🇮🇱","AR":"🇦🇷",
    "MX":"🇲🇽","TH":"🇹🇭","ID":"🇮🇩","KR":"🇰🇷","TW":"🇹🇼","NZ":"🇳🇿",
}

def iso3(code):
    if not code:
        return "UNK"
    try:
        import pycountry
        country = pycountry.countries.get(alpha_2=code)
        return country.alpha_3 if country else code
    except Exception:
        return code

def tag_items(items, pool):
    codes = geo_codes(items)
    tagged = []
    for item, code in zip(items, codes):
        node = copy.deepcopy(item["outbound"])
        country = iso3(code)
        country = {"DEU": "GER"}.get(country, country)
        flag = FLAGS.get(code, "🏳️")
        prefix = "AVYRN | " if pool == "regular" else "AVYRN БС | "
        node["tag"] = f"{flag} {prefix}{country}"
        tagged.append(node)
    return tagged

def unique_internal_tags(items):
    # Internal Xray tags must be unique inside a single AUTO profile.
    counts, result = {}, []
    for node in items:
        clone = copy.deepcopy(node)
        base = clone["tag"]
        counts[base] = counts.get(base, 0) + 1
        clone["tag"] = f"{base} [{counts[base]}]"
        result.append(clone)
    return result

def main():
    regular_raw = collect(SOURCES["regular"])
    whitelist_raw = deduplicate(
        collect(SOURCES["whitelist"]) + collect_happ_json(WHITELIST_HAPP_JSON)
    )
    regular_raw = live_filter(regular_raw)
    whitelist_raw = live_filter(whitelist_raw)
    if len(regular_raw) < MIN_PER_POOL or len(whitelist_raw) < MIN_PER_POOL:
        raise SystemExit(
            f"Not enough reachable nodes: regular={len(regular_raw)}, "
            f"whitelist={len(whitelist_raw)}. Refusing to publish a broken subscription."
        )
    # Keep the source order after live checks; the upstreams already sort/test their feeds.
    regular_raw = regular_raw[:MAX_PER_POOL]
    whitelist_raw = whitelist_raw[:MAX_PER_POOL]
    regular = tag_items(regular_raw, "regular")
    whitelist = tag_items(whitelist_raw, "whitelist")

    template = fetch_json(BASE_HAPP)
    helpers = [copy.deepcopy(x) for x in template.get("outbounds", [])
               if not str(x.get("tag", "")).startswith("igareck-node-")]
    base = copy.deepcopy(template)
    base.pop("_meta", None)
    base.pop("remarks", None)
    base["outbounds"] = []
    base["observatory"] = {
        "subjectSelector": ["AVYRN | ", "AVYRN БС | "],
        "probeURL": PROBE_URL,
        "probeInterval": "5m",
        "enableConcurrency": True,
    }
    routing = base.setdefault("routing", {})
    common_rules = [copy.deepcopy(x) for x in routing.get("rules", [])
                    if not x.get("balancerTag") and x.get("outboundTag") != "igareck-auto"]

    def shell(title):
        profile = copy.deepcopy(base)
        profile["remarks"] = title
        return profile

    def manual_profiles(items, title_prefix):
        profiles = []
        for item in items:
            profile = shell(item["tag"])
            profile["outbounds"] = [copy.deepcopy(item)] + copy.deepcopy(helpers)
            profile.pop("observatory", None)
            profile["routing"]["balancers"] = []
            profile["routing"]["rules"] = copy.deepcopy(common_rules)
            profiles.append(profile)
        return profiles

    def auto_profile(items, pool, title, balancer_tag):
        if not items:
            raise SystemExit("Empty AUTO pool: " + title)
        profile = shell(title)
        internal = unique_internal_tags(items)
        profile["outbounds"] = internal + copy.deepcopy(helpers)
        selectors = list(dict.fromkeys(node["tag"].rsplit(" [", 1)[0] for node in internal))
        profile["observatory"] = {
            "subjectSelector": [selector for selector in selectors],
            "probeURL": PROBE_URL,
            "probeInterval": "5m",
            "enableConcurrency": True,
        }
        profile["routing"]["balancers"] = [{
            "tag": balancer_tag,
            "selector": [node["tag"] for node in internal],
            "fallbackTag": internal[0]["tag"],
            "strategy": {"type": "leastPing"},
        }]
        profile["routing"]["rules"] = copy.deepcopy(common_rules) + [{
            "type": "field", "network": "tcp,udp", "balancerTag": balancer_tag
        }]
        return profile

    profiles = (
        manual_profiles(regular, "regular")
        + [auto_profile(regular, "regular", "AVYRN | AUTO", "AVYRN-AUTO-REG")]
        + manual_profiles(whitelist, "whitelist")
        + [auto_profile(whitelist, "whitelist", "AVYRN БС | AUTO", "AVYRN-AUTO-BS")]
    )
    expected = len(regular) + len(whitelist) + 2
    if len(profiles) != expected:
        raise SystemExit("Unexpected subscription entry count")
    Path("subscription.json").write_text(
        json.dumps(profiles, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(
        f"AVYRN built: regular={len(regular)}, whitelist={len(whitelist)}, "
        f"regular AUTO pool={len(regular)}, whitelist AUTO pool={len(whitelist)}, "
        f"profiles={len(profiles)}"
    )

if __name__ == "__main__":
    main()
