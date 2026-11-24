#!/usr/bin/env python3
import json
import urllib.request
from pathlib import Path

SOURCES = {
    "regular": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Export/Happ/GLOBAL/BLACK_VLESS_RUS_mobile_Happ_global.json",
    "whitelist": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Export/Happ/GLOBAL/Vless-Reality-White-Lists-Rus-Mobile-Happ-global.json",
}

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AVYRN-VPN-sync/1.0"})
    with urllib.request.urlopen(req, timeout=45) as response:
        return json.loads(response.read().decode("utf-8"))

regular = fetch(SOURCES["regular"])
white = fetch(SOURCES["whitelist"])

def node_outbounds(config):
    return [item for item in config.get("outbounds", [])
            if str(item.get("tag", "")).startswith("igareck-node-")]

regular_nodes = node_outbounds(regular)
white_nodes = node_outbounds(white)
if len(regular_nodes) < 5 or len(white_nodes) < 5:
    raise SystemExit(f"Refusing to publish: too few source nodes (regular={len(regular_nodes)}, whitelist={len(white_nodes)})")

def resolve_hosts(nodes):
    import socket
    hosts = []
    for node in nodes:
        try:
            host = node["settings"]["vnext"][0]["address"]
            try:
                import ipaddress
                ipaddress.ip_address(host)
            except ValueError:
                host = socket.gethostbyname(host)
            hosts.append(host)
        except Exception:
            hosts.append(None)
    return hosts

def country_codes(nodes):
    # ip-api batch lookup; country codes are converted to ISO-3 for compact labels.
    import ipaddress
    hosts = resolve_hosts(nodes)
    unique = list(dict.fromkeys(h for h in hosts if h))
    lookup = {}
    for offset in range(0, len(unique), 100):
        batch = unique[offset:offset + 100]
        payload = [{"query": host, "fields": "status,countryCode"} for host in batch]
        request = urllib.request.Request(
            "http://ip-api.com/batch",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "AVYRN-VPN-sync/1.0"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                results = json.loads(response.read().decode("utf-8"))
            for host, result in zip(batch, results):
                if result.get("status") == "success" and result.get("countryCode"):
                    lookup[host] = result["countryCode"]
        except Exception as error:
            print(f"GeoIP lookup batch failed: {error}")
    try:
        import pycountry
    except ImportError:
        pycountry = None
    labels = []
    for host in hosts:
        code = lookup.get(host)
        country = pycountry.countries.get(alpha_2=code) if code and pycountry else None
        labels.append(country.alpha_3 if country else (code or "UNK"))
    return labels

def rename_nodes(nodes, prefix):
    labels = country_codes(nodes)
    totals = {}
    for label in labels:
        totals[label] = totals.get(label, 0) + 1
    seen = {}
    renamed = []
    for node, label in zip(nodes, labels):
        seen[label] = seen.get(label, 0) + 1
        number = seen[label]
        suffix = ""
        if totals[label] > 1:
            letters = ""
            while number:
                number, remainder = divmod(number - 1, 26)
                letters = chr(65 + remainder) + letters
            suffix = f" {letters}"
        item = json.loads(json.dumps(node))
        pool = "AVYRN | " if prefix == "REG" else "AVYRN БС | "
        item["tag"] = f"{pool}{label}{suffix}"
        renamed.append(item)
    return renamed

regular_nodes = rename_nodes(regular_nodes, "REG")
white_nodes = rename_nodes(white_nodes, "BS")

# Keep the whitelist profile's DNS, inbounds, routing baseline and helper outbounds.
# Reuse its fragment/direct/block/dns outbounds only once; both node pools can reference them.
helper_outbounds = [
    item for item in white.get("outbounds", [])
    if not str(item.get("tag", "")).startswith("igareck-node-")
]
# Keep fragmentation lightweight to avoid adding unnecessary handshake delay.
for helper in helper_outbounds:
    if helper.get("tag") == "fragment":
        settings = helper.setdefault("settings", {})
        if isinstance(settings.get("fragment"), dict):
            settings["fragment"]["interval"] = "1-3"
        for noise in settings.get("noises", []):
            noise["delay"] = "1-3"
base = json.loads(json.dumps(white))
base["remarks"] = "AVYRN VPN"
base["_meta"] = {
    "name": "AVYRN VPN — Обычные / AUTO / Белый список / AUTO БС",
    "generator": "AVYRN-VPN",
    "client": "Happ",
    "notes": [
        f"{len(regular_nodes)} обычных серверов",
        f"{len(white_nodes)} серверов белого списка",
        "Два независимых leastPing AUTO-балансира; обновление источников каждые 2 часа"
    ],
    "source_datetime_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
}
base["outbounds"] = regular_nodes + white_nodes + helper_outbounds
base["observatory"] = {
    "subjectSelector": ["AVYRN | ", "AVYRN БС | "],
    "probeURL": "https://www.gstatic.com/generate_204",
    "probeInterval": "5m",
    "enableConcurrency": True
}
routing = base.setdefault("routing", {})
routing["balancers"] = [
    {
        "tag": "AVYRN-AUTO-REG",
        "selector": ["AVYRN | "],
        "fallbackTag": regular_nodes[0]["tag"],
        "strategy": {"type": "leastPing"}
    },
    {
        "tag": "AVYRN-AUTO-BS",
        "selector": ["AVYRN БС | "],
        "fallbackTag": white_nodes[0]["tag"],
        "strategy": {"type": "leastPing"}
    }
]
rules = routing.get("rules", [])
for rule in rules:
    if rule.get("balancerTag"):
        rule["balancerTag"] = "AVYRN-AUTO-REG"
    if rule.get("outboundTag") == "igareck-auto":
        rule["outboundTag"] = "AVYRN-AUTO-REG"
routing["rules"] = rules

# Sanity checks before publishing.
tags = [item.get("tag") for item in base["outbounds"]]
if len(tags) != len(set(tags)):
    raise SystemExit("Refusing to publish: duplicate outbound tags")
for balancer in routing["balancers"]:
    prefix = balancer["selector"][0]
    if not any(tag.startswith(prefix) for tag in tags):
        raise SystemExit(f"Refusing to publish: empty selector {prefix}")
if not any(item.get("tag") == "direct" for item in base["outbounds"]):
    raise SystemExit("Refusing to publish: missing direct outbound")
Path("subscription.json").write_text(json.dumps(base, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Built AVYRN: regular={len(regular_nodes)}, whitelist={len(white_nodes)}, total={len(base['outbounds'])}")
