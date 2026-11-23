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

def rename_nodes(nodes, prefix):
    renamed = []
    for index, node in enumerate(nodes, 1):
        item = json.loads(json.dumps(node))
        item["tag"] = f"AVYRN-{prefix}-{index:03d}"
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
base = json.loads(json.dumps(white))
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
    "subjectSelector": ["AVYRN-REG-", "AVYRN-BS-"],
    "probeURL": "https://www.gstatic.com/generate_204",
    "probeInterval": "5m",
    "enableConcurrency": True
}
routing = base.setdefault("routing", {})
routing["balancers"] = [
    {
        "tag": "AVYRN-AUTO-REG",
        "selector": ["AVYRN-REG-"],
        "fallbackTag": regular_nodes[0]["tag"],
        "strategy": {"type": "leastPing"}
    },
    {
        "tag": "AVYRN-AUTO-BS",
        "selector": ["AVYRN-BS-"],
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
