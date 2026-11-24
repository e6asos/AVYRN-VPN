#!/usr/bin/env python3
import copy
import json
import socket
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
    import ipaddress
    hosts = []
    for node in nodes:
        try:
            host = node["settings"]["vnext"][0]["address"]
            try:
                ipaddress.ip_address(host)
            except ValueError:
                host = socket.gethostbyname(host)
            hosts.append(host)
        except Exception:
            hosts.append(None)
    return hosts

def country_codes(nodes):
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

def alpha_suffix(number):
    letters = ""
    while number:
        number, remainder = divmod(number - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters

def rename_nodes(nodes, prefix):
    labels = country_codes(nodes)
    totals = {}
    for label in labels:
        totals[label] = totals.get(label, 0) + 1
    seen = {}
    renamed = []
    pool = "AVYRN | " if prefix == "REG" else "AVYRN БС | "
    for node, label in zip(nodes, labels):
        seen[label] = seen.get(label, 0) + 1
        suffix = f" {alpha_suffix(seen[label])}" if totals[label] > 1 else ""
        item = copy.deepcopy(node)
        item["tag"] = f"{pool}{label}{suffix}"
        renamed.append(item)
    return renamed

regular_nodes = rename_nodes(regular_nodes, "REG")
white_nodes = rename_nodes(white_nodes, "BS")

helper_outbounds = [
    copy.deepcopy(item) for item in white.get("outbounds", [])
    if not str(item.get("tag", "")).startswith("igareck-node-")
]
for helper in helper_outbounds:
    if helper.get("tag") == "fragment":
        settings = helper.setdefault("settings", {})
        if isinstance(settings.get("fragment"), dict):
            settings["fragment"]["interval"] = "1-3"
        for noise in settings.get("noises", []):
            noise["delay"] = "1-3"

base = copy.deepcopy(white)
base.pop("_meta", None)
base.pop("remarks", None)
base["outbounds"] = []
base["observatory"] = {
    "subjectSelector": ["AVYRN | ", "AVYRN БС | "],
    "probeURL": "https://www.gstatic.com/generate_204",
    "probeInterval": "5m",
    "enableConcurrency": True
}

def profile_shell(remarks):
    profile = copy.deepcopy(base)
    profile["remarks"] = remarks
    profile["name"] = remarks
    return profile

def make_manual_profile(node):
    tag = node["tag"]
    profile = profile_shell(tag)
    profile["outbounds"] = [copy.deepcopy(node)] + copy.deepcopy(helper_outbounds)
    profile["observatory"] = {
        "subjectSelector": [tag],
        "probeURL": "https://www.gstatic.com/generate_204",
        "probeInterval": "5m",
        "enableConcurrency": True
    }
    routing = profile.setdefault("routing", {})
    routing["balancers"] = []
    rewritten = []
    for rule in routing.get("rules", []):
        rule = copy.deepcopy(rule)
        if rule.get("balancerTag"):
            rule.pop("balancerTag", None)
            rule["outboundTag"] = tag
        if rule.get("outboundTag") == "igareck-auto":
            rule["outboundTag"] = tag
        rewritten.append(rule)
    routing["rules"] = rewritten
    return profile

def make_auto_profile(nodes, prefix, title, balancer_tag):
    if not nodes:
        raise SystemExit(f"Refusing to publish: empty AUTO pool {title}")
    profile = profile_shell(title)
    profile["outbounds"] = copy.deepcopy(nodes) + copy.deepcopy(helper_outbounds)
    profile["observatory"] = {
        "subjectSelector": [prefix],
        "probeURL": "https://www.gstatic.com/generate_204",
        "probeInterval": "5m",
        "enableConcurrency": True
    }
    routing = profile.setdefault("routing", {})
    routing["balancers"] = [{
        "tag": balancer_tag,
        "selector": [prefix],
        "fallbackTag": nodes[0]["tag"],
        "strategy": {"type": "leastPing"}
    }]
    rewritten = []
    has_default_balancer_rule = False
    for rule in routing.get("rules", []):
        rule = copy.deepcopy(rule)
        if rule.get("balancerTag"):
            rule["balancerTag"] = balancer_tag
            if rule.get("network") == "tcp,udp":
                has_default_balancer_rule = True
        if rule.get("outboundTag") == "igareck-auto":
            rule["outboundTag"] = balancer_tag
        rewritten.append(rule)
    if not has_default_balancer_rule:
        rewritten.append({
            "type": "field",
            "network": "tcp,udp",
            "balancerTag": balancer_tag
        })
    routing["rules"] = rewritten
    return profile

# Happ accepts a JSON array of independent Xray configurations.
# Each manual node is one selectable profile; the two AUTO profiles
# independently balance only their own pool.
profiles = []
profiles.extend(make_manual_profile(node) for node in regular_nodes)
profiles.append(make_auto_profile(
    regular_nodes, "AVYRN | ", "AVYRN | AUTO", "AVYRN-AUTO-REG"
))
profiles.extend(make_manual_profile(node) for node in white_nodes)
profiles.append(make_auto_profile(
    white_nodes, "AVYRN БС | ", "AVYRN БС | AUTO", "AVYRN-AUTO-BS"
))

# Sanity checks before publishing.
for profile in profiles:
    tags = [item.get("tag") for item in profile.get("outbounds", [])]
    if len(tags) != len(set(tags)):
        raise SystemExit(f"Refusing to publish: duplicate tags in {profile.get('remarks')}")
    if not profile.get("outbounds"):
        raise SystemExit(f"Refusing to publish: no outbounds in {profile.get('remarks')}")
if profiles[-1]["routing"]["balancers"][0]["selector"] != ["AVYRN БС | "]:
    raise SystemExit("Refusing to publish: whitelist AUTO selector mismatch")
if profiles[len(regular_nodes)]["routing"]["balancers"][0]["selector"] != ["AVYRN | "]:
    raise SystemExit("Refusing to publish: regular AUTO selector mismatch")

Path("subscription.json").write_text(
    json.dumps(profiles, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8"
)
print(
    f"Built AVYRN 4-in-1: regular_manual={len(regular_nodes)}, "
    f"regular_auto=1, whitelist_manual={len(white_nodes)}, whitelist_auto=1, "
    f"profiles={len(profiles)}"
)
