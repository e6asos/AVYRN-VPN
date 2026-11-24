#!/usr/bin/env python3
import copy, json, socket, urllib.request
from pathlib import Path

SOURCES = {
 "regular": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Export/Happ/GLOBAL/BLACK_VLESS_RUS_mobile_Happ_global.json",
 "whitelist": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Export/Happ/GLOBAL/Vless-Reality-White-Lists-Rus-Mobile-Happ-global.json",
}
def fetch(url):
 req=urllib.request.Request(url,headers={"User-Agent":"AVYRN-VPN-sync/1.0"})
 with urllib.request.urlopen(req,timeout=45) as r: return json.loads(r.read().decode("utf-8"))
regular, white = fetch(SOURCES["regular"]), fetch(SOURCES["whitelist"])
def nodes(config):
 return [x for x in config.get("outbounds",[]) if str(x.get("tag","")).startswith("igareck-node-")]
reg, bs = nodes(regular), nodes(white)
if len(reg)<5 or len(bs)<5: raise SystemExit(f"Too few nodes: regular={len(reg)} whitelist={len(bs)}")

def country_codes(items):
 import ipaddress
 hosts=[]
 for item in items:
  try:
   host=item["settings"]["vnext"][0]["address"]
   try: ipaddress.ip_address(host)
   except ValueError: host=socket.gethostbyname(host)
   hosts.append(host)
  except Exception: hosts.append(None)
 unique=list(dict.fromkeys(x for x in hosts if x)); found={}
 for start in range(0,len(unique),100):
  batch=unique[start:start+100]
  req=urllib.request.Request("http://ip-api.com/batch",data=json.dumps([{"query":x,"fields":"status,countryCode"} for x in batch]).encode(),headers={"Content-Type":"application/json"},method="POST")
  try:
   with urllib.request.urlopen(req,timeout=45) as r: result=json.loads(r.read().decode())
   for host,item in zip(batch,result):
    if item.get("status")=="success" and item.get("countryCode"): found[host]=item["countryCode"]
  except Exception as e: print("GeoIP error:",e)
 try: import pycountry
 except ImportError: pycountry=None
 return [(pycountry.countries.get(alpha_2=found[h]).alpha_3 if h in found and pycountry and pycountry.countries.get(alpha_2=found[h]) else found.get(h,"UNK")) for h in hosts]

def suffix(n):
 out=""
 while n: n,r=divmod(n-1,26); out=chr(65+r)+out
 return out
def rename(items,prefix):
 labels=country_codes(items); totals={x:labels.count(x) for x in set(labels)}; seen={}; out=[]
 label_prefix="AVYRN | " if prefix=="REG" else "AVYRN БС | "
 for item,country in zip(items,labels):
  seen[country]=seen.get(country,0)+1
  tag=label_prefix+country+((" "+suffix(seen[country])) if totals[country]>1 else "")
  node=copy.deepcopy(item); node["tag"]=tag; out.append(node)
 return out
reg,bs=rename(reg,"REG"),rename(bs,"BS")
# AVYRN layout: 40 regular manual servers; every other profile has exactly one node.
reg,bs=reg[:40],bs[:40]
reg_auto=reg
bs_auto=bs
helpers=[copy.deepcopy(x) for x in white.get("outbounds",[]) if not str(x.get("tag","")).startswith("igareck-node-")]
for h in helpers:
 if h.get("tag")=="fragment":
  st=h.setdefault("settings",{})
  if isinstance(st.get("fragment"),dict): st["fragment"]["interval"]="1-3"
  for noise in st.get("noises",[]): noise["delay"]="1-3"

base=copy.deepcopy(white); base.pop("_meta",None); base.pop("remarks",None)
base["dns"]["servers"]=base.get("dns",{}).get("servers",[])[:3]
base["outbounds"]=[]
base["observatory"]={"subjectSelector":["AVYRN | ","AVYRN БС | "],"probeURL":"https://www.gstatic.com/generate_204","probeInterval":"5m","enableConcurrency":True}
routing=base.setdefault("routing",{})
common_rules=[copy.deepcopy(x) for x in routing.get("rules",[]) if not x.get("balancerTag") and x.get("outboundTag")!="igareck-auto"]
def shell(title):
 p=copy.deepcopy(base); p["remarks"]=title; return p
def manual_one(item):
 p=shell(item["tag"]); p["outbounds"]=[copy.deepcopy(item)]+copy.deepcopy(helpers)
 p.pop("observatory",None); p["routing"]["balancers"]=[]
 p["routing"]["rules"]=copy.deepcopy(common_rules)
 return p
def manual_profiles(items):
 return [manual_one(item) for item in items]
def auto(items,prefix,title,tag):
 if not items: raise SystemExit("Empty AUTO pool: "+title)
 p=shell(title); p["outbounds"]=copy.deepcopy(items)+copy.deepcopy(helpers)
 p["observatory"]={"subjectSelector":[prefix],"probeURL":"https://www.gstatic.com/generate_204","probeInterval":"5m","enableConcurrency":True}
 p["routing"]["balancers"]=[{"tag":tag,"selector":[prefix],"fallbackTag":items[0]["tag"],"strategy":{"type":"leastPing"}}]
 p["routing"]["rules"]=copy.deepcopy(common_rules)+[{"type":"field","network":"tcp,udp","balancerTag":tag}]
 return p

# One Happ JSON-array subscription: every manual server is a selectable profile,
# plus two independent leastPing profiles that only see their own server pool.
profiles=manual_profiles(reg)+[auto(reg_auto,"AVYRN | ","AVYRN | AUTO","AVYRN-AUTO-REG")]+manual_profiles(bs)+[auto(bs_auto,"AVYRN БС | ","AVYRN БС | AUTO","AVYRN-AUTO-BS")]
if len(profiles)!=len(reg)+len(bs)+2: raise SystemExit("Unexpected subscription entry count")
Path("subscription.json").write_text(json.dumps(profiles,ensure_ascii=False,separators=(",",":"))+"\n",encoding="utf-8")
print(f"AVYRN: regular manual={len(reg)}, regular AUTO pool={len(reg_auto)}, whitelist manual={len(bs)}, whitelist AUTO pool={len(bs_auto)}, subscription entries={len(profiles)}")
