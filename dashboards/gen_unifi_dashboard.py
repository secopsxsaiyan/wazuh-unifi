#!/usr/bin/env python3
"""Generate the 'UniFi Threats' dashboard NDJSON.

Indexed (level >= 3) UniFi telemetry:
  - gateway iptables drops (decoder unifi-fw) and MISP matches on those addresses
  - CEF policy blocks (rule 100305) with srcip, dstip, and unifi.firewallPolicy
  - IPS/IDS (100309/100310) with signature, risk, srcip, and dstip
  - admin console (100307/100308) and honeypot (100311)
Level 1-2 noise and operational client chatter (100301) stay off the board.
"""
import json
ALERTS = "wazuh-alerts-*"
OSD = "2.16.0"
objects = []

def ss(query=""):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})

def viz(vid, title, vistype, aggs, params, query=""):
    # Tables need bucket aggs with schema "bucket" to split rows; "segment"/"group"
    # (right for pie/xy) make a table show only the metric count. Force "bucket".
    if vistype == "table":
        for _a in aggs:
            if _a.get("type") in ("terms", "date_histogram", "histogram") \
                    and _a.get("schema") in ("segment", "group"):
                _a["schema"] = "bucket"
    objects.append({"id": vid, "type": "visualization", "attributes": {
        "title": title, "visState": json.dumps({"title": title, "type": vistype, "aggs": aggs, "params": params}),
        "uiStateJSON": "{}", "description": "", "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": ss(query)}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": ALERTS}]})
    return vid

def dash(did, title, panels, desc=""):
    pj, refs = [], []
    x, y = 0, 0
    for i, item in enumerate(panels):
        if isinstance(item, tuple):
            v, w = item
        else:
            v, w = item, 24
        if x + w > 48:
            x = 0
            y += 15
        pi = str(i)
        pj.append({"version": OSD, "gridData": {"x": x, "y": y, "w": w, "h": 15, "i": pi},
                   "panelIndex": pi, "embeddableConfig": {}, "panelRefName": "panel_" + pi})
        refs.append({"name": "panel_" + pi, "type": "visualization", "id": v})
        x += w
        if x >= 48:
            x = 0
            y += 15
    objects.append({"id": did, "type": "dashboard", "attributes": {
        "title": title, "hits": 0, "description": desc, "panelsJSON": json.dumps(pj),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}), "version": 1, "timeRestore": False,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}},
        "references": refs})

def count(i="1"): return {"id": i, "enabled": True, "type": "count", "schema": "metric", "params": {}}
def terms(i, f, n=10, schema="segment"): return {"id": i, "enabled": True, "type": "terms", "schema": schema,
    "params": {"field": f, "orderBy": "1", "order": "desc", "size": n, "otherBucket": False,
               "otherBucketLabel": "Other", "missingBucket": False, "missingBucketLabel": "Missing"}}
def datehist(i): return {"id": i, "enabled": True, "type": "date_histogram", "schema": "segment",
    "params": {"field": "@timestamp", "useNormalizedEsInterval": True, "interval": "auto",
               "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}
def p_table(): return {"perPage": 12, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "sort": {"columnIndex": None, "direction": None}, "showTotal": True, "totalFunc": "sum", "percentageCol": ""}
def p_pie(): return {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}
def p_metric(sub): return {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {
    "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red", "metricColorMode": "None",
    "colorsRange": [{"from": 0, "to": 1000000}], "labels": {"show": True}, "invertColors": False,
    "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": sub, "fontSize": 40}}}
def p_area():
    return {"type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {},
            "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
            "style": {}, "scale": {"type": "linear", "mode": "normal"},
            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "events"}}],
        "seriesParams": [{"show": True, "type": "area", "mode": "stacked", "data": {"label": "Count", "id": "1"},
            "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True,
            "interpolate": "linear"}], "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "labels": {}, "thresholdLine": {"show": False, "value": 10, "width": 1,
            "style": "full", "color": "#E7664C"}}

# ---- query scopes ----
# unifi-fw is the gateway iptables feed (srcip/dstport plus data.unifi.fw_*).
# CEF rule 100305 is the short firewall shape: srcip, dstip, data.unifi.firewallPolicy.
# IPS rules 100309/100310 carry the signature and, when the event has them, srcip/dstip.
# Rules 100313/100314 still need direction and srcZone, which that short shape does not send.
# Level 1-2 rules are not indexed. Rule 100301 (client connect/roam) is operational and omitted.
# 100320 (allowed flows) is indexed at L3, so every "drops" panel scopes to fw_action:D.
# 100210/100211/100216-100218 come from the optional wazuh-misp-ioc pack and 101410 from the
# optional wazuh-threat-detection pack; those panels stay empty without them.
FW      = "decoder.name:unifi-fw and data.unifi.fw_action:D"   # iptables drops only
FW_IN   = "rule.id:(100328 or 100323)"            # inbound drops from the Internet
EGRESS  = "rule.id:(100322 or 100327)"            # internal host blocked leaving (LAN_WAN / VPN_WAN)
ALLOWIN = "rule.id:(100324 or 100325 or 100329)"  # inbound ALLOWED from the Internet (+ scan->allow)
MISP    = "rule.id:(100210 or 100211)"            # MISP IOC on traffic that was NOT dropped (actionable)
MISP_BLK= "rule.id:(100216 or 100217 or 100218)"  # MISP IOC on traffic the firewall dropped
SCAN    = "rule.id:(100314 or 100323 or 100329)"  # repeated drops from one source -> scan/recon
ADMIN   = "rule.id:(100307 or 100308 or 100332 or 100333 or 100334 or 100336 or 100337 or 100338 or 100339)"
HONEY   = "rule.id:100311"                         # honeypot triggered
IPS     = "rule.id:(100304 or 100309 or 100310 or 101410)"  # CEF IPS/IDS
IPS_REAL= "rule.id:(100309 or 100310 or 101410)"  # IPS minus reputation-only blocks
CEF_FW  = "rule.id:(100305 or 100312 or 100313)"  # CEF policy blocks with addresses
# master security scope: UniFi threat/admin rules, excluding operational 100301 and
# L1-2 suppressed-noise rules (100312/100315) and the high-volume L3 flow rules (100320/100321).
THREATS = ("rule.id:(100210 or 100211 or 100305 or 100306 or 100307 or 100308 or "
           "100309 or 100310 or 100311 or 100323 or 100325 or 100327 or 100329 or 100333 or "
           "100336 or 100337 or 100339 or 101410)")

# Row 1 — headline KPIs
viz("uni-kpi-malicious", "MISP IOC on ALLOWED traffic (actionable)", "metric", [count("1")], p_metric("not dropped"), query=MISP)
viz("uni-kpi-misp-blocked", "MISP-listed sources dropped", "metric", [count("1")], p_metric("already blocked"), query=MISP_BLK)
viz("uni-kpi-drops", "Firewall drops (iptables, action D)", "metric", [count("1")], p_metric("drops"), query=FW)
viz("uni-kpi-allowin", "Inbound ALLOWED from Internet", "metric", [count("1")], p_metric("WAN allows"), query=ALLOWIN)
viz("uni-kpi-cef", "CEF firewall blocks", "metric", [count("1")], p_metric("policy blocks"), query=CEF_FW)
viz("uni-cef-policy", "CEF blocks by firewall policy", "pie",
    [count("1"), terms("2", "data.unifi.firewallPolicy", 8)], p_pie(), query=CEF_FW)
viz("uni-cef-blocks", "CEF firewall blocks by source, destination, and policy", "table",
    [count("1"), terms("2", "data.srcip", 15), terms("3", "data.dstip", 5),
     terms("4", "data.unifi.firewallPolicy", 4)], p_table(), query=CEF_FW)
# Trend + geo
viz("uni-timeline", "UniFi security events over time (by level)", "area",
    [count("1"), datehist("2"), terms("3", "rule.level", 6, schema="group")], p_area(), query=THREATS)
viz("uni-countries", "Blocked-source countries", "pie",
    [count("1"), terms("2", "GeoLocation.country_name", 10)], p_pie(), query=FW)
# Who (malicious-known vs all iptables drops)
viz("uni-misp-ips", "Malicious blocked source IPs (MISP IOC, dropped)", "table",
    [count("1"), terms("2", "data.srcip", 20), terms("3", "GeoLocation.country_name", 1)], p_table(), query=MISP_BLK)
viz("uni-top-srcips", "Top blocked source IPs (all firewall drops)", "table",
    [count("1"), terms("2", "data.srcip", 20), terms("3", "GeoLocation.country_name", 1)], p_table(), query=FW)
# What (ports + chain/proto)
viz("uni-ports", "Dropped destination ports (all chains)", "table",
    [count("1"), terms("2", "data.dstport", 15)], p_table(), query=FW)
viz("uni-chain", "Firewall drops by chain + protocol", "table",
    [count("1"), terms("2", "data.unifi.fw_chain", 8), terms("3", "data.unifi.fw_proto", 4)], p_table(), query=FW)
# Recon + admin
viz("uni-scanners", "Scan / recon sources (repeated drops)", "table",
    [count("1"), terms("2", "data.srcip", 15)], p_table(), query=SCAN)
viz("uni-admin", "UniFi admin-plane activity", "table",
    [count("1"), terms("2", "rule.description", 10)], p_table(), query=ADMIN)
# Honeypot + IPS with the addresses the CEF decoders now extract
viz("uni-honeypot", "Honeypot hits (by client MAC)", "table",
    [count("1"), terms("2", "data.unifi.clientMac", 15)], p_table(), query=HONEY)
viz("uni-ips", "IPS/IDS signatures with source and destination", "table",
    [count("1"), terms("2", "rule.id", 6), terms("3", "data.unifi.ipsSignature", 12), terms("4", "data.srcip", 5),
     terms("5", "data.dstip", 3), terms("6", "data.unifi.risk", 2)], p_table(), query=IPS)
viz("uni-ips-real", "IPS hits excluding reputation-only blocks", "table",
    [count("1"), terms("2", "data.unifi.ipsSignature", 12), terms("3", "data.unifi.act", 2),
     terms("4", "data.unifi.risk", 2)], p_table(), query=IPS_REAL)
viz("uni-allowin", "Inbound ALLOWED from Internet (source, port, policy)", "table",
    [count("1"), terms("2", "data.srcip", 15), terms("3", "data.dstport", 5),
     terms("4", "data.unifi.fw_policy", 4)], p_table(), query=ALLOWIN)
viz("uni-egress", "Internal hosts blocked on egress (by policy)", "table",
    [count("1"), terms("2", "data.srcip", 15), terms("3", "data.unifi.fw_policy", 5),
     terms("4", "data.dstport", 5)], p_table(), query=EGRESS)
viz("uni-wan-ports", "Inbound WAN drops: targeted ports", "table",
    [count("1"), terms("2", "data.dstport", 15)], p_table(), query=FW_IN)

dash("unifi-threats", "UniFi Threats",
     ["uni-kpi-malicious", "uni-kpi-misp-blocked",
      "uni-kpi-drops", "uni-kpi-allowin",
      "uni-kpi-cef", "uni-cef-policy",
      ("uni-cef-blocks", 48),
      "uni-timeline", "uni-countries",
      "uni-misp-ips", "uni-top-srcips",
      "uni-ports", "uni-chain",
      "uni-scanners", "uni-admin",
      "uni-honeypot", "uni-ips-real",
      ("uni-ips", 48),
      "uni-allowin", "uni-egress",
      "uni-wan-ports"],
     "UniFi perimeter security from gateway iptables drops, CEF policy blocks, MISP IOC matches, "
     "honeypot, admin-plane, and IPS/IDS events. CEF firewall blocks show source, destination, "
     "and firewall policy. Inbound level 1-2 noise stays off this board.")

with open("wazuh_unifi_dashboard.ndjson", "w") as f:
    for o in objects:
        f.write(json.dumps(o) + "\n")
print("wrote", len(objects), "objects (1 dashboard,", len(objects) - 1, "visualizations)")
