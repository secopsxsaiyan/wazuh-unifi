#!/usr/bin/env python3
"""Generate the 'UniFi Threats' dashboard NDJSON. Uses only indexed (L>=3) UniFi threat
rules — IPS (100309/100310), honeypot (100311), outbound block (100313), scan (100314).
External-inbound firewall blocks are L2/suppressed by design, so they don't appear here."""
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
    for i, v in enumerate(panels):
        pi = str(i)
        pj.append({"version": OSD, "gridData": {"x": (i % 2) * 24, "y": (i // 2) * 15, "w": 24, "h": 15, "i": pi},
                   "panelIndex": pi, "embeddableConfig": {}, "panelRefName": "panel_" + pi})
        refs.append({"name": "panel_" + pi, "type": "visualization", "id": v})
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

# ---- live-verified query scopes ----
# Reality of what reaches Wazuh: the CEF IPS / firewall-sigId-203 path is NOT forwarded here,
# so rules 100309/100310/100313/100314 never fire (the old board queried those -> 5 empty panels).
# The real perimeter telemetry is the gateway's iptables firewall syslog (decoder unifi-fw) with
# canonical srcip/dstip/dstport + data.unifi.fw_* and GeoLocation, the MISP IOC matches on that
# srcip (rule 100210), the CEF admin events (100307/8), and honeypot (100311). All fields below
# were aggregation-verified live. NOTE: L1-2 firewall noise is suppressed (not indexed), so the
# indexed unifi-fw set is already the threat-relevant subset (MISP-malicious + scans + outbound).
FW      = "decoder.name:unifi-fw"                  # indexed firewall drops (threat-relevant only)
MISP    = "rule.id:(100210 or 100211)"            # firewall srcip/dstip matched a MISP IOC
SCAN    = "rule.id:(100314 or 100323)"            # repeated drops from one source -> scan/recon (100323 fires)
ADMIN   = "rule.id:(100307 or 100308)"            # UniFi OS admin console access / config change
HONEY   = "rule.id:100311"                         # honeypot triggered
IPS     = "rule.id:(100309 or 100310)"            # CEF IPS/IDS — populates only if Threat Management is on + forwarded
# master security scope: all UniFi threat/admin rules, excluding operational (100301) and the
# L1-2 suppressed-noise rules (100312/100315/100320/100321) that are never indexed anyway.
THREATS = ("rule.id:(100210 or 100211 or 100305 or 100306 or 100307 or 100308 or "
           "100309 or 100310 or 100311 or 100322 or 100323)")

# Row 1 — headline KPIs
viz("uni-kpi-malicious", "Malicious IPs blocked (MISP IOC)", "metric", [count("1")], p_metric("MISP-matched drops"), query=MISP)
viz("uni-kpi-drops", "Firewall drops indexed (threat-relevant)", "metric", [count("1")], p_metric("WAN drops"), query=FW)
# Row 2 — trend + geo
viz("uni-timeline", "UniFi security events over time (by level)", "area",
    [count("1"), datehist("2"), terms("3", "rule.level", 6, schema="group")], p_area(), query=THREATS)
viz("uni-countries", "Blocked-source countries", "pie",
    [count("1"), terms("2", "GeoLocation.country_name", 10)], p_pie(), query=FW)
# Row 3 — who (malicious-known vs all)
viz("uni-misp-ips", "Malicious blocked source IPs (MISP IOC)", "table",
    [count("1"), terms("2", "data.srcip", 20), terms("3", "GeoLocation.country_name", 1)], p_table(), query=MISP)
viz("uni-top-srcips", "Top blocked source IPs (all firewall drops)", "table",
    [count("1"), terms("2", "data.srcip", 20), terms("3", "GeoLocation.country_name", 1)], p_table(), query=FW)
# Row 4 — what (ports + chain/proto)
viz("uni-ports", "Targeted destination ports", "table",
    [count("1"), terms("2", "data.dstport", 15)], p_table(), query=FW)
viz("uni-chain", "Firewall drops by chain + protocol", "table",
    [count("1"), terms("2", "data.unifi.fw_chain", 8), terms("3", "data.unifi.fw_proto", 4)], p_table(), query=FW)
# Row 5 — recon + admin
viz("uni-scanners", "Scan / recon sources (repeated drops)", "table",
    [count("1"), terms("2", "data.srcip", 15)], p_table(), query=SCAN)
viz("uni-admin", "UniFi admin-plane activity", "table",
    [count("1"), terms("2", "rule.description", 10)], p_table(), query=ADMIN)
# Row 6 — honeypot + forward-looking IPS
viz("uni-honeypot", "Honeypot hits (by client MAC)", "table",
    [count("1"), terms("2", "data.unifi.clientMac", 15)], p_table(), query=HONEY)
viz("uni-ips", "IPS/IDS signatures (enable UniFi Threat Management to populate)", "table",
    [count("1"), terms("2", "data.unifi.ipsSignature", 15), terms("3", "data.unifi.risk", 3)], p_table(), query=IPS)

dash("unifi-threats", "UniFi Threats",
     ["uni-kpi-malicious", "uni-kpi-drops", "uni-timeline", "uni-countries",
      "uni-misp-ips", "uni-top-srcips", "uni-ports", "uni-chain",
      "uni-scanners", "uni-admin", "uni-honeypot", "uni-ips"],
     "UniFi perimeter security from the gateway firewall syslog (iptables drops + MISP IOC matches on "
     "source IPs), honeypot, and admin-plane events. The CEF IPS/firewall-203 path is not forwarded to "
     "Wazuh and L1-2 inbound firewall noise is suppressed, so this board shows the threat-relevant subset. "
     "The IPS/IDS panel populates only if UniFi Threat Management is enabled and forwarded.")

with open("wazuh_unifi_dashboard.ndjson", "w") as f:
    for o in objects:
        f.write(json.dumps(o) + "\n")
print("wrote", len(objects), "objects (1 dashboard,", len(objects) - 1, "visualizations)")
