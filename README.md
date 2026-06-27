# UniFi → Wazuh: custom decoders, alert rules & dashboard

Custom Wazuh content that ingests **UniFi** security telemetry over syslog, classifies it
into Wazuh alerts (with MITRE ATT&CK tags and noise suppression), and ships a ready-made
**"UniFi Threats"** dashboard.

It decodes two separate UniFi syslog streams:

1. **CEF feed** — the UniFi OS *SIEM Server / Activity Logging* export. Carries UniFi OS
   admin events, UniFi **Network** IPS/IDS threat detections, honeypot triggers, the
   firewall (sigId 203) events, VPN connects, and admin-audit logins.
2. **Gateway iptables firewall syslog** — the raw `[ZONE_ZONE-X-NNN] DESCR=...` netfilter
   LOG stream the gateway emits (not CEF). Previously "No decoder matched" → dropped.

> No agent, poller, or cloud component. Everything here is plain Wazuh decoders/rules plus
> a dashboard generator. UniFi pushes syslog; Wazuh decodes it.

## Contents

```
custom_rules/
  unifi_cef_decoders.xml   # CEF feed decoders (threat / honeypot / firewall / admin / VPN)
  unifi_fw_decoders.xml    # gateway iptables firewall syslog decoders
  unifi_rules.xml          # classification + alerting rules (IDs 100301–100360)
dashboards/
  gen_unifi_dashboard.py   # generator for the "UniFi Threats" dashboard
  wazuh_unifi_dashboard.ndjson   # pre-generated saved-objects export (import this)
```

## Requirements

- **Wazuh manager 4.x** (uses standard custom decoder/rule syntax + PCRE2).
- **Wazuh dashboard / OpenSearch Dashboards 2.16.x** with a `wazuh-alerts-*` index pattern
  (for importing the dashboard).
- A UniFi gateway (tested against a UniFi OS console / Dream Machine line) able to forward
  syslog to the Wazuh manager.

## Install

### 1. Forward UniFi syslog to the Wazuh manager

- **CEF feed:** UniFi OS → **Settings → Control Plane → Integrations → Activity Logging
  (SIEM Server)** → point it at `<WAZUH MANAGER IP>` on port `514`.
- **Firewall syslog:** enable remote syslog for the gateway's firewall/traffic logs to the
  same `<WAZUH MANAGER IP>:514`. (On UniFi these can be two separate forwarding configs —
  enable both if you want IPS/admin *and* the iptables firewall stream.)

### 2. Add a syslog listener to the Wazuh manager

In `ossec.conf` (skip if you already accept syslog on 514):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips><YOUR LAN CIDR></allowed-ips>   <!-- e.g. 10.0.0.0/8 -->
</remote>
```

### 3. Install the decoders and rules

Copy into the manager's ruleset directory, then restart:

```bash
# bare-metal / VM
cp unifi_cef_decoders.xml unifi_fw_decoders.xml /var/ossec/etc/decoders/
cp unifi_rules.xml                              /var/ossec/etc/rules/
chown root:wazuh /var/ossec/etc/decoders/unifi_*.xml /var/ossec/etc/rules/unifi_rules.xml

# Docker (adjust container/volume names to your deployment)
# docker cp unifi_cef_decoders.xml wazuh.manager:/var/ossec/etc/decoders/
# docker cp unifi_fw_decoders.xml  wazuh.manager:/var/ossec/etc/decoders/
# docker cp unifi_rules.xml        wazuh.manager:/var/ossec/etc/rules/

/var/ossec/bin/wazuh-control restart
```

Validate the ruleset loads cleanly:

```bash
/var/ossec/bin/wazuh-analysisd -t      # expect no errors
```

### 4. Test the decoders

Paste a sample line into `wazuh-logtest` and confirm it decodes + fires the expected rule,
e.g. a CEF threat event or an iptables firewall line:

```bash
/var/ossec/bin/wazuh-logtest
# CEF:0|Ubiquiti|UniFi Network|<ver>|201|Threat Detected and Blocked|7|...UNIFIipsSignature=...
# <13>... DM [WAN_LOCAL-D-10005] DESCR="Block All" ... SRC=<src> DST=<dst> PROTO=TCP SPT=.. DPT=..
```

### 5. Import the dashboard

Wazuh dashboard → **Dashboards Management → Saved Objects → Import** → select
`wazuh_unifi_dashboard.ndjson` (choose *overwrite*). Or via API:

```bash
curl -k -u <DASHBOARD USER>:<DASHBOARD PASS> -X POST \
  "https://<WAZUH DASHBOARD>/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" --form file=@wazuh_unifi_dashboard.ndjson
```

To regenerate the ndjson after editing panels: `python3 gen_unifi_dashboard.py`
(stdlib only; writes `wazuh_unifi_dashboard.ndjson` in the current directory).

## Alert rules (IDs 100301–100360)

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100301 | 3 | UniFi base event (operational) | |
| 100302 | 0 | SIEM "Test Syslog" (suppressed) | |
| 100305 | 5 | Firewall block/deny (keyword) | |
| 100306 | 10 | IPS/IDS/threat (keyword) | |
| 100307 | 8 | UniFi OS admin **configuration change** | T1562.007 |
| 100308 | 5 | UniFi OS admin **console access** | |
| 100309 | 10 | IPS/IDS **blocked** (mitigated) | |
| 100310 | 12 | IPS/IDS **detected, not blocked** | |
| 100311 | 12 | **Honeypot** triggered | T1046 |
| 100312 | 2 | External inbound firewall block (noise, suppressed) | |
| 100313 | 7 | **Outbound** firewall block (internal host blocked) | |
| 100314 | 8 | Repeated external blocks from one source (scan) | T1046 |
| 100315 | 1 | UniFi **Protect** camera/sensor event (de-rated, not cyber) | |
| 100316 | 8 | UniFi **NAS** (UNAS Pro) backup **FAILED** | T1490 |
| 100317 | 8 | UniFi NAS backup **deleted / removed** | T1485 / T1490 |
| 100318 | 2 | UniFi NAS routine backup success/start (suppressed) | |
| 100320 | 1 | Gateway iptables firewall (any, captured/suppressed) | |
| 100321 | 2 | iptables **drop** (suppressed) | |
| 100322 | 7 | iptables **outbound drop** (internal host blocked) | |
| 100323 | 8 | Repeated iptables drops from one source (scan) | T1046 |
| 100360 | 8 | **VPN Client Connected** (verify user/time) | T1133 |

Levels follow a triage gate of **L10** (≥10 reaches analyst triage). Inbound firewall noise
and Protect camera events are intentionally de-rated below the gate; outbound blocks, IPS
detections, honeypot, and scans surface above it.

## Notes & tuning

- **Canonical fields:** firewall src/dst decode into Wazuh's canonical `srcip`/`dstip`/
  `srcport`/`dstport`, and admin/VPN events into `srcuser`/`srcip`. This lets standard
  Wazuh frequency rules (`same_source_ip`) and any IP-IOC rules you run match automatically.
- **Optional MISP dependency:** the dashboard includes panels for *MISP IOC matches* that
  query rule IDs **100210/100211** (a MISP IP-IOC ruleset from the broader stack, **not
  included here**). Those panels stay empty unless you also run such rules; everything else
  works standalone.
- **Decoder ordering gotcha:** Wazuh evaluates only the **first** matching child decoder
  unless each child has a distinguishing `<prematch>`. The child decoders here are
  prematch-anchored (threat / honeypot / firewall / admin / VPN), with a generic
  `-fields` fallback kept **last**. Preserve that ordering if you add children.
- **Rule/decoder ID range:** custom rule IDs `100301–100360` and decoder names `unifi-cef*`
  / `unifi-fw*`. Check these don't collide with your existing custom content.
- **Sample/placeholder values** in comments use `<...>` placeholders and documentation-safe
  values — substitute your own where shown.

## Disclaimer

Provided as-is, with no warranty. Review and tune alert levels and suppression to your own
environment before relying on them.
