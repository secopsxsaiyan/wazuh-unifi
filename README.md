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
  unifi_cef_decoders.xml   # CEF decoders (threat, honeypot, firewall, client, admin, VPN)
  unifi_fw_decoders.xml    # gateway iptables firewall syslog decoders
  unifi_rules.xml          # classification + alerting rules (IDs 100300–100339, 100360)
lists/
  internal-networks        # CDB list of RFC 1918 prefixes (used by rule 100333)
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

Install the `internal-networks` CDB list (rule 100333 uses it to flag admin logins from
outside your networks) and declare it in the `<ruleset>` block of `ossec.conf`:

```bash
cp lists/internal-networks /var/ossec/etc/lists/internal-networks
chown wazuh:wazuh /var/ossec/etc/lists/internal-networks
```

```xml
<ruleset>
  ...
  <list>etc/lists/audit-keys</list>
  <list>etc/lists/internal-networks</list>   <!-- add -->
  ...
</ruleset>
```

The shipped list holds the RFC 1918 prefixes (`10.`, `172.16.`–`172.31.`, `192.168.`) in
CDB `address_match_key` form. Add any other ranges your admins legitimately log in from
(e.g. a VPN pool or CGNAT `100.64.`). If the list is not declared, analysisd loads without an
error but 100333 never fires; 100332 (L5) still records every admin login. If you already
keep an `internal-networks` list for other content, reuse it instead of copying this one.

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

## Alert rules (IDs 100300–100339, 100360)

### CEF feed — base, IPS/IDS, honeypot, firewall, NAS

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100301 | 3 | UniFi base event (operational) | |
| 100302 | 0 | SIEM "Test Syslog" (suppressed) | |
| 100305 | 5 | Firewall block/deny (keyword) | |
| 100306 | 10 | IPS/IDS/threat (keyword) | |
| 100309 | 10 | IPS/IDS **blocked** (mitigated) | |
| 100304 | 7 | IPS/IDS blocked, **reputation-only** signature (ET CINS / DROP / DShield / Compromised / 3CORESec / TOR, "Poor Reputation") | |
| 100310 | 12 | IPS/IDS **detected, not blocked** | T1190 |
| 100311 | 12 | **Honeypot** triggered | T1046 |
| 100312 | 2 | Firewall block from an **External** zone source (noise, suppressed) | |
| 100313 | 7 | Firewall block of an **internal** source leaving (internal host blocked) | |
| 100314 | 10 | Repeated external blocks from one source (scan) | T1046 |
| 100315 | 1 | UniFi **Protect** camera/sensor event (de-rated, not cyber) | |
| 100316 | 8 | UniFi **NAS** (UNAS Pro) backup **FAILED** | T1490 |
| 100317 | 8 | UniFi NAS backup **deleted / removed** | T1485 / T1490 |
| 100318 | 2 | UniFi NAS routine backup success/start (suppressed) | |
| 100360 | 8 | **VPN Client Connected** (verify user/time) | T1133 |

### CEF feed — admin plane, config audit, clients

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100307 | 8 | UniFi OS admin **configuration created/changed/removed** (sigid 1004–1007) | T1098 |
| 100308 | 5 | UniFi OS admin **console access** (sigid 1000) | |
| 100337 | 10 | UniFi OS **new console user activated** (sigid 1018) | T1136 / T1098 |
| 100332 | 5 | UniFi Network **admin login** (sigid 544) — admin + source IP | T1078 |
| 100333 | 10 | Admin login from a source **not** in `internal-networks` | T1078 / T1133 |
| 100334 | 5 | Network **config audit** (sigid 545–549: created/modified/paused/resumed/removed) | T1098 |
| 100335 | 2 | Config change made by the controller itself (`Network Application`, suppressed) | |
| 100336 | 8 | **Security-relevant** config change (Firewall, Port Forward, Security, VPN, WireGuard, Policy-Based Route, System, Admin, Traffic, Zone) | T1562.004 |
| 100338 | 6 | Admin **login failure** (keyword; forward-looking) | T1110 |
| 100339 | 10 | 5 admin login failures in 5 min (brute force) | T1110 |
| 100330 | 3 | Client connect/disconnect/roam, AP mesh (sigid 400–404, 575, 576) | |
| 100331 | 3 | High Internet traffic for a client (sigid 407) | |
| 100300 | 4 | Hotspot guest connected (sigid 405) | |

### Gateway iptables firewall syslog

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100320 | 3 | Gateway iptables flow (any action; indexed as a flow record) | |
| 100321 | 3 | iptables **drop** | |
| 100322 | 3 | **Egress drop** — internal host blocked leaving (`LAN_WAN` / `VPN_WAN`) | |
| 100326 | 3 | Egress drop to port 53/853 (DNS/DoT pinning blocked by policy; excluded from 100327) | |
| 100327 | 7 | 30 egress drops in 5 min from one internal host (malware retry / misconfiguration) | T1571 |
| 100328 | 3 | **Inbound WAN drop** (`WAN_*` chains) | |
| 100323 | 10 | 20 inbound WAN drops in 2 min from one source (scan) | T1046 |
| 100324 | 3 | Inbound flow from the Internet **allowed** (`WAN_*`, action A — e.g. WireGuard) | |
| 100325 | 6 | Internet → **internal host** allowed (`WAN_LAN`/`WAN_IN`/`WAN_DMZ`, port-forward) | T1133 |
| 100329 | 12 | A source that tripped 100323 gets an **allowed** inbound flow within 1 h (scan → allow) | T1046 / T1133 |

Levels follow a triage gate of **L10** (≥10 reaches analyst triage). Inbound firewall noise,
reputation-only IPS blocks, controller auto-changes and Protect camera events are
intentionally de-rated below the gate; IPS detections, honeypot, scans, scan-then-allow,
off-network admin logins and new console users surface at or above it.

**IPS/IDS severity is not de-rated by category.** Apart from the reputation-only blocks
(100304), every IPS signature (including P2P, policy and malware categories) keeps the
100309 (L10, blocked) / 100310 (L12, not blocked) path. 100304 explicitly excludes any
signature that names P2P.

**Cross-pack:** [wazuh-threat-detection](https://github.com/secopsxsaiyan/wazuh-threat-detection)
chains off this pack — 101410 (L14, critical/high IPS signature **not** blocked) is a child of
100310, and its blocklist rules are children of 100320. Load this pack whenever you load that one.

## Notes & tuning

- **Canonical fields:** the long `UNIFIpolicyType=Firewall` events map src/dst into
  `srcip`/`dstip` plus `srcport`/`dstport`. Shorter blocks that carry
  `UNIFIfirewallPolicy` map `src=`/`dst=`, or `dst=` plus `UNIFIsrcClientIp`, into
  `srcip`/`dstip` and `unifi.firewallPolicy`. WiFi and wired client events map
  `UNIFIclientIp` to `srcip`. Admin and VPN events map `srcuser`/`srcip` from
  `UNIFIadmin`/`suser` and `src=` (admin names may contain spaces). VPN is matched before the client decoder so the
  tunnel address in `UNIFIclientIp` is not copied over `src=`. These canonical
  fields let `same_source_ip` and IP-IOC rules match.
- **Optional MISP / threat-detection dependency:** the dashboard includes panels for *MISP
  IOC matches* that query rule IDs **100210/100211** (IOC on traffic that was not dropped) and
  **100216–100218** (IOC on traffic the firewall dropped) from the companion
  [wazuh-misp-ioc](https://github.com/secopsxsaiyan/wazuh-misp-ioc) pack (**not included
  here**), and the IPS panels include 101410 from
  [wazuh-threat-detection](https://github.com/secopsxsaiyan/wazuh-threat-detection). Those
  panels stay empty unless you also run those rules; everything else works standalone.
- **Decoder ordering gotcha:** Wazuh evaluates only the **first** matching child decoder
  unless each child has a distinguishing `<prematch>`. The child decoders here are
  prematch-anchored (threat, honeypot, firewall, config, admin, VPN, client), with a generic
  `-fields` fallback kept **last**. Preserve that ordering if you add children.
- **Rule/decoder ID range:** custom rule IDs `100300–100339` and `100360`, decoder names
  `unifi-cef*` / `unifi-fw*`. Check these don't collide with your existing custom content:

  ```bash
  grep -rlE 'rule id="(1003[0-3][0-9]|100360)"' /var/ossec/etc/rules/ \
    | grep -v '/unifi_rules.xml$'                               # expect no output
  grep -rlE 'decoder name="unifi-(cef|fw)' /var/ossec/etc/decoders/ \
    | grep -vE '/unifi_(cef|fw)_decoders.xml$'                  # expect no output
  ```
- **Wazuh evaluates sibling rules highest-level first**, not in file order. A low-level
  de-rate (e.g. 100335, 100326) must therefore be a *child* of the rule it overrides. Keep
  that pattern if you add your own exceptions.
- **iptables volume (100320 at L3).** Every gateway flow — allows included — is indexed so the
  alerts index doubles as a flow record when archives are off. Expect roughly 200k
  docs/day (~75–85 MB/day) on a typical home/SMB gateway with logging enabled on allow
  rules. To keep only drops and the security-relevant allows, set 100320 to `level="1"`:
  its children (100321–100329) still fire. Dashboard "drop" panels filter on
  `data.unifi.fw_action:D`, so allows never inflate them.
- **CEF firewall direction.** CEF blocks from the Internet arrive with
  `UNIFIdirection=outgoing` and `UNIFIsrcZone=External`; 100312/100313 key on the source
  zone, not the direction label.
- **Config audit decoder.** `unifi-cef-*-config` extracts `unifi.settingsSection`,
  `unifi.settingsEntry` and the admin (`srcuser`, may contain spaces). It sits before the
  `-netaccess` child, because human edits also carry `UNIFIaccessMethod=`. Adjust the
  section list in 100336 to match the sections your controller version reports.
- **Login failures (100338/100339)** are keyword-based on the CEF EventName (no sample
  sigid yet). 100338 also chains off stock 2501/1002 because a CEF line containing
  "failed"/"authentication failure" is claimed by those stock rules first.
- **Sample/placeholder values** in comments use `<...>` placeholders and documentation-safe
  values — substitute your own where shown.

## Disclaimer

Provided as-is, with no warranty. Review and tune alert levels and suppression to your own
environment before relying on them.
