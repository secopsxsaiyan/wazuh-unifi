# Changelog

All notable changes to this pack are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-10-26

### Added
- Gateway iptables rules for the real chain layout: egress drops (`LAN_WAN`/`VPN_WAN`, 100322),
  DNS/DoT policy blocks (100326, excluded from the burst count), internal egress burst
  (100327, L7), inbound WAN drop parent (100328), inbound allows from the Internet (100324)
  and to internal hosts / port-forwards (100325, L6), and scan-then-allowed (100329, L12).
- CEF admin plane: Network admin login (100332, L5) and login from a non-internal address
  (100333, L10, uses the new `lists/internal-networks` CDB list); new console user
  activated (100337, L10); keyword-based admin login failure (100338) and brute force
  (100339, L10).
- CEF config audit: new `unifi-cef-config` / `unifi-cef-pn-config` decoders extract the
  settings section, entry and admin; rules 100334 (L5), 100335 (controller auto-changes,
  L2) and 100336 (security-relevant sections, L8).
- CEF client chatter labelled: association/roam/mesh (100330), high traffic (100331),
  hotspot guest (100300).
- IPS reputation-only blocks (ET CINS / DROP / DShield / Compromised / 3CORESec / TOR,
  "Poor Reputation") de-rated to L7 (100304). Signatures naming P2P are excluded, so every
  other IPS signature keeps the 100309 (L10) / 100310 (L12) path.
- `lists/internal-networks` (RFC 1918 prefixes) and README steps to declare it.
- Dashboard: MISP IOC split into allowed (actionable) vs dropped, inbound-allowed KPI and
  table, internal egress-block table, inbound WAN targeted ports, and an IPS panel that
  excludes reputation-only hits.

### Changed
- 100307 now covers UniFi OS sigid 1004–1007 (created/changed/removed config) and shows the
  event detail; MITRE T1562.007 → T1098.
- 100310 tagged MITRE T1190.
- 100312 no longer requires `UNIFIdirection=incoming`: CEF blocks from the Internet carry
  `UNIFIdirection=outgoing` with `UNIFIsrcZone=External`, so 100312 never fired and those
  events were mislabelled by 100313 as internal hosts blocked. 100313 now excludes
  `srcZone=External`.
- 100320 (all iptables flows) L1 → L3 and 100321 (drops) L2 → L3, so flows are stored; the
  README explains the volume and how to revert. 100322 L7 → L3 and fixed to the real egress
  chains (it keyed on `LOCAL_*`, which never drops).
- 100323 (scan, L10) counts Internet-sourced drops only (via 100328), so internal DNS/DoT
  pinning no longer triggers it.
- Admin netaccess decoders keep admin names that contain spaces.
- Dashboard "drops" panels filter on `data.unifi.fw_action:D`; scopes and the master
  security query include the new rules.
- README: rule tables split by feed, levels for 100314/100323 corrected to L10, ID-collision
  check commands, tuning notes.

## [1.1.0] — 2026-10-26

### Added
- CEF decoders for the short firewall-block shape that carries `UNIFIfirewallPolicy`
  (`src=`/`dst=`, or `dst=` plus `UNIFIsrcClientIp`) instead of
  `UNIFIpolicyType=Firewall`. Addresses map to canonical `srcip`/`dstip`; the policy
  name lands in `unifi.firewallPolicy`.
- CEF decoders for IPS/IDS lines that include `src=` and/or `dst=`, so threat
  alerts now carry the attacker and target addresses.
- CEF decoder for WiFi/wired client events (`UNIFIclientIp` → `srcip`).
- Dashboard: CEF firewall-block KPI, blocks-by-policy pie, and a source/destination/policy
  table. IPS/IDS panel now shows source and destination addresses.

### Changed
- Dashboard generator supports full-width panels; layout regenerated.
- README documents the new canonical-field mappings and links the companion
  [wazuh-misp-ioc](https://github.com/secopsxsaiyan/wazuh-misp-ioc) pack.

## [1.0.0] — 2026-06-27

- Initial public release: CEF and gateway iptables decoders, classification rules
  (IDs 100301–100360), and the "UniFi Threats" dashboard.
