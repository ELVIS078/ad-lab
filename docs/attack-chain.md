# Attack chain — ATT&CK mapping

Modeled on a realistic Active Directory intrusion chain: initial access →
enumeration → credential access (Kerberoasting / AS-REP roasting) →
lateral movement via ACL abuse → domain compromise (DCSync). Each row
links to its `ttps/<id>/` folder once implemented.

| Phase | Technique | ATT&CK ID | Status | Folder |
|---|---|---|---|---|
| Initial Access | Phishing: spearphishing via macro attachment | T1566.001 | ✅ Done | [`ttps/T1566.001-phishing-macro`](../ttps/T1566.001-phishing-macro) |
| Discovery | Account/Group/Trust Discovery (SMB enum, BloodHound collection) | T1087.002 / T1482 | 🔲 Planned | — |
| Credential Access | Kerberoasting (request TGS for SPN account, crack offline) | T1558.003 | ✅ Done | [`ttps/T1558.003-kerberoasting`](../ttps/T1558.003-kerberoasting) |
| Credential Access | AS-REP Roasting (accounts with Kerberos pre-auth disabled) | T1558.004 | 🔲 Planned | — |
| Privilege Escalation | Abuse of weak ACLs (e.g. GenericAll on a user → password reset) | T1098.002 / T1484.002 | 🔲 Planned | — |
| Credential Access | DCSync (abuse Replicating Directory Changes rights) | T1003.006 | ✅ Done | [`ttps/T1003.006-dcsync`](../ttps/T1003.006-dcsync) |
| Impact | Data Encrypted for Impact (simulated, non-destructive) | T1486 | 🔲 Planned | — |

## Kill chain narrative

1. **Initial access** — phishing macro lands on `client01`, spawns a shell
   (T1566.001).
2. **Discovery** — from that foothold, enumerate the domain: SMB shares
   (`netexec smb`), then a full BloodHound collection
   (`bloodhound.py -c All`) to map accounts, group memberships and ACLs.
3. **Credential access #1 — Kerberoasting** — the lab's `svc-sql` service
   account (deliberately given a weak password and an SPN in
   `ansible/playbooks/promote-dc.yml`) is roasted: request its TGS,
   crack the ticket offline with hashcat (mode 13100).
4. **Credential access #2 — AS-REP roasting** — a second lab account has
   Kerberos pre-authentication disabled; its AS-REP is requestable
   without any credentials and crackable offline (hashcat mode 18200).
5. **Privilege escalation — ACL abuse** — BloodHound surfaces a path like
   `helpdesk --GenericAll--> jsmith`: abuse that right to reset
   `jsmith`'s password without ever touching their original credential.
6. **Domain compromise — DCSync** — if the compromised account (or a
   group it belongs to) holds `Replicating Directory Changes` /
   `Replicating Directory Changes All`, impersonate a domain controller
   and pull every account hash via `secretsdump.py`.

## Concepts to be able to explain for each step

This is the part that actually matters for a portfolio — being able to
explain *why* each technique works, not just that it does:

- **Kerberos basics**: AS-REQ/AS-REP (issues the TGT) and TGS-REQ/TGS-REP
  (issues a service ticket). Kerberoasting abuses the fact that *any*
  authenticated user can request a TGS for *any* SPN — the returned
  ticket is encrypted with the service account's NTLM hash, crackable
  offline with no further access needed. AS-REP roasting abuses accounts
  with pre-auth disabled: the AS-REP itself is partly encrypted with the
  user's hash, so it's requestable (and crackable) with zero credentials.
- **DCSync**: AD replication between domain controllers is implemented
  as a *permission* (`DS-Replication-Get-Changes[-All]` via the DRSUAPI
  RPC interface), not a hard rule. Any principal holding it can request
  a full account/hash sync as if it were a legitimate DC — which is why
  it shows up as a specific, identifiable event (4662 with the
  replication GUIDs), not as something that looks like "logging in".
- **BloodHound's model**: a directed graph where nodes are
  principals/objects and edges are relationships (group membership,
  ACL rights, session data). It surfaces non-obvious paths — a helpdesk
  account with `GenericAll` on a target user is a privesc path nobody
  configured on purpose, which is exactly the class of risk it's built
  to find.
- **Detection engineering fundamentals**: a good rule states a precise
  correlation condition, documents its false-positive conditions, and
  is mapped to ATT&CK — not just "this looked suspicious."
- **The Windows logging trinity**: Sysmon Event ID 1 (process creation
  with full command line and parent/child relationships) + PowerShell
  ScriptBlockLogging + Event ID 4688 (process creation with command
  line, native Windows auditing) together give near-complete visibility
  into what actually ran and how.

## Conventions per TTP folder

Every `ttps/<ATT&CK-ID>-<short-name>/` directory follows the same shape:

```
<id>-<name>/
├── README.md         # objective, prerequisites, attacker narrative, cleanup
├── execute.(ps1|py)  # the attack script, annotated
├── sigma/<id>.yml     # Sigma detection rule
├── detection/          # Wazuh rule / KQL / SPL query used against the Sigma logic
└── evidence/            # screenshots + raw log excerpts captured from a real run
```

`evidence/` is gitignored by default (lab telemetry can contain
hostnames, usernames, internal IPs) — recorded screenshots are the
exception and should be redacted before committing.

## Safety / scope note

Everything in `ttps/` targets the lab's own `dc01`/`client01` only, on
the isolated `labnet`. Tools referenced (Impacket's `GetUserSPNs.py`,
`secretsdump.py`, `netexec`, `bloodhound.py`, `hashcat`) are standard,
publicly available offensive-security tooling used here strictly
against infrastructure you own, for detection-engineering purposes —
never point any of this at a network you don't have explicit
authorization to test.

## Adding a new TTP

1. Pick the next row above, create its folder from the template.
2. Run the attack against the live `client01`/`dc01` from the attacker host.
3. Capture the resulting Sysmon/Windows Event Log telemetry.
4. Write the Sigma rule against that telemetry (not from memory).
5. Convert it to a Wazuh rule (or KQL/SPL if you swap detection backends)
   and confirm it fires.
6. Screenshot the alert, redact, drop in `evidence/`, flip status to ✅ above.
