# T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

## Objective

Request a service ticket (TGS) for the lab's `svc-sql` account (created
with a deliberately weak password and an SPN in
`ansible/files/deploy-ad.ps1` / `ansible/playbooks/promote-dc.yml`),
then crack it offline — demonstrating why SPN accounts need strong,
randomly generated passwords regardless of how obscure the service is.

## Why this works

Any authenticated domain user can request a TGS for **any** SPN — that
request is a normal, legitimate Kerberos operation (TGS-REQ/TGS-REP),
not a vulnerability by itself. The ticket returned is encrypted with
the *service account's* NTLM hash. If that password is weak, the hash
cracks offline, with zero further interaction with the domain — this is
what makes it quiet and hard to prevent purely through monitoring
logon failures (there are none).

## Prerequisites

- `client01` domain-joined, attacker has valid (even low-priv) domain creds
- `svc-sql` account exists with SPN `MSSQLSvc/dc01.lab.local:1433`
- Kerberos auditing enabled on `dc01` (done by `deploy-ad.ps1`)
- Impacket and hashcat available on the attacker host (Kali)

## Attacker narrative

1. Attacker has low-privilege domain creds from the T1566.001 foothold
   (or any valid account — this needs no special rights).
2. Enumerate SPN accounts: `GetUserSPNs.py` lists every account with an
   SPN set, i.e. every roastable target.
3. Request and dump their TGS tickets in crackable (hashcat) format.
4. Crack offline — no further contact with the domain, no lockout risk.

## How to run

From the attacker host (Kali), against the lab domain only:

```bash
# 1. Enumerate + dump roastable tickets (requires any valid domain creds)
impacket-GetUserSPNs lab.local/attacker-user:'AttackerPass123' \
  -dc-ip 192.168.50.10 -request -outputfile svc-sql.hashes

# 2. Crack offline (mode 13100 = Kerberos 5 TGS-REP etype 23)
hashcat -m 13100 svc-sql.hashes /usr/share/wordlists/rockyou.txt
```

See `execute.sh` for the same two commands wrapped with timestamps, so
the run lines up cleanly with what you'll see in the Sysmon/Wazuh
timeline when reviewing the alert.

## Cleanup

Nothing persists on the domain — this is a read-only Kerberos operation.
Just remove the local hash/crack output on the attacker host:

```bash
rm -f svc-sql.hashes svc-sql.cracked
```

## Files

- `execute.sh` — enumeration + TGS request + crack, with timestamps
- `../../detections/sigma/T1558.003-kerberoasting.yml` — detection rule (RC4 TGS request for an SPN account)
- `../../detections/wazuh/T1558.003-kerberoasting.xml` — Wazuh custom rule
- `../../detections/queries/T1558.003-kerberoasting.md` — deployment steps + KQL/SPL equivalents
- `../../screenshots/` — evidence from a real run (add your own)
