# T1003.006 — OS Credential Dumping: DCSync

## Objective

Demonstrate the end of the chain: once an account holding (or added to
a group holding) `Replicating Directory Changes` / `Replicating
Directory Changes All` is compromised — here, `jsmith`, reached via the
`helpdesk → GenericAll → jsmith` ACL abuse path surfaced by BloodHound —
impersonate a domain controller and pull every account hash in the
domain, including `krbtgt`.

## Why this works

AD replication between real domain controllers is implemented as a
**permission** over the DRSUAPI RPC interface, not a special
DC-only capability enforced by anything else. Any principal holding
`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` can
issue a replication request and the DC will answer it as if talking to
a peer DC — because, as far as the protocol is concerned, that's
exactly what's happening.

## Prerequisites

- `jsmith` compromised (password reset via the `helpdesk` ACL-abuse
  path — see `docs/attack-chain.md`)
- `jsmith` (directly or via `Tier1-Admins`) holds DCSync rights, granted
  in `ansible/files/deploy-ad.ps1` (the `dsacls` step)
- Directory Service Access/Changes auditing enabled on `dc01` (also done
  by `deploy-ad.ps1`)
- Impacket available on the attacker host

## Attacker narrative

1. `jsmith`'s password was reset via the `helpdesk` account's abused
   `GenericAll` right (separate ACL-abuse TTP, not scripted here — do it
   manually with `rpcclient` or Impacket's `net rpc password`/
   `Set-ADAccountPassword` from a `helpdesk`-authenticated session).
2. Attacker now holds valid `jsmith` creds, and `jsmith` has DCSync
   rights.
3. `secretsdump.py` run with `jsmith`'s creds triggers a DRSUAPI
   replication request against `dc01` — the DC complies, hashes
   (NTLM, and anything else `-just-dc` pulls) for every domain account
   come back.

## How to run

```bash
export DC_IP=192.168.50.10
export DOMAIN=lab.local
export COMPROMISED_USER=jsmith
export COMPROMISED_PASS='<the password jsmith was reset to>'
./execute.sh
```

See `execute.sh` for the exact `secretsdump.py` invocation and
timestamps.

## Cleanup

This is a read operation against AD — nothing to roll back on the
domain. Securely delete the dumped hashes on the attacker host:

```bash
shred -u dcsync-dump.ntds 2>/dev/null || rm -f dcsync-dump.ntds
```

If you changed `jsmith`'s password as part of the ACL-abuse step and
want the lab back to baseline, revert the VM snapshot taken before that
step rather than trying to manually undo the password change.

## Files

- `execute.sh` — `secretsdump.py` DCSync invocation, timestamped
- `../../detections/sigma/T1003.006-dcsync.yml` — detection rule (4662 with the replication GUIDs, from a non-DC)
- `../../detections/wazuh/T1003.006-dcsync.xml` — Wazuh custom rule
- `../../detections/queries/T1003.006-dcsync.md` — deployment steps + KQL/SPL equivalents
- `../../screenshots/` — evidence from a real run (add your own)
