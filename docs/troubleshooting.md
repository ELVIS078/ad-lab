# Runbook / Pièges connus

Notes issues du déploiement réel de ce lab, pour éviter de perdre du temps
sur des blocages déjà rencontrés et résolus.

## DNS : ne pas casser la résolution du domaine

Un contrôleur de domaine doit résoudre son propre domaine via son propre
service DNS (en général `127.0.0.1`). Le pointer temporairement vers un
DNS public (8.8.8.8) pour télécharger un fichier externe (ex: l'agent
Wazuh) fonctionne, mais casse Active Directory tant que le changement
n'est pas annulé.

```powershell
# Pour débloquer temporairement une résolution externe
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8,1.1.1.1
Clear-DnsClientCache

# À remettre IMMÉDIATEMENT après usage
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
Clear-DnsClientCache
```

## Wazuh : agent visible mais aucune alerte dans le dashboard

Symptôme : l'agent apparaît "Active" dans Endpoints Summary, mais Discover /
Threat Hunting affiche "No template found for the selected index-pattern
title [wazuh-alerts-*]".

Cause : désynchronisation entre le mot de passe de l'indexer OpenSearch et
celui que Filebeat (dans le conteneur du manager) utilise pour s'y connecter.

Diagnostic :
```bash
docker compose exec wazuh.manager filebeat test output
# ERROR 401 Unauthorized = mots de passe désynchronisés
```

Correction :
```bash
# Aligner INDEXER_PASSWORD dans docker-compose.yml sur le vrai mot de passe
sed -i 's/INDEXER_PASSWORD=.*/INDEXER_PASSWORD=<vrai_mot_de_passe>/' docker-compose.yml
docker compose up -d --force-recreate wazuh.manager
```

## Comptes AD qui refusent toute authentification malgré un mot de passe "correct"

Symptôme : `Enabled: True`, `LockedOut: False`, mais toute authentification
(SMB, LDAP) échoue avec `STATUS_LOGON_FAILURE` / `data 52e`.

Cause possible : décalage clavier AZERTY/QWERTY lors de la saisie manuelle
d'un mot de passe contenant des caractères spéciaux (`_`, `!`) directement
dans la console de la VM.

Diagnostic fiable (à exécuter sur le DC, pas via un outil externe) :
```powershell
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
    [System.DirectoryServices.AccountManagement.ContextType]::Domain, "lab.local")
$ctx.ValidateCredentials("<user>", "<mot_de_passe_supposé>")
# False = le mot de passe stocké diffère de ce qui a été saisi
```

Correction : redéfinir le mot de passe en évitant les caractères sensibles
au layout clavier, ou coller la commande plutôt que la taper à la main.

## Noms de paquets/commandes sur Kali

Les noms "intuitifs" ne sont pas toujours les bons sur Kali :

| Outil         | Nom du paquet apt     | Commande réelle           |
|---------------|------------------------|----------------------------|
| Impacket      | impacket-scripts       | impacket-GetUserSPNs, impacket-GetNPUsers, etc. |
| BloodHound.py | bloodhound.py          | bloodhound-python          |
| NetExec       | netexec                | netexec ou nxc (selon version) |

## rockyou.txt absent

La wordlist par défaut n'est pas toujours décompressée sur une install Kali fraîche :
```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```
