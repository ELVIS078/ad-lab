# ad-lab

Home adversary lab reproducing a realistic Active Directory intrusion
chain end-to-end: **execute → detect → document**. Every technique ships
as `script → Sigma rule → Wazuh rule / KQL / SPL → screenshot evidence`,
mapped to [MITRE ATT&CK](https://attack.mitre.org/).

> **Resource note.** Scoped for a single host with ~8GB RAM — see
> `docs/architecture.md`. VMs run sequentially, not all at once.

## Repo layout

```
ad-lab/
├── infrastructure/
│   ├── vagrant/            # Vagrantfile (dc01 + client01, libvirt)
│   ├── ansible/             # playbooks, roles, inventory, deploy-ad.ps1
│   └── wazuh/                # README + low-mem override for the official wazuh-docker stack
├── attacks/
│   ├── T1566.001-phishing-macro/
│   ├── T1558.003-kerberoasting/
│   └── T1003.006-dcsync/
│       ├── README.md        # objective, prerequisites, how to run
│       └── execute.(ps1|sh) # the attack script
├── detections/
│   ├── sigma/                # one Sigma rule per TTP
│   ├── wazuh/                 # Wazuh custom rule XML per TTP
│   └── queries/                # KQL/SPL reference + validation steps per TTP
├── docs/
│   ├── architecture.md       # diagram + design rationale
│   └── attack-chain.md       # full ATT&CK mapping, kill chain narrative
└── screenshots/                # evidence captures (gitignored raw logs, keep redacted images)
```

## Status

- ✅ **T1566.001** — Phishing: spearphishing via macro
- ✅ **T1558.003** — Kerberoasting
- ✅ **T1003.006** — DCSync
- 🔲 Discovery (BloodHound enum), AS-REP roasting, ACL-abuse privesc — planned, see `docs/attack-chain.md`

## Quickstart

```bash
# 1. Bring up the DC only first (client needs it to join the domain)
cd infrastructure/vagrant && vagrant up dc01
# (or: build dc01 by hand in virt-manager, then run
#  infrastructure/ansible/files/deploy-ad.ps1 on it directly)

# 2. Provision AD (creates the domain + the vulnerable-by-design test
#    accounts the attack chain targets: svc-sql, backup-svc, helpdesk/jsmith)
ansible-playbook -i ../ansible/inventory.ini ../ansible/playbooks/promote-dc.yml

# 3. Bring up client01 and join it to the domain
vagrant up client01
ansible-playbook -i ../ansible/inventory.ini ../ansible/playbooks/join-domain.yml

# 4. Install Sysmon + Wazuh agent on both (telemetry pipeline)
ansible-playbook -i ../ansible/inventory.ini ../ansible/playbooks/site.yml

# 5. Start the detection stack only when ready to capture evidence
#    (see infrastructure/wazuh/README.md)
```

Full walkthrough for each TTP lives in `attacks/<id>/README.md`.

## Disclaimer

Everything here runs in an isolated, non-production lab you own. Scripts
simulate known, publicly documented techniques for detection-engineering
and training purposes. Do not run any of this against systems you don't
own or have explicit authorization to test.
