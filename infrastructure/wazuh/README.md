# Wazuh deployment (single-node docker, v4.9.1)

## Deploy
git clone --depth 1 -b v4.9.1 https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
sysctl -w vm.max_map_count=262144   # (once, add to /etc/sysctl.conf to persist)
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d

## Admin credentials
Set via config/wazuh_indexer/internal_users.yml (bcrypt hash via htpasswd).
NOTE: config security is persisted in the indexer volume on first boot —
changing it requires `docker compose down -v` (wipes data volumes).

## Known issues hit during setup
- curl -sO on nonexistent paths silently saves the 404 body — verify with `head -5` or use curl -f
- bcrypt hash must have NO trailing spaces inside quotes
