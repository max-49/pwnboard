# PWNBoard Setup
Written by Massimo Marino (max-49)

## Deploying

Install the Docker engine using the instructions on the Docker website.

Docker makes deployment of the PWNBoard very very simple. See [docker-compose.yml](../docker-compose.yml) for a well-commented example of a docker-compose file with basic configuration options.

1. Create `.env` and `board.json`. The setup script prompts for the domain, admin password and Flask secret key, then launches the board generator:
```bash
python3 scripts/setup.py
```
You can also edit `.env` and run `scripts/gen_config.py` by hand; see the [README](../README.md#quick-start).

2. Deploy PWNBoard with the following command:
```bash
docker compose up -d
```

HTTPS is handled by Caddy (see [conf/reverse-proxy/Caddyfile](../conf/reverse-proxy/Caddyfile)), so you do not need to generate certificates. The dashboard is served at `https://<PWNBOARD_DOMAIN>` and Grafana at `https://<PWNBOARD_DOMAIN>:8443`.

## Resetting test data

Testing with `sim_callbacks.py` and `sim_creds.py` leaves fake callbacks and credentials in the database. Clear them before the real deployment using one of the options below.

### Keep users and access tokens

The worker image includes a reset command that deletes all callbacks, credentials, host information, callback history (what Grafana graphs) and the queued/cached board data in Redis, but keeps user accounts and access tokens:

```bash
docker compose stop pwnboard worker
```

```bash
docker compose run --rm --no-deps worker python -m pwnboard.worker.reset --yes
```

```bash
docker compose start pwnboard worker
```

- Stop `pwnboard` and `worker` first so nothing writes new data while the reset runs. The database and Redis containers must still be running (`--no-deps` does not start them).
- Without `--yes` the command prints a warning and deletes nothing.
- If Redis cannot be reached, the command stops before deleting anything.

### Full reset (also removes users and tokens)

To start from an empty database, remove the Postgres volume. The default admin account is recreated from `.env` on startup, so create your real users and tokens after resetting:

```bash
docker compose down && docker volume rm pwnboard_pwnboard-data && docker compose up -d
```

The volume is named `<project>_pwnboard-data`, where the project defaults to the directory name. Check with `docker volume ls` if yours differs. Do not use `docker compose down -v`: it also deletes the Caddy volumes, which hold your HTTPS certificates.

## Exporting and backing up data

Export what you need before you [reset the test data](#resetting-test-data) or remove the database volume.

Full backup of the database (users, tokens, callbacks, credentials):
```bash
docker compose exec -T db pg_dump -U pwnboard_user pwnboard_db > pwnboard-backup.sql
```

To restore it into an empty database (for example after a [full reset](#full-reset-also-removes-users-and-tokens)):
```bash
docker compose exec -T db psql -U pwnboard_user pwnboard_db < pwnboard-backup.sql
```

Callback history as CSV (one row per callback received, handy for reports):
```bash
docker compose exec -T db psql -U pwnboard_user -d pwnboard_db -c "COPY (SELECT received_at, team, ip, application, access_info FROM callback_events ORDER BY received_at) TO STDOUT WITH CSV HEADER" > callbacks.csv
```

Host information notes as CSV:
```bash
docker compose exec -T db psql -U pwnboard_user -d pwnboard_db -c "COPY (SELECT ip, info_key, info_value, application, updated_at FROM host_info ORDER BY ip, info_key) TO STDOUT WITH CSV HEADER" > host_info.csv
```

Captured credentials as CSV:
```bash
docker compose exec -T db psql -U pwnboard_user -d pwnboard_db -c "COPY (SELECT ip, username, password, server, to_timestamp(last_seen) AS last_seen FROM credentials_by_user ORDER BY ip, username) TO STDOUT WITH CSV HEADER" > credentials.csv
```

## Troubleshooting

### 1) Navbar shows wrong user/options (SHOULD BE FIXED NOW)
> **Issue:** Home page navbar may show the wrong logged-in user and incorrect account options. The session details are correct, this is only a visual bug.
>
> **Current workaround:** This should be working now. If it doesn't work and you need admin user management, go directly to `/manage_user_accounts` and open an issue on GitHub!

### 2) POST requests are not appearing
> **Issue:** Beacon/POST data is not showing up on PWNBoard.
>
> **Check the following:**
> - Confirm you are POSTing to the correct PWNBoard IP/URL.
> - Confirm the `ip` field matches an IP address present on PWNBoard (sometimes tools will return the wrong IP address depending on how you gather it)
> - Confirm the `application` field exactly matches your token's application name (if using Access Tokens).
> - If necessary, tokens with application name `global` will ignore the application name in the POST request, so you can use this token for everything

### 3) Self-signed certs and failed POST requests
> **Issue:** POST requests fail with a certificate error. This happens when `PWNBOARD_DOMAIN` is `localhost` or an IP address, or when `tls internal` is set in the Caddyfile, because Caddy signs the certificate with its own internal CA.
>
> **Fix:** Disable certificate validation in your client/tool (for example: `curl -k ...`, `requests.post("...", verify=False)`, etc.). Alternatively, copy Caddy's root certificate out of the container and trust it:

```bash
docker compose cp reverse-proxy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
curl --cacert caddy-root.crt https://<PWNBOARD_DOMAIN>/pwn ...
```

### 4) Build hangs while installing packages on PWNBoard container (development deploy, ghcr container should not have this issue)

> Find networking interface using `ip a`. Check MTU of interface using `ip link show <interface>` and note the number next to `mtu`. Then run the following command and note the container MTU.

```bash
docker run --rm alpine sh -c "ip link show eth0"
```

> If this MTU is greater than the host MTU, lower the default Docker networking MTU by running the following commands:

```bash
cat <<EOF > /etc/docker/daemon.json
{
  "mtu": 1400
}
EOF
systemctl restart docker
```

> Then you can rebuild the container

```bash
docker compose build --no-cache
docker compose up -d
```

### 5) Any error that says "disk quota exceeded"

> Try to increase the amount of space on whichever disk partition you are working on

### 6) Caddy cannot get a certificate for my domain

> **Issue:** The browser reports a certificate error or cannot connect, and `docker compose logs reverse-proxy` shows ACME/Let's Encrypt failures.
>
> **Check the following:**
> - `PWNBOARD_DOMAIN` in `.env` is only the hostname (ex. `pwnboard.win`), with no `https://` and no port.
> - The domain's DNS record points at this host, and ports 80 and 443 are reachable from the internet (Let's Encrypt validates over them).
> - If the name only resolves on a private network, Let's Encrypt can never validate it. Add `tls internal` inside both site blocks of `conf/reverse-proxy/Caddyfile`, then run `docker compose up -d` again. Clients will then need to skip validation or trust Caddy's root certificate (see issue 3).

### 7) "Too many failed login attempts"

> **Issue:** The login page says "Too many failed login attempts. Try again in 15 minutes."
>
> **Cause:** After 10 failed logins from one IP address, or 20 for one username, logins from that IP or for that username are blocked for 15 minutes. A successful login clears the username's count.
>
> **Fix:** Wait 15 minutes, or clear the counters:

```bash
docker compose exec redis sh -c "redis-cli --scan --pattern 'login_fail:*' | xargs -r redis-cli del"
```
