# PWNBoard Setup
Written by Massimo Marino (max-49)

## Deploying

Install the Docker engine using the instructions on the Docker website.

Docker makes deployment of the PWNBoard very very simple. See [docker-compose.yml](../docker-compose.yml) for a well-commented example of a docker-compose file with basic configuration options.

You can deploy PWNBoard with the following command:
```bash
docker compose up -d
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
> **Issue:** POST requests fail when using self-signed certificates.
>
> **Fix:** Disable certificate validation in your client/tool (for example: `curl -k ...`, `requests.post("...", verify=False)`, etc.).

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


