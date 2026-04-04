# PWNBoard

**PWNBoard** is a real-time web dashboard for tracking and visualizing beacons from offensive security tools and Command & Control (C2) frameworks during red team engagements and competitions.

![GitHub](https://img.shields.io/github/license/max-49/pwnboard)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-latest-green.svg)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Acknowledgements](#acknowledgements)

## Overview

PWNBoard provides a centralized dashboard for tracking compromised hosts, active beacons, and harvested credentials across multiple teams during red team operations. This fork enhances the original [ztgrace/pwnboard](https://github.com/ztgrace/pwnboard) and [nullmonk/pwnboard](https://github.com/nullmonk/pwnboard) projects with a lot of really cool features (trust)

![PWNBoard](doc/img/pwnboard.png)

## Features

- Track active Red Team beacons and captured credentials in a visual dashboard
- Optional tool authentication through access tokens
- Easily manage multiple red teamers with RBAC features
- Quick containerized deploy using Docker

## Quick Start

### Prerequisites

- Ensure Docker is installed (see Docker documentation for installation instructions)
- A `board.json` configuration file (see [Board Setup](#board-setup))

### Board Setup

PWNBoard requires a topology configuration to define teams and target hosts. Generate your board configuration using the included Topology Generator:

1. **Create a topology** using `Topology-Generator/generator.py`:
   ```bash
   cd Topology-Generator
   python3 generator.py
   ```
   Follow the prompts to define your teams and hosts. This creates `topology.json`.

2. **Convert topology to board format**:
   ```bash
   # From project root
   python3 scripts/gen_config.py Topology-Generator/topology.json board.json
   ```

This generates `board.json` in the project root, which defines which IP addresses can submit beacons.

### Deployment (Docker Compose)

**Docker Compose is the recommended deployment method.**

1. **Configure environment** (edit `docker-compose.yml`):
   ```yaml
   - SECRET_KEY=change-me-please # PLEASE CHANGE THIS TO SOMETHING ELSE BEFORE DEPLOYING
   - PWNBOARD_URL=https://pwnboard.win # Change this line to your full PWNBoard URL (https://domain[:port], ex. https://pwnboard.win, https://10.1.1.10:443)
   - CACHE_TIME=-1 # Change this to a positive value to cache the board JSON for a certain amount of time. Might help with performance
   - HOST_TIMEOUT=5 # Change this to the amount of time (in minutes) after which callbacks should time out if an update is not received
   - CREDS_TIMEOUT=30 # Change this to the amount of time (in minutes) after which credentials should time out if an update is not received
   - POSTGRES_HOST=db # PostgreSQL host (docker compose service name)
   - POSTGRES_PORT=5432 # PostgreSQL port
   - POSTGRES_DB=pwnboard_db # Database name
   - POSTGRES_USER=pwnboard_user # Database user
   - POSTGRES_PASSWORD=password # Database password
   - DEFAULT_USER=admin # Change this to be your default admin user
   - DEFAULT_USER_PASSWORD=password # Change this to be your default admin password (can be changed later in the GUI)
   - LOGIN_PAGE_MESSAGE=Contact an admin to get an account! # Change this if you want your welcome message on the home page to be different
   - USE_ACCESS_TOKENS=true # SET THIS TO FALSE IF YOU DO NOT WANT TO USE ACCESS TOKENS 
   ```

2. **Set up HTTPS with certificiates**:
   ```bash
   cd scripts
   sudo ./setup_certs_letsencrypt.sh
   ```

   ```bash
   cd scripts
   sudo ./setup_certs_self_signed.sh
   ```

3. **Deploy**:
   ```bash
   docker compose up -d
   ```

### Local Development Without Pulling from GHCR

When testing local uncommitted changes, use the development override file so Docker builds from your working tree and never pulls the `ghcr.io` image for `pwnboard`:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d
```

This keeps `docker-compose.yml` suitable for quick deployment while `docker-compose.dev.yml` forces local image use during development.

4. **Access the dashboard**:
   - Navigate to `PWNBOARD_URL`
   - Login with default credentials set up in environment variables

For detailed setup instructions and troubleshooting, see [doc/setup.md](doc/setup.md).

## Configuration

PWNBoard is configured via environment variables, set in `docker-compose.yml`.

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-please` | Flask secret key for sessions (**please change**) |
| `DEFAULT_USER` | `admin` | Default admin username |
| `DEFAULT_USER_PASSWORD` | `password` | Default admin password |
| `PWNBOARD_URL` | — | Base URL for your deployment (e.g., `https://pwnboard.example.com:8080`) |
| `HOST_TIMEOUT` | `2` | Minutes before host marked offline |
| `CREDS_TIMEOUT` | `30` | Minutes before credentials marked stale |
| `PWN_THEME` | `blue` | Color theme: `blue` (red=active) or `green` (green=active) |
| `CACHE_TIME` | `-1` | Board cache seconds (-1 = disabled) |
| `LOGIN_PAGE_MESSAGE` | `Contact an admin to get an account!` | Message that shows on the login page by default
| `USE_ACCESS_TOKENS` | `true` | Use access tokens for POST authentication
| `POSTGRES_HOST` | `db` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `pwnboard_db` | PostgreSQL database name |
| `POSTGRES_USER` | `pwnboard_user` | PostgreSQL username |
| `POSTGRES_PASSWORD` | `password` | PostgreSQL password |
| `DATABASE_URL` | — | Optional full DSN override (`postgres://user:pass@host:5432/dbname`) |

For a complete list of configuration options, see [doc/config.md](doc/config.md).

## Using PWNBoard

See the [usage guide](doc/usage.md) for detailed instructions on how to actually use PWNBoard!

## Documentation

- **[Setup Guide](doc/setup.md)** — Detailed deployment instructions and troubleshooting
- **[Configuration Reference](doc/config.md)** — Complete environment variable reference
- **[Development Guide](doc/development.md)** — Architecture, file structure, and contribution guidelines

## Testing your PWNBoard deployment

The [sim_callbacks](scripts/sim_callbacks.py) testing tool can be used to test your PWNBoard deployment
1. Log into PWNBoard

2. If `USE_ACCESS_TOKENS=true`, create an access token at `/manage_apps` with the application name `global` and copy it. If you don't want to input it into the script, you can configure an environment variable `ACCESS_TOKEN` on your local machine.

3. Run the Python script
```bash
python3 scripts/sim_callbacks.py [/path/to/board/file]
```

4. If board file was not specified, follow the script instructions to set up IP addresses to POST to

5. Include your `global` Access Token when prompted (if using access tokens)

6. Include the full POST endpoint URL of your PWNBoard (ex. https://www.pwnboard.win/pwn, https://10.1.1.11:8443/pwn)

## Troubleshooting/Known Issues

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

For more troubleshooting tips, check the bottom of the [setup guide](doc/setup.md).

## Feature Wishlist

To view the PWNBoard feature wishlist, please navigate to the [Issues](https://github.com/max-49/pwnboard/issues) tab on GitHub and look for issues that start with `FEATURE REQUEST`!

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Test thoroughly
5. Submit a Pull Request

See [doc/DEVELOPMENT.md](doc/DEVELOPMENT.md) for detailed contribution guidelines.

## Acknowledgements

This project builds upon the work of:
- **[ztgrace/pwnboard](https://github.com/ztgrace/pwnboard)** — Original pwnboard implementation
- **[nullmonk/pwnboard](https://github.com/nullmonk/pwnboard)** — Improvements for RIT Red Team
- **[RITRedteam/Topology-Generator](https://github.com/RITRedteam/Topology-Generator)** — Topology generation tool

## License

This project inherits the licensing from its upstream repositories. See original projects for specific license terms.

---

**Questions or Issues?** Open an issue on GitHub.
