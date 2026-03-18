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

## Features

- There are a lot of features (They will be listed here soon)

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

1. **Configure environment** (edit `docker-compose.yml` or create `.env`):
   ```bash
   export PWNBOARD_URL="http://your-domain.com:8080"
   export PWNBOARD_PORT=8080
   export SECRET_KEY="your-secret-key-here"
   export DEFAULT_USER_PASSWORD="strong-password"
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

4. **Access the dashboard**:
   - Navigate to `https://your-domain.com/`
   - Login with default credentials

For detailed setup instructions and troubleshooting, see [doc/setup.md](doc/setup.md).

## Configuration

PWNBoard is configured via environment variables, set in `docker-compose.yml`.

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret` | Flask secret key for sessions (**please change**) |
| `DEFAULT_USER` | `admin` | Default admin username |
| `DEFAULT_USER_PASSWORD` | `password` | Default admin password |
| `PWNBOARD_URL` | — | Base URL for your deployment (e.g., `https://pwnboard.example.com:8080`) |
| `HOST_TIMEOUT` | `2` | Minutes before host marked offline |
| `CREDS_TIMEOUT` | `30` | Minutes before credentials marked stale |
| `PWN_THEME` | `blue` | Color theme: `blue` (red=active) or `green` (green=active) |
| `CACHE_TIME` | `-1` | Board cache seconds (-1 = disabled) |
| `LOGIN_PAGE_MESSAGE` | `Contact an admin to get an account!` | Message that shows on the login page by default

For a complete list of configuration options, see [doc/config.md](doc/config.md).

## Using PWNBoard


## Documentation

- **[Setup Guide](doc/setup.md)** — Detailed deployment instructions and troubleshooting
- **[Configuration Reference](doc/config.md)** — Complete environment variable reference
- **[Development Guide](doc/DEVELOPMENT.md)** — Architecture, file structure, and contribution guidelines

## Acknowledgements

This project builds upon the work of:
- **[ztgrace/pwnboard](https://github.com/ztgrace/pwnboard)** — Original pwnboard implementation
- **[nullmonk/pwnboard](https://github.com/nullmonk/pwnboard)** — Improvements for RIT Red Team
- **[RITRedteam/Topology-Generator](https://github.com/RITRedteam/Topology-Generator)** — Topology generation tool

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Test thoroughly
5. Submit a Pull Request

See [doc/DEVELOPMENT.md](doc/DEVELOPMENT.md) for detailed contribution guidelines.

## Troubleshooting/Known Issues
**ISSUE:** Visual bug on home page showing incorrect user on navbar + incorrect options for current logged in user
**SOLUTION:** No solution as of this commit, if you need to access user account management page as an admin user, go to `/manage_user_accounts`

**ISSUE:** Alpine Docker container hangs on package installation
**SOLUTION:** Diagnose your own networking issues by creating your own Alpine docker container and trying to install packages using apk. If Alpine isn't working, you can try swapping Alpine for debian:slim and changing apk to apt

**ISSUE:** My POST requests are not appearing on PWNBoard
**SOLUTION:** Ensure the IP address you are POSTing to PWNBoard is correct and ensure the application field value matches your token application name. An access token with the application name "global" will accept POST requests from any application name, but it is not recommended you use this.

## License

This project inherits the licensing from its upstream repositories. See original projects for specific license terms.

---

**Questions or Issues?** Open an issue on GitHub.