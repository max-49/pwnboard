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

- Ensure the Docker Engine is installed on your machine

### Board Setup

PWNBoard requires a topology configuration to define teams and hosts. Generate your board configuration using the included Topology Generator:

1. **Create a board file** using `gen_config.py`:
   ```bash
   python3 scripts/gen_config.py
   ```

Follow the steps in the script to define your hosts. This will generate a `board.json` in the project root, necessary for PWNBoard to deploy correctly.

### Environment Setup

1. **Configure environment** (edit `docker-compose.yml`):
   ```yaml
   - SECRET_KEY=change-me-please # CHANGE THIS TO SOMETHING ELSE BEFORE DEPLOYING
   - PWNBOARD_URL=https://pwnboard.win # Change this line to your full PWNBoard URL (https://domain[:port], ex. https://pwnboard.win, https://10.1.1.10:443). This is used in certificate generation
   - CACHE_TIME=-1 # Change this to a positive value to cache the board JSON for a certain amount of time. Might help with performance
   - REFRESH_SECONDS=10 # Change this to the amount of time (in seconds) after which you want your page to refresh with new data. Setting this to 0 or -1 will disable refreshing
   - HOST_TIMEOUT=5 # Change this to the amount of time (in minutes) after which callbacks should time out if an update is not received
   - CREDS_TIMEOUT=30 # Change this to the amount of time (in minutes) after which credentials should time out if an update is not received
   - POSTGRES_PASSWORD=password # Database user password (if you change this, also change the variable in the db service)
   - DEFAULT_USER=admin # Change this to be your default admin user
   - DEFAULT_USER_PASSWORD=password # Change this to be your default admin password (can be changed later in the GUI)
   - LOGIN_PAGE_MESSAGE=Contact an admin to get an account! # Change this if you want your welcome message on the home page to be different
   - USE_ACCESS_TOKENS=true # SET THIS TO FALSE IF YOU DO NOT WANT TO USE ACCESS TOKENS 
   ```

2. **Set up HTTPS certificates**:
If using a domain that you own (ex. pwnboard.win, pwnboard.red.team, etc.), run this command to generate letsencrypt certificates for your domain.
   ```bash
   cd scripts
   sudo ./setup_certs_letsencrypt.sh
   ```

If using only internally resolvable DNS or just your IP address to access PWNboard, run this command to generate self signed certificates. Keep in mind that you might have to jump through some extra hoops to POST data "insecurely".
   ```bash
   cd scripts
   sudo ./setup_certs_self_signed.sh
   ```

### Deploy

1. **Start PWNBoard with Docker Compose**:
   ```bash
   docker compose up -d
   ```

2. **Access the dashboard**:
   - Navigate to `PWNBOARD_URL` in your browser
   - Login with default credentials set up in environment variables!

For detailed setup instructions and troubleshooting, see [doc/setup.md](doc/setup.md).

### Key Environment Variables

For a complete list of configuration options, see [doc/config.md](doc/config.md).

## Using PWNBoard

See the [usage guide](doc/usage.md) for detailed instructions on how to send data to PWNBoard!

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

For troubleshooting tips, check the bottom of the [setup guide](doc/setup.md).

## Feature Wishlist

To view the PWNBoard feature wishlist, please navigate to the [Issues](https://github.com/max-49/pwnboard/issues) tab on GitHub and look for issues that start with `FEATURE REQUEST`!

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Test thoroughly
5. Submit a Pull Request

See [doc/development.md](doc/development.md) for detailed contribution guidelines.

## Acknowledgements

This project builds upon the work of:
- **[ztgrace/pwnboard](https://github.com/ztgrace/pwnboard)** — Original PWNboard
- **[nullmonk/pwnboard](https://github.com/nullmonk/pwnboard)** — Improvements for RIT Red Team
- **[RITRedteam/Topology-Generator](https://github.com/RITRedteam/Topology-Generator)** — Topology generation tool

## License

This project inherits the licensing from its upstream repositories. See original projects for specific license terms.

---

**Questions or Issues?** Open an issue on GitHub.
