# Development Guide

Guide for developers contributing to or extending PWNboard.

## Table of Contents

- [Architecture](#architecture)
- [Local Development Setup](#local-development-setup)
- [Key Components](#key-components)
- [Testing](#testing)
- [Contributing](#contributing)

## Architecture

### High-Level Overview

```
┌─────────────────┐
│   C2 / Tools    │  ← POST beacons/creds
└────────┬────────┘
         │
         ▼
┌─────────────────┐        ┌─────────────────┐
│  Web (Flask)    │ ─────▶ │  Redis          │
│  - Routes       │ queue  │  - callback_    │
│  - Auth         │        │    queue        │
│  - Dashboard    │ ◀───── │  - creds_queue  │
└────────┬────────┘ cache  │  - board_cache  │
         │                 └────────┬────────┘
         │ users, tokens            │
         ▼                          ▼
┌─────────────────┐        ┌─────────────────┐
│  PostgreSQL DB  │ ◀───── │  Worker         │
│  - Users        │ batch  │  - Ingest queue │
│  - Callbacks    │ writes │  - Build board  │
│  - Tokens       │        │    cache        │
└─────────────────┘        └─────────────────┘
```

The web app and the worker are separate containers built from separate targets of the same
`Dockerfile`. Shared code lives in `pwnboard/core/` and must not import Flask.

### Project Layout

```
pwnboard/
  core/     Shared by web and worker: Postgres pool, schema, Redis queues, board.json loading,
            board state queries (no Flask)
  web/      Flask app: routes, endpoints, authentication, templates, static files
  worker/   Redis queue ingestion and board cache builder (run with `python -m pwnboard.worker`)
```

### Data Flow

1. **Beacons/Creds** → POST to `/pwn`, `/creds` endpoints
2. **Validation** → IP checked against `board.json` configuration (loaded into `IP_SET`)
3. **Queueing** → The web app pushes the payload onto a Redis list and returns immediately
4. **Storage** → The worker pops batches from Redis and writes host state, callbacks, and credentials to PostgreSQL
5. **Caching** → After each batch (and at least every 15 seconds) the worker rebuilds the board, applying timeouts, and stores it in Redis as `board_cache`
6. **Rendering** → The dashboard renders the cached board as HTML. If the cache is empty it builds the board from Postgres directly

### Technology Stack

- **Flask** — Web framework
- **PostgreSQL** — Database
- **Redis** — Callback/credential queues and the board cache
- **Argon2** — Password hashing
- **Jinja2** — HTML templating
- **Bootstrap** — UI framework for login page

## Local Development Setup

### Prerequisites

- Python 3.8+
- PostgreSQL server
- Git

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/max-49/pwnboard.git
   cd pwnboard
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate.ps1
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Start Redis**
   ```bash
   # Using Docker (recommended)
   docker run -d -p 6379:6379 --name pwnboard-redis redis:alpine
   
   # Or install locally
   # Ubuntu/Debian: sudo apt install redis-server && redis-server
   # macOS: brew install redis && redis-server
   ```

5. **Create board.json**
   ```bash
   cd Topology-Generator
   python3 generator.py
   cd ..
   python3 scripts/gen_config.py Topology-Generator/topology.json board.json
   ```

6. **Run in debug mode**
   ```bash
   export FLASK_DEBUG=true
   export FLASK_PORT=5000
   export SECRET_KEY=dev-secret-change-in-production
   export POSTGRES_HOST=localhost REDIS_HOST=localhost
   python3 -m pwnboard.web
   ```

   Beacons are only written to Postgres by the worker, so also run it in a second terminal
   (with the same `POSTGRES_HOST` and `REDIS_HOST`):
   ```bash
   python3 -m pwnboard.worker
   ```

7. **Access the app**
   - Open http://localhost:5000
   - Login: `admin` / `password` (defaults)

## Local Docker Development Without Pulling from GHCR

When testing local uncommitted changes, use the development override file so Docker builds both the web and worker images from your working tree and never pulls the `ghcr.io` images:

```bash
docker compose -f docker-compose.yml -f scripts/docker-compose.dev.yml up --build -d
```

This keeps `docker-compose.yml` suitable for quick deployment while `docker-compose.dev.yml` forces local image use during development.

## Key Components

### Redis Keys

Defined in `pwnboard/core/queues.py`.

| Key | Type | Written by | Read by |
|-----|------|-----------|---------|
| `callback_queue` | List of JSON beacons (`LPUSH`) | Web (`/pwn`, `/checkin`) | Worker (`RPOP`, up to 500 at a time) |
| `creds_queue` | List of JSON credential reports (`LPUSH`) | Web (`/creds`) | Worker (`RPOP`, up to 500 at a time) |
| `board_cache` | String, JSON board | Worker | Web dashboard |

## Testing

### Manual Testing

**Test beacon submission:**
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.5", "application":"test", "access_type":"http"}' \
  http://localhost:5000/pwn
```

**Test credential submission:**
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.5","username":"admin","password":"test"}' \
  http://localhost:5000/creds
```

### Simulating Beacons

Use the included simulation script:
```bash
python3 scripts/sim_callbacks.py
```

This will POST random beacons to configured hosts.

## Contributing

### Workflow

1. **Fork the repository** on GitHub
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```
3. **Make your changes**
4. **Test thoroughly** (see Testing section)
5. **Commit with clear messages**:
   ```bash
   git commit -m "Add feature: brief description"
   ```
6. **Push to your fork**:
   ```bash
   git push origin feature/my-new-feature
   ```
7. **Open a Pull Request** on GitHub

### PR Guidelines

- Keep changes focused (one feature/fix per PR)
- Update documentation if adding features or changing behavior
- Add examples for new API endpoints
- Test with both SQLite and production-like setups
- Update `doc/config.md` if adding environment variables

---

For questions or help, open an issue on GitHub!
