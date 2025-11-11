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
┌─────────────────┐
│  Flask App      │
│  - Routes       │
│  - Auth         │
│  - Data Layer   │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌──────────┐
│ Redis  │ │ SQLite   │
│ (State)│ │ (Users)  │
└────────┘ └──────────┘
```

### Data Flow

1. **Beacons/Creds** → POST to `/checkin`, `/creds` endpoints
2. **Validation** → IP checked against `board.json` configuration (loaded into `IP_SET`)
3. **Storage** → Redis hashes store host state, callbacks, and credentials
4. **Rendering** → Dashboard pulls data from Redis, applies timeouts, generates HTML
5. **Caching** → Board HTML cached (configurable via `CACHE_TIME`) to reduce Redis load

### Technology Stack

- **Flask** — Web framework
- **Redis** — In-memory data store for host state and real-time data
- **SQLite** — User authentication database
- **Argon2** — Password hashing
- **Pandas** — Data aggregation for graphs
- **Jinja2** — HTML templating
- **Bootstrap** — UI framework for login page

## Local Development Setup

### Prerequisites

- Python 3.8+
- Redis server
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
   python3 pwnboard.py
   ```

7. **Access the app**
   - Open http://localhost:5000
   - Login: `admin` / `password` (defaults)

## Key Components

### Redis Data Structure

**Host callbacks:**
- Key: `{ip}:callbacks`
- Type: Hash
- Fields: `{application_name}` → JSON string
  ```json
  {
    "last_seen": 1234567890,
    "online": "True",
    "access_info": "..."
  }
  ```

**Host credentials:**
- Key: `{ip}:allcreds`
- Type: Hash
- Fields: `{username}` → JSON string
  ```json
  {
    "last_seen": 1234567890,
    "creds": "username:password",
    "admin": 0,
    "creds_online": "True"
  }
  ```

**Legacy single callback per host:**
- Key: `{ip}`
- Type: Hash
- Fields: `server`, `application`, `last_seen`, `message`, `online`, `access_type`

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
