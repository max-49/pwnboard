# Configuration Settings

Each setting can be set as an environment variable in docker-compose.yml. Below is all the
environment variables and their default settings.

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-please` | Flask secret key for sessions (**please change**). Logins are cookies signed with it, so changing it logs everyone out. Change it whenever you wipe the database, or users who were logged in stay logged in |
| `DEFAULT_USER` | `admin` | Default admin username |
| `DEFAULT_USER_PASSWORD` | `password` | Default admin password |
| `PWNBOARD_DOMAIN` | `localhost` | Hostname or IP PWNBoard is served on, without `https://` or a port (set in `.env`; read by `docker-compose.yml` and the Caddyfile, not by the app) |
| `HOST_TIMEOUT` | `5` | Minutes without a callback before a host is shown as offline. Set it in `.env`; `docker-compose.yml` passes it to both the web app and the worker, which must agree |
| `CREDS_TIMEOUT` | `30` | Minutes without new credentials before they are marked stale. Stale credentials stay listed in the host's popup. Set it in `.env`; passed to both the web app and the worker |
| `PWN_THEME` | `blue` | Color theme: `blue` (red=active) or `green` (green=active) |
| `PWNBOARD_LOG_LEVEL` | `INFO` | Log level for the web app and worker (`DEBUG`, `INFO`, `WARNING`, ...) |
| `GRAFANA_DB_PASSWORD` | `PWNBOARD_PASSWORD` | Password of the read-only database user Grafana connects with (set in `.env`; `scripts/setup.py` generates one). Avoid single quotes in it |
| `LOGIN_PAGE_MESSAGE` | `Contact an admin to get an account!` | Message that shows on the login page by default
| `USE_ACCESS_TOKENS` | `true` | Use access tokens for POST authentication
| `POSTGRES_HOST` | `db` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `pwnboard_db` | PostgreSQL database name |
| `POSTGRES_USER` | `pwnboard_user` | PostgreSQL username |
| `POSTGRES_PASSWORD` | `password` | PostgreSQL password |
| `DATABASE_URL` | — | Optional full DSN override (`postgres://user:pass@host:5432/dbname`) |
| `REDIS_HOST` | `redis` | Redis host (used by both the web app and the worker) |
| `REDIS_PORT` | `6379` | Redis port |

this is an easter egg