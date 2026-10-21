# Configuration Settings

Each setting can be set as an environment variable in docker-compose.yml. Below is all the
environment variables and their default settings.

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-please` | Flask secret key for sessions (**please change**) |
| `DEFAULT_USER` | `admin` | Default admin username |
| `DEFAULT_USER_PASSWORD` | `password` | Default admin password |
| `PWNBOARD_DOMAIN` | `localhost` | Hostname or IP PWNBoard is served on, without `https://` or a port (set in `.env`; read by `docker-compose.yml` and the Caddyfile, not by the app) |
| `HOST_TIMEOUT` | `2` | Minutes before host marked offline |
| `CREDS_TIMEOUT` | `30` | Minutes before credentials marked stale |
| `PWN_THEME` | `blue` | Color theme: `blue` (red=active) or `green` (green=active) |
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