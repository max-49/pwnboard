# Configuration Settings

Each setting can be set as an environment variable in docker-compose.yml. Below is all the
environment variables and their default settings.

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

this is an easter egg