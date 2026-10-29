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
## board.json

`board.json` lists the teams and the machines, and says how each machine's address is made from the team number. `scripts/setup.py` creates it for you by running `scripts/gen_config.py`. You can also write or edit it by hand:

```json
{
  "version": 2,
  "teams": [1, 2, 5],
  "machines": [
    {"name": "DC01", "ip": "10.x.1.10"},
    {"name": "Web",  "ip": "10.x.1.20", "skip": [5]},
    {"name": "Mail", "ip": "10.x.1.30", "ips": {"2": "10.2.9.30"}}
  ]
}
```

- `teams` sets the columns and `machines` the rows, in the order they are listed. Team numbers are whole numbers and do not have to be consecutive.
- `ip` is a pattern: every `x` is replaced by the team number. `10.x.1.10` is `10.1.1.10` for team 1 and `10.5.1.10` for team 5. A machine appears in every team's column.
- `skip` (optional) lists teams that have no host for this machine. Their cell is shown blank. In the example, `Web` has no team 5 host.
- `ips` (optional) gives the address of a team whose host does not follow the pattern. In the example, team 2's `Mail` is `10.2.9.30` and the other teams use `10.x.1.30`.
- `test_teams` (optional) lists teams that are not real competitors, such as `"test_teams": [99]` (the team must also be in `teams`). The team's header is striped and labelled **TEST**. Its data is stored and shown like any other team's.
- To add a team, add its number to `teams`. To add a machine, add a line to `machines`.
- A mistake in the file (a duplicate address, a pattern with no `x` that several teams would share, a team that is not in `teams`, a misspelled key, ...) stops PWNBoard from starting, and the message says what to fix.

Boards in the older format (`{"teams": [1, 2], "board": [{"name": ..., "hosts": [{"ip": ..., "team": "1"}]}]}`) still work. They are converted when PWNBoard starts, and the file itself is not changed.

To convert a file yourself, for example to edit it by hand, use `scripts/convert_board.py`:

```bash
python3 scripts/convert_board.py board.json new-board.json   # write a new file
python3 scripts/convert_board.py board.json --in-place       # rewrite board.json, saving board.json.bak
python3 scripts/convert_board.py board.json                  # just print the result
```

It works out each machine's pattern from its addresses and keeps any address that does not fit as an `ips` entry, so no address changes. It tells you when that happens, and when it had to rename a machine because two rows had the same name. It stops with a message if the file has a problem.
