# PWNBoard prediction market

Turns the scoring engine's live scores and PWNBoard's red team callbacks into "who wins" prices
and shows them on its own prediction-market website, `http://<host>:8080` (a price chart, a Yes/No
list of teams, details per team, and a play-money trade ticket). The Grafana odds panels read the same data.

**This lives on the `competition/prediction-market` branch only. It is not part of CI and the
image is not published: it is built on the host.**

## What it uses

Only what the scoring site shows without logging in:

- `GET /api/round/info` (live stream): every team's cumulative `uptime_score` and `last_round_points`
  each round. It is the only scoring data used, so **injects, KOTH and adjustments are invisible**.
- PWNBoard's own `callback_events` table: how many hosts each team has called back from in the last
  5 minutes (the "hosts held" red team has).

`/scores/*` and `/settings` need a login and are not used, so no credentials are needed.

## How the odds are made

Every tick (and straight away when a new round arrives) the service plays the rest of the
competition out 20,000 times. A team's final score is

    score now  +  rounds left x checks x projected uptime rate  +  luck we cannot see

- **Projected uptime rate** mixes the team's whole-game rate with its recent form (recent rounds count
  more), then loses `ACCESS_PENALTY` (6%) of itself for every host red team holds.
- **Luck we cannot see** stands in for injects and everything else, and is fat-tailed, so long shots
  keep a real chance. This is why a leader is not a certainty.
- A team's price is the share of the 20,000 runs it wins, floored at 0.5% and smoothed a little against
  the last tick so the lines move like a market and don't jitter.

On a real snapshot (round 293), the leader sat near 28-54% depending on how many hosts red team held
on it; ten hosts on the leader handed the favourite spot to another team.

## Knobs

Set these in `.env` next to `docker-compose.yml` (then `docker compose up -d market`). Empty or
unset means the default.

| Variable | Default | Effect |
|---|---|---|
| `COMPETITION_END` | none | End time as `2026-10-31T18:00:00-04:00`. Without it, `ROUNDS_REMAINING` is used. |
| `ROUNDS_REMAINING` | 60 | Rounds left when the service starts, if no end time is set. |
| `UNKNOWN_POINTS_SD` | 250 | Points we cannot see. **Lower = the leader runs away; higher = flatter, more upsets.** |
| `ACCESS_PENALTY` | 0.06 | Share of projected uptime lost per host red team holds. Higher = red team moves prices more. |
| `FORM_WEIGHT` | 0.7 | 0 = whole-game uptime only, 1 = recent rounds only. Higher = twitchier. |
| `FORM_HALF_LIFE` | 6 | Rounds for an old result to count half as much. Lower = twitchier. |
| `PRICE_KEEP` | 0.4 | Share of the last price kept each tick. 0 = no smoothing. |
| `TAIL_DF` | 4 | Luck's tail weight. Lower = wilder (must be above 2). |

## Deploying without downtime

`docker compose up -d --build market` creates only the `market` container. The other services' config
is unchanged, so compose leaves them running. Port 8080 is published by the `market` container alone.

```bash
git fetch origin
git checkout competition/prediction-market      # or: git pull, if you are already on it
echo 'COMPETITION_END=2026-10-31T18:00:00-04:00' >> .env   # optional, see above
docker compose up -d --build market
docker compose logs -f market
```

Healthy startup logs look like `connected to .../round/info`, then `round N: 20 teams` for each round.
Then open `http://<host>:8080`. (The Grafana odds panels read `market.odds`, which the service creates on its
first start, so they show no data for the first minute.)

**Port 8080 has no login**, and the page shows how many hosts red team holds on each team. To keep it to the
VM itself (for example behind an SSH tunnel), add `MARKET_BIND=127.0.0.1:8080` to `.env` before starting.

The page is backed by a small JSON API: `GET /api/odds` (current prices and details),
`GET /api/history?minutes=60` (price series for charts) and `GET /healthz`.

### Rolling back

```bash
docker compose rm -sf market        # stops and removes only the market container
git checkout main                   # Grafana restores the old odds panels within ~10 seconds
```

The `market` schema in Postgres is left behind and harmless (`DROP SCHEMA market CASCADE;` removes it).

## Behaviour to know about

- If the scoring stream drops, the service reconnects with backoff and keeps pricing from the last
  scores, marking rows `stale` after 3 minutes without a round.
- If the database hiccups, a tick is skipped and the connection is reopened; the last known red team
  access is used if only that read fails.
- Scoring pauses (lunch) are ignored: a round where nobody scored does not count against anyone's recent
  form. The whole-game rate counts only rounds that scored, worked out from the best score divided by the
  checks per round, which relies on one team having perfect uptime (the test team, 21). If it ever stops
  being perfect, whole-game rates read slightly high.
- After a restart the last 40 rounds are reloaded so "recent form" does not reset.
  `ROUNDS_REMAINING` counts from each start, so prefer `COMPETITION_END`.
- Teams 19 (did not show up), 20 (red team test team) and 21 (blue team test team) get no odds. This is
  hardcoded in `excluded_teams` in `pwnmarket/config.py` for this competition.

## Development

```bash
cd market
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests
```
