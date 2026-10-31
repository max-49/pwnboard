"""Reads the scoring engine's public /round/info stream (no login needed)."""
import json
import logging
import time
from dataclasses import dataclass

import requests

logger = logging.getLogger("market.scoring")


@dataclass(frozen=True)
class RoundUpdate:
    round: int
    uptime_score: dict  # team_number -> cumulative uptime points
    last_round_points: dict  # team_number -> points earned in this round
    checks_per_team: int  # most points a team can earn in one round


def parse_sse(lines):
    """Yield (event, data) for each complete server-sent event in an iterable of text lines."""
    event, data = "message", []
    for line in lines:
        if line == "":
            if data:
                yield event, "\n".join(data)
            event, data = "message", []
        elif line.startswith(":"):
            continue  # comment / keep-alive
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())


def parse_round_update(payload):
    """Turn one updated_round_data payload into a RoundUpdate."""
    scores = payload["scores"]
    per_team = {}
    for response in payload.get("responses") or []:
        per_team[response["user_id"]] = per_team.get(response["user_id"], 0) + 1
    return RoundUpdate(
        round=int(payload["round"]),
        uptime_score={s["team_number"]: int(s["uptime_score"]) for s in scores},
        last_round_points={s["team_number"]: int(s["last_round_points"]) for s in scores},
        checks_per_team=max(per_team.values(), default=0) or 11,
    )


def stream_rounds(url, stop, session=None):
    """Yield a RoundUpdate for every round, reconnecting forever until `stop` is set."""
    session = session or requests.Session()
    delay = 1.0
    while not stop.is_set():
        try:
            with session.get(f"{url}/round/info", stream=True, timeout=(10, 300)) as response:
                response.raise_for_status()
                logger.info("connected to %s/round/info", url)
                lines = response.iter_lines(chunk_size=None, decode_unicode=True)
                for event, data in parse_sse(lines):
                    if stop.is_set():
                        return
                    if event != "updated_round_data":
                        continue
                    delay = 1.0
                    try:
                        yield parse_round_update(json.loads(data))
                    except (ValueError, KeyError) as e:
                        logger.warning("ignoring a round update I could not read: %r", e)
            logger.warning("scoring stream closed; reconnecting")
        except requests.RequestException as e:
            logger.warning("scoring stream error: %s; retrying in %.0fs", e, delay)
        stop.wait(delay)
        delay = min(delay * 2, 30)
