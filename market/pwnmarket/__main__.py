import logging
import signal
import threading
from datetime import datetime, timezone

from .config import Config
from .scoring import stream_rounds
from .server import make_server
from .service import Market
from .store import Store


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("market")
    cfg = Config.from_env()
    stop, wake = threading.Event(), threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (stop.set(), wake.set()))

    store = Store(cfg)
    while not stop.is_set():
        try:
            store.setup()
            break
        except Exception as e:
            log.warning("database not ready (%s); retrying", e)
            stop.wait(3)

    market = Market(cfg, store)
    try:
        market.restore()
    except Exception:
        log.exception("could not restore recent rounds; starting fresh")
    if cfg.competition_end is None:
        log.warning("COMPETITION_END is not set; assuming %.0f scoring rounds remain", cfg.rounds_remaining)
    else:
        log.info("competition ends at %s", cfg.competition_end.isoformat())
        if cfg.competition_end <= datetime.now(timezone.utc):
            log.warning("COMPETITION_END is already in the past, so no rounds are left; check the date, time and UTC offset")

    def follow_scores():
        for update in stream_rounds(cfg.scoring_url, stop):
            if market.on_round(update):
                log.info("round %d: %d teams", update.round, len(update.uptime_score))
                wake.set()  # price the new round straight away

    threading.Thread(target=follow_scores, daemon=True).start()
    make_server(market, cfg.http_port)
    log.info("market running; tick every %.0fs", cfg.tick_seconds)

    while not stop.is_set():
        wake.wait(cfg.tick_seconds)
        wake.clear()
        if stop.is_set():
            break
        try:
            market.tick()
        except Exception:
            log.exception("tick failed")


if __name__ == "__main__":
    main()
