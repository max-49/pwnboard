import logging
import os

# Shared pwnboard logger configuration. Importing this module configures
# basic console (and optional file) logging without triggering other
# package-level side-effects.

logger = logging.getLogger('pwnboard')

# Allow overriding logfile via env var `PWNBOARD_LOGFILE`
_logfile = os.environ.get('PWNBOARD_LOGFILE', '')

FMT = logging.Formatter(fmt="[%(asctime)s] %(levelname)s: %(message)s",
                        datefmt="%x %I:%M:%S")

if _logfile:
    _fh = logging.FileHandler(_logfile)
    _fh.setFormatter(FMT)
    logger.addHandler(_fh)

# Console handler
_sh = logging.StreamHandler()
_sh.setFormatter(FMT)
logger.addHandler(_sh)

logger.setLevel(logging.DEBUG)
