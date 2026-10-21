FROM python:3.12-alpine AS base

WORKDIR /opt/pwnboard

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN addgroup -S pwnboard && adduser -S pwnboard -G pwnboard

# Worker: ingests queued callbacks into Postgres and keeps the board cache fresh
FROM base AS worker

COPY requirements/ /tmp/requirements/
RUN /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements/worker.txt

COPY pwnboard/__init__.py /opt/pwnboard/pwnboard/
COPY pwnboard/core/ /opt/pwnboard/pwnboard/core/
COPY pwnboard/worker/ /opt/pwnboard/pwnboard/worker/

USER pwnboard

CMD ["python", "-m", "pwnboard.worker"]

# Web: dashboard and beacon endpoints (last stage, so a plain `docker build .` produces this one)
FROM base AS web

EXPOSE 5000

COPY requirements/ /tmp/requirements/
RUN /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements/web.txt

COPY pwnboard/__init__.py /opt/pwnboard/pwnboard/
COPY pwnboard/core/ /opt/pwnboard/pwnboard/core/
COPY pwnboard/web/ /opt/pwnboard/pwnboard/web/

USER pwnboard

CMD ["gunicorn", "-c", "python:pwnboard.web.gunicorn_conf", "pwnboard.web:app"]
