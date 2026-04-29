FROM python:3.12-alpine

WORKDIR /opt/pwnboard
EXPOSE 5000

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install package dependencies
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# Install the code
COPY pwnboard.py /opt/pwnboard/
COPY pwnboard-queue/ /opt/pwnboard/pwnboard/

RUN addgroup -S pwnboard && adduser -S pwnboard -G pwnboard
USER pwnboard

# CMD ["python", "pwnboard.py"] # uncomment for non gunicorn deploy
CMD /opt/venv/bin/gunicorn --bind 0.0.0.0:$FLASK_PORT --workers 3 --threads 4 pwnboard:app