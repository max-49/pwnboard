FROM alpine:latest

EXPOSE 5000

# Install package dependencies
RUN apk add --update python3 uwsgi py3-pip
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip3 install -r /tmp/requirements.txt

# PWNboard environment variables (timeouts in minutes)
ENV HOST_TIMEOUT=5
ENV CREDS_TIMEOUT=30

# Install the code
COPY . /opt/pwnboard/
WORKDIR /opt/pwnboard

# Build the board file if one isnt given
RUN /bin/sh scripts/setup.sh

CMD ["python", "pwnboard.py"]

#CMD ["uwsgi", "--yaml", "/opt/pwnboard/config/wsgi.yml"]
