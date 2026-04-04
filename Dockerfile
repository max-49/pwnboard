FROM alpine:latest

EXPOSE 5000

# Install package dependencies
RUN apk add --update python3 py3-pip
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip3 install -r /tmp/requirements.txt

# Install the code
# COPY pwnboard.py /opt/pwnboard/ # uncomment for non gunicorn deploy
COPY pwnboard/ /opt/pwnboard/
WORKDIR /opt/pwnboard

# CMD ["python", "pwnboard.py"] # uncomment for non gunicorn deploy
CMD /opt/venv/bin/gunicorn --bind 0.0.0.0:$FLASK_PORT --workers 3 --threads 4 pwnboard:app