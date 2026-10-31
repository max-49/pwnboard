FROM python:3.12-slim

WORKDIR /opt/market

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

RUN useradd --system --no-create-home market
COPY pwnmarket/ /opt/market/pwnmarket/
USER market

CMD ["python", "-m", "pwnmarket"]
