#!/bin/sh

# If there is a toplogy file, but not a board file, generate the baord
# from the topology.json
TOPO="topology.json"
BOARD="board.json"

# Check topo in the main dir first
if [ -f "$TOPO" ] && [ ! -f "$BOARD" ]; then
    echo "Generating $BOARD from $TOPO"
    python3 "scripts/gen_config.py" "$TOPO" "$BOARD"
    exit
fi


TOPO="config/topology.json"
if [ -f "$TOPO" ] && [ ! -f "$BOARD" ]; then
    echo "Generating $BOARD from $TOPO"
    python3 "scripts/gen_config.py" "$TOPO" "$BOARD"
    exit
fi

sudo apt-get update
sudo apt-get install -y certbot
domain=$(cat ../.env | grep PWNBOARD_URL | cut -d '=' -f2 | cut -d '/' -f3)
certbot certonly -d $domain --agree-tos --email admin@$domain --manual --preferred-challenges dns
mv /etc/letsencrypt/live/$domain/fullchain.pem ../cert.pem
mv /etc/letsencrypt/live/$domain/privkey.pem ../key.pem
