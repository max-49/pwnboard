#!/bin/bash

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo "Run as root"
    exit
fi

apt-get update
apt-get install -y certbot
domain=$(cat ../docker-compose.yml | grep PWNBOARD_URL | cut -d '=' -f2 | cut -d '/' -f3)
certbot certonly -d "$domain" --agree-tos --email "admin@$domain" --manual --preferred-challenges dns
cp "/etc/letsencrypt/archive/$domain/fullchain1.pem" ../reverse-proxy/cert.pem
cp "/etc/letsencrypt/archive/$domain/privkey1.pem" ../reverse-proxy/key.pem