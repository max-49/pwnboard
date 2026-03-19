#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

domain=$(cat ../docker-compose.yml | grep PWNBOARD_URL | cut -d '=' -f2 | cut -d '/' -f3)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ../reverse-proxy/key.pem -out ../reverse-proxy/cert.pem -subj "/C=US/ST=State/L=Town/O=PWNBoard/OU=Development/CN=$domain"