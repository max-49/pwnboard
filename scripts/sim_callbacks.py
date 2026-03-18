#!/usr/bin/env python3
import random
import requests
import json
import time

def random_callbacks(server, time_interval, hosts, access_token):
    callback_infos = ["https://thisisac2.xyz/<hostinfo>/<shell> - red:letredin", "https://discord.com/channel/<id>", "https://c2domain.com - goop:bob"]
    while True:
        for i in range(random.randint(0,20)):
            ip = random.choice(hosts)
            data = json.dumps({'ip': ip, "application": f"c2_{random.randint(1,12)}", "access_type": "c2", "access_info": random.choice(callback_infos)})
            headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {access_token}'}
            r = requests.post(server,headers=headers,data=data)
            print(r)
            time.sleep(0.1)
        time.sleep(time_interval)

def get_board():
    start = int(input("Starting team number: "))
    end = int(input("Ending team number: "))
    teams = [i for i in range(start, end+1)]
    networks = input("What are your networks? (separated by commas, ex: 192.168.x.0, 10.x.1.0): ").split(',')
    networks = [network.strip() for network in networks]
    board = []
    for network in networks:
        ip = ".".join(network.split(".")[:3]).lower()
        boxes_in_net = input(f"List final octet of boxes in network {network} (ex: 1,2,3 for {ip}.1, {ip}.2, {ip}.3): ").split(',')
        boxes = [ip+"."+box.strip() for box in boxes_in_net]
        for i in teams:
            for box in boxes:
                board.append(box.replace("x", str(i)))
    return board

def main():
    board = get_board()
    access_token = input("Input your global access token (token with application name global): ").strip()
    server = input("Full POST URL for PWNBoard website (ex. https://www.pwnboard.win/pwn): ").strip()
    random_callbacks(server, 5, board, access_token)

if __name__ == '__main__':
    main()
