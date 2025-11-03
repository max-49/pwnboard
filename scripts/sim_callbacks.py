#!/usr/bin/env python3
import random
import requests
import json
import time

def random_callbacks(server, time_interval, hosts):
    while True:
        for i in range(random.randint(0,20)):
            ip = random.choice(hosts)
            data = json.dumps({'ip': ip, "application": f"c2_{random.randint(1,20)}"})
            headers = {'Content-Type': 'application/json'}
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
    server = input("Server Name?: ").strip()
    random_callbacks(server, 1, board)

if __name__ == '__main__':
    main()
