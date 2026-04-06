#!/usr/bin/env python3
import os
import sys
import random
import urllib3
import requests
import json
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def random_callbacks(server, time_interval, hosts, access_token, verify):
    # callback_infos = ["https://thisisac2.xyz/<hostinfo>/<shell> - red:letredin", "https://discord.com/channel/<id>", "https://c2domain.com - goop:bob"]
    creds = [
        ('admin','Change.me123!'),
        ('biguser','hugepassword'),
        ('ccdc','ccdc'),
        ('darthvader','LemonJumpSlide1#'),
        ('bob','bob123123'),
        ('apple','bottom1password23'),
        ('president','21stcentury'),
    ]

    while True:
        for i in range(random.randint(0,5)):
            ip = random.choice(hosts)
            cred = random.choice(creds)
            data = json.dumps({'ip': ip, 'application': f'credstealer{random.randint(1,6)}', 'username': cred[0], 'password': cred[1]})
            headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {access_token}'}
            r = requests.post(server,headers=headers,data=data,verify=verify)
            print({'status_code': r.status_code, 'response': r.text})
            time.sleep(1)
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
    if (len(sys.argv) > 1):
        try:
            board_path = sys.argv[1]
            with open(board_path, 'r') as f:
                board_file = json.load(f)
            board = []
            subnets = board_file["board"]
            for subnet in subnets:
                hosts = subnet["hosts"]
                for host in hosts:
                    board.append(host["ip"])  
        except:
            print("Invalid board file")
            exit(1)
    else:
        board = get_board()

    access_token = os.environ.get("ACCESS_TOKEN", None)
    if not access_token:
        access_token = input("Input your global access token (token with application name global): ").strip()
    server = input("Full POST URL for PWNBoard website (ex. https://www.pwnboard.win/creds): ").strip()
    self = input("Using self signed certs (Y/N)?: ")
    self_res = False if self.strip().lower() == "y" else True
    random_callbacks(server, 5, board, access_token, self_res)

if __name__ == '__main__':
    main()
