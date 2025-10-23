import sys
import json

SKEL = """'''
This is an auto generated detfile build from a topology file: {filename}

{info}

https://github.com/RITRedteam/Topology-Generator
https://github.com/micahjmartin/detcord
'''

# pylint: disable=import-error, invalid-name, unused-wildcard-import

import os
from detcord import action, display

if os.path.exists('actions'):
    from actions import *

env = dict()
env['user'] = 'root'
env['pass'] = 'changeme'
env['hosts'] = []  # DYNAMICALLY GENERATED IN build_hosts()
env['silent'] = False  # https://github.com/micahjmartin/detcord/wiki/Detfile-Environment#silent
env['threading'] = False

{hosts}

{teams}


@action
def test(host):
    '''Print the hostname of the box'''
    display(host.run("command hostname"))

def on_detcord_begin(detfile="", hosts=[], actions=[], threading=False):
    pass

def on_detcord_action(host="", action="", return_value=None):
    pass

def on_detcord_action_fail(host="", action="", exception=None):
    pass

def on_detcord_end(detfile=""):
    pass

def build_hosts():
    '''Build the hosts for the ENV dynamically
    '''
    global env
    env['hosts'] = []
    for team in TEAMS:
        for ip in HOSTS:
            new = ip.replace("x", str(team))
            env['hosts'].append(new)

build_hosts()
"""

def get_hosts(data):
    hosts = []
    for network in data['networks']:
        netip = network['ip']
        for nethost in network['hosts']:
            host = nethost.copy()
            if nethost['ip'].lower() == "dhcp":
                host['ip'] = "dhcp"
            else:
                host['ip'] = ".".join((netip, nethost['ip']))
            hosts += [host]
    return hosts

def build_detfile(filename, data):
    # Build the hosts section
    hosts = "HOSTS = [\n"
    for host in get_hosts(data):
        if host['ip'].lower() == 'dhcp':
            continue
        # Skip windows hosts
        if 'win' in host.get('os', '').lower():
            continue
        hosts += "\t'{}',".format(host['ip'])
        comment = []
        if host.get('name', False): comment += [host['name']]
        if host.get('os', False): comment += [host['os']]
        comment = " - ".join(comment)
        if comment:
            hosts += "  # " + comment
        hosts += '\n'
    hosts += "]"

    # Build the teams
    teams = 'TEAMS = ' + str(data['teams'])


    # Information about the competition
    info = []
    if data.get('name', False): info += [data['name']]
    if data.get('date', False): info += [data['date']]
    info = " - ".join(info)
    return SKEL.format(filename=filename, info=info, teams=teams, hosts=hosts)
        

def main():
    try:
        config = sys.argv[1]
        with open(config) as fil:
            config = json.load(fil)
    except (IndexError) as E:
        print("USAGE: {} <topology>".format(sys.argv[0]))
        quit(1)
    with open("detfile.py", 'w') as fil:
        fil.write(build_detfile(sys.argv[1], config))

if __name__ == "__main__":
    main()