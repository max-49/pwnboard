"""Generate a pwnboard config from the generic topology format

https://github.com/ritredteam/topology-generator
"""
import os
import sys
try:
    from termcolor import colored as c
except:
    def c(text, *ars, **kwargs):
        return text

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
from pwnboard.core.board_format import BoardError, format_board, normalize_board  # noqa: E402

COLOR = 'blue'

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

def gen_board(data):
    """Build a version 2 board: one line per machine, with the team number as an `x` in its ip."""
    machines, names = [], []
    for host in get_hosts(data):
        # Machine names identify the rows, so they must be unique
        name = base = host.get('name', host.get('ip'))
        n = 1
        while name in names:
            n += 1
            name = f"{base} ({n})"
        names.append(name)
        machines.append({'name': name, 'ip': host['ip']})
    return {'version': 2, 'teams': list(data['teams']), 'machines': machines}


def prompt(text="", color=COLOR):
    '''
    Generate a prompt with the given color and return the output
    '''
    return input(c(text, color, attrs=('bold',)))


def getTeamRange():
    '''
    Generate a list of the team numbers based on starting and ending values
    '''
    while True:
        try:
            # Get the input
            start = int(prompt("Starting team number: ", COLOR))
            end = int(prompt("Ending team number: ", COLOR))
            # Generate an array with the team numbers
            teams = [i for i in range(start, end+1)]
            # Validate that the input is correct
            print(teams)
            isGood = prompt("Correct? [Y/n] ", "green")
            if isGood.lower() in ("", "y", "yes"):
                # If its right, return the array
                return teams
            # Loop if not correct
        except Exception as E:
            print("Invalid range")
            # Loop if there is any errors


def addHost(network):
    '''
    Get the input information for a host on the network
    '''
    while True:
        ip = input(c('IP: ', COLOR, attrs=('bold',))+network+".")
        hostname = prompt("Hostname: ")
        # os = prompt("OS: ")
        isGood = prompt("Correct? [Y/n] ", "green")
        if isGood.lower() in ("", "y", "yes"):
            # If its right, return the host info
            return {'ip': ip, 'name': hostname}


def addNetwork():
    '''
    Add a network to the config. add hosts to each network
    '''
    data = {}
    # Get the network ip. Keep trying until it is right
    while True:
        try:
            ip = prompt(
                'Network IP (e.g. "10.2.x.0"): ')
            ip = ".".join(ip.split(".")[:3]).lower()
            data['ip'] = ip
            # Make sure there is an 'x' in the ip
            ip.index("x")
            break
        except Exception as E:
            print("Invalid Network Name")
    # get the network name
    # data['name'] = prompt('Network name (e.g. "cloud"): ')
    # Add hosts to the network
    data['hosts'] = []
    while True:
        # Keep adding hosts until we are done
        newHost = prompt("Add a host to this network? [Y/n] ", "green")
        if newHost.lower() not in ("", "y", "yes"):
            break
        # Create a new host and add it to the dataset
        data['hosts'] += [addHost(ip)]
    return data


def addNetworks():
    data = []
    while True:
        # Keep adding networks until we are done
        newNetwork = prompt("Add network? [Y/n] ", "green")
        if newNetwork.lower() not in ("", "y", "yes"):
            break
        # Create a new network and add it to the dataset
        data += [addNetwork()]
    return data

def main():
    '''
    Call all the generate functions and build a json config
    '''
    config = {}
    # Get the teams
    config['teams'] = getTeamRange()
    # Get the networks
    config['networks'] = addNetworks()
    data = config
    board = gen_board(data)
    try:
        normalize_board(board)
    except BoardError as e:
        print(f"Cannot create board.json: {e}")
        sys.exit(1)
    with open("board.json", 'w') as fil:
        fil.write(format_board(board))

if __name__ == "__main__":
    main()
