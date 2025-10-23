import json


class Topology(object):
    '''
    A topology object which allows for useful data to be returned from a topo.
    config file (topology.json). To create a config use the generator in scripts
    '''
    def __init__(self, config):
        '''
        Takes a filename and reads it in
        '''
        self.name = config
        with open(config) as conf:
            self.config = json.load(conf)
        self.hosts = []
        self.getHosts()

    def reload(self):
        '''
        Reload a the config and update the json
        '''
        with open(config) as conf:
            self.config = json.load(conf)

    def getHosts(self):
        '''
        Initialize an array containing the data for each host stored as a dict
        '''
        retval = []
        for network in self.config.get('networks', []):
            netip = network.get('ip','')
            for host in network.get('hosts'):
                ip = ".".join((netip, host.get('ip')))
                retval += [{'ip': ip, 'name': host.get('name'),
                            'os': host.get('os')}]
        self.host = retval

    def classifyOs(os):
        '''
        Determine what OS the given 'os' tag is
        '''
        if os.lower() in ('centos', 'linux', 'ubuntu', 'rhel', 'kali'):
            return 'linux'
        elif os.lower() in ('windows', 'win', 'server2012', 'server2016',
                            'server2008', 'win8', 'win2012', 'win10',
                            'win7'):
            return 'windows'
        else:
            return 'other'

    def getLinuxHosts(self):
        '''
        return all the linux hosts
        '''
        retval = []
        for h in self.hosts:
            if classifyOs(h['os']) == 'linux':
                ip = h['ip']
                retval += [ip.replace('x',t) for t in self.config.get('teams',
                                                                      ())]
        return retval
