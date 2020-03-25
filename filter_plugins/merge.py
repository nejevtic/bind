
import re

from ansible.utils.display import Display
display = Display()


def flip_octets(net):
    if re.match('^[\d\.]+$', net):
        octets = net.split('.')
        octets.reverse()
        flipped = '.'.join(octets)
        display.vvvv("FLIP %s to %s" % (net, flipped))
        return flipped

    else:
        return net


def parse_hashes(lines):
    hashes = []
    for line in lines:
        n, h = line.split(':;')
        hashes.append({
            'name': flip_octets(n),
            'hash': ';' + h
        })

    return hashes


def qualify(host, domain):
    qualified = ''
    domain = domain.rstrip('.')

    # translate the apex entry
    if host == '@':
        qualified = "%s." % domain

    # if the host is already terminated with a period, keep it as is
    elif host[-1] == '.':
        qualified = host

    # append the domain name
    else:
        qualified = "%s.%s." % (host, domain)

    display.vvvv("ZONE MERGE   '%s' => '%s'" % (host, qualified))
    return qualified


def merge_zones(domains):
    merged = {}
    hosts = []
    networks = {}

    for domain in domains:

        # consider domains that have networks: defined only
        if 'networks' not in domain:
            continue

        display.vvv("ZONE MERGE %s" % domain['name'])

        # carry name server data into the new zone
        if 'name_servers' in domain:
            merged['name_servers'] = domain['name_servers']

        # use any / all hostmaster_email values for the new zone - should all be the same
        if 'hostmaster_email' in domain:
            merged['hostmaster_email'] = qualify(domain['hostmaster_email'], domain['name'])

        # build a unique set of networks across all domains
        for network in domain['networks']:
            networks[network] = 1

        # build a list of host entries with ip - amend the domain name if needed
        for host in domain['hosts']:
            if 'ip' in host:
                hosts.append({
                    'name': qualify(host['name'], domain['name']),
                    'ip':   host['ip']
                })

    # insert a list of networks and list of host dicts as the template expects
    merged['networks'] = networks.keys()
    merged['hosts'] = hosts
    merged['name'] = 'PTR'

    # the template expects a list of domains
    return [ merged ]


class FilterModule(object):
    def filters(self):
        return {
            'flip_octets': flip_octets,
            'merge_zones': merge_zones,
            'parse_hashes': parse_hashes,
        }
