
import dns.dnssec
import dns.resolver
import glob
import re

from ansible.utils.display import Display
display = Display()

def query_dnskey(domain):
    dnskeys = []
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['10.90.2.91']
    try:
        answers = resolver.query(domain, dns.rdatatype.DNSKEY)
    except:
        return dnskeys

    for answer in answers:
        rec = answer.to_text().split(' ')
        t, algorithm, dnskey = rec[0], rec[2], ''.join(rec[3:])
        # DNSKEY record 256 is the public key called Zone-signing-key, used to verify the DNS record signatures for A, MX, CNAME, SRV, etc.
        # DNSKEY record 257 is called the Key-Signing Key, used to verify the signatures of the DNSKEY, CDS, and CDNSKEY records.
        i = dns.dnssec.key_id(answer)
        base = "/var/named/keys/K%s.+%03d+%05d" % (domain, int(algorithm), int(i))
        dnskeys.append({
            'domain': domain,
            'type': 'KSK' if t == '257' else 'ZSK',
            'algorithm': dns.dnssec.algorithm_to_text(int(algorithm)),
            'dnskey': dnskey,
            'key': base + '.key',
            'private': base + '.private',
            'id': str(i),
        })

    return dnskeys


def read_dnskeys(domain, keypath):
    dnskeys = []
    for k in glob.glob("%s/K%s.*key" % (keypath, domain)):
        display.vvv("Reading %s" % k)
        p = k.replace('.key', '.private')
        m = re.search('\+(\d+)\.key$', k)
        key_id = m.group(1)

        with open(k) as fp:
            for line in fp:
                line = line.rstrip('\n')
                display.vvvv("  %s" % line)

                if line.startswith("; Created:"):
                    r = re.match("; Created: (\d+)", line)
                    created = r.groups()[0]

                if line.startswith("%s. IN DNSKEY" % domain):
                    rec = line.split(' ')
                    t, algorithm, dnskey = rec[3], rec[5], ''.join(rec[6:])
                    dnskeys.append({
                        'domain': domain,
                        'type': 'KSK' if t == '257' else 'ZSK',
                        'algorithm': dns.dnssec.algorithm_to_text(int(algorithm)),
                        'dnskey': dnskey,
                        'created': created,
                        'key': k,
                        'private': p,
                        'id': key_id,
                    })

    return dnskeys


def latest_dnskeys(dnskeys):
    latest = {'KSK': 0, 'ZSK': 0}
    latest_keys = {'KSK': '', 'ZSK': ''}
    for dnskey in dnskeys:
        t = dnskey['type']
        display.vvvv("Checking %s" % dnskey)
        if dnskey['created'] > latest[t]:
            latest[t] = dnskey['created']
            display.vvvv("Found latest with %s over %s" % (latest[t], latest_keys[t]))
            latest_keys[t] = dnskey
    return latest_keys.values()


def diff_dnskeys(a, b):
    dict_a = { x['id']: x for x in a }
    dict_b = { x['id']: x for x in b }
    return [ dict_a[x] for x in list(set(dict_a) - set(dict_b)) ]

class FilterModule(object):
    def filters(self):
        return {
            'query_dnskey': query_dnskey,
            'read_dnskeys': read_dnskeys,
            'latest_dnskeys': latest_dnskeys,
            'diff_dnskeys': diff_dnskeys,
        }
