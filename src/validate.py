#!python
'''
validate - validate configuration.

Test if this server is listening on the required ports.

Usage: validate.py spec.yaml

Spec example:

listen on a specific ip address:
  socket.listening:
    - local_ip: 10.0.0.0
    - proto: tcp

listen on a specific ipv6 address:
  socket.listening:
    - local_ip: '0000:0000:0000:0000:0000:0000:0000:0000'
    - proto: tcp6

listen on a specific udp port:
  socket.listening:
    - local_port: 222
    - proto: udp

:maintainer: Gerhard Muntingh <gerhard@qux.nl>
:maturity: new
:platform: linux
'''

import sys
import yaml
import argparse

proc_net = {
    'tcp': "/proc/net/tcp",
    'udp': "/proc/net/udp",
    'tcp6': "/proc/net/tcp6",
    'udp6': "/proc/net/udp6",
}

tcp_state = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def enumSockets(proto):
    """
    Generate a sequence of sockets the linux is using.

    Usage:
        u4_sockets = enumSockets("udp")
        t6_sockets = enumSockets("tcp6")
    """
    if proto not in proc_net:
        raise Exception('unknown protocol: {}'.format(proto))
    with open(proc_net[proto], 'r') as f:
        # skip header
        next(f)
        for line in f:
            fields = line.strip().split()
            ip_port = fields[1].split(':')
            socket = {}
            socket['local_ip'] = convertIp(ip_port[0])
            socket['local_port'] = int(ip_port[1], 16)
            socket['state'] = tcp_state[fields[3]]
            socket['inode'] = int(fields[9])
            yield socket


def grepSockets(hitlist):
    """
    Generate a sequence of sockets the linux is using, but only
    yield sockets that match some search criteria.
    """
    for proto in ['tcp', 'tcp6']:
        sockets = enumSockets(proto)
        for socket in sockets:
            socket['proto'] = proto
            # Examine if this line occurs on the hitlist
            for search_key, search_crit in hitlist.iteritems():
                target = search_crit['socket.listening']
                # guilty until proven innocent
                match_found = True
                # loop over the search parameters
                for k in target:
                    if target[k] != socket[k]:
                        match_found = False
                        break
                if match_found:
                    yield socket, search_key, target


def nonGrepSockets(searchitems):
    """
    Return a list of search criteria for which no match was found in the
    current linux socket list.
    """
    for search_key, search_crit in searchitems.iteritems():
        # Ensure a dict
        if type(search_crit['socket.listening']) is list:
            search_crit['socket.listening'] = \
                list2dict(search_crit['socket.listening'])
        if 'proto' not in search_crit['socket.listening']:
            search_crit['socket.listening']['proto'] = 'tcp'
        if 'state' not in search_crit['socket.listening']:
            search_crit['socket.listening']['state'] = 'LISTEN'
        else:
            search_crit['socket.listening']['state'] = \
                search_crit['socket.listening']['state'].upper()
    remaining_searchitems = searchitems.copy()
    results = grepSockets(searchitems)
    for s, search_key, target in results:
        if search_key in remaining_searchitems:
            del remaining_searchitems[search_key]
    return remaining_searchitems


def list2dict(list_):
    dict_ = dict()
    for l in list_:
        for k, v in l.iteritems():
            dict_[k] = v
    return dict_

def convertIp(ip):
    """
    Converts the hexadecimal ip sequences found in /proc/net/tcp(6)
    to dotted quad syntax.

    E.g.
        0100007F becomes 127.0.0.1

    The IPv6 syntax is even more non-intuitive, but can be understood by
    reading: http://lxr.free-electrons.com/source/net/ipv6/tcp_ipv6.c#L1680
    """
    if len(ip) > 8:
        return "{}{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}{}".format(
            ip[6:8], ip[4:6], ip[2:4], ip[0:2],
            ip[14:16], ip[12:14], ip[10:12], ip[8:10],
            ip[22:24], ip[20:22], ip[18:20], ip[16:18],
            ip[30:32], ip[28:30], ip[26:28], ip[24:26],
        )
    else:
        return "{}.{}.{}.{}".format(
            int(ip[6:8], 16),
            int(ip[4:6], 16),
            int(ip[2:4], 16),
            int(ip[0:2], 16),
        )


if __name__ == "__main__":
    argv_parser = argparse.ArgumentParser(description='Server Validator')
    argv_parser.add_argument('file', type=str,
                             help='Filename containing the spec')
    argv = vars(argv_parser.parse_args())
    with open(argv['file']) as f:
        spec = yaml.load(f)
        results = nonGrepSockets(spec)
        if len(results):
            print("Failed. The followin specs didn't match")
            print results
            sys.exit(1)
    sys.exit(0)
