#!/usr/bin/env python

import json
import logging
import os
import signal
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from time import sleep

from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

from dotenv import load_dotenv
load_dotenv()

SERIAL_NO = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
    'SPF': (dns.TXT, QTYPE.TXT),
}


class Record:
    def __init__(self, rname, rtype, args):
        self._rname = DNSLabel(rname)

        rd_cls, self._rtype = TYPE_LOOKUP[rtype]

        if self._rtype == QTYPE.SOA and len(args) == 2:
            # add sensible times to SOA
            args += (SERIAL_NO, 3600, 3600 * 3, 3600 * 24, 3600),

        if self._rtype == QTYPE.TXT and len(args) == 1 and isinstance(args[0], str) and len(args[0]) > 255:
            # wrap long TXT records as per dnslib's docs.
            args = wrap(args[0], 255),

        if self._rtype in (QTYPE.NS, QTYPE.SOA):
            ttl = 3600 * 24
        else:
            ttl = 300

        self.rr = RR(
            rname=self._rname,
            rtype=self._rtype,
            rdata=rd_cls(*args),
            ttl=ttl,
        )

    def match(self, q):
        return q.qname == self._rname and (q.qtype == QTYPE.ANY or q.qtype == self._rtype)

    def sub_match(self, q):
        return self._rtype == QTYPE.SOA and q.qname.matchSuffix(self._rname)

    def __str__(self):
        return str(self.rr)


class Resolver(ProxyResolver):
    def __init__(self, upstream, myip_queries, zone_file):
        super().__init__(upstream, 5353, 5)
        self.myip_queries = myip_queries
        self.records = self.load_zones(zone_file)

        logger.info("myip query is ")
        for myip_query in self.myip_queries:
            logger.info("    %s %s", myip_query[0], myip_query[1])

    def zone_lines(self):
        current_line = ''
        for line in zone_file.open():
            if line.startswith('#'):
                continue
            line = line.rstrip('\r\n\t ')
            if not line.startswith(' ') and current_line:
                yield current_line
                current_line = ''
            current_line += line.lstrip('\r\n\t ')
        if current_line:
            yield current_line

    def load_zones(self, zone_file):
        assert zone_file.exists(), f'zone files "{zone_file}" does not exist'
        logger.info('loading zone file "%s":', zone_file)
        zones = []
        for line in self.zone_lines():
            try:
                rname, rtype, args_ = line.split(maxsplit=2)

                if args_.startswith('['):
                    args = tuple(json.loads(args_))
                else:
                    args = (args_,)
                record = Record(rname, rtype, args)
                zones.append(record)
                logger.info(' %2d: %s', len(zones), record)
            except Exception as e:
                raise RuntimeError(f'Error processing line ({e.__class__.__name__}: {e}) "{line.strip()}"') from e
        logger.info('%d zone resource records generated from zone file', len(zones))
        return zones

    def _match_query(self, qname, qtype):
        for myip_query in self.myip_queries:
            if DNSLabel(myip_query[0]) == qname and (qtype == QTYPE.ANY or myip_query[1] == QTYPE[qtype]):
                return True
        return False

    def resolve(self, request, handler):
        type_name = QTYPE[request.q.qtype]
        reply = request.reply()

        # if request.q.qname == DNSLabel("myip.opendns.com") and (request.q.qtype == QTYPE.ANY or type_name == 'A'):
        if self._match_query(request.q.qname, request.q.qtype):
            args = (handler.client_address[0],)
            if request.q.qtype == QTYPE.A:
                rr = RR(
                    rname=request.q.qname,
                    rtype=request.q.qtype,
                    rdata=dns.A(*args),
                    ttl=60,
                )
            elif request.q.qtype == QTYPE.TXT:
                rr = RR(
                    rname=request.q.qname,
                    rtype=request.q.qtype,
                    rdata=dns.TXT(*args),
                    ttl=60,
                )
            else:
                rr = RR(
                    rname=request.q.qname,
                    rtype=request.q.qtype,
                    rdata=dns.A(*args),
                    ttl=60,
                )
            reply.add_answer(rr)

        for record in self.records:
            if record.match(request.q):
                reply.add_answer(record.rr)

        if reply.rr:
            logger.info('found zone for %s[%s], %d replies', request.q.qname, type_name, len(reply.rr))
            return reply

        # no direct zone so look for an SOA record for a higher level zone
        for record in self.records:
            if record.sub_match(request.q):
                reply.add_answer(record.rr)

        if reply.rr:
            logger.info('found higher level SOA resource for %s[%s]', request.q.qname, type_name)
            return reply

        logger.info('no local zone found, proxying %s[%s]', request.q.qname, type_name)
        return super().resolve(request, handler)


def handle_sig(signum, frame):
    logger.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sig)

    bind_addr = os.getenv('BIND_ADDR', '0.0.0.0')
    port = int(os.getenv('PORT', 53))
    upstream = os.getenv('UPSTREAM', '127.0.0.1')
    myip_queries_preset = """
        myip.opendns.com A
        o-o.myaddr.l.google.com TXT
        whoami.akamai.net A
    """
    myip_queries = [line.strip().split(None, 2) for line in os.getenv('MYIP_QUERY', myip_queries_preset).strip().splitlines()]
    zone_file = Path(os.getenv('ZONE_FILE', 'zones.txt'))
    resolver = Resolver(upstream, myip_queries, zone_file)
    udp_server = DNSServer(resolver, address=bind_addr, port=port)
    tcp_server = DNSServer(resolver, address=bind_addr, port=port, tcp=True)

    logger.info('starting DNS server on %s:%d, upstream DNS server "%s"', bind_addr, port, upstream)
    udp_server.start_thread()
    tcp_server.start_thread()

    try:
        while udp_server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        pass