import json
import logging
import os
import signal
from time import sleep
from dnslib import QTYPE, RR, A, TXT, CNAME
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

from dotenv import load_dotenv
load_dotenv()

handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

from pprint import pprint as pp

class SubProxy(ProxyResolver):
    def __init__(self, myip_queries, upstream_addr, upstream_port):
        super().__init__(upstream_addr, upstream_port, 5)
        self.myip_queries = myip_queries

    def _is_myip_query(self, request):
        qname = request.q.qname
        qtype = request.q.qtype

        for myip_query in self.myip_queries:
            myip_query_qname, myip_query_qtype = myip_query
            if myip_query_qname == str(qname) and myip_query_qtype == str(QTYPE[qtype]):
                return True

        return False

    def resolve(self, request, handler):
        if not self._is_myip_query(request):
            logger.debug("Request %s is not myip query. Forward request to upstream server.", str(request.q.qname))
            return super().resolve(request, handler)

        logger.debug("Request %s is myip query.", str(request.q.qname))
        client_address = handler.client_address[0]

        if request.q.qtype == QTYPE.A:
            rdata_qtype = A
        elif request.q.qtype == QTYPE.TXT:
            rdata_qtype = TXT
        elif request.q.qtype == QTYPE.CNAME:
            rdata_qtype = CNAME
        else:
            rdata_qtype = A

        answer = RR(
            rname=request.q.qname,
            rtype=request.q.qtype,
            rdata=rdata_qtype(client_address),
            ttl=60,
        )

        reply = request.reply()
        reply.add_answer(answer)
        return reply


def handle_sig(signum, frame):
    logger.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sig)

    bind_addr = os.getenv('BIND_ADDR', '0.0.0.0')
    port = int(os.getenv('PORT', 53))
    upstream_addr = os.getenv('UPSTREAM_ADDR', '127.0.0.1')
    upstream_port = int(os.getenv('UPSTREAM_PORT', 53))
    myip_queries_preset = "myip.opendns.com.:A,o-o.myaddr.l.google.com.:TXT,whoami.akamai.net.:A"
    myip_queries_str = os.getenv('MYIP_QUERY', myip_queries_preset)

    myip_queries = [query.strip().split(":", 2) for query in myip_queries_str.strip().split(",")]

    resolver = SubProxy(myip_queries=myip_queries, upstream_addr=upstream_addr, upstream_port=upstream_port)
    udp_server = DNSServer(
        resolver,
        address=bind_addr,
        port=port,
    )
    logger.info('starting DNS server on %s:%d, upstream DNS server "%s:%s"', bind_addr, port, upstream_addr, upstream_port)
    logger.info('myip query is below.')
    for myip_query in myip_queries:
        logger.info('  %s %s', myip_query[0], myip_query[1])

    udp_server.start_thread()

    try:
        while udp_server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        pass