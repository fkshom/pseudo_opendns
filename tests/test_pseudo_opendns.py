from unittest.mock import MagicMock
from unittest.mock import patch
import pytest
from dnslib import DNSRecord, DNSQuestion, QTYPE
from pseudo_opendns import SubProxy, ProxyResolver

class TestSubProxy:
    def test_1(self):
        myip_queries = [
            ("myip.example.com.", "A"),
        ]
        subproxy = SubProxy(myip_queries=myip_queries, upstream_addr="1.1.1.1", upstream_port=53)

        request = DNSRecord()
        request.add_question(DNSQuestion(qname="myip.example.com.", qtype=1))

        import json
        from types import SimpleNamespace
        handler = SimpleNamespace(** dict(
                client_address=("1.2.3.4", "12345")
        ))

        reply = subproxy.resolve(request, handler)
        assert str(reply.rr[0].rname) == 'myip.example.com.'
        assert QTYPE[reply.rr[0].rtype] == 'A'
        assert str(reply.rr[0].rdata) == '1.2.3.4'

    @patch("pseudo_opendns.ProxyResolver.resolve")
    def test2(self, resolve_patch):
        myip_queries = [
            ("myip.example.com.", "A"),
        ]
        subproxy = SubProxy(myip_queries=myip_queries, upstream_addr="1.1.1.1", upstream_port=53)

        request = DNSRecord()
        request.add_question(DNSQuestion(qname="realquery.example.com.", qtype=1))

        from types import SimpleNamespace
        handler = SimpleNamespace(** dict(
                client_address=("1.2.3.4", "12345")
        ))

        reply = subproxy.resolve(request, handler)
        args = resolve_patch.call_args.args
        assert args[0] == request
