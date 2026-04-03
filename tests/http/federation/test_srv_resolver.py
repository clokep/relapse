# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from unittest.mock import AsyncMock, patch

import dns.asyncresolver

from twisted.internet.error import ConnectError

from relapse.http.federation.srv_resolver import Server, SrvResolver

from tests import unittest


class SrvResolverTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.cache: dict[str, list[Server]] = {}
        self.resolver = SrvResolver(self.cache)
        self.resolve_mock = AsyncMock()
        patch.object(
            dns.asyncresolver.Resolver, "resolve", new=self.resolve_mock
        ).start()

    def make_answer(self, service_name: str, *records: dns.rdata.Rdata) -> None:
        query = dns.message.make_query(service_name, dns.rdatatype.SRV)
        response = dns.message.make_response(query)
        for record in records:
            rrs = response.get_rrset(
                response.answer,
                dns.name.from_text(service_name),
                dns.rdataclass.IN,
                record.rdtype,
                create=True,
            )
            assert rrs is not None
            rrs.add(record, 300)

        self.resolve_mock.return_value = dns.resolver.Answer(
            dns.name.from_text(service_name),
            dns.rdatatype.SRV,
            dns.rdataclass.IN,
            response,  # type: ignore[arg-type]
        )

    async def test_resolve(self) -> None:
        service_name = "test_service.example.com"
        host_name = "example.com"

        self.make_answer(
            service_name,
            dns.rdata.from_text(
                dns.rdataclass.IN, dns.rdatatype.SRV, f"0 0 0 {host_name}"
            ),
        )

        servers = await self.resolver.resolve_service(service_name)

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers, self.cache[service_name])
        self.assertEqual(servers[0].host, host_name)

    async def test_from_cache_expired_and_dns_fail(self) -> None:
        self.resolve_mock.side_effect = dns.exception.DNSException()

        service_name = "test_service.example.com"

        entry = Server(service_name, 8888, 0, 0, 0)

        self.cache[service_name] = [entry]
        servers = await self.resolver.resolve_service(service_name)

        self.resolve_mock.assert_called_once_with(service_name, dns.rdatatype.SRV)

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers, [entry])

    async def test_from_cache(self) -> None:
        self.resolve_mock.side_effect = dns.exception.DNSException()

        service_name = "test_service.example.com"

        entry = Server(service_name, 8888, 0, 0, 0)

        self.cache[service_name] = [entry]
        servers = await self.resolver.resolve_service(service_name)

        self.resolve_mock.assert_called_once_with(service_name, dns.rdatatype.SRV)

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers, [entry])

    async def test_empty_cache(self) -> None:
        self.resolve_mock.side_effect = dns.exception.DNSException()

        service_name = "test_service.example.com"

        with self.assertRaises(dns.exception.DNSException):
            await self.resolver.resolve_service(service_name)

    async def test_name_error(self) -> None:
        self.resolve_mock.side_effect = dns.resolver.NXDOMAIN()

        service_name = "test_service.example.com"
        servers = await self.resolver.resolve_service(service_name)

        self.assertEqual(len(servers), 0)
        self.assertEqual(len(self.cache), 0)

    async def test_disabled_service(self) -> None:
        """
        test the behaviour when there is a single record which is ".".
        """
        service_name = "test_service.example.com"

        # returning a single "." should make the lookup fail with a ConenctError
        self.make_answer(
            service_name,
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SRV, "0 0 0 ."),
        )

        with self.assertRaises(ConnectError):
            await self.resolver.resolve_service(service_name)

    async def test_non_srv_answer(self) -> None:
        """
        test the behaviour when the dns server gives us a spurious non-SRV response
        """
        service_name = "test_service.example.com"

        self.make_answer(
            service_name,
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1"),
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SRV, "0 0 0 host"),
        )

        servers = await self.resolver.resolve_service(service_name)

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers, self.cache[service_name])
        self.assertEqual(servers[0].host, "host")
