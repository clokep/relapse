# Copyright 2018-2022 The Matrix.org Foundation C.I.C.
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


from twisted.test.proto_helpers import MemoryReactor

from relapse.api.errors import Codes
from relapse.rest import admin
from relapse.rest.client import (
    login,
    whois,
)
from relapse.server import HomeServer
from relapse.util import Clock

from tests import unittest


class WhoisRestTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        whois.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.url = f"/_matrix/client/r0/admin/whois/{self.other_user}"

    def test_no_auth(self) -> None:
        """
        Try to get information of an user without authentication.
        """
        channel = self.make_request("GET", self.url, b"{}")
        self.assertEqual(401, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_not_admin(self) -> None:
        """
        If the user is not a server admin, an error is returned.
        """
        self.register_user("user2", "pass")
        other_user2_token = self.login("user2", "pass")

        channel = self.make_request(
            "GET",
            self.url,
            access_token=other_user2_token,
        )
        self.assertEqual(403, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_user_is_not_local(self) -> None:
        """
        Tests that a lookup for a user that is not a local returns a 400
        """
        url = "/_matrix/client/r0/admin/whois/@unknown_person:unknown_domain"

        channel = self.make_request(
            "GET",
            url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(400, channel.code, msg=channel.json_body)
        self.assertEqual("Can only whois a local user", channel.json_body["error"])

    def test_get_whois_admin(self) -> None:
        """
        The lookup should succeed for an admin.
        """
        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.other_user, channel.json_body["user_id"])
        self.assertIn("devices", channel.json_body)

    def test_get_whois_user(self) -> None:
        """
        The lookup should succeed for a normal user looking up their own information.
        """
        other_user_token = self.login("user", "pass")

        channel = self.make_request(
            "GET",
            self.url,
            access_token=other_user_token,
        )
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(self.other_user, channel.json_body["user_id"])
        self.assertIn("devices", channel.json_body)
