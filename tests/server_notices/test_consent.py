# Copyright 2018 New Vector Ltd
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

import os

from twisted.test.proto_helpers import MemoryReactor

import relapse.rest.admin
from relapse.rest.client import login, room, sync
from relapse.server import HomeServer
from relapse.util import Clock

from tests import unittest


class ConsentNoticesTests(unittest.HomeserverTestCase):
    servlets = [
        sync.register_servlets,
        relapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        tmpdir = self.mktemp()
        os.mkdir(tmpdir)
        self.consent_notice_message = "consent %(consent_uri)s"
        config = self.default_config()
        config["user_consent"] = {
            "version": "1",
            "template_dir": tmpdir,
            "server_notice_content": {
                "msgtype": "m.text",
                "body": self.consent_notice_message,
            },
        }
        config["public_baseurl"] = "https://example.com/"
        config["form_secret"] = "123abc"

        config["server_notices"] = {
            "system_mxid_localpart": "notices",
            "system_mxid_display_name": "test display name",
            "system_mxid_avatar_url": None,
            "room_name": "Server Notices",
        }

        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user_id = self.register_user("bob", "abc123")
        self.access_token = self.login("bob", "abc123")

    def test_get_sync_message(self) -> None:
        """
        When user consent server notices are enabled, a sync will cause a notice
        to fire (in a room which the user is invited to). The notice contains
        the notice URL + an authentication code.
        """
        # Initial sync, to get the user consent room invite
        channel = self.make_request(
            "GET", "/_matrix/client/r0/sync", access_token=self.access_token
        )
        self.assertEqual(channel.code, 200)

        # Get the Room ID to join
        room_id = list(channel.json_body["rooms"]["invite"].keys())[0]

        # Join the room
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/" + room_id + "/join",
            access_token=self.access_token,
        )
        self.assertEqual(channel.code, 200)

        # Sync again, to get the message in the room
        channel = self.make_request(
            "GET", "/_matrix/client/r0/sync", access_token=self.access_token
        )
        self.assertEqual(channel.code, 200)

        # Get the message
        room = channel.json_body["rooms"]["join"][room_id]
        messages = [
            x for x in room["timeline"]["events"] if x["type"] == "m.room.message"
        ]

        # One message, with the consent URL
        self.assertEqual(len(messages), 1)
        self.assertTrue(
            messages[0]["content"]["body"].startswith(
                "consent https://example.com/_matrix/consent"
            )
        )
