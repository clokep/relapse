# Copyright 2018 New Vector
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
from http import HTTPStatus

from twisted.internet.testing import MemoryReactor

from relapse.api.urls import ConsentURIBuilder
from relapse.rest import admin
from relapse.rest.client import login, room
from relapse.rest.consent import ConsentServlet
from relapse.server import HomeServer
from relapse.util import Clock

from tests import unittest


class ConsentResourceTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
        lambda hs, http_server: ConsentServlet(hs).register(http_server),
    ]
    user_id = True
    hijack_auth = False

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["form_secret"] = "123abc"

        # Make some temporary templates...
        temp_consent_path = self.mktemp()
        os.mkdir(temp_consent_path)
        os.mkdir(os.path.join(temp_consent_path, "en"))

        config["user_consent"] = {
            "version": "1",
            "template_dir": os.path.abspath(temp_consent_path),
        }

        with open(os.path.join(temp_consent_path, "en/1.html"), "w") as f:
            f.write("{{version}},{{has_consented}}")

        with open(os.path.join(temp_consent_path, "en/success.html"), "w") as f:
            f.write("yay!")

        hs = self.setup_test_homeserver(config=config)
        return hs

    def test_render_public_consent(self) -> None:
        """You can observe the terms form without specifying a user"""
        channel = self.make_request(
            "GET",
            "/_matrix/consent?v=1",
            shorthand=False,
        )
        self.assertEqual(channel.code, HTTPStatus.OK)

    def test_accept_consent(self) -> None:
        """
        A user can use the consent form to accept the terms.
        """
        uri_builder = ConsentURIBuilder(self.hs.config)

        # Register a user
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Fetch the consent page, to get the consent version
        consent_uri = uri_builder.build_user_consent_uri(user_id)
        consent_uri = consent_uri[consent_uri.find("/_matrix") :] + "&u=user"
        channel = self.make_request(
            "GET",
            consent_uri,
            access_token=access_token,
            shorthand=False,
        )
        self.assertEqual(channel.code, HTTPStatus.OK)

        # Get the version from the body, and whether we've consented
        version, consented = channel.result["body"].decode("ascii").split(",")
        self.assertEqual(consented, "False")

        # POST to the consent page, saying we've agreed
        channel = self.make_request(
            "POST",
            consent_uri + "&v=" + version,
            access_token=access_token,
            shorthand=False,
        )
        self.assertEqual(channel.code, HTTPStatus.OK)

        # Fetch the consent page, to get the consent version -- it should have
        # changed
        channel = self.make_request(
            "GET",
            consent_uri,
            access_token=access_token,
            shorthand=False,
        )
        self.assertEqual(channel.code, HTTPStatus.OK)

        # Get the version from the body, and check that it's the version we
        # agreed to, and that we've consented to it.
        version, consented = channel.result["body"].decode("ascii").split(",")
        self.assertEqual(consented, "True")
        self.assertEqual(version, "1")
