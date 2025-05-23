# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import logging
from typing import TYPE_CHECKING

from twisted.web.server import Request

from relapse.http.server import HttpServer
from relapse.http.servlet import RestServlet
from relapse.types import JsonDict

from ._base import client_patterns

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class PasswordPolicyServlet(RestServlet):
    PATTERNS = client_patterns("/password_policy$")
    CATEGORY = "Registration/login requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()

        self.policy = hs.config.auth.password_policy
        self.enabled = hs.config.auth.password_policy_enabled

    def on_GET(self, request: Request) -> tuple[int, JsonDict]:
        if not self.enabled or not self.policy:
            return 200, {}

        policy = {}

        for param in [
            "minimum_length",
            "require_digit",
            "require_symbol",
            "require_lowercase",
            "require_uppercase",
        ]:
            if param in self.policy:
                policy["m.%s" % param] = self.policy[param]

        return 200, policy


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    PasswordPolicyServlet(hs).register(http_server)
