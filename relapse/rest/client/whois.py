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
from http import HTTPStatus
from typing import TYPE_CHECKING

from relapse.api.errors import RelapseError
from relapse.http.server import HttpServer
from relapse.http.servlet import (
    RestServlet,
)
from relapse.http.site import RelapseRequest
from relapse.rest.admin._base import (
    assert_user_is_admin,
)
from relapse.rest.client._base import client_patterns
from relapse.types import JsonMapping, UserID

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class WhoisRestServlet(RestServlet):
    path_regex = "/whois/(?P<user_id>[^/]*)$"
    PATTERNS = client_patterns("/admin" + path_regex)

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()
        self.is_mine = hs.is_mine

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonMapping]:
        target_user = UserID.from_string(user_id)
        requester = await self.auth.get_user_by_req(request)

        if target_user != requester.user:
            await assert_user_is_admin(self.auth, requester)

        if not self.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only whois a local user")

        ret = await self.admin_handler.get_whois(target_user)

        return HTTPStatus.OK, ret


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    WhoisRestServlet(hs).register(http_server)
