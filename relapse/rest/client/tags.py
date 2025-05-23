# Copyright 2015, 2016 OpenMarket Ltd
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

from relapse.api.errors import AuthError
from relapse.http.server import HttpServer
from relapse.http.servlet import RestServlet, parse_json_object_from_request
from relapse.http.site import RelapseRequest
from relapse.types import JsonDict

from ._base import client_patterns

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class TagListServlet(RestServlet):
    """
    GET /user/{user_id}/rooms/{room_id}/tags HTTP/1.1
    """

    PATTERNS = client_patterns(
        "/user/(?P<user_id>[^/]*)/rooms/(?P<room_id>[^/]*)/tags$"
    )
    CATEGORY = "Account data requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(
        self, request: RelapseRequest, user_id: str, room_id: str
    ) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        if user_id != requester.user.to_string():
            raise AuthError(403, "Cannot get tags for other users.")

        tags = await self.store.get_tags_for_room(user_id, room_id)

        return 200, {"tags": tags}


class TagServlet(RestServlet):
    """
    PUT /user/{user_id}/rooms/{room_id}/tags/{tag} HTTP/1.1
    DELETE /user/{user_id}/rooms/{room_id}/tags/{tag} HTTP/1.1
    """

    PATTERNS = client_patterns(
        "/user/(?P<user_id>[^/]*)/rooms/(?P<room_id>[^/]*)/tags/(?P<tag>[^/]*)"
    )
    CATEGORY = "Account data requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.handler = hs.get_account_data_handler()

    async def on_PUT(
        self, request: RelapseRequest, user_id: str, room_id: str, tag: str
    ) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        if user_id != requester.user.to_string():
            raise AuthError(403, "Cannot add tags for other users.")

        body = parse_json_object_from_request(request)

        await self.handler.add_tag_to_room(user_id, room_id, tag, body)

        return 200, {}

    async def on_DELETE(
        self, request: RelapseRequest, user_id: str, room_id: str, tag: str
    ) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        if user_id != requester.user.to_string():
            raise AuthError(403, "Cannot add tags for other users.")

        await self.handler.remove_tag_from_room(user_id, room_id, tag)

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    TagListServlet(hs).register(http_server)
    TagServlet(hs).register(http_server)
