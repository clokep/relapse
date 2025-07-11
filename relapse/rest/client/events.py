# Copyright 2014-2016 OpenMarket Ltd
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

"""This module contains REST servlets to do with event streaming, /events."""

import logging
from typing import TYPE_CHECKING, Union

from relapse.api.errors import RelapseError
from relapse.events.utils import SerializeEventConfig
from relapse.http.server import HttpServer
from relapse.http.servlet import RestServlet, parse_string
from relapse.http.site import RelapseRequest
from relapse.rest.client._base import client_patterns
from relapse.streams.config import PaginationConfig
from relapse.types import JsonDict

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class EventStreamRestServlet(RestServlet):
    PATTERNS = client_patterns("/events$")
    CATEGORY = "Sync requests"

    DEFAULT_LONGPOLL_TIME_MS = 30000

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.event_stream_handler = hs.get_event_stream_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        args: dict[bytes, list[bytes]] = request.args  # type: ignore
        if requester.is_guest:
            if b"room_id" not in args:
                raise RelapseError(400, "Guest users must specify room_id param")
        room_id = parse_string(request, "room_id")

        pagin_config = await PaginationConfig.from_request(
            self.store, request, default_limit=10
        )
        timeout = EventStreamRestServlet.DEFAULT_LONGPOLL_TIME_MS
        if b"timeout" in args:
            try:
                timeout = int(args[b"timeout"][0])
            except ValueError:
                raise RelapseError(400, "timeout must be in milliseconds.")

        as_client_event = b"raw" not in args

        chunk = await self.event_stream_handler.get_stream(
            requester,
            pagin_config,
            timeout=timeout,
            as_client_event=as_client_event,
            affect_presence=(not requester.is_guest),
            room_id=room_id,
        )

        return 200, chunk


class EventRestServlet(RestServlet):
    PATTERNS = client_patterns("/events/(?P<event_id>[^/]*)$")
    CATEGORY = "Client API requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.clock = hs.get_clock()
        self.event_handler = hs.get_event_handler()
        self.auth = hs.get_auth()
        self._event_serializer = hs.get_event_client_serializer()

    async def on_GET(
        self, request: RelapseRequest, event_id: str
    ) -> tuple[int, Union[str, JsonDict]]:
        requester = await self.auth.get_user_by_req(request)
        event = await self.event_handler.get_event(requester.user, None, event_id)

        if event:
            result = await self._event_serializer.serialize_event(
                event,
                self.clock.time_msec(),
                config=SerializeEventConfig(requester=requester),
            )
            return 200, result
        else:
            return 404, "Event not found."


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    EventStreamRestServlet(hs).register(http_server)
    EventRestServlet(hs).register(http_server)
