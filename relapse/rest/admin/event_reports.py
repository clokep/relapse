# Copyright 2020 Dirk Klimpel
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

from relapse.api.constants import Direction
from relapse.api.errors import Codes, NotFoundError, RelapseError
from relapse.http.servlet import RestServlet, parse_enum, parse_integer, parse_string
from relapse.http.site import RelapseRequest
from relapse.rest.admin._base import admin_patterns, assert_requester_is_admin
from relapse.types import JsonDict

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class EventReportsRestServlet(RestServlet):
    """
    List all reported events that are known to the homeserver. Results are returned
    in a dictionary containing report information. Supports pagination.
    The requester must have administrator access in Relapse.

    GET /_relapse/admin/v1/event_reports
    returns:
        200 OK with list of reports if success otherwise an error.

    Args:
        The parameters `from` and `limit` are required only for pagination.
        By default, a `limit` of 100 is used.
        The parameter `dir` can be used to define the order of results.
        The parameter `user_id` can be used to filter by user id.
        The parameter `room_id` can be used to filter by room id.
    Returns:
        A list of reported events and an integer representing the total number of
        reported events that exist given this query
    """

    PATTERNS = admin_patterns("/event_reports$")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)
        direction = parse_enum(request, "dir", Direction, Direction.BACKWARDS)
        user_id = parse_string(request, "user_id")
        room_id = parse_string(request, "room_id")

        if start < 0:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "The start parameter must be a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        if limit < 0:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "The limit parameter must be a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        event_reports, total = await self._store.get_event_reports_paginate(
            start, limit, direction, user_id, room_id
        )
        ret = {"event_reports": event_reports, "total": total}
        if (start + limit) < total:
            ret["next_token"] = start + len(event_reports)

        return HTTPStatus.OK, ret


class EventReportDetailRestServlet(RestServlet):
    """
    Get a specific reported event that is known to the homeserver. Results are returned
    in a dictionary containing report information.
    The requester must have administrator access in Relapse.

    GET /_relapse/admin/v1/event_reports/<report_id>
    returns:
        200 OK with details report if success otherwise an error.

    Args:
        The parameter `report_id` is the ID of the event report in the database.
    Returns:
        JSON blob of information about the event report
    """

    PATTERNS = admin_patterns("/event_reports/(?P<report_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(
        self, request: RelapseRequest, report_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        message = (
            "The report_id parameter must be a string representing a positive integer."
        )
        try:
            resolved_report_id = int(report_id)
        except ValueError:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, message, errcode=Codes.INVALID_PARAM
            )

        if resolved_report_id < 0:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, message, errcode=Codes.INVALID_PARAM
            )

        ret = await self._store.get_event_report(resolved_report_id)
        if not ret:
            raise NotFoundError("Event report not found")

        return HTTPStatus.OK, ret

    async def on_DELETE(
        self, request: RelapseRequest, report_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        message = (
            "The report_id parameter must be a string representing a positive integer."
        )
        try:
            resolved_report_id = int(report_id)
        except ValueError:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, message, errcode=Codes.INVALID_PARAM
            )

        if resolved_report_id < 0:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, message, errcode=Codes.INVALID_PARAM
            )

        if await self._store.delete_event_report(resolved_report_id):
            return HTTPStatus.OK, {}

        raise NotFoundError("Event report not found")
