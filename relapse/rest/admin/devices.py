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

from relapse.api.errors import NotFoundError, RelapseError
from relapse.handlers.device import DeviceHandler
from relapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from relapse.http.site import RelapseRequest
from relapse.rest.admin._base import admin_patterns, assert_requester_is_admin
from relapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class DeviceRestServlet(RestServlet):
    """
    Get, update or delete the given user's device
    """

    PATTERNS = admin_patterns(
        "/users/(?P<user_id>[^/]*)/devices/(?P<device_id>[^/]*)$", "v2"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.device_handler = handler
        self.store = hs.get_datastores().main
        self.is_mine = hs.is_mine

    async def on_GET(
        self, request: RelapseRequest, user_id: str, device_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        device = await self.device_handler.get_device(
            target_user.to_string(), device_id
        )
        if device is None:
            raise NotFoundError("No device found")
        return HTTPStatus.OK, device

    async def on_DELETE(
        self, request: RelapseRequest, user_id: str, device_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        await self.device_handler.delete_devices(target_user.to_string(), [device_id])
        return HTTPStatus.OK, {}

    async def on_PUT(
        self, request: RelapseRequest, user_id: str, device_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        body = parse_json_object_from_request(request, allow_empty_body=True)
        await self.device_handler.update_device(
            target_user.to_string(), device_id, body
        )
        return HTTPStatus.OK, {}


class DevicesRestServlet(RestServlet):
    """
    Retrieve the given user's devices
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/devices$", "v2")

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.device_handler = handler
        self.store = hs.get_datastores().main
        self.is_mine = hs.is_mine

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        devices = await self.device_handler.get_devices_by_user(target_user.to_string())
        return HTTPStatus.OK, {"devices": devices, "total": len(devices)}

    async def on_POST(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        """Creates a new device for the user."""
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Can only create devices for local users"
            )

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        body = parse_json_object_from_request(request)
        device_id = body.get("device_id")
        if not device_id:
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Missing device_id")
        if not isinstance(device_id, str):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "device_id must be a string")

        await self.device_handler.check_device_registered(
            user_id=user_id, device_id=device_id
        )

        return HTTPStatus.CREATED, {}


class DeleteDevicesRestServlet(RestServlet):
    """
    API for bulk deletion of devices. Accepts a JSON object with a devices
    key which lists the device_ids to delete.
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/delete_devices$", "v2")

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.device_handler = handler
        self.store = hs.get_datastores().main
        self.is_mine = hs.is_mine

    async def on_POST(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only lookup local users")

        u = await self.store.get_user_by_id(target_user.to_string())
        if u is None:
            raise NotFoundError("Unknown user")

        body = parse_json_object_from_request(request, allow_empty_body=False)
        assert_params_in_dict(body, ["devices"])

        await self.device_handler.delete_devices(
            target_user.to_string(), body["devices"]
        )
        return HTTPStatus.OK, {}
