# Copyright 2016 OpenMarket Ltd
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

from relapse.handlers.device import DeviceHandler
from relapse.http.server import HttpServer
from relapse.http.servlet import RestServlet
from relapse.http.site import RelapseRequest
from relapse.rest.client._base import client_patterns
from relapse.types import JsonDict

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class LogoutRestServlet(RestServlet):
    PATTERNS = client_patterns("/logout$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self._device_handler = handler

    async def on_POST(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(
            request, allow_expired=True, allow_locked=True
        )

        if requester.device_id is None:
            # The access token wasn't associated with a device.
            # Just delete the access token
            access_token = self.auth.get_access_token_from_request(request)
            await self._auth_handler.delete_access_token(access_token)
        else:
            await self._device_handler.delete_devices(
                requester.user.to_string(), [requester.device_id]
            )

        return 200, {}


class LogoutAllRestServlet(RestServlet):
    PATTERNS = client_patterns("/logout/all$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self._device_handler = handler

    async def on_POST(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(
            request, allow_expired=True, allow_locked=True
        )
        user_id = requester.user.to_string()

        # first delete all of the user's devices
        await self._device_handler.delete_all_devices_for_user(user_id)

        # .. and then delete any access tokens which weren't associated with
        # devices.
        await self._auth_handler.delete_access_tokens_for_user(user_id)
        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if hs.config.experimental.msc3861.enabled:
        return

    LogoutRestServlet(hs).register(http_server)
    LogoutAllRestServlet(hs).register(http_server)
