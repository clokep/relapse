# Copyright 2017 New Vector Ltd
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
from typing import TYPE_CHECKING, Optional

from relapse.api.errors import Codes, RelapseError, StoreError
from relapse.handlers.device import DeviceHandler
from relapse.types import Requester

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class SetPasswordHandler:
    """Handler which deals with changing user account passwords"""

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self._auth_handler = hs.get_auth_handler()
        # This can only be instantiated on the main process.
        device_handler = hs.get_device_handler()
        assert isinstance(device_handler, DeviceHandler)
        self._device_handler = device_handler

    async def set_password(
        self,
        user_id: str,
        password_hash: str,
        logout_devices: bool,
        requester: Optional[Requester] = None,
    ) -> None:
        if not self._auth_handler.can_change_password():
            raise RelapseError(403, "Password change disabled", errcode=Codes.FORBIDDEN)

        try:
            await self.store.user_set_password_hash(user_id, password_hash)
        except StoreError as e:
            if e.code == 404:
                raise RelapseError(404, "Unknown user", Codes.NOT_FOUND)
            raise e

        # Optionally, log out all of the user's other sessions.
        if logout_devices:
            except_device_id = requester.device_id if requester else None
            except_access_token_id = requester.access_token_id if requester else None

            # First delete all of their other devices.
            await self._device_handler.delete_all_devices_for_user(
                user_id, except_device_id=except_device_id
            )

            # and now delete any access tokens which weren't associated with
            # devices (or were associated with this device).
            await self._auth_handler.delete_access_tokens_for_user(
                user_id, except_token_id=except_access_token_id
            )
