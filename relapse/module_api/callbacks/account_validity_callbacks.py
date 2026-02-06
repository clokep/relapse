# Copyright 2023 The Matrix.org Foundation C.I.C.
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
from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

# Types for callbacks to be registered via the module api
IS_USER_EXPIRED_CALLBACK = Callable[[str], Awaitable[bool | None]]
ON_USER_REGISTRATION_CALLBACK = Callable[[str], Awaitable]
ON_USER_LOGIN_CALLBACK = Callable[[str, str | None, str | None], Awaitable]


class AccountValidityModuleApiCallbacks:
    def __init__(self) -> None:
        self.is_user_expired_callbacks: list[IS_USER_EXPIRED_CALLBACK] = []
        self.on_user_registration_callbacks: list[ON_USER_REGISTRATION_CALLBACK] = []
        self.on_user_login_callbacks: list[ON_USER_LOGIN_CALLBACK] = []

    def register_callbacks(
        self,
        is_user_expired: IS_USER_EXPIRED_CALLBACK | None = None,
        on_user_registration: ON_USER_REGISTRATION_CALLBACK | None = None,
        on_user_login: ON_USER_LOGIN_CALLBACK | None = None,
    ) -> None:
        """Register callbacks from module for each hook."""
        if is_user_expired is not None:
            self.is_user_expired_callbacks.append(is_user_expired)

        if on_user_registration is not None:
            self.on_user_registration_callbacks.append(on_user_registration)

        if on_user_login is not None:
            self.on_user_login_callbacks.append(on_user_login)
