# Copyright 2021 The Matrix.org Foundation C.I.C.
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
import re
from typing import TYPE_CHECKING

from twisted.web.server import Request

from relapse.api.errors import RelapseError
from relapse.handlers.sso import get_username_mapping_session_cookie_from_request
from relapse.http.servlet import RestServlet

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class SsoRegisterServlet(RestServlet):
    """A servlet which completes SSO registration

    This servlet gets mounted at /_relapse/client/sso_register, and is shown
    after we collect username and/or consent for a new SSO user. It (finally) registers
    the user, and confirms redirect to the client
    """

    PATTERNS = [re.compile(r"/_relapse/client/sso_register$")]

    def __init__(self, hs: "HomeServer"):
        self._sso_handler = hs.get_sso_handler()

    async def on_GET(self, request: Request) -> None:
        try:
            session_id = get_username_mapping_session_cookie_from_request(request)
        except RelapseError as e:
            logger.warning("Error fetching session cookie: %s", e)
            self._sso_handler.render_error(request, "bad_session", e.msg, code=e.code)
            return
        await self._sso_handler.register_sso_user(request, session_id)
