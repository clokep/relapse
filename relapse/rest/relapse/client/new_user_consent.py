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
from collections.abc import Generator
from typing import TYPE_CHECKING

from twisted.web.server import Request

from relapse.api.errors import RelapseError
from relapse.handlers.sso import get_username_mapping_session_cookie_from_request
from relapse.http.server import DirectServeHtmlResource, respond_with_html
from relapse.http.servlet import parse_string
from relapse.http.site import RelapseRequest
from relapse.types import UserID
from relapse.util.templates import build_jinja_env

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class NewUserConsentResource(DirectServeHtmlResource):
    """A resource which collects consent to the server's terms from a new user

    This resource gets mounted at /_relapse/client/new_user_consent, and is shown
    when we are automatically creating a new user due to an SSO login.

    It shows a template which prompts the user to go and read the Ts and Cs, and click
    a clickybox if they have done so.
    """

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._sso_handler = hs.get_sso_handler()
        self._server_name = hs.hostname
        self._consent_version = hs.config.consent.user_consent_version

        def template_search_dirs() -> Generator[str, None, None]:
            if hs.config.server.custom_template_directory:
                yield hs.config.server.custom_template_directory
            if hs.config.sso.sso_template_dir:
                yield hs.config.sso.sso_template_dir
            yield hs.config.sso.default_template_dir

        self._jinja_env = build_jinja_env(list(template_search_dirs()), hs.config)

    async def _async_render_GET(self, request: Request) -> None:
        try:
            session_id = get_username_mapping_session_cookie_from_request(request)
            session = self._sso_handler.get_mapping_session(session_id)
        except RelapseError as e:
            logger.warning("Error fetching session: %s", e)
            self._sso_handler.render_error(request, "bad_session", e.msg, code=e.code)
            return

        # It should be impossible to get here without either the user or the mapping provider
        # having chosen a username, which ensures chosen_localpart gets set.
        if not session.chosen_localpart:
            logger.warning("Session has no user name selected")
            self._sso_handler.render_error(
                request, "no_user", "No user name has been selected.", code=400
            )
            return

        user_id = UserID(session.chosen_localpart, self._server_name)
        user_profile = {
            "display_name": session.display_name,
        }

        template_params = {
            "user_id": user_id.to_string(),
            "user_profile": user_profile,
            "consent_version": self._consent_version,
            "terms_url": "/_matrix/consent?v=%s" % (self._consent_version,),
        }

        template = self._jinja_env.get_template("sso_new_user_consent.html")
        html = template.render(template_params)
        respond_with_html(request, 200, html)

    async def _async_render_POST(self, request: RelapseRequest) -> None:
        try:
            session_id = get_username_mapping_session_cookie_from_request(request)
        except RelapseError as e:
            logger.warning("Error fetching session cookie: %s", e)
            self._sso_handler.render_error(request, "bad_session", e.msg, code=e.code)
            return

        try:
            accepted_version = parse_string(request, "accepted_version", required=True)
        except RelapseError as e:
            self._sso_handler.render_error(request, "bad_param", e.msg, code=e.code)
            return

        await self._sso_handler.handle_terms_accepted(
            request, session_id, accepted_version
        )
