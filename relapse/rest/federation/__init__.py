# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
# Copyright 2020 Sorunome
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
from collections.abc import Iterable
from typing import TYPE_CHECKING, Literal

from relapse.api.errors import FederationDeniedError, RelapseError
from relapse.http.server import HttpServer
from relapse.http.servlet import (
    parse_boolean_from_args,
    parse_integer_from_args,
    parse_string_from_args,
)
from relapse.rest.federation._base import (
    Authenticator,
    BaseFederationServlet,
)
from relapse.rest.federation.federation import (
    FEDERATION_SERVLET_CLASSES,
    FederationAccountStatusServlet,
    FederationUnstableClientKeysClaimServlet,
)
from relapse.types import JsonDict, StrCollection, ThirdPartyInstanceID
from relapse.util.ratelimitutils import FederationRateLimiter

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class PublicRoomList(BaseFederationServlet):
    """
    Fetch the public room list for this server.

    This API returns information in the same format as /publicRooms on the
    client API, but will only ever include local public rooms and hence is
    intended for consumption by other homeservers.

    GET /publicRooms HTTP/1.1

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "chunk": [
            {
                "aliases": [
                    "#test:localhost"
                ],
                "guest_can_join": false,
                "name": "test room",
                "num_joined_members": 3,
                "room_id": "!whkydVegtvatLfXmPN:localhost",
                "world_readable": false
            }
        ],
        "end": "END",
        "start": "START"
    }
    """

    PATH = "/publicRooms"
    CATEGORY = "Federation requests"

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_room_list_handler()
        self.allow_access = hs.config.server.allow_public_rooms_over_federation

    async def on_GET(
        self, origin: str, content: Literal[None], query: dict[bytes, list[bytes]]
    ) -> tuple[int, JsonDict]:
        if not self.allow_access:
            raise FederationDeniedError(origin)

        limit = parse_integer_from_args(query, "limit", 0)
        since_token = parse_string_from_args(query, "since", None)
        include_all_networks = parse_boolean_from_args(
            query, "include_all_networks", default=False
        )
        third_party_instance_id = parse_string_from_args(
            query, "third_party_instance_id", None
        )

        if include_all_networks:
            network_tuple = None
        elif third_party_instance_id:
            network_tuple = ThirdPartyInstanceID.from_string(third_party_instance_id)
        else:
            network_tuple = ThirdPartyInstanceID(None, None)

        if limit == 0:
            # zero is a special value which corresponds to no limit.
            limit = None

        data = await self.handler.get_local_public_room_list(
            limit, since_token, network_tuple=network_tuple, from_federation=True
        )
        return 200, data

    async def on_POST(
        self, origin: str, content: JsonDict, query: dict[bytes, list[bytes]]
    ) -> tuple[int, JsonDict]:
        # This implements MSC2197 (Search Filtering over Federation)
        if not self.allow_access:
            raise FederationDeniedError(origin)

        limit: int | None = int(content.get("limit", 100))
        since_token = content.get("since", None)
        search_filter = content.get("filter", None)

        include_all_networks = content.get("include_all_networks", False)
        third_party_instance_id = content.get("third_party_instance_id", None)

        if include_all_networks:
            network_tuple = None
            if third_party_instance_id is not None:
                raise RelapseError(
                    400, "Can't use include_all_networks with an explicit network"
                )
        elif third_party_instance_id is None:
            network_tuple = ThirdPartyInstanceID(None, None)
        else:
            network_tuple = ThirdPartyInstanceID.from_string(third_party_instance_id)

        if search_filter is None:
            logger.warning("Nonefilter")

        if limit == 0:
            # zero is a special value which corresponds to no limit.
            limit = None

        data = await self.handler.get_local_public_room_list(
            limit=limit,
            since_token=since_token,
            search_filter=search_filter,
            network_tuple=network_tuple,
            from_federation=True,
        )

        return 200, data


class OpenIdUserInfo(BaseFederationServlet):
    """
    Exchange a bearer token for information about a user.

    The response format should be compatible with:
        http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

    GET /openid/userinfo?access_token=ABDEFGH HTTP/1.1

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "sub": "@userpart:example.org",
    }
    """

    PATH = "/openid/userinfo"
    CATEGORY = "Federation requests"

    REQUIRE_AUTH = False

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_federation_server()

    async def on_GET(
        self,
        origin: str | None,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
    ) -> tuple[int, JsonDict]:
        token = parse_string_from_args(query, "access_token")
        if token is None:
            return (
                401,
                {"errcode": "M_MISSING_TOKEN", "error": "Access Token required"},
            )

        user_id = await self.handler.on_openid_userinfo(token)

        if user_id is None:
            return (
                401,
                {
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Access Token unknown or expired",
                },
            )

        return 200, {"sub": user_id}


SERVLET_GROUPS: dict[str, Iterable[type[BaseFederationServlet]]] = {
    "federation": FEDERATION_SERVLET_CLASSES,
    "room_list": (PublicRoomList,),
    "openid": (OpenIdUserInfo,),
}


def register_servlets(
    hs: "HomeServer",
    http_server: HttpServer,
    servlet_groups: StrCollection | None = None,
) -> None:
    """Initialize and register servlet classes.

    Will by default register all servlets. For custom behaviour, pass in
    a list of servlet_groups to register.

    Args:
        hs: homeserver
        http_server: router to register to
        servlet_groups: List of servlet groups to register.
            Defaults to ``DEFAULT_SERVLET_GROUPS``.
    """

    authenticator = Authenticator(hs)
    ratelimiter = hs.get_federation_ratelimiter()

    if not servlet_groups:
        servlet_groups = SERVLET_GROUPS.keys()

    for servlet_group in servlet_groups:
        # Skip unknown servlet groups.
        if servlet_group not in SERVLET_GROUPS:
            raise RuntimeError(
                f"Attempting to register unknown federation servlet: '{servlet_group}'"
            )

        for servletclass in SERVLET_GROUPS[servlet_group]:
            # Only allow the `/account_status` servlet if msc3720 is enabled
            if (
                servletclass == FederationAccountStatusServlet
                and not hs.config.experimental.msc3720_enabled
            ):
                continue
            if (
                servletclass == FederationUnstableClientKeysClaimServlet
                and not hs.config.experimental.msc3983_appservice_otk_claims
            ):
                continue

            servletclass(
                hs=hs,
                authenticator=authenticator,
                ratelimiter=ratelimiter,
                server_name=hs.hostname,
            ).register(http_server)
