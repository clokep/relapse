#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Optional, Union

from typing_extensions import Literal

from relapse.api.constants import Direction, EduTypes
from relapse.api.errors import Codes, RelapseError
from relapse.api.room_versions import RoomVersions
from relapse.api.urls import FEDERATION_UNSTABLE_PREFIX, FEDERATION_V2_PREFIX
from relapse.federation.transport.server._base import (
    Authenticator,
    BaseFederationServlet,
)
from relapse.http.servlet import (
    parse_boolean_from_args,
    parse_integer_from_args,
    parse_string_from_args,
    parse_strings_from_args,
)
from relapse.types import JsonDict
from relapse.util import RELAPSE_VERSION
from relapse.util.ratelimitutils import FederationRateLimiter

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)
issue_8631_logger = logging.getLogger("relapse.8631_debug")


class BaseFederationServerServlet(BaseFederationServlet):
    """Abstract base class for federation servlet classes which provides a federation server handler.

    See BaseFederationServlet for more information.
    """

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_federation_server()


class FederationSendServlet(BaseFederationServerServlet):
    PATH = "/send/(?P<transaction_id>[^/]*)/?"
    CATEGORY = "Inbound federation transaction request"

    # We ratelimit manually in the handler as we queue up the requests and we
    # don't want to fill up the ratelimiter with blocked requests.
    RATELIMIT = False

    # This is when someone is trying to send us a bunch of data.
    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        transaction_id: str,
    ) -> tuple[int, JsonDict]:
        """Called on PUT /send/<transaction_id>/

        Args:
            transaction_id: The transaction_id associated with this request. This
                is *not* None.

        Returns:
            Tuple of `(code, response)`, where
            `response` is a python dict to be converted into JSON that is
            used as the response body.
        """
        # Parse the request
        try:
            transaction_data = content

            logger.debug("Decoded %s: %s", transaction_id, str(transaction_data))

            logger.info(
                "Received txn %s from %s. (PDUs: %d, EDUs: %d)",
                transaction_id,
                origin,
                len(transaction_data.get("pdus", [])),
                len(transaction_data.get("edus", [])),
            )

            if issue_8631_logger.isEnabledFor(logging.DEBUG):
                DEVICE_UPDATE_EDUS = [
                    EduTypes.DEVICE_LIST_UPDATE,
                    EduTypes.SIGNING_KEY_UPDATE,
                ]
                device_list_updates = [
                    edu.get("content", {})
                    for edu in transaction_data.get("edus", [])
                    if edu.get("edu_type") in DEVICE_UPDATE_EDUS
                ]
                if device_list_updates:
                    issue_8631_logger.debug(
                        "received transaction [%s] including device list updates: %s",
                        transaction_id,
                        device_list_updates,
                    )

        except Exception as e:
            logger.exception(e)
            return 400, {"error": "Invalid transaction"}

        code, response = await self.handler.on_incoming_transaction(
            origin, transaction_id, self.server_name, transaction_data
        )

        return code, response


class FederationEventServlet(BaseFederationServerServlet):
    PATH = "/event/(?P<event_id>[^/]*)/?"
    CATEGORY = "Federation requests"

    # This is when someone asks for a data item for a given server data_id pair.
    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        event_id: str,
    ) -> tuple[int, Union[JsonDict, str]]:
        return await self.handler.on_pdu_request(origin, event_id)


class FederationStateV1Servlet(BaseFederationServerServlet):
    PATH = "/state/(?P<room_id>[^/]*)/?"
    CATEGORY = "Federation requests"

    # This is when someone asks for all data for a given room.
    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        return await self.handler.on_room_state_request(
            origin,
            room_id,
            parse_string_from_args(query, "event_id", None, required=True),
        )


class FederationStateIdsServlet(BaseFederationServerServlet):
    PATH = "/state_ids/(?P<room_id>[^/]*)/?"
    CATEGORY = "Federation requests"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        return await self.handler.on_state_ids_request(
            origin,
            room_id,
            parse_string_from_args(query, "event_id", None, required=True),
        )


class FederationBackfillServlet(BaseFederationServerServlet):
    PATH = "/backfill/(?P<room_id>[^/]*)/?"
    CATEGORY = "Federation requests"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        versions = [x.decode("ascii") for x in query[b"v"]]
        limit = parse_integer_from_args(query, "limit", None)

        if not limit:
            return 400, {"error": "Did not include limit param"}

        return await self.handler.on_backfill_request(origin, room_id, versions, limit)


class FederationTimestampLookupServlet(BaseFederationServerServlet):
    """
    API endpoint to fetch the `event_id` of the closest event to the given
    timestamp (`ts` query parameter) in the given direction (`dir` query
    parameter).

    Useful for other homeservers when they're unable to find an event locally.

    `ts` is a timestamp in milliseconds where we will find the closest event in
    the given direction.

    `dir` can be `f` or `b` to indicate forwards and backwards in time from the
    given timestamp.

    GET /_matrix/federation/v1/timestamp_to_event/<roomID>?ts=<timestamp>&dir=<direction>
    {
        "event_id": ...
    }
    """

    PATH = "/timestamp_to_event/(?P<room_id>[^/]*)/?"
    CATEGORY = "Federation requests"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        timestamp = parse_integer_from_args(query, "ts", required=True)
        direction_str = parse_string_from_args(
            query, "dir", allowed_values=["f", "b"], required=True
        )
        direction = Direction(direction_str)

        return await self.handler.on_timestamp_to_event_request(
            origin, room_id, timestamp, direction
        )


class FederationQueryServlet(BaseFederationServerServlet):
    PATH = "/query/(?P<query_type>[^/]*)"
    CATEGORY = "Federation requests"

    # This is when we receive a server-server Query
    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        query_type: str,
    ) -> tuple[int, JsonDict]:
        args = {k.decode("utf8"): v[0].decode("utf-8") for k, v in query.items()}
        args["origin"] = origin
        return await self.handler.on_query_request(query_type, args)


class FederationMakeJoinServlet(BaseFederationServerServlet):
    PATH = "/make_join/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
        user_id: str,
    ) -> tuple[int, JsonDict]:
        """
        Args:
            origin: The authenticated server_name of the calling server

            content: (GETs don't have bodies)

            query: Query params from the request.

            **kwargs: the dict mapping keys to path components as specified in
                the path match regexp.

        Returns:
            Tuple of (response code, response object)
        """
        supported_versions = parse_strings_from_args(query, "ver", encoding="utf-8")
        if supported_versions is None:
            supported_versions = ["1"]

        result = await self.handler.on_make_join_request(
            origin, room_id, user_id, supported_versions=supported_versions
        )
        return 200, result


class FederationMakeLeaveServlet(BaseFederationServerServlet):
    PATH = "/make_leave/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
        user_id: str,
    ) -> tuple[int, JsonDict]:
        result = await self.handler.on_make_leave_request(origin, room_id, user_id)
        return 200, result


class FederationV1SendLeaveServlet(BaseFederationServerServlet):
    PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
        event_id: str,
    ) -> tuple[int, tuple[int, JsonDict]]:
        result = await self.handler.on_send_leave_request(origin, content, room_id)
        return 200, (200, result)


class FederationV2SendLeaveServlet(BaseFederationServerServlet):
    PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    CATEGORY = "Federation requests"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
        event_id: str,
    ) -> tuple[int, JsonDict]:
        result = await self.handler.on_send_leave_request(origin, content, room_id)
        return 200, result


class FederationMakeKnockServlet(BaseFederationServerServlet):
    PATH = "/make_knock/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
        user_id: str,
    ) -> tuple[int, JsonDict]:
        # Retrieve the room versions the remote homeserver claims to support
        supported_versions = parse_strings_from_args(
            query, "ver", required=True, encoding="utf-8"
        )

        result = await self.handler.on_make_knock_request(
            origin, room_id, user_id, supported_versions=supported_versions
        )
        return 200, result


class FederationV1SendKnockServlet(BaseFederationServerServlet):
    PATH = "/send_knock/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
        event_id: str,
    ) -> tuple[int, JsonDict]:
        result = await self.handler.on_send_knock_request(origin, content, room_id)
        return 200, result


class FederationEventAuthServlet(BaseFederationServerServlet):
    PATH = "/event_auth/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
        event_id: str,
    ) -> tuple[int, JsonDict]:
        return await self.handler.on_event_auth(origin, room_id, event_id)


class FederationV1SendJoinServlet(BaseFederationServerServlet):
    PATH = "/send_join/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
        event_id: str,
    ) -> tuple[int, tuple[int, JsonDict]]:
        # TODO(paul): assert that event_id parsed from path actually
        #   match those given in content
        result = await self.handler.on_send_join_request(origin, content, room_id)
        return 200, (200, result)


class FederationV2SendJoinServlet(BaseFederationServerServlet):
    PATH = "/send_join/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    CATEGORY = "Federation requests"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
        event_id: str,
    ) -> tuple[int, JsonDict]:
        # TODO(paul): assert that event_id parsed from path actually
        #   match those given in content

        partial_state = parse_boolean_from_args(query, "omit_members", default=False)

        result = await self.handler.on_send_join_request(
            origin, content, room_id, caller_supports_partial_state=partial_state
        )
        return 200, result


class FederationV1InviteServlet(BaseFederationServerServlet):
    PATH = "/invite/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
        event_id: str,
    ) -> tuple[int, tuple[int, JsonDict]]:
        # We don't get a room version, so we have to assume its EITHER v1 or
        # v2. This is "fine" as the only difference between V1 and V2 is the
        # state resolution algorithm, and we don't use that for processing
        # invites
        result = await self.handler.on_invite_request(
            origin, content, room_version_id=RoomVersions.V1.identifier
        )

        # V1 federation API is defined to return a content of `[200, {...}]`
        # due to a historical bug.
        return 200, (200, result)


class FederationV2InviteServlet(BaseFederationServerServlet):
    PATH = "/invite/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    CATEGORY = "Federation requests"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
        event_id: str,
    ) -> tuple[int, JsonDict]:
        # TODO(paul): assert that room_id/event_id parsed from path actually
        #   match those given in content

        room_version = content["room_version"]
        event = content["event"]
        invite_room_state = content.get("invite_room_state", [])

        # Relapse expects invite_room_state to be in unsigned, as it is in v1
        # API

        event.setdefault("unsigned", {})["invite_room_state"] = invite_room_state

        result = await self.handler.on_invite_request(
            origin, event, room_version_id=room_version
        )

        # We only store invite_room_state for internal use, so remove it before
        # returning the event to the remote homeserver.
        result["event"].get("unsigned", {}).pop("invite_room_state", None)

        return 200, result


class FederationThirdPartyInviteExchangeServlet(BaseFederationServerServlet):
    PATH = "/exchange_third_party_invite/(?P<room_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        await self.handler.on_exchange_third_party_invite_request(content)
        return 200, {}


class FederationClientKeysQueryServlet(BaseFederationServerServlet):
    PATH = "/user/keys/query"
    CATEGORY = "Federation requests"

    async def on_POST(
        self, origin: str, content: JsonDict, query: dict[bytes, list[bytes]]
    ) -> tuple[int, JsonDict]:
        return await self.handler.on_query_client_keys(origin, content)


class FederationUserDevicesQueryServlet(BaseFederationServerServlet):
    PATH = "/user/devices/(?P<user_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        user_id: str,
    ) -> tuple[int, JsonDict]:
        return await self.handler.on_query_user_devices(origin, user_id)


class FederationClientKeysClaimServlet(BaseFederationServerServlet):
    PATH = "/user/keys/claim"
    CATEGORY = "Federation requests"

    async def on_POST(
        self, origin: str, content: JsonDict, query: dict[bytes, list[bytes]]
    ) -> tuple[int, JsonDict]:
        # Generate a count for each algorithm, which is hard-coded to 1.
        key_query: list[tuple[str, str, str, int]] = []
        for user_id, device_keys in content.get("one_time_keys", {}).items():
            for device_id, algorithm in device_keys.items():
                key_query.append((user_id, device_id, algorithm, 1))

        response = await self.handler.on_claim_client_keys(
            key_query, always_include_fallback_keys=False
        )
        return 200, response


class FederationUnstableClientKeysClaimServlet(BaseFederationServerServlet):
    """
    Identical to the stable endpoint (FederationClientKeysClaimServlet) except
    it allows for querying for multiple OTKs at once and always includes fallback
    keys in the response.
    """

    PREFIX = FEDERATION_UNSTABLE_PREFIX
    PATH = "/user/keys/claim"
    CATEGORY = "Federation requests"

    async def on_POST(
        self, origin: str, content: JsonDict, query: dict[bytes, list[bytes]]
    ) -> tuple[int, JsonDict]:
        # Generate a count for each algorithm.
        key_query: list[tuple[str, str, str, int]] = []
        for user_id, device_keys in content.get("one_time_keys", {}).items():
            for device_id, algorithms in device_keys.items():
                counts = Counter(algorithms)
                for algorithm, count in counts.items():
                    key_query.append((user_id, device_id, algorithm, count))

        response = await self.handler.on_claim_client_keys(
            key_query, always_include_fallback_keys=True
        )
        return 200, response


class FederationGetMissingEventsServlet(BaseFederationServerServlet):
    PATH = "/get_missing_events/(?P<room_id>[^/]*)"
    CATEGORY = "Federation requests"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: dict[bytes, list[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        limit = int(content.get("limit", 10))
        earliest_events = content.get("earliest_events", [])
        latest_events = content.get("latest_events", [])

        result = await self.handler.on_get_missing_events(
            origin,
            room_id=room_id,
            earliest_events=earliest_events,
            latest_events=latest_events,
            limit=limit,
        )

        return 200, result


class On3pidBindServlet(BaseFederationServerServlet):
    PATH = "/3pid/onbind"
    CATEGORY = "Federation requests"

    REQUIRE_AUTH = False

    async def on_POST(
        self, origin: Optional[str], content: JsonDict, query: dict[bytes, list[bytes]]
    ) -> tuple[int, JsonDict]:
        if "invites" in content:
            last_exception = None
            for invite in content["invites"]:
                try:
                    if "signed" not in invite or "token" not in invite["signed"]:
                        message = (
                            "Rejecting received notification of third-"
                            "party invite without signed: %s" % (invite,)
                        )
                        logger.info(message)
                        raise RelapseError(400, message)
                    await self.handler.exchange_third_party_invite(
                        invite["sender"],
                        invite["mxid"],
                        invite["room_id"],
                        invite["signed"],
                    )
                except Exception as e:
                    last_exception = e
            if last_exception:
                raise last_exception
        return 200, {}


class FederationVersionServlet(BaseFederationServlet):
    PATH = "/version"
    CATEGORY = "Federation requests"

    REQUIRE_AUTH = False

    async def on_GET(
        self,
        origin: Optional[str],
        content: Literal[None],
        query: dict[bytes, list[bytes]],
    ) -> tuple[int, JsonDict]:
        return (
            200,
            {
                "server": {
                    "name": "Relapse",
                    "version": RELAPSE_VERSION,
                }
            },
        )


class FederationRoomHierarchyServlet(BaseFederationServlet):
    PATH = "/hierarchy/(?P<room_id>[^/]*)"
    CATEGORY = "Federation requests"

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_room_summary_handler()

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Mapping[bytes, Sequence[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        suggested_only = parse_boolean_from_args(query, "suggested_only", default=False)
        return 200, await self.handler.get_federation_hierarchy(
            origin, room_id, suggested_only
        )


class RoomComplexityServlet(BaseFederationServlet):
    """
    Indicates to other servers how complex (and therefore likely
    resource-intensive) a public room this server knows about is.
    """

    PATH = "/rooms/(?P<room_id>[^/]*)/complexity"
    PREFIX = FEDERATION_UNSTABLE_PREFIX
    CATEGORY = "Federation requests (unstable)"

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self._store = self.hs.get_datastores().main

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: dict[bytes, list[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        is_public = await self._store.is_room_world_readable_or_publicly_joinable(
            room_id
        )

        if not is_public:
            raise RelapseError(404, "Room not found", errcode=Codes.INVALID_PARAM)

        complexity = await self._store.get_room_complexity(room_id)
        return 200, complexity


class FederationAccountStatusServlet(BaseFederationServerServlet):
    PATH = "/query/account_status"
    PREFIX = FEDERATION_UNSTABLE_PREFIX + "/org.matrix.msc3720"

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self._account_handler = hs.get_account_handler()

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Mapping[bytes, Sequence[bytes]],
        room_id: str,
    ) -> tuple[int, JsonDict]:
        if "user_ids" not in content:
            raise RelapseError(
                400, "Required parameter 'user_ids' is missing", Codes.MISSING_PARAM
            )

        statuses, failures = await self._account_handler.get_account_statuses(
            content["user_ids"],
            allow_remote=False,
        )

        return 200, {"account_statuses": statuses, "failures": failures}


FEDERATION_SERVLET_CLASSES: tuple[type[BaseFederationServlet], ...] = (
    FederationSendServlet,
    FederationEventServlet,
    FederationStateV1Servlet,
    FederationStateIdsServlet,
    FederationBackfillServlet,
    FederationTimestampLookupServlet,
    FederationQueryServlet,
    FederationMakeJoinServlet,
    FederationMakeLeaveServlet,
    FederationEventServlet,
    FederationV1SendJoinServlet,
    FederationV2SendJoinServlet,
    FederationV1SendLeaveServlet,
    FederationV2SendLeaveServlet,
    FederationV1InviteServlet,
    FederationV2InviteServlet,
    FederationGetMissingEventsServlet,
    FederationEventAuthServlet,
    FederationClientKeysQueryServlet,
    FederationUserDevicesQueryServlet,
    FederationClientKeysClaimServlet,
    FederationUnstableClientKeysClaimServlet,
    FederationThirdPartyInviteExchangeServlet,
    On3pidBindServlet,
    FederationVersionServlet,
    RoomComplexityServlet,
    FederationRoomHierarchyServlet,
    FederationV1SendKnockServlet,
    FederationMakeKnockServlet,
    FederationAccountStatusServlet,
)
