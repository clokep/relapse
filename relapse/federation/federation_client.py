# Copyright 2015-2022 The Matrix.org Foundation C.I.C.
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


import copy
import itertools
import logging
from collections.abc import (
    Awaitable,
    Callable,
    Collection,
    Container,
    Iterable,
    Mapping,
    Sequence,
    Set,
)
from typing import TYPE_CHECKING, Any, BinaryIO, TypeVar

import attr
from prometheus_client import Counter

from relapse.api.constants import Direction, EventContentFields, EventTypes, Membership
from relapse.api.errors import (
    CodeMessageException,
    Codes,
    FederationDeniedError,
    HttpResponseException,
    RelapseError,
    RequestSendFailed,
    UnsupportedRoomVersionError,
)
from relapse.api.room_versions import (
    KNOWN_ROOM_VERSIONS,
    EventFormatVersions,
    RoomVersion,
    RoomVersions,
)
from relapse.api.urls import FEDERATION_UNSTABLE_PREFIX, FEDERATION_V1_PREFIX
from relapse.events import EventBase, builder, make_event_from_dict
from relapse.federation.federation_base import (
    FederationBase,
    InvalidEventSignatureError,
    event_from_pdu_json,
)
from relapse.federation.federation_client_helpers import (
    SendJoinParser,
    SendJoinResponse,
    TimestampToEventResponse,
    _create_path,
    _create_v1_path,
    _create_v2_path,
    _StateParser,
    _validate_hierarchy_event,
)
from relapse.federation.units import Transaction
from relapse.http.client import is_unknown_endpoint
from relapse.http.matrixfederationclient import LegacyJsonSendParser
from relapse.http.types import QueryParams
from relapse.logging.opentracing import RelapseTags, log_kv, set_tag, tag_args, trace
from relapse.types import JsonDict, StrCollection, UserID, get_domain_from_id
from relapse.util.async_helpers import concurrently_execute
from relapse.util.caches.expiringcache import ExpiringCache
from relapse.util.retryutils import NotRetryingDestination

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)

sent_queries_counter = Counter("relapse_federation_client_sent_queries", "", ["type"])


PDU_RETRY_TIME_MS = 1 * 60 * 1000

T = TypeVar("T")


@attr.s(frozen=True, slots=True, auto_attribs=True)
class PulledPduInfo:
    """
    A result object that stores the PDU and info about it like which homeserver we
    pulled it from (`pull_origin`)
    """

    pdu: EventBase
    # Which homeserver we pulled the PDU from
    pull_origin: str


class InvalidResponseError(RuntimeError):
    """Helper for _try_destination_list: indicates that the server returned a response
    we couldn't parse
    """


@attr.s(slots=True, frozen=True, auto_attribs=True)
class SendJoinResult:
    # The event to persist.
    event: EventBase
    # A string giving the server the event was sent to.
    origin: str
    state: list[EventBase]
    auth_chain: list[EventBase]

    # True if 'state' elides non-critical membership events
    partial_state: bool

    # If 'partial_state' is set, a set of the servers in the room (otherwise empty).
    # Always contains the server we joined off.
    servers_in_room: Set[str]


class FederationClient(FederationBase):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.pdu_destination_tried: dict[str, dict[str, int]] = {}
        self._clock.looping_call(self._clear_tried_cache, 60 * 1000)
        self.state = hs.get_state_handler()
        self.client = hs.get_federation_http_client()
        self._is_mine_server_name = hs.is_mine_server_name

        self.hostname = hs.hostname
        self.signing_key = hs.signing_key

        # Cache mapping `event_id` to a tuple of the event itself and the `pull_origin`
        # (which server we pulled the event from)
        self._get_pdu_cache: ExpiringCache[str, tuple[EventBase, str]] = ExpiringCache(
            cache_name="get_pdu_cache",
            clock=self._clock,
            max_len=1000,
            expiry_ms=120 * 1000,
            reset_expiry_on_get=False,
        )

        # A cache for fetching the room hierarchy over federation.
        #
        # Some stale data over federation is OK, but must be refreshed
        # periodically since the local server is in the room.
        #
        # It is a map of (room ID, suggested-only) -> the response of
        # get_room_hierarchy.
        self._get_room_hierarchy_cache: ExpiringCache[
            tuple[str, bool],
            tuple[JsonDict, Sequence[JsonDict], Sequence[JsonDict], Sequence[str]],
        ] = ExpiringCache(
            cache_name="get_room_hierarchy_cache",
            clock=self._clock,
            max_len=1000,
            expiry_ms=5 * 60 * 1000,
            reset_expiry_on_get=False,
        )

    def _clear_tried_cache(self) -> None:
        """Clear pdu_destination_tried cache"""
        now = self._clock.time_msec()

        old_dict = self.pdu_destination_tried
        self.pdu_destination_tried = {}

        for event_id, destination_dict in old_dict.items():
            destination_dict = {
                dest: time
                for dest, time in destination_dict.items()
                if time + PDU_RETRY_TIME_MS > now
            }
            if destination_dict:
                self.pdu_destination_tried[event_id] = destination_dict

    async def make_query(
        self,
        destination: str,
        query_type: str,
        args: QueryParams,
        retry_on_dns_fail: bool = False,
        ignore_backoff: bool = False,
    ) -> JsonDict:
        """Sends a federation Query to a remote homeserver of the given type
        and arguments.

        Args:
            destination: Domain name of the remote homeserver
            query_type: Category of the query type; should match the
                handler name used in register_query_handler().
            args: Mapping of strings to strings containing the details
                of the query request.
            ignore_backoff: true to ignore the historical backoff data
                and try the request anyway.

        Returns:
            The JSON object from the response
        """
        sent_queries_counter.labels(query_type).inc()

        path = _create_path(FEDERATION_V1_PREFIX, "/query/%s", query_type)

        return await self.client.get_json(
            destination=destination,
            path=path,
            args=args,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=10000,
            ignore_backoff=ignore_backoff,
        )

    async def query_client_keys(
        self, destination: str, content: JsonDict, timeout: int
    ) -> JsonDict:
        """Query device keys for a device hosted on a remote server.

        Args:
            destination: Domain name of the remote homeserver
            content: The query content.

        Returns:
            The JSON object from the response
        """
        sent_queries_counter.labels("client_device_keys").inc()
        path = _create_v1_path("/user/keys/query")
        return await self.client.post_json(
            destination=destination, path=path, data=content, timeout=timeout
        )

    async def query_user_devices(
        self, destination: str, user_id: str, timeout: int = 30000
    ) -> JsonDict:
        """Query the device keys for a list of user ids hosted on a remote
        server.
        """
        sent_queries_counter.labels("user_devices").inc()
        path = _create_v1_path("/user/devices/%s", user_id)
        return await self.client.get_json(
            destination=destination, path=path, timeout=timeout
        )

    async def claim_client_keys(
        self,
        user: UserID,
        destination: str,
        query: dict[str, dict[str, dict[str, int]]],
        timeout: int | None,
    ) -> JsonDict:
        """Claims one-time keys for a device hosted on a remote server.

        Args:
            user: The user id of the requesting user
            destination: Domain name of the remote homeserver
            content: The query content.

        Returns:
            The JSON object from the response
        """
        sent_queries_counter.labels("client_one_time_keys").inc()

        # Convert the query with counts into a stable and unstable query and check
        # if attempting to claim more than 1 OTK.
        content: dict[str, dict[str, str]] = {}
        unstable_content: dict[str, dict[str, list[str]]] = {}
        use_unstable = False
        for user_id, one_time_keys in query.items():
            for device_id, algorithms in one_time_keys.items():
                # If more than one algorithm is requested, attempt to use the unstable
                # endpoint.
                if sum(algorithms.values()) > 1:
                    use_unstable = True
                if algorithms:
                    # For the stable query, choose only the first algorithm.
                    content.setdefault(user_id, {})[device_id] = next(iter(algorithms))
                    # For the unstable query, repeat each algorithm by count, then
                    # splat those into chain to get a flattened list of all algorithms.
                    #
                    # Converts from {"algo1": 2, "algo2": 2} to ["algo1", "algo1", "algo2"].
                    unstable_content.setdefault(user_id, {})[device_id] = list(
                        itertools.chain(
                            *(
                                itertools.repeat(algorithm, count)
                                for algorithm, count in algorithms.items()
                            )
                        )
                    )

        if use_unstable:
            try:
                path = _create_path(FEDERATION_UNSTABLE_PREFIX, "/user/keys/claim")
                return await self.client.post_json(
                    destination=destination,
                    path=path,
                    data={"one_time_keys": unstable_content},
                    timeout=timeout,
                )
            except HttpResponseException as e:
                # If an error is received that is due to an unrecognised endpoint,
                # fallback to the v1 endpoint. Otherwise, consider it a legitimate error
                # and raise.
                if not is_unknown_endpoint(e):
                    raise

            logger.debug(
                "Couldn't claim client keys with the unstable API, falling back to the v1 API"
            )
        else:
            logger.debug("Skipping unstable claim client keys API")

        # TODO Potentially attempt multiple queries and combine the results?
        path = _create_v1_path("/user/keys/claim")
        return await self.client.post_json(
            destination=destination,
            path=path,
            data={"one_time_keys": content},
            timeout=timeout,
        )

    @trace
    @tag_args
    async def backfill(
        self, destination: str, room_id: str, limit: int, extremities: Collection[str]
    ) -> list[EventBase] | None:
        """Requests some more historic PDUs for the given room from the
        given destination server.

        Args:
            dest: The remote homeserver to ask.
            room_id: The room_id to backfill.
            limit: The maximum number of events to return.
            extremities: our current backwards extremities, to backfill from
                Must be a Collection that is falsy when empty.
                (Iterable is not enough here!)
        """
        logger.debug("backfill extrem=%s", extremities)

        # If there are no extremities then we've (probably) reached the start.
        if not extremities:
            return None

        logger.debug(
            "backfill dest=%s, room_id=%s, event_tuples=%r, limit=%s",
            destination,
            room_id,
            extremities,
            str(limit),
        )

        path = _create_v1_path("/backfill/%s", room_id)

        args = {"v": extremities, "limit": [str(limit)]}

        transaction_data = await self.client.get_json(
            destination, path=path, args=args, try_trailing_slash_on_400=True
        )

        logger.debug("backfill transaction_data=%r", transaction_data)

        if not isinstance(transaction_data, dict):
            raise InvalidResponseError("Backfill transaction_data is not a dict.")

        transaction_data_pdus = transaction_data.get("pdus")
        if not isinstance(transaction_data_pdus, list):
            raise InvalidResponseError("transaction_data.pdus is not a list.")

        room_version = await self.store.get_room_version(room_id)

        pdus = [event_from_pdu_json(p, room_version) for p in transaction_data_pdus]

        # Check signatures and hash of pdus, removing any from the list that fail checks
        pdus[:] = await self._check_sigs_and_hash_for_pulled_events_and_fetch(
            destination, pdus, room_version=room_version
        )

        return pdus

    async def get_pdu_from_destination_raw(
        self,
        destination: str,
        event_id: str,
        room_version: RoomVersion,
        timeout: int | None = None,
    ) -> EventBase | None:
        """Requests the PDU with given origin and ID from the remote home
        server. Does not have any caching or rate limiting!

        Args:
            destination: Which homeserver to query
            event_id: event to fetch
            room_version: version of the room
            timeout: How long to try (in ms) each destination for before
                moving to the next destination. None indicates no timeout.

        Returns:
            A copy of the requested PDU that is safe to modify, or None if we
            were unable to find it.

        Raises:
            RelapseError, NotRetryingDestination, FederationDeniedError
        """
        logger.debug("get_pdu dest=%s, event_id=%s", destination, event_id)

        path = _create_v1_path("/event/%s", event_id)
        transaction_data = await self.client.get_json(
            destination, path=path, timeout=timeout, try_trailing_slash_on_400=True
        )

        logger.debug(
            "get_pdu_from_destination_raw: retrieved event id %s from %s: %r",
            event_id,
            destination,
            transaction_data,
        )

        pdu_list: list[EventBase] = [
            event_from_pdu_json(p, room_version) for p in transaction_data["pdus"]
        ]

        if pdu_list and pdu_list[0]:
            pdu = pdu_list[0]

            # Check signatures are correct.
            try:

                async def _record_failure_callback(
                    event: EventBase, cause: str
                ) -> None:
                    await self.store.record_event_failed_pull_attempt(
                        event.room_id, event.event_id, cause
                    )

                signed_pdu = await self._check_sigs_and_hash(
                    room_version, pdu, _record_failure_callback
                )
            except InvalidEventSignatureError as e:
                errmsg = f"event id {pdu.event_id}: {e}"
                logger.warning("%s", errmsg)
                raise RelapseError(403, errmsg, Codes.FORBIDDEN)

            return signed_pdu

        return None

    @trace
    @tag_args
    async def get_pdu(
        self,
        destinations: Collection[str],
        event_id: str,
        room_version: RoomVersion,
        timeout: int | None = None,
    ) -> PulledPduInfo | None:
        """Requests the PDU with given origin and ID from the remote home
        servers.

        Will attempt to get the PDU from each destination in the list until
        one succeeds.

        Args:
            destinations: Which homeservers to query
            event_id: event to fetch
            room_version: version of the room
            timeout: How long to try (in ms) each destination for before
                moving to the next destination. None indicates no timeout.

        Returns:
            The requested PDU wrapped in `PulledPduInfo`, or None if we were unable to find it.
        """

        logger.debug(
            "get_pdu(event_id=%s): from destinations=%s", event_id, destinations
        )

        # TODO: Rate limit the number of times we try and get the same event.

        # We might need the same event multiple times in quick succession (before
        # it gets persisted to the database), so we cache the results of the lookup.
        # Note that this is separate to the regular get_event cache which caches
        # events once they have been persisted.
        get_pdu_cache_entry = self._get_pdu_cache.get(event_id)

        event = None
        pull_origin = None
        if get_pdu_cache_entry:
            event, pull_origin = get_pdu_cache_entry
        # If we don't see the event in the cache, go try to fetch it from the
        # provided remote federated destinations
        else:
            pdu_attempts = self.pdu_destination_tried.setdefault(event_id, {})

            # TODO: We can probably refactor this to use `_try_destination_list`
            for destination in destinations:
                now = self._clock.time_msec()
                last_attempt = pdu_attempts.get(destination, 0)
                if last_attempt + PDU_RETRY_TIME_MS > now:
                    logger.debug(
                        "get_pdu(event_id=%s): skipping destination=%s because we tried it recently last_attempt=%s and we only check every %s (now=%s)",
                        event_id,
                        destination,
                        last_attempt,
                        PDU_RETRY_TIME_MS,
                        now,
                    )
                    continue

                try:
                    event = await self.get_pdu_from_destination_raw(
                        destination=destination,
                        event_id=event_id,
                        room_version=room_version,
                        timeout=timeout,
                    )
                    pull_origin = destination

                    pdu_attempts[destination] = now

                    if event:
                        # Prime the cache
                        self._get_pdu_cache[event.event_id] = (event, pull_origin)

                        # Now that we have an event, we can break out of this
                        # loop and stop asking other destinations.
                        break

                except NotRetryingDestination as e:
                    logger.info("get_pdu(event_id=%s): %s", event_id, e)
                    continue
                except FederationDeniedError:
                    logger.info(
                        "get_pdu(event_id=%s): Not attempting to fetch PDU from %s because the homeserver is not on our federation whitelist",
                        event_id,
                        destination,
                    )
                    continue
                except RelapseError as e:
                    logger.info(
                        "get_pdu(event_id=%s): Failed to get PDU from %s because %s",
                        event_id,
                        destination,
                        e,
                    )
                    continue
                except Exception as e:
                    pdu_attempts[destination] = now

                    logger.info(
                        "get_pdu(event_id=%s): Failed to get PDU from %s because %s",
                        event_id,
                        destination,
                        e,
                    )
                    continue

        if not event or not pull_origin:
            return None

        # `event` now refers to an object stored in `get_pdu_cache`. Our
        # callers may need to modify the returned object (eg to set
        # `event.internal_metadata.outlier = true`), so we return a copy
        # rather than the original object.
        event_copy = make_event_from_dict(
            event.get_pdu_json(),
            event.room_version,
        )

        return PulledPduInfo(event_copy, pull_origin)

    @trace
    @tag_args
    async def get_room_state_ids(
        self, destination: str, room_id: str, event_id: str
    ) -> tuple[list[str], list[str]]:
        """Calls the /state_ids endpoint to fetch the state at a particular point
        in the room, and the auth events for the given event

        Args:
            destination: The host name of the remote homeserver we want
                to get the state from.
            room_id: the room we want the state of
            event_id: The event we want the context at.

        Returns:
            a tuple of (state event_ids, auth event_ids)

        Raises:
            InvalidResponseError: if fields in the response have the wrong type.
        """
        logger.debug("get_room_state_ids dest=%s, room=%s", destination, room_id)

        path = _create_v1_path("/state_ids/%s", room_id)
        result = await self.client.get_json(
            destination,
            path=path,
            args={"event_id": event_id},
            try_trailing_slash_on_400=True,
        )

        state_event_ids = result["pdu_ids"]
        auth_event_ids = result.get("auth_chain_ids", [])

        set_tag(
            RelapseTags.RESULT_PREFIX + "state_event_ids",
            str(state_event_ids),
        )
        set_tag(
            RelapseTags.RESULT_PREFIX + "state_event_ids.length",
            str(len(state_event_ids)),
        )
        set_tag(
            RelapseTags.RESULT_PREFIX + "auth_event_ids",
            str(auth_event_ids),
        )
        set_tag(
            RelapseTags.RESULT_PREFIX + "auth_event_ids.length",
            str(len(auth_event_ids)),
        )

        if not isinstance(state_event_ids, list) or not isinstance(
            auth_event_ids, list
        ):
            raise InvalidResponseError("invalid response from /state_ids")

        return state_event_ids, auth_event_ids

    @trace
    @tag_args
    async def get_room_state(
        self,
        destination: str,
        room_id: str,
        event_id: str,
        room_version: RoomVersion,
    ) -> tuple[list[EventBase], list[EventBase]]:
        """Calls the /state endpoint to fetch the state at a particular point
        in the room.

        Any invalid events (those with incorrect or unverifiable signatures or hashes)
        are filtered out from the response, and any duplicate events are removed.

        (Size limits and other event-format checks are *not* performed.)

        Note that the result is not ordered, so callers must be careful to process
        the events in an order that handles dependencies.

        Returns:
            a tuple of (state events, auth events)
        """
        path = _create_v1_path("/state/%s", room_id)
        result = await self.client.get_json(
            destination,
            path=path,
            args={"event_id": event_id},
            # This can take a looooooong time for large rooms. Give this a generous
            # timeout of 10 minutes to avoid the partial state resync timing out early
            # and trying a bunch of servers who haven't seen our join yet.
            timeout=600_000,
            parser=_StateParser(room_version),
        )
        state_events = result.state
        auth_events = result.auth_events

        # we may as well filter out any duplicates from the response, to save
        # processing them multiple times. (In particular, events may be present in
        # `auth_events` as well as `state`, which is redundant).
        #
        # We don't rely on the sort order of the events, so we can just stick them
        # in a dict.
        state_event_map = {event.event_id: event for event in state_events}
        auth_event_map = {
            event.event_id: event
            for event in auth_events
            if event.event_id not in state_event_map
        }

        logger.info(
            "Processing from /state: %d state events, %d auth events",
            len(state_event_map),
            len(auth_event_map),
        )

        valid_auth_events = await self._check_sigs_and_hash_for_pulled_events_and_fetch(
            destination, auth_event_map.values(), room_version
        )

        valid_state_events = (
            await self._check_sigs_and_hash_for_pulled_events_and_fetch(
                destination, state_event_map.values(), room_version
            )
        )

        return valid_state_events, valid_auth_events

    @trace
    async def _check_sigs_and_hash_for_pulled_events_and_fetch(
        self,
        origin: str,
        pdus: Collection[EventBase],
        room_version: RoomVersion,
    ) -> list[EventBase]:
        """
        Checks the signatures and hashes of a list of pulled events we got from
        federation and records any signature failures as failed pull attempts.

        If a PDU fails its signature check then we check if we have it in
        the database, and if not then request it from the sender's server (if that
        is different from `origin`). If that still fails, the event is omitted from
        the returned list.

        If a PDU fails its content hash check then it is redacted.

        Also runs each event through the spam checker; if it fails, redacts the event
        and flags it as soft-failed.

        The given list of PDUs are not modified; instead the function returns
        a new list.

        Args:
            origin: The server that sent us these events
            pdus: The events to be checked
            room_version: the version of the room these events are in

        Returns:
            A list of PDUs that have valid signatures and hashes.
        """
        set_tag(
            RelapseTags.RESULT_PREFIX + "pdus.length",
            str(len(pdus)),
        )

        # We limit how many PDUs we check at once, as if we try to do hundreds
        # of thousands of PDUs at once we see large memory spikes.

        valid_pdus: list[EventBase] = []

        async def _record_failure_callback(event: EventBase, cause: str) -> None:
            await self.store.record_event_failed_pull_attempt(
                event.room_id, event.event_id, cause
            )

        async def _execute(pdu: EventBase) -> None:
            valid_pdu = await self._check_sigs_and_hash_and_fetch_one(
                pdu=pdu,
                origin=origin,
                room_version=room_version,
                record_failure_callback=_record_failure_callback,
            )

            if valid_pdu:
                valid_pdus.append(valid_pdu)

        await concurrently_execute(_execute, pdus, 10000)

        return valid_pdus

    @trace
    @tag_args
    async def _check_sigs_and_hash_and_fetch_one(
        self,
        pdu: EventBase,
        origin: str,
        room_version: RoomVersion,
        record_failure_callback: Callable[[EventBase, str], Awaitable[None]]
        | None = None,
    ) -> EventBase | None:
        """Takes a PDU and checks its signatures and hashes.

        If the PDU fails its signature check then we check if we have it in the
        database; if not, we then request it from sender's server (if that is not the
        same as `origin`). If that still fails, we return None.

        If the PDU fails its content hash check, it is redacted.

        Also runs the event through the spam checker; if it fails, redacts the event
        and flags it as soft-failed.

        Args:
            origin
            pdu
            room_version
            record_failure_callback: A callback to run whenever the given event
                fails signature or hash checks. This includes exceptions
                that would be normally be thrown/raised but also things like
                checking for event tampering where we just return the redacted
                event.

        Returns:
            The PDU (possibly redacted) if it has valid signatures and hashes.
            None if no valid copy could be found.
        """

        try:
            return await self._check_sigs_and_hash(
                room_version, pdu, record_failure_callback
            )
        except InvalidEventSignatureError as e:
            logger.warning(
                "Signature on retrieved event %s was invalid (%s). "
                "Checking local store/origin server",
                pdu.event_id,
                e,
            )
            log_kv(
                {
                    "message": "Signature on retrieved event was invalid. "
                    "Checking local store/origin server",
                    "event_id": pdu.event_id,
                    "InvalidEventSignatureError": e,
                }
            )

        # Check local db.
        res = await self.store.get_event(
            pdu.event_id, allow_rejected=True, allow_none=True
        )

        # If the PDU fails its signature check and we don't have it in our
        # database, we then request it from sender's server (if that is not the
        # same as `origin`).
        pdu_origin = get_domain_from_id(pdu.sender)
        if not res and pdu_origin != origin:
            try:
                pulled_pdu_info = await self.get_pdu(
                    destinations=[pdu_origin],
                    event_id=pdu.event_id,
                    room_version=room_version,
                    timeout=10000,
                )
                if pulled_pdu_info is not None:
                    res = pulled_pdu_info.pdu
            except RelapseError:
                pass

        if not res:
            logger.warning(
                "Failed to find copy of %s with valid signature", pdu.event_id
            )

        return res

    async def get_event_auth(
        self, destination: str, room_id: str, event_id: str
    ) -> list[EventBase]:
        path = _create_v1_path("/event_auth/%s/%s", room_id, event_id)
        res = await self.client.get_json(destination=destination, path=path)

        room_version = await self.store.get_room_version(room_id)

        auth_chain = [event_from_pdu_json(p, room_version) for p in res["auth_chain"]]

        signed_auth = await self._check_sigs_and_hash_for_pulled_events_and_fetch(
            destination, auth_chain, room_version=room_version
        )

        return signed_auth

    async def _try_destination_list(
        self,
        description: str,
        destinations: Iterable[str],
        callback: Callable[[str], Awaitable[T]],
        failover_errcodes: Container[str] | None = None,
        failover_on_unknown_endpoint: bool = False,
    ) -> T:
        """Try an operation on a series of servers, until it succeeds

        Args:
            description: description of the operation we're doing, for logging

            destinations: list of server_names to try

            callback:  Function to run for each server. Passed a single
                argument: the server_name to try.

                If the callback raises a CodeMessageException with a 300/400 code or
                an UnsupportedRoomVersionError, attempts to perform the operation
                stop immediately and the exception is reraised.

                Otherwise, if the callback raises an Exception the error is logged and the
                next server tried. Normally the stacktrace is logged but this is
                suppressed if the exception is an InvalidResponseError.

            failover_errcodes: Error codes (specific to this endpoint) which should
                cause a failover when received as part of an HTTP 400 error.

            failover_on_unknown_endpoint: if True, we will try other servers if it looks
                like a server doesn't support the endpoint. This is typically useful
                if the endpoint in question is new or experimental.

        Returns:
            The result of callback, if it succeeds

        Raises:
            RelapseError if the chosen remote server returns a 300/400 code, or
            no servers were reachable.
        """
        if failover_errcodes is None:
            failover_errcodes = ()

        if not destinations:
            # Give a bit of a clearer message if no servers were specified at all.
            raise RelapseError(
                502, f"Failed to {description} via any server: No servers specified."
            )

        for destination in destinations:
            # We don't want to ask our own server for information we don't have
            if self._is_mine_server_name(destination):
                continue

            try:
                return await callback(destination)
            except (
                RequestSendFailed,
                InvalidResponseError,
            ) as e:
                logger.warning("Failed to %s via %s: %s", description, destination, e)
                # Skip to the next homeserver in the list to try.
                continue
            except NotRetryingDestination as e:
                logger.info("%s: %s", description, e)
                continue
            except FederationDeniedError:
                logger.info(
                    "%s: Not attempting to %s from %s because the homeserver is not on our federation whitelist",
                    description,
                    description,
                    destination,
                )
                continue
            except UnsupportedRoomVersionError:
                raise
            except HttpResponseException as e:
                relapse_error = e.to_relapse_error()
                failover = False

                # Failover should occur:
                #
                # * On internal server errors.
                # * If the destination responds that it cannot complete the request.
                # * If the destination doesn't implemented the endpoint for some reason.
                if 500 <= e.code < 600:
                    failover = True

                elif 400 <= e.code < 500 and relapse_error.errcode in failover_errcodes:
                    failover = True

                elif failover_on_unknown_endpoint and is_unknown_endpoint(
                    e, relapse_error
                ):
                    failover = True

                if not failover:
                    raise relapse_error from e

                logger.warning(
                    "Failed to %s via %s: %i %s",
                    description,
                    destination,
                    e.code,
                    e.args[0],
                )
            except Exception:
                logger.warning(
                    "Failed to %s via %s", description, destination, exc_info=True
                )

        raise RelapseError(502, f"Failed to {description} via any server")

    async def make_membership_event(
        self,
        destinations: Iterable[str],
        room_id: str,
        user_id: str,
        membership: str,
        content: dict,
        params: Mapping[str, str | Iterable[str]] | None,
    ) -> tuple[str, EventBase, RoomVersion]:
        """
        Creates an m.room.member event, with context, without participating in the room.

        Does so by asking one of the already participating servers to create an
        event with proper context.

        Returns a fully signed and hashed event.

        Note that this does not append any events to any graphs.

        Args:
            destinations: Candidate homeservers which are probably
                participating in the room.
            room_id: The room in which the event will happen.
            user_id: The user whose membership is being evented.
            membership: The "membership" property of the event. Must be one of
                "join" or "leave".
            content: Any additional data to put into the content field of the
                event.
            params: Query parameters to include in the request.

        Returns:
            `(origin, event, room_version)` where origin is the remote
            homeserver which generated the event, and room_version is the
            version of the room.

        Raises:
            UnsupportedRoomVersionError: if remote responds with
                a room version we don't understand.

            RelapseError: if the chosen remote server returns a 300/400 code, or
                no servers successfully handle the request.
        """
        valid_memberships = {Membership.JOIN, Membership.LEAVE, Membership.KNOCK}

        if membership not in valid_memberships:
            raise RuntimeError(
                "make_membership_event called with membership='{}', must be one of {}".format(
                    membership, ",".join(valid_memberships)
                )
            )

        async def send_request(destination: str) -> tuple[str, EventBase, RoomVersion]:
            path = _create_v1_path("/make_%s/%s/%s", membership, room_id, user_id)

            ignore_backoff = False
            retry_on_dns_fail = False

            if membership == Membership.LEAVE:
                # we particularly want to do our best to send leave events. The
                # problem is that if it fails, we won't retry it later, so if the
                # remote server was just having a momentary blip, the room will be
                # out of sync.
                ignore_backoff = True
                retry_on_dns_fail = True

            ret = await self.client.get_json(
                destination=destination,
                path=path,
                args=params,
                retry_on_dns_fail=retry_on_dns_fail,
                timeout=20000,
                ignore_backoff=ignore_backoff,
            )

            # Note: If not supplied, the room version may be either v1 or v2,
            # however either way the event format version will be v1.
            room_version_id = ret.get("room_version", RoomVersions.V1.identifier)
            room_version = KNOWN_ROOM_VERSIONS.get(room_version_id)
            if not room_version:
                raise UnsupportedRoomVersionError()

            if not room_version.knock_join_rule and membership == Membership.KNOCK:
                raise RelapseError(
                    400,
                    "This room version does not support knocking",
                    errcode=Codes.FORBIDDEN,
                )

            pdu_dict = ret.get("event", None)
            if not isinstance(pdu_dict, dict):
                raise InvalidResponseError("Bad 'event' field in response")

            logger.debug("Got response to make_%s: %s", membership, pdu_dict)

            pdu_dict["content"].update(content)

            # The protoevent received over the JSON wire may not have all
            # the required fields. Lets just gloss over that because
            # there's some we never care about
            ev = builder.create_local_event_from_event_dict(
                self._clock,
                self.hostname,
                self.signing_key,
                room_version=room_version,
                event_dict=pdu_dict,
            )

            return destination, ev, room_version

        failover_errcodes = {Codes.NOT_FOUND}
        # MSC3083 defines additional error codes for room joins. Unfortunately
        # we do not yet know the room version, assume these will only be returned
        # by valid room versions.
        if membership == Membership.JOIN:
            failover_errcodes.add(Codes.UNABLE_AUTHORISE_JOIN)
            failover_errcodes.add(Codes.UNABLE_TO_GRANT_JOIN)

        return await self._try_destination_list(
            "make_" + membership,
            destinations,
            send_request,
            failover_errcodes=failover_errcodes,
        )

    async def send_join(
        self,
        destinations: Iterable[str],
        pdu: EventBase,
        room_version: RoomVersion,
        partial_state: bool = True,
    ) -> SendJoinResult:
        """Sends a join event to one of a list of homeservers.

        Doing so will cause the remote server to add the event to the graph,
        and send the event out to the rest of the federation.

        Args:
            destinations: Candidate homeservers which are probably
                participating in the room.
            pdu: event to be sent
            room_version: the version of the room (according to the server that
                did the make_join)
            partial_state: whether to ask the remote server to omit membership state
                events from the response. If the remote server complies,
                `partial_state` in the send join result will be set. Defaults to
                `True`.

        Returns:
            The result of the send join request.

        Raises:
            RelapseError: if the chosen remote server returns a 300/400 code, or
                no servers successfully handle the request.
        """

        async def send_request(destination: str) -> SendJoinResult:
            response = await self._do_send_join(
                room_version, destination, pdu, omit_members=partial_state
            )

            # If an event was returned (and expected to be returned):
            #
            # * Ensure it has the same event ID (note that the event ID is a hash
            #   of the event fields for versions which support MSC3083).
            # * Ensure the signatures are good.
            #
            # Otherwise, fallback to the provided event.
            if room_version.restricted_join_rule and response.event:
                event = response.event

                valid_pdu = await self._check_sigs_and_hash_and_fetch_one(
                    pdu=event,
                    origin=destination,
                    room_version=room_version,
                )

                if valid_pdu is None or event.event_id != pdu.event_id:
                    raise InvalidResponseError("Returned an invalid join event")
            else:
                event = pdu

            state = response.state
            auth_chain = response.auth_events

            create_event = None
            for e in state:
                if (e.type, e.state_key) == (EventTypes.Create, ""):
                    create_event = e
                    break

            if create_event is None:
                # If the state doesn't have a create event then the room is
                # invalid, and it would fail auth checks anyway.
                raise InvalidResponseError("No create event in state")

            # the room version should be sane.
            create_room_version = create_event.content.get(
                "room_version", RoomVersions.V1.identifier
            )
            if create_room_version != room_version.identifier:
                # either the server that fulfilled the make_join, or the server that is
                # handling the send_join, is lying.
                raise InvalidResponseError(
                    f"Unexpected room version {create_room_version} in create event"
                )

            logger.info(
                "Processing from send_join %d events", len(state) + len(auth_chain)
            )

            # We now go and check the signatures and hashes for the event. Note
            # that we limit how many events we process at a time to keep the
            # memory overhead from exploding.
            valid_pdus_map: dict[str, EventBase] = {}

            async def _execute(pdu: EventBase) -> None:
                valid_pdu = await self._check_sigs_and_hash_and_fetch_one(
                    pdu=pdu,
                    origin=destination,
                    room_version=room_version,
                )

                if valid_pdu:
                    valid_pdus_map[valid_pdu.event_id] = valid_pdu

            await concurrently_execute(
                _execute, itertools.chain(state, auth_chain), 10000
            )

            # NB: We *need* to copy to ensure that we don't have multiple
            # references being passed on, as that causes... issues.
            signed_state = [
                copy.copy(valid_pdus_map[p.event_id])
                for p in state
                if p.event_id in valid_pdus_map
            ]

            signed_auth = [
                valid_pdus_map[p.event_id]
                for p in auth_chain
                if p.event_id in valid_pdus_map
            ]

            # NB: We *need* to copy to ensure that we don't have multiple
            # references being passed on, as that causes... issues.
            for s in signed_state:
                s.internal_metadata = copy.deepcopy(s.internal_metadata)

            # double-check that the auth chain doesn't include a different create event
            auth_chain_create_events = [
                e.event_id
                for e in signed_auth
                if (e.type, e.state_key) == (EventTypes.Create, "")
            ]
            if auth_chain_create_events and auth_chain_create_events != [
                create_event.event_id
            ]:
                raise InvalidResponseError(
                    f"Unexpected create event(s) in auth chain: {auth_chain_create_events}"
                )

            servers_in_room = None
            if response.servers_in_room is not None:
                servers_in_room = set(response.servers_in_room)

            if response.members_omitted:
                if not servers_in_room:
                    raise InvalidResponseError(
                        "members_omitted was set, but no servers were listed in the room"
                    )

                if not partial_state:
                    raise InvalidResponseError(
                        "members_omitted was set, but we asked for full state"
                    )

                # `servers_in_room` is supposed to be a complete list.
                # Fix things up in case the remote homeserver is badly behaved.
                servers_in_room.add(destination)

            return SendJoinResult(
                event=event,
                state=signed_state,
                auth_chain=signed_auth,
                origin=destination,
                partial_state=response.members_omitted,
                servers_in_room=servers_in_room or frozenset(),
            )

        # MSC3083 defines additional error codes for room joins.
        failover_errcodes = None
        if room_version.restricted_join_rule:
            failover_errcodes = (
                Codes.UNABLE_AUTHORISE_JOIN,
                Codes.UNABLE_TO_GRANT_JOIN,
            )

            # If the join is being authorised via allow rules, we need to send
            # the /send_join back to the same server that was originally used
            # with /make_join.
            if EventContentFields.AUTHORISING_USER in pdu.content:
                destinations = [
                    get_domain_from_id(pdu.content[EventContentFields.AUTHORISING_USER])
                ]

        return await self._try_destination_list(
            "send_join", destinations, send_request, failover_errcodes=failover_errcodes
        )

    async def _do_send_join(
        self,
        room_version: RoomVersion,
        destination: str,
        pdu: EventBase,
        omit_members: bool,
    ) -> SendJoinResponse:
        time_now = self._clock.time_msec()

        try:
            path = _create_v2_path("/send_join/%s/%s", pdu.room_id, pdu.event_id)
            query_params: dict[str, str] = {
                # lazy-load state on join
                "omit_members": "true" if omit_members else "false"
            }

            return await self.client.put_json(
                destination=destination,
                path=path,
                args=query_params,
                data=pdu.get_pdu_json(time_now),
                parser=SendJoinParser(room_version, v1_api=False),
            )
        except HttpResponseException as e:
            # If an error is received that is due to an unrecognised endpoint,
            # fallback to the v1 endpoint. Otherwise, consider it a legitimate error
            # and raise.
            if not is_unknown_endpoint(e):
                raise

        logger.debug("Couldn't send_join with the v2 API, falling back to the v1 API")

        path = _create_v1_path("/send_join/%s/%s", pdu.room_id, pdu.event_id)
        return await self.client.put_json(
            destination=destination,
            path=path,
            data=pdu.get_pdu_json(time_now),
            parser=SendJoinParser(room_version, v1_api=True),
        )

    async def send_invite(
        self,
        destination: str,
        room_id: str,
        event_id: str,
        pdu: EventBase,
    ) -> EventBase:
        room_version = await self.store.get_room_version(room_id)

        content = await self._do_send_invite(destination, pdu, room_version)

        pdu_dict = content["event"]

        logger.debug("Got response to send_invite: %s", pdu_dict)

        pdu = event_from_pdu_json(pdu_dict, room_version)

        # Check signatures are correct.
        try:
            pdu = await self._check_sigs_and_hash(room_version, pdu)
        except InvalidEventSignatureError as e:
            errmsg = f"event id {pdu.event_id}: {e}"
            logger.warning("%s", errmsg)
            raise RelapseError(403, errmsg, Codes.FORBIDDEN)

            # FIXME: We should handle signature failures more gracefully.

        return pdu

    async def _do_send_invite(
        self, destination: str, pdu: EventBase, room_version: RoomVersion
    ) -> JsonDict:
        """Actually sends the invite, first trying v2 API and falling back to
        v1 API if necessary.

        Returns:
            The event as a dict as returned by the remote server

        Raises:
            RelapseError: if the remote server returns an error or if the server
                only supports the v1 endpoint and a room version other than "1"
                or "2" is requested.
        """
        time_now = self._clock.time_msec()

        try:
            path = _create_v2_path("/invite/%s/%s", pdu.room_id, pdu.event_id)

            return await self.client.put_json(
                destination=destination,
                path=path,
                data={
                    "event": pdu.get_pdu_json(time_now),
                    "room_version": room_version.identifier,
                    "invite_room_state": pdu.unsigned.get("invite_room_state", []),
                },
                ignore_backoff=True,
            )
        except HttpResponseException as e:
            # If an error is received that is due to an unrecognised endpoint,
            # fallback to the v1 endpoint if the room uses old-style event IDs.
            # Otherwise, consider it a legitimate error and raise.
            err = e.to_relapse_error()
            if is_unknown_endpoint(e, err):
                if room_version.event_format != EventFormatVersions.ROOM_V1_V2:
                    raise RelapseError(
                        400,
                        "User's homeserver does not support this room version",
                        Codes.UNSUPPORTED_ROOM_VERSION,
                    )
            else:
                raise err

        # Didn't work, try v1 API.
        # Note the v1 API returns a tuple of `(200, content)`
        path = _create_v1_path("/invite/%s/%s", pdu.room_id, pdu.event_id)
        _, content = await self.client.put_json(
            destination=destination,
            path=path,
            data=pdu.get_pdu_json(time_now),
            ignore_backoff=True,
            parser=LegacyJsonSendParser(),
        )
        return content

    async def send_leave(self, destinations: Iterable[str], pdu: EventBase) -> None:
        """Sends a leave event to one of a list of homeservers.

        Doing so will cause the remote server to add the event to the graph,
        and send the event out to the rest of the federation.

        This is mostly useful to reject received invites.

        Args:
            destinations: Candidate homeservers which are probably
                participating in the room.
            pdu: event to be sent

        Raises:
            RelapseError: if the chosen remote server returns a 300/400 code, or
                no servers successfully handle the request.
        """

        async def send_request(destination: str) -> None:
            content = await self._do_send_leave(destination, pdu)
            logger.debug("Got content: %s", content)

        return await self._try_destination_list(
            "send_leave", destinations, send_request
        )

    async def _do_send_leave(self, destination: str, pdu: EventBase) -> JsonDict:
        time_now = self._clock.time_msec()

        try:
            path = _create_v2_path("/send_leave/%s/%s", pdu.room_id, pdu.event_id)
            return await self.client.put_json(
                destination=destination,
                path=path,
                data=pdu.get_pdu_json(time_now),
                # we want to do our best to send this through. The problem is
                # that if it fails, we won't retry it later, so if the remote
                # server was just having a momentary blip, the room will be out of
                # sync.
                ignore_backoff=True,
            )
        except HttpResponseException as e:
            # If an error is received that is due to an unrecognised endpoint,
            # fallback to the v1 endpoint. Otherwise, consider it a legitimate error
            # and raise.
            if not is_unknown_endpoint(e):
                raise

        logger.debug("Couldn't send_leave with the v2 API, falling back to the v1 API")

        path = _create_v1_path("/send_leave/%s/%s", pdu.room_id, pdu.event_id)
        resp = await self.client.put_json(
            destination=destination,
            path=path,
            data=pdu.get_pdu_json(time_now),
            # we want to do our best to send this through. The problem is
            # that if it fails, we won't retry it later, so if the remote
            # server was just having a momentary blip, the room will be out of
            # sync.
            ignore_backoff=True,
            parser=LegacyJsonSendParser(),
        )

        # We expect the v1 API to respond with [200, content], so we only return the
        # content.
        return resp[1]

    async def send_knock(self, destinations: list[str], pdu: EventBase) -> JsonDict:
        """Attempts to send a knock event to a given list of servers. Iterates
        through the list until one attempt succeeds.

        Doing so will cause the remote server to add the event to the graph,
        and send the event out to the rest of the federation.

        Args:
            destinations: A list of candidate homeservers which are likely to be
                participating in the room.
            pdu: The event to be sent.

        Returns:
            The remote homeserver return some state from the room. The response
            dictionary is in the form:

            {"knock_room_state": [<state event dict>, ...]}

            The list of state events may be empty.

        Raises:
            RelapseError: If the chosen remote server returns a 3xx/4xx code.
            RuntimeError: If no servers were reachable.
        """

        async def send_request(destination: str) -> JsonDict:
            return await self._do_send_knock(destination, pdu)

        return await self._try_destination_list(
            "send_knock", destinations, send_request
        )

    async def _do_send_knock(self, destination: str, pdu: EventBase) -> JsonDict:
        """Send a knock event to a remote homeserver.

        Args:
            destination: The homeserver to send to.
            pdu: The event to send.

        Returns:
            The remote homeserver can optionally return some state from the room. The response
            dictionary is in the form:

            {"knock_room_state": [<state event dict>, ...]}

            The list of state events may be empty.
        """
        time_now = self._clock.time_msec()
        path = _create_v1_path("/send_knock/%s/%s", pdu.room_id, pdu.event_id)
        return await self.client.put_json(
            destination=destination, path=path, data=pdu.get_pdu_json(time_now)
        )

    async def get_public_rooms(
        self,
        remote_server: str,
        limit: int | None = None,
        since_token: str | None = None,
        search_filter: dict | None = None,
        include_all_networks: bool = False,
        third_party_instance_id: str | None = None,
    ) -> JsonDict:
        """Get the list of public rooms from a remote homeserver

        Args:
            remote_server: The name of the remote server
            limit: Maximum amount of rooms to return
            since_token: Used for result pagination
            search_filter: A filter dictionary to send the remote homeserver
                and filter the result set
            include_all_networks: Whether to include results from all third party instances
            third_party_instance_id: Whether to only include results from a specific third
                party instance

        Returns:
            The response from the remote server.

        Raises:
            HttpResponseException / RequestSendFailed: There was an exception
                returned from the remote server
            RelapseException: M_FORBIDDEN when the remote server has disallowed publicRoom
                requests over federation

        """
        path = _create_v1_path("/publicRooms")

        if search_filter:
            # this uses MSC2197 (Search Filtering over Federation)
            data: dict[str, Any] = {"include_all_networks": include_all_networks}
            if third_party_instance_id:
                data["third_party_instance_id"] = third_party_instance_id
            if limit:
                data["limit"] = limit
            if since_token:
                data["since"] = since_token

            data["filter"] = search_filter

            try:
                response = await self.client.post_json(
                    destination=remote_server, path=path, data=data, ignore_backoff=True
                )
            except HttpResponseException as e:
                if e.code == 403:
                    raise RelapseError(
                        403,
                        f"You are not allowed to view the public rooms list of {remote_server}",
                        errcode=Codes.FORBIDDEN,
                    )
                raise
        else:
            args: dict[str, str | Iterable[str]] = {
                "include_all_networks": "true" if include_all_networks else "false"
            }
            if third_party_instance_id:
                args["third_party_instance_id"] = third_party_instance_id
            if limit:
                args["limit"] = str(limit)
            if since_token:
                args["since"] = since_token

            try:
                response = await self.client.get_json(
                    destination=remote_server, path=path, args=args, ignore_backoff=True
                )
            except HttpResponseException as e:
                if e.code == 403:
                    raise RelapseError(
                        403,
                        f"You are not allowed to view the public rooms list of {remote_server}",
                        errcode=Codes.FORBIDDEN,
                    )
                raise

        return response

    async def get_missing_events(
        self,
        destination: str,
        room_id: str,
        earliest_events_ids: Iterable[str],
        latest_events: Iterable[EventBase],
        limit: int,
        min_depth: int,
        timeout: int,
    ) -> list[EventBase]:
        """Tries to fetch events we are missing. This is called when we receive
        an event without having received all of its ancestors.

        Args:
            destination
            room_id
            earliest_events_ids: List of event ids. Effectively the
                events we expected to receive, but haven't. `get_missing_events`
                should only return events that didn't happen before these.
            latest_events: List of events we have received that we don't
                have all previous events for.
            limit: Maximum number of events to return.
            min_depth: Minimum depth of events to return.
            timeout: Max time to wait in ms
        """
        try:
            path = _create_v1_path("/get_missing_events/%s", room_id)
            content = await self.client.post_json(
                destination=destination,
                path=path,
                data={
                    "limit": int(limit),
                    "min_depth": int(min_depth),
                    "earliest_events": earliest_events_ids,
                    "latest_events": [e.event_id for e in latest_events],
                },
                timeout=timeout,
            )

            room_version = await self.store.get_room_version(room_id)

            events = [
                event_from_pdu_json(e, room_version) for e in content.get("events", [])
            ]

            signed_events = await self._check_sigs_and_hash_for_pulled_events_and_fetch(
                destination, events, room_version=room_version
            )
        except HttpResponseException as e:
            if not e.code == 400:
                raise

            # We are probably hitting an old server that doesn't support
            # get_missing_events
            signed_events = []

        return signed_events

    async def forward_third_party_invite(
        self, destinations: Iterable[str], room_id: str, event_dict: JsonDict
    ) -> None:
        for destination in destinations:
            if self._is_mine_server_name(destination):
                continue

            try:
                path = _create_v1_path("/exchange_third_party_invite/%s", room_id)
                await self.client.put_json(
                    destination=destination, path=path, data=event_dict
                )
                return
            except CodeMessageException:
                raise
            except Exception as e:
                logger.exception(
                    "Failed to send_third_party_invite via %s: %s", destination, str(e)
                )

        raise RuntimeError("Failed to send to any server.")

    async def get_room_complexity(
        self, destination: str, room_id: str
    ) -> JsonDict | None:
        """
        Fetch the complexity of a remote room from another server.

        Args:
            destination: The remote server
            room_id: The room ID to ask about.

        Returns:
            Dict contains the complexity metric versions, while None means we
            could not fetch the complexity.
        """
        try:
            path = _create_path(
                FEDERATION_UNSTABLE_PREFIX, "/rooms/%s/complexity", room_id
            )
            return await self.client.get_json(destination=destination, path=path)
        except CodeMessageException as e:
            # We didn't manage to get it -- probably a 404. We are okay if other
            # servers don't give it to us.
            logger.debug(
                "Failed to fetch room complexity via %s for %s, got a %d",
                destination,
                room_id,
                e.code,
            )
        except Exception:
            logger.exception(
                "Failed to fetch room complexity via %s for %s", destination, room_id
            )

        # If we don't manage to find it, return None. It's not an error if a
        # server doesn't give it to us.
        return None

    async def get_room_hierarchy(
        self,
        destinations: Iterable[str],
        room_id: str,
        suggested_only: bool,
    ) -> tuple[JsonDict, Sequence[JsonDict], Sequence[JsonDict], Sequence[str]]:
        """
        Call other servers to get a hierarchy of the given room.

        Performs simple data validates and parsing of the response.

        Args:
            destinations: The remote servers. We will try them in turn, omitting any
                that have been blacklisted.
            room_id: ID of the space to be queried
            suggested_only:  If true, ask the remote server to only return children
                with the "suggested" flag set

        Returns:
            A tuple of:
                The room as a JSON dictionary, without a "children_state" key.
                A list of `m.space.child` state events.
                A list of children rooms, as JSON dictionaries.
                A list of inaccessible children room IDs.

        Raises:
            RelapseError if we were unable to get a valid summary from any of the
               remote servers
        """

        cached_result = self._get_room_hierarchy_cache.get((room_id, suggested_only))
        if cached_result:
            return cached_result

        async def send_request(
            destination: str,
        ) -> tuple[JsonDict, Sequence[JsonDict], Sequence[JsonDict], Sequence[str]]:
            try:
                path = _create_v1_path("/hierarchy/%s", room_id)
                res = await self.client.get_json(
                    destination=destination,
                    path=path,
                    args={"suggested_only": "true" if suggested_only else "false"},
                )
            except HttpResponseException as e:
                # If an error is received that is due to an unrecognised endpoint,
                # fallback to the unstable endpoint. Otherwise, consider it a
                # legitimate error and raise.
                if not is_unknown_endpoint(e):
                    raise

                logger.debug(
                    "Couldn't fetch room hierarchy with the v1 API, falling back to the unstable API"
                )

                path = _create_path(
                    FEDERATION_UNSTABLE_PREFIX,
                    "/org.matrix.msc2946/hierarchy/%s",
                    room_id,
                )
                res = await self.client.get_json(
                    destination=destination,
                    path=path,
                    args={"suggested_only": "true" if suggested_only else "false"},
                )

            room = res.get("room")
            if not isinstance(room, dict):
                raise InvalidResponseError("'room' must be a dict")
            if room.get("room_id") != room_id:
                raise InvalidResponseError("wrong room returned in hierarchy response")

            # Validate children_state of the room.
            children_state = room.pop("children_state", [])
            if not isinstance(children_state, list):
                raise InvalidResponseError("'room.children_state' must be a list")
            if any(not isinstance(e, dict) for e in children_state):
                raise InvalidResponseError("Invalid event in 'children_state' list")
            try:
                for child_state in children_state:
                    _validate_hierarchy_event(child_state)
            except ValueError as e:
                raise InvalidResponseError(str(e))

            # Validate the children rooms.
            children = res.get("children", [])
            if not isinstance(children, list):
                raise InvalidResponseError("'children' must be a list")
            if any(not isinstance(r, dict) for r in children):
                raise InvalidResponseError("Invalid room in 'children' list")

            # Validate the inaccessible children.
            inaccessible_children = res.get("inaccessible_children", [])
            if not isinstance(inaccessible_children, list):
                raise InvalidResponseError("'inaccessible_children' must be a list")
            if any(not isinstance(r, str) for r in inaccessible_children):
                raise InvalidResponseError(
                    "Invalid room ID in 'inaccessible_children' list"
                )

            return room, children_state, children, inaccessible_children

        result = await self._try_destination_list(
            "fetch room hierarchy",
            destinations,
            send_request,
            failover_on_unknown_endpoint=True,
        )

        # Cache the result to avoid fetching data over federation every time.
        self._get_room_hierarchy_cache[(room_id, suggested_only)] = result
        return result

    async def timestamp_to_event(
        self,
        *,
        destinations: StrCollection,
        room_id: str,
        timestamp: int,
        direction: Direction,
    ) -> TimestampToEventResponse | None:
        """
        Calls each remote federating server from `destinations` asking for their closest
        event to the given timestamp in the given direction until we get a response.
        Also validates the response to always return the expected keys or raises an
        error.

        Args:
            destinations: The domains of homeservers to try fetching from
            room_id: Room to fetch the event from
            timestamp: The point in time (inclusive) we should navigate from in
                the given direction to find the closest event.
            direction: indicates whether we should navigate forward
                or backward from the given timestamp to find the closest event.

        Returns:
            A parsed TimestampToEventResponse including the closest event_id
            and origin_server_ts or None if no destination has a response.
        """

        async def _timestamp_to_event_from_destination(
            destination: str,
        ) -> TimestampToEventResponse:
            return await self._timestamp_to_event_from_destination(
                destination, room_id, timestamp, direction
            )

        try:
            # Loop through each homeserver candidate until we get a succesful response
            timestamp_to_event_response = await self._try_destination_list(
                "timestamp_to_event",
                destinations,
                # TODO: The requested timestamp may lie in a part of the
                #   event graph that the remote server *also* didn't have,
                #   in which case they will have returned another event
                #   which may be nowhere near the requested timestamp. In
                #   the future, we may need to reconcile that gap and ask
                #   other homeservers, and/or extend `/timestamp_to_event`
                #   to return events on *both* sides of the timestamp to
                #   help reconcile the gap faster.
                _timestamp_to_event_from_destination,
                # Since this endpoint is new, we should try other servers before giving up.
                # We can safely remove this in a year (remove after 2023-11-16).
                failover_on_unknown_endpoint=True,
            )
            return timestamp_to_event_response
        except RelapseError as e:
            logger.warn(
                "timestamp_to_event(room_id=%s, timestamp=%s, direction=%s): encountered error when trying to fetch from destinations: %s",
                room_id,
                timestamp,
                direction,
                e,
            )
            return None

    async def _timestamp_to_event_from_destination(
        self, destination: str, room_id: str, timestamp: int, direction: Direction
    ) -> TimestampToEventResponse:
        """
        Calls a remote federating server at `destination` asking for their
        closest event to the given timestamp in the given direction. Also
        validates the response to always return the expected keys or raises an
        error.

        Args:
            destination: Domain name of the remote homeserver
            room_id: Room to fetch the event from
            timestamp: The point in time (inclusive) we should navigate from in
                the given direction to find the closest event.
            direction: indicates whether we should navigate forward
                or backward from the given timestamp to find the closest event.

        Returns:
            A parsed TimestampToEventResponse including the closest event_id
            and origin_server_ts

        Raises:
            Various exceptions when the request fails
            InvalidResponseError when the response does not have the correct
            keys or wrong types
        """
        path = _create_v1_path(
            "/timestamp_to_event/%s",
            room_id,
        )

        args = {"ts": [str(timestamp)], "dir": [direction.value]}

        remote_response = await self.client.get_json(
            destination, path=path, args=args, try_trailing_slash_on_400=True
        )

        if not isinstance(remote_response, dict):
            raise InvalidResponseError(
                f"Response must be a JSON dictionary but received {remote_response!r}"
            )

        try:
            return TimestampToEventResponse.from_json_dict(remote_response)
        except ValueError as e:
            raise InvalidResponseError(str(e))

    async def download_media(
        self,
        destination: str,
        media_id: str,
        output_stream: BinaryIO,
        max_size: int,
        max_timeout_ms: int,
    ) -> tuple[int, dict[bytes, list[bytes]]]:
        try:
            path = f"/_matrix/media/v3/download/{destination}/{media_id}"
            return await self.client.get_file(
                destination,
                path,
                output_stream=output_stream,
                max_size=max_size,
                args={
                    # tell the remote server to 404 if it doesn't
                    # recognise the server_name, to make sure we don't
                    # end up with a routing loop.
                    "allow_remote": "false",
                    "timeout_ms": str(max_timeout_ms),
                    # Matrix 1.7 allows for this to redirect to another URL, this should
                    # just be ignored for an old homeserver, so always provide it.
                    "allow_redirect": "true",
                },
                follow_redirects=True,
            )
        except HttpResponseException as e:
            # If an error is received that is due to an unrecognised endpoint,
            # fallback to the r0 endpoint. Otherwise, consider it a legitimate error
            # and raise.
            if not is_unknown_endpoint(e):
                raise

        logger.debug(
            "Couldn't download media %s/%s with the v3 API, falling back to the r0 API",
            destination,
            media_id,
        )

        path = f"/_matrix/media/r0/download/{destination}/{media_id}"
        return await self.client.get_file(
            destination,
            path,
            output_stream=output_stream,
            max_size=max_size,
            args={
                # tell the remote server to 404 if it doesn't
                # recognise the server_name, to make sure we don't
                # end up with a routing loop.
                "allow_remote": "false",
                "timeout_ms": str(max_timeout_ms),
            },
        )

    async def send_transaction(
        self,
        transaction: Transaction,
        json_data_callback: Callable[[], JsonDict] | None = None,
    ) -> JsonDict:
        """Sends the given Transaction to its destination

        Args:
            transaction

        Returns:
            Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body.

            Fails with ``HTTPRequestException`` if we get an HTTP response
            code >= 300.

            Fails with ``NotRetryingDestination`` if we are not yet ready
            to retry this server.

            Fails with ``FederationDeniedError`` if this destination
            is not on our federation whitelist
        """
        logger.debug(
            "send_data dest=%s, txid=%s",
            transaction.destination,
            transaction.transaction_id,
        )

        if self._is_mine_server_name(transaction.destination):
            raise RuntimeError("Transport layer cannot send to itself!")

        # FIXME: This is only used by the tests. The actual json sent is
        # generated by the json_data_callback.
        json_data = transaction.get_dict()

        path = _create_v1_path("/send/%s", transaction.transaction_id)

        return await self.client.put_json(
            transaction.destination,
            path=path,
            data=json_data,
            json_data_callback=json_data_callback,
            long_retries=True,
            try_trailing_slash_on_400=True,
            # Sending a transaction should always succeed, if it doesn't
            # then something is wrong and we should backoff.
            backoff_on_all_error_codes=True,
        )
