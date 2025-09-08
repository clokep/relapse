# Copyright 2014-2022 The Matrix.org Foundation C.I.C.
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
import urllib
from collections.abc import Generator, Iterable
from typing import TYPE_CHECKING, Any, Optional

import attr
import ijson

from relapse.api.room_versions import RoomVersion
from relapse.api.urls import (
    FEDERATION_V1_PREFIX,
    FEDERATION_V2_PREFIX,
)
from relapse.events import EventBase, make_event_from_dict
from relapse.http.matrixfederationclient import ByteParser
from relapse.types import JsonDict
from relapse.util import ExceptionBundle

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@attr.s(frozen=True, slots=True, auto_attribs=True)
class TimestampToEventResponse:
    """Typed response dictionary for the federation /timestamp_to_event endpoint"""

    event_id: str
    origin_server_ts: int

    # the raw data, including the above keys
    data: JsonDict

    @classmethod
    def from_json_dict(cls, d: JsonDict) -> "TimestampToEventResponse":
        """Parsed response from the federation /timestamp_to_event endpoint

        Args:
            d: JSON object response to be parsed

        Raises:
            ValueError if d does not the correct keys or they are the wrong types
        """

        event_id = d.get("event_id")
        if not isinstance(event_id, str):
            raise ValueError(
                "Invalid response: 'event_id' must be a str but received %r" % event_id
            )

        origin_server_ts = d.get("origin_server_ts")
        if type(origin_server_ts) is not int:  # noqa: E721
            raise ValueError(
                "Invalid response: 'origin_server_ts' must be a int but received %r"
                % origin_server_ts
            )

        return cls(event_id, origin_server_ts, d)


def _validate_hierarchy_event(d: JsonDict) -> None:
    """Validate an event within the result of a /hierarchy request

    Args:
        d: json object to be parsed

    Raises:
        ValueError if d is not a valid event
    """

    event_type = d.get("type")
    if not isinstance(event_type, str):
        raise ValueError("Invalid event: 'event_type' must be a str")

    state_key = d.get("state_key")
    if not isinstance(state_key, str):
        raise ValueError("Invalid event: 'state_key' must be a str")

    content = d.get("content")
    if not isinstance(content, dict):
        raise ValueError("Invalid event: 'content' must be a dict")

    via = content.get("via")
    if not isinstance(via, list):
        raise ValueError("Invalid event: 'via' must be a list")
    if any(not isinstance(v, str) for v in via):
        raise ValueError("Invalid event: 'via' must be a list of strings")


def _create_path(federation_prefix: str, path: str, *args: str) -> str:
    """
    Ensures that all args are url encoded.
    """
    return federation_prefix + path % tuple(urllib.parse.quote(arg, "") for arg in args)


def _create_v1_path(path: str, *args: str) -> str:
    """Creates a path against V1 federation API from the path template and
    args. Ensures that all args are url encoded.

    Example:

        _create_v1_path("/event/%s", event_id)

    Args:
        path: String template for the path
        args: Args to insert into path. Each arg will be url encoded
    """
    return _create_path(FEDERATION_V1_PREFIX, path, *args)


def _create_v2_path(path: str, *args: str) -> str:
    """Creates a path against V2 federation API from the path template and
    args. Ensures that all args are url encoded.

    Example:

        _create_v2_path("/event/%s", event_id)

    Args:
        path: String template for the path
        args: Args to insert into path. Each arg will be url encoded
    """
    return _create_path(FEDERATION_V2_PREFIX, path, *args)


@attr.s(slots=True, auto_attribs=True)
class SendJoinResponse:
    """The parsed response of a `/send_join` request."""

    # The list of auth events from the /send_join response.
    auth_events: list[EventBase]
    # The list of state from the /send_join response.
    state: list[EventBase]
    # The raw join event from the /send_join response.
    event_dict: JsonDict
    # The parsed join event from the /send_join response. This will be None if
    # "event" is not included in the response.
    event: Optional[EventBase] = None

    # The room state is incomplete
    members_omitted: bool = False

    # List of servers in the room
    servers_in_room: Optional[list[str]] = None


@attr.s(slots=True, auto_attribs=True)
class StateRequestResponse:
    """The parsed response of a `/state` request."""

    auth_events: list[EventBase]
    state: list[EventBase]


@ijson.coroutine
def _event_parser(event_dict: JsonDict) -> Generator[None, tuple[str, Any], None]:
    """Helper function for use with `ijson.kvitems_coro` to parse key-value pairs
    to add them to a given dictionary.
    """

    while True:
        key, value = yield
        event_dict[key] = value


@ijson.coroutine
def _event_list_parser(
    room_version: RoomVersion, events: list[EventBase]
) -> Generator[None, JsonDict, None]:
    """Helper function for use with `ijson.items_coro` to parse an array of
    events and add them to the given list.
    """

    while True:
        obj = yield
        event = make_event_from_dict(obj, room_version)
        events.append(event)


@ijson.coroutine
def _members_omitted_parser(response: SendJoinResponse) -> Generator[None, Any, None]:
    """Helper function for use with `ijson.items_coro`

    Parses the members_omitted field in send_join responses
    """
    while True:
        val = yield
        if not isinstance(val, bool):
            raise TypeError("members_omitted must be a boolean")
        response.members_omitted = val


@ijson.coroutine
def _servers_in_room_parser(response: SendJoinResponse) -> Generator[None, Any, None]:
    """Helper function for use with `ijson.items_coro`

    Parses the servers_in_room field in send_join responses
    """
    while True:
        val = yield
        if not isinstance(val, list) or any(not isinstance(x, str) for x in val):
            raise TypeError("servers_in_room must be a list of strings")
        response.servers_in_room = val


class SendJoinParser(ByteParser[SendJoinResponse]):
    """A parser for the response to `/send_join` requests.

    Args:
        room_version: The version of the room.
        v1_api: Whether the response is in the v1 format.
    """

    CONTENT_TYPE = "application/json"

    # /send_join responses can be huge, so we override the size limit here. The response
    # is parsed in a streaming manner, which helps alleviate the issue of memory
    # usage a bit.
    MAX_RESPONSE_SIZE = 500 * 1024 * 1024

    def __init__(self, room_version: RoomVersion, v1_api: bool):
        self._response = SendJoinResponse([], [], event_dict={})
        self._room_version = room_version
        self._coros: list[Generator[None, bytes, None]] = []

        # The V1 API has the shape of `[200, {...}]`, which we handle by
        # prefixing with `item.*`.
        prefix = "item." if v1_api else ""

        self._coros = [
            ijson.items_coro(
                _event_list_parser(room_version, self._response.state),
                prefix + "state.item",
                use_float=True,
            ),
            ijson.items_coro(
                _event_list_parser(room_version, self._response.auth_events),
                prefix + "auth_chain.item",
                use_float=True,
            ),
            ijson.kvitems_coro(
                _event_parser(self._response.event_dict),
                prefix + "event",
                use_float=True,
            ),
        ]

        if not v1_api:
            self._coros.append(
                ijson.items_coro(
                    _members_omitted_parser(self._response),
                    "members_omitted",
                    use_float="True",
                )
            )

            # Again, stable field name comes last
            self._coros.append(
                ijson.items_coro(
                    _servers_in_room_parser(self._response),
                    "servers_in_room",
                    use_float="True",
                )
            )

    def write(self, data: bytes) -> int:
        for c in self._coros:
            c.send(data)

        return len(data)

    def finish(self) -> SendJoinResponse:
        _close_coros(self._coros)

        if self._response.event_dict:
            self._response.event = make_event_from_dict(
                self._response.event_dict, self._room_version
            )
        return self._response


class _StateParser(ByteParser[StateRequestResponse]):
    """A parser for the response to `/state` requests.

    Args:
        room_version: The version of the room.
    """

    CONTENT_TYPE = "application/json"

    # As with /send_join, /state responses can be huge.
    MAX_RESPONSE_SIZE = 500 * 1024 * 1024

    def __init__(self, room_version: RoomVersion):
        self._response = StateRequestResponse([], [])
        self._room_version = room_version
        self._coros: list[Generator[None, bytes, None]] = [
            ijson.items_coro(
                _event_list_parser(room_version, self._response.state),
                "pdus.item",
                use_float=True,
            ),
            ijson.items_coro(
                _event_list_parser(room_version, self._response.auth_events),
                "auth_chain.item",
                use_float=True,
            ),
        ]

    def write(self, data: bytes) -> int:
        for c in self._coros:
            c.send(data)
        return len(data)

    def finish(self) -> StateRequestResponse:
        _close_coros(self._coros)
        return self._response


def _close_coros(coros: Iterable[Generator[None, bytes, None]]) -> None:
    """Close each of the given coroutines.

    Always calls .close() on each coroutine, even if doing so raises an exception.
    Any exceptions raised are aggregated into an ExceptionBundle.

    :raises ExceptionBundle: if at least one coroutine fails to close.
    """
    exceptions = []
    for c in coros:
        try:
            c.close()
        except Exception as e:
            exceptions.append(e)

    if exceptions:
        # raise from the first exception so that the traceback has slightly more context
        raise ExceptionBundle(
            f"There were {len(exceptions)} errors closing coroutines", exceptions
        ) from exceptions[0]
