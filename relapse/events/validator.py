# Copyright 2014-2016 OpenMarket Ltd
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
import collections.abc
from typing import TYPE_CHECKING, Union, cast

import jsonschema

from relapse._pydantic_compat import HAS_PYDANTIC_V2

if TYPE_CHECKING or HAS_PYDANTIC_V2:
    from pydantic.v1 import Field, StrictBool, StrictStr
else:
    from pydantic import Field, StrictBool, StrictStr

from relapse.api.constants import (
    MAX_ALIAS_LENGTH,
    EventContentFields,
    EventTypes,
    Membership,
)
from relapse.api.errors import Codes, RelapseError
from relapse.api.room_versions import EventFormatVersions
from relapse.config.homeserver import HomeServerConfig
from relapse.events import EventBase
from relapse.events.builder import EventBuilder
from relapse.events.utils import (
    CANONICALJSON_MAX_INT,
    CANONICALJSON_MIN_INT,
    validate_canonicaljson,
)
from relapse.http.servlet import validate_json_object
from relapse.rest.models import RequestBodyModel
from relapse.storage.controllers.state import server_acl_evaluator_from_event
from relapse.types import EventID, JsonDict, RoomID, StrCollection, UserID


class EventValidator:
    def validate_new(self, event: EventBase, config: HomeServerConfig) -> None:
        """Validates the event has roughly the right format

        Suitable for checking a locally-created event. It has stricter checks than
        is appropriate for an event received over federation (for which, see
        event_auth.validate_event_for_room_version)

        Args:
            event: The event to validate.
            config: The homeserver's configuration.
        """
        self.validate_builder(event)

        if event.format_version == EventFormatVersions.ROOM_V1_V2:
            EventID.from_string(event.event_id)

        required = [
            "auth_events",
            "content",
            "hashes",
            "origin",
            "prev_events",
            "sender",
            "type",
        ]

        for k in required:
            if k not in event:
                raise RelapseError(400, "Event does not have key %s" % (k,))

        # Check that the following keys have string values
        event_strings = ["origin"]

        for s in event_strings:
            if not isinstance(getattr(event, s), str):
                raise RelapseError(400, "'%s' not a string type" % (s,))

        # Depending on the room version, ensure the data is spec compliant JSON.
        if event.room_version.strict_canonicaljson:
            # Note that only the client controlled portion of the event is
            # checked, since we trust the portions of the event we created.
            validate_canonicaljson(event.content)

        if event.type == EventTypes.Aliases:
            if "aliases" in event.content:
                for alias in event.content["aliases"]:
                    if len(alias) > MAX_ALIAS_LENGTH:
                        raise RelapseError(
                            400,
                            (
                                "Can't create aliases longer than"
                                " %d characters" % (MAX_ALIAS_LENGTH,)
                            ),
                            Codes.INVALID_PARAM,
                        )

        elif event.type == EventTypes.Retention:
            self._validate_retention(event)

        elif event.type == EventTypes.ServerACL:
            server_acl_evaluator = server_acl_evaluator_from_event(event)
            if not server_acl_evaluator.server_matches_acl_event(
                config.server.server_name
            ):
                raise RelapseError(
                    400, "Can't create an ACL event that denies the local server"
                )

        elif event.type == EventTypes.PowerLevels:
            try:
                jsonschema.validate(
                    instance=event.content,
                    schema=POWER_LEVELS_SCHEMA,
                    cls=POWER_LEVELS_VALIDATOR,
                )
            except jsonschema.ValidationError as e:
                if e.path:
                    # example: "users_default": '0' is not of type 'integer'
                    # cast safety: path entries can be integers, if we fail to validate
                    # items in an array. However, the POWER_LEVELS_SCHEMA doesn't expect
                    # to see any arrays.
                    message = (
                        '"' + cast(str, e.path[-1]) + '": ' + e.message  # noqa: B306
                    )
                    # jsonschema.ValidationError.message is a valid attribute
                else:
                    # example: '0' is not of type 'integer'
                    message = e.message  # noqa: B306
                    # jsonschema.ValidationError.message is a valid attribute

                raise RelapseError(
                    code=400,
                    msg=message,
                    errcode=Codes.BAD_JSON,
                )

        # If the event contains a mentions key, validate it.
        if EventContentFields.MENTIONS in event.content:
            validate_json_object(event.content[EventContentFields.MENTIONS], Mentions)

    def _validate_retention(self, event: EventBase) -> None:
        """Checks that an event that defines the retention policy for a room respects the
        format enforced by the spec.

        Args:
            event: The event to validate.
        """
        if not event.is_state():
            raise RelapseError(code=400, msg="must be a state event")

        min_lifetime = event.content.get("min_lifetime")
        max_lifetime = event.content.get("max_lifetime")

        if min_lifetime is not None:
            if type(min_lifetime) is not int:  # noqa: E721
                raise RelapseError(
                    code=400,
                    msg="'min_lifetime' must be an integer",
                    errcode=Codes.BAD_JSON,
                )

        if max_lifetime is not None:
            if type(max_lifetime) is not int:  # noqa: E721
                raise RelapseError(
                    code=400,
                    msg="'max_lifetime' must be an integer",
                    errcode=Codes.BAD_JSON,
                )

        if (
            min_lifetime is not None
            and max_lifetime is not None
            and min_lifetime > max_lifetime
        ):
            raise RelapseError(
                code=400,
                msg="'min_lifetime' can't be greater than 'max_lifetime",
                errcode=Codes.BAD_JSON,
            )

    def validate_builder(self, event: Union[EventBase, EventBuilder]) -> None:
        """Validates that the builder/event has roughly the right format. Only
        checks values that we expect a proto event to have, rather than all the
        fields an event would have
        """

        strings = ["room_id", "sender", "type"]

        if hasattr(event, "state_key"):
            strings.append("state_key")

        for s in strings:
            if not isinstance(getattr(event, s), str):
                raise RelapseError(400, "Not '%s' a string type" % (s,))

        RoomID.from_string(event.room_id)
        UserID.from_string(event.sender)

        if event.type == EventTypes.Message:
            strings = ["body", "msgtype"]

            self._ensure_strings(event.content, strings)

        elif event.type == EventTypes.Topic:
            self._ensure_strings(event.content, ["topic"])
            self._ensure_state_event(event)
        elif event.type == EventTypes.Name:
            self._ensure_strings(event.content, ["name"])
            self._ensure_state_event(event)
        elif event.type == EventTypes.Member:
            if "membership" not in event.content:
                raise RelapseError(400, "Content has not membership key")

            if event.content["membership"] not in Membership.LIST:
                raise RelapseError(400, "Invalid membership key")

            self._ensure_state_event(event)
        elif event.type == EventTypes.Tombstone:
            if "replacement_room" not in event.content:
                raise RelapseError(400, "Content has no replacement_room key")

            if event.content["replacement_room"] == event.room_id:
                raise RelapseError(
                    400, "Tombstone cannot reference the room it was sent in"
                )

            self._ensure_state_event(event)

    def _ensure_strings(self, d: JsonDict, keys: StrCollection) -> None:
        for s in keys:
            if s not in d:
                raise RelapseError(400, "'%s' not in content" % (s,))
            if not isinstance(d[s], str):
                raise RelapseError(400, "'%s' not a string type" % (s,))

    def _ensure_state_event(self, event: Union[EventBase, EventBuilder]) -> None:
        if not event.is_state():
            raise RelapseError(400, "'%s' must be state events" % (event.type,))


POWER_LEVELS_SCHEMA = {
    "type": "object",
    "properties": {
        "ban": {"$ref": "#/definitions/int"},
        "events": {"$ref": "#/definitions/objectOfInts"},
        "events_default": {"$ref": "#/definitions/int"},
        "invite": {"$ref": "#/definitions/int"},
        "kick": {"$ref": "#/definitions/int"},
        "notifications": {"$ref": "#/definitions/objectOfInts"},
        "redact": {"$ref": "#/definitions/int"},
        "state_default": {"$ref": "#/definitions/int"},
        "users": {"$ref": "#/definitions/objectOfInts"},
        "users_default": {"$ref": "#/definitions/int"},
    },
    "definitions": {
        "int": {
            "type": "integer",
            "minimum": CANONICALJSON_MIN_INT,
            "maximum": CANONICALJSON_MAX_INT,
        },
        "objectOfInts": {
            "type": "object",
            "additionalProperties": {"$ref": "#/definitions/int"},
        },
    },
}


class Mentions(RequestBodyModel):
    user_ids: list[StrictStr] = Field(default_factory=list)
    room: StrictBool = False


# This could return something newer than Draft 7, but that's the current "latest"
# validator.
def _create_validator(schema: JsonDict) -> type[jsonschema.Draft7Validator]:
    validator = jsonschema.validators.validator_for(schema)

    # by default jsonschema does not consider a immutabledict to be an object so
    # we need to use a custom type checker
    # https://python-jsonschema.readthedocs.io/en/stable/validate/?highlight=object#validating-with-additional-types
    type_checker = validator.TYPE_CHECKER.redefine(
        "object", lambda checker, thing: isinstance(thing, collections.abc.Mapping)
    )

    return jsonschema.validators.extend(validator, type_checker=type_checker)


POWER_LEVELS_VALIDATOR = _create_validator(POWER_LEVELS_SCHEMA)
