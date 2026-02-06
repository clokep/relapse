# Copyright 2015-2021 The Matrix.org Foundation C.I.C.
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

from collections.abc import Iterable
from typing import Any

from relapse.api.constants import EventTypes
from relapse.config._base import Config
from relapse.config._util import validate_config
from relapse.types import JsonDict
from relapse.types.state import StateFilter


class ApiConfig(Config):
    section = "api"

    room_prejoin_state: StateFilter
    track_puppetted_users_ips: bool

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        validate_config(_MAIN_SCHEMA, config, ())
        self.room_prejoin_state = StateFilter.from_types(
            self._get_prejoin_state_entries(config)
        )
        self.track_puppeted_user_ips = config.get("track_puppeted_user_ips", False)

    def _get_prejoin_state_entries(
        self, config: JsonDict
    ) -> Iterable[tuple[str, str | None]]:
        """Get the event types and state keys to include in the prejoin state."""
        room_prejoin_state_config = config.get("room_prejoin_state") or {}

        if not room_prejoin_state_config.get("disable_default_event_types"):
            yield from _DEFAULT_PREJOIN_STATE_TYPES_AND_STATE_KEYS

        for entry in room_prejoin_state_config.get("additional_event_types", []):
            if isinstance(entry, str):
                yield entry, None
            else:
                yield entry


_DEFAULT_PREJOIN_STATE_TYPES_AND_STATE_KEYS = [
    (EventTypes.JoinRules, ""),
    (EventTypes.CanonicalAlias, ""),
    (EventTypes.RoomAvatar, ""),
    (EventTypes.RoomEncryption, ""),
    (EventTypes.Name, ""),
    # Per MSC1772.
    (EventTypes.Create, ""),
    # Per MSC3173.
    (EventTypes.Topic, ""),
]


# room_prejoin_state can either be None (as it is in the default config), or
# an object containing other config settings
_ROOM_PREJOIN_STATE_CONFIG_SCHEMA = {
    "oneOf": [
        {
            "type": "object",
            "properties": {
                "disable_default_event_types": {"type": "boolean"},
                "additional_event_types": {
                    "type": "array",
                    "items": {
                        "oneOf": [
                            {"type": "string"},
                            {
                                "type": "array",
                                "items": {"type": "string"},
                                "minItems": 2,
                                "maxItems": 2,
                            },
                        ],
                    },
                },
            },
        },
        {"type": "null"},
    ]
}

_MAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "room_prejoin_state": _ROOM_PREJOIN_STATE_CONFIG_SCHEMA,
        "track_puppeted_user_ips": {
            "type": "boolean",
        },
    },
}
