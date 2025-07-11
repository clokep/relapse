# Copyright 2015, 2016 OpenMarket Ltd
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

from typing import Any

from relapse.types import JsonDict

from ._base import Config


class PushConfig(Config):
    section = "push"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        push_config = config.get("push") or {}
        self.push_include_content = push_config.get("include_content", True)
        self.enable_push = push_config.get("enabled", True)
        self.push_group_unread_count_by_room = push_config.get(
            "group_unread_count_by_room", True
        )

        # Whether to apply a random delay to outbound push.
        self.push_jitter_delay_ms = None
        push_jitter_delay = push_config.get("jitter_delay", None)
        if push_jitter_delay:
            self.push_jitter_delay_ms = self.parse_duration(push_jitter_delay)
