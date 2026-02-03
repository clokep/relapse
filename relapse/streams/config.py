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
import logging
from typing import Optional

import attr

from relapse.api.constants import Direction
from relapse.api.errors import RelapseError
from relapse.http.servlet import parse_enum, parse_integer, parse_string
from relapse.http.site import RelapseRequest
from relapse.storage.databases.main import DataStore
from relapse.types import StreamToken

logger = logging.getLogger(__name__)


MAX_LIMIT = 1000


@attr.s(slots=True, auto_attribs=True)
class PaginationConfig:
    """A configuration object which stores pagination parameters."""

    from_token: Optional[StreamToken]
    to_token: Optional[StreamToken]
    direction: Direction
    limit: int

    @classmethod
    async def from_request(
        cls,
        store: "DataStore",
        request: RelapseRequest,
        default_limit: int,
        default_dir: Direction = Direction.FORWARDS,
    ) -> "PaginationConfig":
        direction = parse_enum(request, "dir", Direction, default=default_dir)

        from_tok_str = parse_string(request, "from")
        to_tok_str = parse_string(request, "to")

        try:
            from_tok = None
            if from_tok_str == "END":
                from_tok = None  # For backwards compat.
            elif from_tok_str:
                from_tok = await StreamToken.from_string(store, from_tok_str)
        except Exception:
            raise RelapseError(400, "'from' parameter is invalid")

        try:
            to_tok = None
            if to_tok_str:
                to_tok = await StreamToken.from_string(store, to_tok_str)
        except Exception:
            raise RelapseError(400, "'to' parameter is invalid")

        limit = parse_integer(request, "limit", default=default_limit)
        if limit < 0:
            raise RelapseError(400, "Limit must be 0 or above")

        limit = min(limit, MAX_LIMIT)

        try:
            return PaginationConfig(from_tok, to_tok, direction, limit)
        except Exception:
            logger.exception("Failed to create pagination config")
            raise RelapseError(400, "Invalid request.")

    def __repr__(self) -> str:
        return f"PaginationConfig(from_tok={self.from_token!r}, to_tok={self.to_token!r}, direction={self.direction!r}, limit={self.limit!r})"
