# Copyright 2023 Beeper Inc.
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

from relapse.api.errors import LimitExceededError
from relapse.api.ratelimiting import Ratelimiter
from relapse.http.servlet import RestServlet
from relapse.http.site import RelapseRequest
from relapse.types import JsonDict

if TYPE_CHECKING:
    from relapse.media.media_repository import MediaRepository
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class CreateServlet(RestServlet):
    PATTERNS = [re.compile("/_matrix/media/v1/create")]

    def __init__(self, hs: "HomeServer", media_repo: "MediaRepository"):
        super().__init__()

        self.media_repo = media_repo
        self.clock = hs.get_clock()
        self.auth = hs.get_auth()
        self.max_pending_media_uploads = hs.config.media.max_pending_media_uploads

        # A rate limiter for creating new media IDs.
        self._create_media_rate_limiter = Ratelimiter(
            store=hs.get_datastores().main,
            clock=self.clock,
            cfg=hs.config.ratelimiting.rc_media_create,
        )

    async def on_POST(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        # If the create media requests for the user are over the limit, drop them.
        await self._create_media_rate_limiter.ratelimit(requester)

        (
            reached_pending_limit,
            first_expiration_ts,
        ) = await self.media_repo.reached_pending_media_limit(requester.user)
        if reached_pending_limit:
            raise LimitExceededError(
                limiter_name="max_pending_media_uploads",
                retry_after_ms=first_expiration_ts - self.clock.time_msec(),
            )

        content_uri, unused_expires_at = await self.media_repo.create_media_id(
            requester.user
        )

        logger.info(
            "Created Media URI %r that if unused will expire at %d",
            content_uri,
            unused_expires_at,
        )
        return 200, {
            "content_uri": content_uri,
            "unused_expires_at": unused_expires_at,
        }
