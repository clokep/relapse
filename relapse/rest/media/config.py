# Copyright 2018 Will Hunt <will@half-shot.uk>
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
#

import re
from typing import TYPE_CHECKING

from relapse.http.servlet import RestServlet
from relapse.http.site import RelapseRequest
from relapse.types import JsonDict

if TYPE_CHECKING:
    from relapse.server import HomeServer


class MediaConfigServlet(RestServlet):
    PATTERNS = [re.compile("/_matrix/media/(r0|v3|v1)/config$")]

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        config = hs.config
        self.clock = hs.get_clock()
        self.auth = hs.get_auth()
        self.limits_dict = {"m.upload.size": config.media.max_upload_size}

    async def on_GET(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        await self.auth.get_user_by_req(request)
        return 200, self.limits_dict
