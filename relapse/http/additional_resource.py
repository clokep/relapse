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

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from twisted.web.server import Request

from relapse.http.server import DirectServeJsonResource

if TYPE_CHECKING:
    from relapse.server import HomeServer


class AdditionalResource(DirectServeJsonResource):
    """Resource wrapper for additional_resources

    If the user has configured additional_resources, we need to wrap the
    handler class with a Resource so that we can map it into the resource tree.

    This class is also where we wrap the request handler with logging, metrics,
    and exception handling.
    """

    def __init__(
        self,
        hs: "HomeServer",
        handler: Callable[[Request], Awaitable[tuple[int, Any] | None]],
    ):
        """Initialise AdditionalResource

        The ``handler`` should return a deferred which completes when it has
        done handling the request. It should write a response with
        ``request.write()``, and call ``request.finish()``.

        Args:
            hs: homeserver
            handler: function to be called to handle the request.
        """
        super().__init__()
        self._handler = handler

    async def _async_render(self, request: Request) -> tuple[int, Any] | None:
        # Cheekily pass the result straight through, so we don't need to worry
        # if its an awaitable or not.
        return await self._handler(request)
