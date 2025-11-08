# Copyright 2018 New Vector Ltd
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
from typing import TYPE_CHECKING, Optional

from twisted.web.server import Request

from relapse.http.server import (
    HttpServer,
    finish_request,
    set_cors_headers,
)
from relapse.http.servlet import RestServlet
from relapse.http.site import RelapseRequest
from relapse.types import JsonDict
from relapse.util import json_encoder
from relapse.util.stringutils import parse_server_name

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class WellKnownBuilder:
    def __init__(self, hs: "HomeServer"):
        self._config = hs.config

    def get_well_known(self) -> Optional[JsonDict]:
        if not self._config.server.serve_client_wellknown:
            return None

        result = {"m.homeserver": {"base_url": self._config.server.public_baseurl}}

        if self._config.registration.default_identity_server:
            result["m.identity_server"] = {
                "base_url": self._config.registration.default_identity_server
            }

        # We use the MSC3861 values as they are used by multiple MSCs
        if self._config.experimental.msc3861.enabled:
            result["org.matrix.msc2965.authentication"] = {
                "issuer": self._config.experimental.msc3861.issuer
            }
            if self._config.experimental.msc3861.account_management_url is not None:
                result["org.matrix.msc2965.authentication"]["account"] = (
                    self._config.experimental.msc3861.account_management_url
                )

        if self._config.server.extra_well_known_client_content:
            for (
                key,
                value,
            ) in self._config.server.extra_well_known_client_content.items():
                if key not in result:
                    result[key] = value

        return result


class ClientWellKnownServlet(RestServlet):
    """A servlet which renders the .well-known/matrix/client file"""

    PATTERNS = [re.compile(r"/.well-known/matrix/client")]

    def __init__(self, hs: "HomeServer"):
        self._well_known_builder = WellKnownBuilder(hs)

    async def on_GET(self, request: RelapseRequest) -> None:
        set_cors_headers(request)
        r = self._well_known_builder.get_well_known()
        if not r:
            request.setResponseCode(404)
            request.setHeader(b"Content-Type", b"text/plain")
            request.write(b".well-known not available")
        else:
            logger.debug("returning: %s", r)
            request.setHeader(b"Content-Type", b"application/json")
            request.write(json_encoder.encode(r).encode("utf-8"))

        finish_request(request)
        return None


class ServerWellKnownServlet(RestServlet):
    """Servlet for .well-known/matrix/server, redirecting to port 443"""

    PATTERNS = [re.compile(r"/.well-known/matrix/server")]

    def __init__(self, hs: "HomeServer"):
        self._serve_server_wellknown = hs.config.server.serve_server_wellknown

        host, port = parse_server_name(hs.config.server.server_name)

        # If we've got this far, then https://<server_name>/ must route to us, so
        # we just redirect the traffic to port 443 instead of 8448.
        if port is None:
            port = 443

        self._response = json_encoder.encode({"m.server": f"{host}:{port}"}).encode(
            "utf-8"
        )

    async def on_GET(self, request: Request) -> None:
        if not self._serve_server_wellknown:
            request.setResponseCode(404)
            request.setHeader(b"Content-Type", b"text/plain")
            request.write(b"404. Is anything ever truly *well* known?\n")
        else:
            request.setHeader(b"Content-Type", b"application/json")
            request.write(self._response)
        finish_request(request)
        return None


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ServerWellKnownServlet(hs).register(http_server)
    ClientWellKnownServlet(hs).register(http_server)
