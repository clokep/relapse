# Copyright 2015-2019 Prometheus Python Client Developers
# Copyright 2019 Matrix.org Foundation C.I.C.
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

import re

from prometheus_client import REGISTRY, CollectorRegistry, generate_latest

from twisted.web.server import Request

from relapse.http.server import finish_request
from relapse.http.servlet import RestServlet

CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"


class MetricsServlet(RestServlet):
    """
    Twisted ``Resource`` that serves prometheus metrics.
    """

    PATTERNS = [re.compile(r"/_relapse/metrics")]

    def __init__(self, registry: CollectorRegistry = REGISTRY):
        self.registry = registry

    async def on_GET(self, request: Request) -> None:
        request.setHeader(b"Content-Type", CONTENT_TYPE_LATEST.encode("ascii"))
        response = generate_latest(self.registry)
        request.setHeader(b"Content-Length", str(len(response)))
        request.write(response)
        finish_request(request)
