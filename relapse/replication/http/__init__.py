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

from typing import TYPE_CHECKING

from relapse.http.server import HttpServer
from relapse.replication.http import (
    account_data,
    devices,
    federation,
    login,
    membership,
    presence,
    push,
    register,
    send_event,
    send_events,
    state,
    streams,
)

if TYPE_CHECKING:
    from relapse.server import HomeServer

REPLICATION_PREFIX = "/_relapse/replication"


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    send_event.register_servlets(hs, http_server)
    send_events.register_servlets(hs, http_server)
    federation.register_servlets(hs, http_server)
    presence.register_servlets(hs, http_server)
    membership.register_servlets(hs, http_server)
    streams.register_servlets(hs, http_server)
    account_data.register_servlets(hs, http_server)
    push.register_servlets(hs, http_server)
    state.register_servlets(hs, http_server)

    # The following can't currently be instantiated on workers.
    if hs.config.worker.worker_app is None:
        login.register_servlets(hs, http_server)
        register.register_servlets(hs, http_server)
        devices.register_servlets(hs, http_server)
