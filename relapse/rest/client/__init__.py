# Copyright 2014-2016 The Matrix.org Foundation C.I.C.
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
from relapse.rest.client import (
    account,
    account_data,
    account_validity,
    appservice_ping,
    auth,
    auth_issuer,
    capabilities,
    devices,
    directory,
    events,
    filter,
    initial_sync,
    keys,
    knock,
    login,
    login_token_request,
    logout,
    mutual_rooms,
    notifications,
    openid,
    password_policy,
    presence,
    profile,
    push_rule,
    pusher,
    read_marker,
    receipts,
    register,
    relations,
    report_event,
    room,
    room_keys,
    room_upgrade_rest_servlet,
    sendtodevice,
    sync,
    tags,
    thirdparty,
    tokenrefresh,
    user_directory,
    versions,
    voip,
    whois,
)

if TYPE_CHECKING:
    from relapse.server import HomeServer


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    # Some servlets are only registered on the main process (and not worker
    # processes).
    is_main_process = hs.config.worker.worker_app is None

    versions.register_servlets(hs, http_server)

    # Deprecated in r0
    initial_sync.register_servlets(hs, http_server)
    room.register_deprecated_servlets(hs, http_server)

    # Partially deprecated in r0
    events.register_servlets(hs, http_server)

    room.register_servlets(hs, http_server)
    login.register_servlets(hs, http_server)
    profile.register_servlets(hs, http_server)
    presence.register_servlets(hs, http_server)
    directory.register_servlets(hs, http_server)
    voip.register_servlets(hs, http_server)
    if is_main_process:
        pusher.register_servlets(hs, http_server)
    push_rule.register_servlets(hs, http_server)
    if is_main_process:
        logout.register_servlets(hs, http_server)
    sync.register_servlets(hs, http_server)
    filter.register_servlets(hs, http_server)
    account.register_servlets(hs, http_server)
    register.register_servlets(hs, http_server)
    if is_main_process:
        auth.register_servlets(hs, http_server)
    receipts.register_servlets(hs, http_server)
    read_marker.register_servlets(hs, http_server)
    room_keys.register_servlets(hs, http_server)
    keys.register_servlets(hs, http_server)
    if is_main_process:
        tokenrefresh.register_servlets(hs, http_server)
    tags.register_servlets(hs, http_server)
    account_data.register_servlets(hs, http_server)
    if is_main_process:
        report_event.register_servlets(hs, http_server)
        openid.register_servlets(hs, http_server)
    notifications.register_servlets(hs, http_server)
    devices.register_servlets(hs, http_server)
    if is_main_process:
        thirdparty.register_servlets(hs, http_server)
    sendtodevice.register_servlets(hs, http_server)
    user_directory.register_servlets(hs, http_server)
    if is_main_process:
        room_upgrade_rest_servlet.register_servlets(hs, http_server)
    capabilities.register_servlets(hs, http_server)
    if is_main_process:
        account_validity.register_servlets(hs, http_server)
    relations.register_servlets(hs, http_server)
    password_policy.register_servlets(hs, http_server)
    knock.register_servlets(hs, http_server)
    appservice_ping.register_servlets(hs, http_server)

    whois.register_servlets(hs, http_server)

    # unstable
    if is_main_process:
        mutual_rooms.register_servlets(hs, http_server)
        login_token_request.register_servlets(hs, http_server)
        auth_issuer.register_servlets(hs, http_server)
