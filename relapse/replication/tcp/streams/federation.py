# Copyright 2017 Vector Creations Ltd
# Copyright 2019 New Vector Ltd
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
from collections.abc import Awaitable
from typing import TYPE_CHECKING, Any, Callable

import attr

from relapse.replication.tcp.streams._base import (
    Stream,
    Token,
    current_token_without_instance,
    make_http_update_function,
)
from relapse.types import JsonDict

if TYPE_CHECKING:
    from relapse.server import HomeServer


class FederationStream(Stream):
    """Data to be sent over federation. Only available when master has federation
    sending disabled.
    """

    @attr.s(slots=True, frozen=True, auto_attribs=True)
    class FederationStreamRow:
        type: str  # the type of data as defined in the BaseFederationRows
        data: JsonDict  # serialization of a federation.send_queue.BaseFederationRow

    NAME = "federation"
    ROW_TYPE = FederationStreamRow

    def __init__(self, hs: "HomeServer"):
        if hs.config.worker.worker_app is None:
            # master process: get updates from the FederationRemoteSendQueue.
            # (if the master is configured to send federation itself, federation_sender
            # will be a real FederationSender, which has stubs for current_token and
            # get_replication_rows.)
            federation_sender = hs.get_federation_sender()
            self.current_token_func = current_token_without_instance(
                federation_sender.get_current_token
            )
            update_function: Callable[
                [str, int, int, int], Awaitable[tuple[list[tuple[int, Any]], int, bool]]
            ] = federation_sender.get_replication_rows

        elif hs.should_send_federation():
            # federation sender: Query master process
            update_function = make_http_update_function(hs, self.NAME)
            self.current_token_func = self._stub_current_token

        else:
            # other worker: stub out the update function (we're not interested in
            # any updates so when we get a POSITION we do nothing)
            update_function = self._stub_update_function
            self.current_token_func = self._stub_current_token

        super().__init__(hs.get_instance_name(), update_function)

    def current_token(self, instance_name: str) -> Token:
        return self.current_token_func(instance_name)

    def minimal_local_current_token(self) -> Token:
        return self.current_token(self.local_instance_name)

    @staticmethod
    def _stub_current_token(instance_name: str) -> int:
        # dummy current-token method for use on workers
        return 0

    @staticmethod
    async def _stub_update_function(
        instance_name: str, from_token: int, upto_token: int, limit: int
    ) -> tuple[list, int, bool]:
        return [], upto_token, False
