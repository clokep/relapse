# Copyright 2016 OpenMarket Ltd
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

from collections.abc import Callable, Iterable
from typing import Any, Optional
from unittest.mock import Mock

from twisted.internet.testing import MemoryReactor

from relapse.server import HomeServer
from relapse.util import Clock

from tests.replication._base import BaseStreamTestCase


class BaseWorkerStoreTestCase(BaseStreamTestCase):
    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        return self.setup_test_homeserver(federation_client=Mock())

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        super().prepare(reactor, clock, hs)

        self.reconnect()

        self.master_store = hs.get_datastores().main
        self.worker_store = self.worker_hs.get_datastores().main
        persistence = hs.get_storage_controllers().persistence
        assert persistence is not None
        self.persistance = persistence

    def replicate(self) -> None:
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        self.streamer.on_notifier_poke()
        self.pump(0.1)

    def check(
        self,
        method: str,
        args: Iterable[Any],
        expected_result: Optional[Any] = None,
        asserter: Optional[Callable[[Any, Any, Optional[Any]], None]] = None,
    ) -> None:
        if asserter is None:
            asserter = self.assertEqual

        master_result = self.get_success(getattr(self.master_store, method)(*args))
        worker_result = self.get_success(getattr(self.worker_store, method)(*args))
        if expected_result is not None:
            asserter(
                master_result,
                expected_result,
                f"Expected master result to be {expected_result!r} but was {master_result!r}",
            )
            asserter(
                worker_result,
                expected_result,
                f"Expected worker result to be {expected_result!r} but was {worker_result!r}",
            )
        asserter(
            master_result,
            worker_result,
            f"Worker result {worker_result!r} does not match master result {master_result!r}",
        )
