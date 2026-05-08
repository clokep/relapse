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

import threading
from io import BytesIO
from typing import BinaryIO, cast
from unittest.mock import NonCallableMock

from zope.interface import implementer

from twisted.internet import defer, reactor as _reactor
from twisted.internet.interfaces import IPullProducer

from relapse.types import IRelapseReactor
from relapse.util.file_consumer import BackgroundFileConsumer

from tests import unittest

reactor = cast(IRelapseReactor, _reactor)


class FileConsumerTests(unittest.TestCase):
    async def test_pull_consumer(self) -> None:
        string_file = BytesIO()
        consumer = BackgroundFileConsumer(string_file, reactor=reactor)

        try:
            producer = DummyPullProducer()

            await producer.register_with_consumer(consumer)

            await producer.write_and_wait(b"Foo")

            self.assertEqual(string_file.getvalue(), b"Foo")

            await producer.write_and_wait(b"Bar")

            self.assertEqual(string_file.getvalue(), b"FooBar")
        finally:
            consumer.unregisterProducer()

        await consumer.wait()

        self.assertTrue(string_file.closed)

    async def test_push_consumer(self) -> None:
        string_file = BlockingBytesWrite()
        consumer = BackgroundFileConsumer(cast(BinaryIO, string_file), reactor=reactor)

        try:
            producer = NonCallableMock(spec_set=[])

            consumer.registerProducer(producer, True)

            consumer.write(b"Foo")
            await string_file.wait_for_n_writes(1)

            self.assertEqual(string_file.buffer, b"Foo")

            consumer.write(b"Bar")
            await string_file.wait_for_n_writes(2)

            self.assertEqual(string_file.buffer, b"FooBar")
        finally:
            consumer.unregisterProducer()

        await consumer.wait()

        self.assertTrue(string_file.closed)

    async def test_push_producer_feedback(
        self,
    ) -> None:
        string_file = BlockingBytesWrite()
        consumer = BackgroundFileConsumer(cast(BinaryIO, string_file), reactor=reactor)

        try:
            producer = NonCallableMock(spec_set=["pauseProducing", "resumeProducing"])

            resume_deferred: defer.Deferred = defer.Deferred()
            producer.resumeProducing.side_effect = lambda: resume_deferred.callback(
                None
            )

            consumer.registerProducer(producer, True)

            number_writes = 0
            with string_file.write_lock:
                for _ in range(consumer._PAUSE_ON_QUEUE_SIZE):
                    consumer.write(b"Foo")
                    number_writes += 1

                producer.pauseProducing.assert_called_once()

            await string_file.wait_for_n_writes(number_writes)

            await resume_deferred
            producer.resumeProducing.assert_called_once()
        finally:
            consumer.unregisterProducer()

        await consumer.wait()

        self.assertTrue(string_file.closed)


@implementer(IPullProducer)
class DummyPullProducer:
    def __init__(self) -> None:
        self.consumer: BackgroundFileConsumer | None = None
        self.deferred: defer.Deferred[object] = defer.Deferred()

    def resumeProducing(self) -> None:
        d = self.deferred
        self.deferred = defer.Deferred()
        d.callback(None)

    def stopProducing(self) -> None:
        raise RuntimeError("Unexpected call")

    def write_and_wait(self, write_bytes: bytes) -> "defer.Deferred[object]":
        assert self.consumer is not None
        d = self.deferred
        self.consumer.write(write_bytes)
        return d

    def register_with_consumer(
        self, consumer: BackgroundFileConsumer
    ) -> "defer.Deferred[object]":
        d = self.deferred
        self.consumer = consumer
        self.consumer.registerProducer(self, False)
        return d


class BlockingBytesWrite:
    def __init__(self) -> None:
        self.buffer = b""
        self.closed = False
        self.write_lock = threading.Lock()

        self._notify_write_deferred: defer.Deferred | None = None
        self._number_of_writes = 0

    def write(self, write_bytes: bytes) -> None:
        with self.write_lock:
            self.buffer += write_bytes
            self._number_of_writes += 1

        reactor.callFromThread(self._notify_write)

    def close(self) -> None:
        self.closed = True

    def _notify_write(self) -> None:
        "Called by write to indicate a write happened"
        with self.write_lock:
            if not self._notify_write_deferred:
                return
            d = self._notify_write_deferred
            self._notify_write_deferred = None
        d.callback(None)

    async def wait_for_n_writes(self, n: int) -> None:
        "Wait for n writes to have happened"
        while True:
            with self.write_lock:
                if n <= self._number_of_writes:
                    return

                if not self._notify_write_deferred:
                    self._notify_write_deferred = defer.Deferred()

                d = self._notify_write_deferred

            await d
